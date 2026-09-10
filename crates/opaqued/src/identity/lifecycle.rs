//! Broker-owned provider-neutral lifecycle state and scoped management ingress.
//! Source adapters never access this database. Every update and final dispatch
//! use the same identity writer lock, so revocation cannot race authorization.
use super::{IdentityRuntime, store::IdentityStore};
use opaque_core::{
    identity::{PrincipalId, PrincipalKind, Role, now_unix, roles_from_string, roles_to_string},
    identity_lifecycle::{
        LifecycleBatch, LifecycleReceipt, LifecycleRequest, LifecycleResponse, MAX_BATCH_BYTES,
        MAX_BATCH_UPDATES, MAX_REQUEST_BYTES,
    },
    tenant::TenantBinding,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
const MAX_SUBJECTS: i64 = 10_000;
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS identity_authority_epochs(principal_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL CHECK(epoch>0));
INSERT OR IGNORE INTO identity_authority_epochs SELECT id,1 FROM principals;
CREATE TRIGGER IF NOT EXISTS identity_authority_insert AFTER INSERT ON principals BEGIN
 INSERT INTO identity_authority_epochs VALUES(NEW.id,1);
END;
CREATE TRIGGER IF NOT EXISTS identity_authority_change AFTER UPDATE ON principals
WHEN OLD.roles IS NOT NEW.roles OR OLD.disabled IS NOT NEW.disabled OR OLD.iss IS NOT NEW.iss OR OLD.sub IS NOT NEW.sub
BEGIN
 UPDATE identity_authority_epochs SET epoch=epoch+1 WHERE principal_id=NEW.id;
 UPDATE human_sessions SET revoked_at=COALESCE(revoked_at,CAST(strftime('%s','now') AS INTEGER)) WHERE principal_id=NEW.id;
 UPDATE delegations SET revoked_at=COALESCE(revoked_at,CAST(strftime('%s','now') AS INTEGER)) WHERE sub_principal=NEW.id OR act_principal=NEW.id OR approved_by=NEW.id;
END;
CREATE TABLE IF NOT EXISTS lifecycle_config(singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL, issuer TEXT NOT NULL, mapping TEXT NOT NULL, admission TEXT NOT NULL, revision INTEGER NOT NULL, source_revision INTEGER NOT NULL DEFAULT 0, source_digest TEXT NOT NULL DEFAULT '', suspended INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS lifecycle_subjects(subject TEXT PRIMARY KEY, principal_id TEXT NOT NULL UNIQUE, active INTEGER NOT NULL, deleted INTEGER NOT NULL, groups_json TEXT NOT NULL);
"#;
fn sql<T>(result: rusqlite::Result<T>) -> Result<T, String> {
    result.map_err(|_| "identity lifecycle store unavailable".into())
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn legacy_state(conn: &Connection) -> Result<bool, String> {
    let exists: bool = sql(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='scim_config')",
        [],
        |r| r.get(0),
    ))?;
    if !exists {
        return Ok(false);
    }
    sql(conn.query_row("SELECT EXISTS(SELECT 1 FROM scim_config)", [], |r| r.get(0)))
}
pub(super) fn ensure_schema(conn: &Connection) -> Result<(), String> {
    if legacy_state(conn)? {
        return Err("legacy managed identity state requires explicit offline migration; refusing to recreate authority".into());
    }
    super::provisioning::ensure_schema(conn)?;
    super::persona::ensure_schema(conn)?;
    sql(conn.execute_batch(SCHEMA))
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleConfig {
    pub socket_path: PathBuf,
    pub allowed_adapter_uids: BTreeSet<u32>,
    #[serde(default)]
    pub socket_gid: Option<u32>,
    pub token_file: PathBuf,
    /// Trusted mappings. Management requests contain memberships, never roles.
    #[serde(default)]
    pub group_roles: BTreeMap<String, Vec<String>>,
}
impl LifecycleConfig {
    fn mapping(&self) -> Result<BTreeMap<String, BTreeSet<Role>>, String> {
        if self.allowed_adapter_uids.is_empty()
            || self.allowed_adapter_uids.len() > 32
            || self.group_roles.len() > 128
        {
            return Err(
                "lifecycle ingress requires explicit adapter UIDs and bounded role mappings".into(),
            );
        }
        self.group_roles
            .iter()
            .map(|(id, roles)| {
                if !identifier(id) {
                    return Err("invalid lifecycle group identifier".into());
                }
                Ok((
                    id.clone(),
                    roles_from_string(&roles.join(",")).map_err(|_| "invalid lifecycle role")?,
                ))
            })
            .collect()
    }
}
#[derive(Clone)]
struct Service {
    runtime: Arc<IdentityRuntime>,
    binding: TenantBinding,
    token_hash: [u8; 32],
}
pub async fn start(
    config: LifecycleConfig,
    runtime: Arc<IdentityRuntime>,
    binding: TenantBinding,
    state_dir: &Path,
) -> Result<tokio::task::JoinHandle<()>, String> {
    binding.validate().map_err(|_| "invalid lifecycle tenant")?;
    if !runtime.config.required || runtime.config.allowed_subjects.is_empty() {
        return Err("lifecycle requires required identity and explicit subject admission".into());
    }
    if config.token_file.parent() != Some(state_dir)
        || config.token_file.file_name().and_then(|s| s.to_str())
            != Some("identity-lifecycle.token")
    {
        return Err(
            "dedicated identity-lifecycle.token must be directly inside broker custody".into(),
        );
    }
    let mapping = config.mapping()?;
    let token = read_token(&config.token_file)?;
    let (listener, endpoint) = bind_endpoint(&config).await?;
    runtime.store.configure_lifecycle(
        &binding,
        &runtime.config.issuer,
        &mapping,
        &runtime.config.allowed_subjects,
    )?;
    let service = Service {
        runtime,
        binding,
        token_hash: Sha256::digest(token.as_bytes()).into(),
    };
    Ok(tokio::spawn(async move {
        let endpoint = Arc::new(endpoint);
        let permits = Arc::new(tokio::sync::Semaphore::new(32));
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::error!(%error, "lifecycle ingress stopped");
                    break;
                }
            };
            use std::os::fd::AsRawFd;
            let Ok(peer) = opaque_core::peer::peer_info_from_fd(stream.as_raw_fd()) else {
                continue;
            };
            if !config.allowed_adapter_uids.contains(&peer.uid) {
                continue;
            }
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let service = service.clone();
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                let _endpoint = endpoint;
                let _permit = permit;
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    handle(service, stream),
                )
                .await;
            });
        }
    }))
}
// Hold endpoint exclusion through shutdown. A stopped broker's owned socket
// can be retired only after acquiring its lifetime writer lock and observing
// connection refusal. Existing listeners and foreign filesystem objects stay.
struct Endpoint {
    path: PathBuf,
    device: u64,
    inode: u64,
    _writer: std::fs::File,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.dev() == self.device && m.ino() == self.inode)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
async fn bind_endpoint(
    config: &LifecycleConfig,
) -> Result<(tokio::net::UnixListener, Endpoint), String> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    opaque_core::identity_lifecycle::validate_socket_path(&config.socket_path, unsafe {
        libc::geteuid()
    })?;
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(config.socket_path.with_extension("writer"))
        .map_err(|_| "lifecycle endpoint writer unavailable")?;
    let metadata = writer
        .metadata()
        .map_err(|_| "lifecycle endpoint writer unavailable")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7077 != 0
        || metadata.nlink() != 1
    {
        return Err("lifecycle endpoint writer must be owner-only and unshared".into());
    }
    if unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("lifecycle endpoint already has a writer".into());
    }
    match std::fs::symlink_metadata(&config.socket_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
                return Err("lifecycle endpoint is not a broker-owned socket".into());
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::net::UnixStream::connect(&config.socket_path),
            )
            .await
            {
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(&config.socket_path)
                        .map_err(|_| "stale lifecycle endpoint unavailable")?;
                }
                _ => {
                    return Err(
                        "lifecycle endpoint is already active or cannot be safely retired".into(),
                    );
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("lifecycle endpoint unavailable".into()),
    }
    let listener = tokio::net::UnixListener::bind(&config.socket_path)
        .map_err(|_| "lifecycle listener unavailable")?;
    let metadata = std::fs::symlink_metadata(&config.socket_path)
        .map_err(|_| "lifecycle endpoint unavailable")?;
    let endpoint = Endpoint {
        path: config.socket_path.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
        _writer: writer,
    };
    if let Some(gid) = config.socket_gid {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(config.socket_path.as_os_str().as_bytes())
            .map_err(|_| "invalid lifecycle path")?;
        if unsafe { libc::chown(path.as_ptr(), u32::MAX, gid) } != 0 {
            return Err("lifecycle socket group unavailable".into());
        }
    }
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o660))
        .map_err(|_| "lifecycle socket permissions unavailable")?;
    Ok((listener, endpoint))
}
async fn handle(service: Service, mut stream: tokio::net::UnixStream) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let length = stream
        .read_u32()
        .await
        .map_err(|_| "lifecycle request unavailable")? as usize;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err("lifecycle request exceeds bound".into());
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "lifecycle request unavailable")?;
    let request: LifecycleRequest =
        serde_json::from_slice(&bytes).map_err(|_| "invalid lifecycle request")?;
    let hash: [u8; 32] = Sha256::digest(request.credential.as_bytes()).into();
    let valid = (32..=128).contains(&request.credential.len())
        && hash
            .iter()
            .zip(service.token_hash)
            .fold(0u8, |d, (a, b)| d | (a ^ b))
            == 0;
    let outcome = if !valid {
        Err("dedicated lifecycle credential required".into())
    } else if serde_json::to_vec(&request.batch)
        .map_err(|_| "invalid lifecycle batch")?
        .len()
        > MAX_BATCH_BYTES
    {
        Err("lifecycle batch exceeds bound".into())
    } else {
        // Peer/credential authentication never substitutes for exact tenant,
        // issuer, revision, subject and role authorization under writer lock.
        service.runtime.store.apply_lifecycle(
            &service.binding,
            &service.runtime.config.issuer,
            &request.batch,
        )
    };
    let response = match outcome {
        Ok(receipt) => {
            service.runtime.emit_audit(
                opaque_core::audit::AuditEvent::new(
                    opaque_core::audit::AuditEventKind::IdentityRoleChanged,
                )
                .with_operation("identity.lifecycle.apply")
                .with_outcome("applied")
                .with_detail(format!(
                    "revision={} digest={}",
                    receipt.revision, receipt.digest
                )),
            );
            LifecycleResponse::Applied { receipt }
        }
        Err(error) => LifecycleResponse::Rejected { error },
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| "invalid lifecycle response")?;
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| "lifecycle response unavailable")?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| "lifecycle response unavailable")?;
    Ok(())
}
fn read_token(path: &Path) -> Result<zeroize::Zeroizing<String>, String> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "Lifecycle management credential unavailable")?;
    let meta = file
        .metadata()
        .map_err(|_| "Lifecycle management credential unavailable")?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7077 != 0
        || meta.nlink() != 1
        || meta.len() > 256
    {
        return Err("Lifecycle management credential must be a private owned regular file".into());
    }
    let mut token = zeroize::Zeroizing::new(String::new());
    file.read_to_string(&mut token)
        .map_err(|_| "Lifecycle management credential unavailable")?;
    if token.len() < 32
        || token.len() > 128
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(
            "Lifecycle management credential must be 32..128 random URL-safe bytes without whitespace".into(),
        );
    }
    Ok(token)
}

fn invalidate(conn: &Connection, id: &str, now: i64) -> Result<(), String> {
    sql(conn.execute(
        "UPDATE identity_authority_epochs SET epoch=epoch+1 WHERE principal_id=?1",
        [id],
    ))?;
    sql(conn.execute(
        "UPDATE human_sessions SET revoked_at=COALESCE(revoked_at,?2) WHERE principal_id=?1",
        params![id, now],
    ))?;
    sql(conn.execute("UPDATE delegations SET revoked_at=COALESCE(revoked_at,?2) WHERE sub_principal=?1 OR act_principal=?1 OR approved_by=?1",params![id,now]))?;
    sql(conn.execute(
        "UPDATE provisioning_principal_epochs SET epoch=epoch+1 WHERE principal_id=?1",
        [id],
    ))?;
    sql(conn.execute("UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,?2) WHERE issuer=?1 OR service=?1",params![id,now]))?;
    sql(conn.execute("UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,?2) WHERE recipient=?1 OR parent_id IN(SELECT id FROM provisioning_mandates WHERE issuer=?1 OR service=?1)",params![id,now]))?;
    sql(conn.execute("UPDATE persona_snapshots SET revision=revision+1,observed_at=0,issued_at=0,expires_at=0 WHERE principal_id=?1",[id]))?;
    Ok(())
}
fn refresh_subject(
    conn: &Connection,
    subject: &str,
    mapping: &BTreeMap<String, BTreeSet<Role>>,
    admission: &[String],
    suspended: bool,
) -> Result<(), String> {
    let (id, active, deleted, groups): (String, bool, bool, String) = sql(conn.query_row(
        "SELECT principal_id,active,deleted,groups_json FROM lifecycle_subjects WHERE subject=?1",
        [subject],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ))?;
    let groups: Vec<String> =
        serde_json::from_str(&groups).map_err(|_| "lifecycle memberships unavailable")?;
    let enabled = active && !deleted && !suspended && admission.iter().any(|s| s == subject);
    let roles: BTreeSet<Role> = if enabled {
        groups
            .iter()
            .filter_map(|g| mapping.get(g))
            .flat_map(|roles| roles.iter().copied())
            .collect()
    } else {
        BTreeSet::new()
    };
    sql(conn.execute(
        "UPDATE principals SET roles=?2,disabled=?3 WHERE id=?1",
        params![id, roles_to_string(&roles), !enabled],
    ))?;
    invalidate(conn, &id, now_unix())
}
impl IdentityStore {
    pub fn authority_epoch(&self, id: &PrincipalId) -> Result<u64, String> {
        sql(self.lock().query_row(
            "SELECT epoch FROM identity_authority_epochs WHERE principal_id=?1",
            [id.as_str()],
            |r| r.get(0),
        ))
    }
    pub fn lifecycle_revision(&self) -> Result<i64, String> {
        sql(self
            .lock()
            .query_row(
                "SELECT revision FROM lifecycle_config WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional())
        .map(|r| r.unwrap_or(0))
    }
    pub fn configure_lifecycle(
        &self,
        binding: &TenantBinding,
        issuer: &str,
        mapping: &BTreeMap<String, BTreeSet<Role>>,
        admitted_subjects: &[String],
    ) -> Result<(), String> {
        binding
            .validate()
            .map_err(|_| "invalid lifecycle binding")?;
        if admitted_subjects.is_empty()
            || admitted_subjects.len() > MAX_SUBJECTS as usize
            || admitted_subjects.iter().any(|s| !identifier(s))
        {
            return Err("bounded explicit lifecycle admission required".into());
        }
        let mut admission = admitted_subjects.to_vec();
        admission.sort();
        admission.dedup();
        let admission_json = serde_json::to_string(&admission).map_err(|_| "invalid admission")?;
        let binding_json = serde_json::to_string(binding).map_err(|_| "invalid binding")?;
        let mapping_json = serde_json::to_string(mapping).map_err(|_| "invalid mapping")?;
        let mut conn = self.lock();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let old:Option<(String,String,String,String,bool)>=sql(tx.query_row("SELECT binding,issuer,mapping,admission,suspended FROM lifecycle_config WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional())?;
        if old
            .as_ref()
            .is_some_and(|(b, i, _, _, _)| b != &binding_json || i != issuer)
        {
            return Err("lifecycle tenant/issuer cannot be rebound".into());
        }
        if old.as_ref().is_some_and(|(_, _, _, _, s)| *s) {
            return Err("lifecycle source suspended; explicit offline recovery required".into());
        }
        if old
            .as_ref()
            .is_none_or(|(_, _, m, a, _)| m != &mapping_json || a != &admission_json)
        {
            sql(tx.execute("INSERT INTO lifecycle_config(singleton,binding,issuer,mapping,admission,revision) VALUES(1,?1,?2,?3,?4,1) ON CONFLICT(singleton) DO UPDATE SET mapping=excluded.mapping,admission=excluded.admission,revision=revision+1",params![binding_json,issuer,mapping_json,admission_json]))?;
            let subjects: Vec<String> = sql(tx.prepare("SELECT subject FROM lifecycle_subjects"))?
                .query_map([], |r| r.get(0))
                .map_err(|_| "lifecycle subjects unavailable")?
                .collect::<rusqlite::Result<_>>()
                .map_err(|_| "lifecycle subjects unavailable")?;
            for subject in subjects {
                refresh_subject(&tx, &subject, mapping, &admission, false)?;
            }
            let ids:Vec<String>=sql(tx.prepare("SELECT id FROM principals WHERE kind='human' AND NOT EXISTS(SELECT 1 FROM lifecycle_subjects s WHERE s.principal_id=principals.id)"))?.query_map([],|r|r.get(0)).map_err(|_|"principals unavailable")?.collect::<rusqlite::Result<_>>().map_err(|_|"principals unavailable")?;
            for id in ids {
                sql(tx.execute(
                    "UPDATE principals SET disabled=1,roles='' WHERE id=?1",
                    [&id],
                ))?;
                invalidate(&tx, &id, now_unix())?;
            }
        }
        sql(tx.commit())
    }
    pub fn apply_lifecycle(
        &self,
        binding: &TenantBinding,
        issuer: &str,
        batch: &LifecycleBatch,
    ) -> Result<LifecycleReceipt, String> {
        if batch.schema_version != 1
            || &batch.binding != binding
            || batch.issuer != issuer
            || batch.revision == 0
            || batch.revision > i64::MAX as u64
            || batch.updates.len() > MAX_BATCH_UPDATES
            || (batch.suspend && !batch.updates.is_empty())
        {
            return Err("lifecycle scope, operation or revision denied".into());
        }
        let mut seen = BTreeSet::new();
        for update in &batch.updates {
            let groups: BTreeSet<_> = update.groups.iter().collect();
            if !identifier(&update.subject)
                || !seen.insert(&update.subject)
                || update.groups.len() > 128
                || groups.len() != update.groups.len()
                || update.groups.iter().any(|g| !identifier(g))
                || (update.deleted && (update.active || !update.groups.is_empty()))
            {
                return Err("invalid lifecycle subject update".into());
            }
        }
        let bytes = serde_json::to_vec(batch).map_err(|_| "invalid lifecycle batch")?;
        if bytes.len() > MAX_BATCH_BYTES {
            return Err("lifecycle batch exceeds bound".into());
        }
        let digest = format!("{:x}", Sha256::digest(bytes));
        let receipt = LifecycleReceipt {
            schema_version: 1,
            binding: binding.clone(),
            issuer: issuer.into(),
            revision: batch.revision,
            digest: digest.clone(),
        };
        let mut conn = self.lock();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let (b,i,mapping,admission,source_revision,source_digest,suspended):(String,String,String,String,u64,String,bool)=sql(tx.query_row("SELECT binding,issuer,mapping,admission,source_revision,source_digest,suspended FROM lifecycle_config WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))))?;
        if b != serde_json::to_string(binding).map_err(|_| "invalid binding")? || i != issuer {
            return Err("management tenant/issuer not authorized".into());
        }
        if batch.revision == source_revision && digest == source_digest {
            return Ok(receipt);
        }
        if suspended || source_revision.checked_add(1) != Some(batch.revision) {
            return Err("source revision stale, conflicting, skipped or suspended".into());
        }
        let mapping: BTreeMap<String, BTreeSet<Role>> =
            serde_json::from_str(&mapping).map_err(|_| "mapping unavailable")?;
        let admission: Vec<String> =
            serde_json::from_str(&admission).map_err(|_| "admission unavailable")?;
        for update in &batch.updates {
            let previous:Option<(String,bool,bool,String)>=sql(tx.query_row("SELECT principal_id,active,deleted,groups_json FROM lifecycle_subjects WHERE subject=?1",[&update.subject],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional())?;
            if previous
                .as_ref()
                .is_some_and(|(_, _, deleted, _)| *deleted && !update.deleted)
            {
                return Err("permanent lifecycle tombstone cannot be restored".into());
            }
            if !admission.contains(&update.subject) && (update.active || previous.is_none()) {
                return Err("subject outside trusted issuer admission".into());
            }
            let groups = serde_json::to_string(&update.groups).map_err(|_| "invalid groups")?;
            if previous.as_ref().is_some_and(|(_, active, deleted, g)| {
                *active == update.active && *deleted == update.deleted && g == &groups
            }) {
                continue;
            }
            let principal = match previous {
                Some((id, _, _, _)) => id,
                None => {
                    let count: i64 = sql(tx.query_row(
                        "SELECT COUNT(*) FROM lifecycle_subjects",
                        [],
                        |r| r.get(0),
                    ))?;
                    if count >= MAX_SUBJECTS {
                        return Err(
                            "lifecycle subject capacity exhausted; recovery required".into()
                        );
                    }
                    let existing: Option<String> = sql(tx
                        .query_row(
                            "SELECT id FROM principals WHERE kind='human' AND iss=?1 AND sub=?2",
                            params![issuer, update.subject],
                            |r| r.get(0),
                        )
                        .optional())?;
                    let id = existing.unwrap_or_else(|| {
                        PrincipalId::generate(&PrincipalKind::Human {
                            iss: issuer.into(),
                            sub: update.subject.clone(),
                            email: None,
                            name: None,
                        })
                        .as_str()
                        .to_string()
                    });
                    sql(tx.execute("INSERT OR IGNORE INTO principals(id,kind,iss,sub,roles,created_at,last_seen,disabled) VALUES(?1,'human',?2,?3,'',?4,?4,1)",params![id,issuer,update.subject,now_unix()]))?;
                    id
                }
            };
            sql(tx.execute("INSERT INTO lifecycle_subjects VALUES(?1,?2,?3,?4,?5) ON CONFLICT(subject) DO UPDATE SET active=excluded.active,deleted=excluded.deleted,groups_json=excluded.groups_json",params![update.subject,principal,update.active,update.deleted,groups]))?;
            refresh_subject(&tx, &update.subject, &mapping, &admission, false)?;
        }
        if batch.suspend {
            let ids: Vec<String> = sql(tx.prepare("SELECT id FROM principals WHERE kind='human'"))?
                .query_map([], |r| r.get(0))
                .map_err(|_| "principals unavailable")?
                .collect::<rusqlite::Result<_>>()
                .map_err(|_| "principals unavailable")?;
            for id in ids {
                sql(tx.execute(
                    "UPDATE principals SET disabled=1,roles='' WHERE id=?1",
                    [&id],
                ))?;
                invalidate(&tx, &id, now_unix())?;
            }
        }
        sql(tx.execute("UPDATE lifecycle_config SET source_revision=?1,source_digest=?2,revision=revision+1,suspended=?3 WHERE singleton=1",params![batch.revision,digest,batch.suspend]))?;
        sql(tx.commit())?;
        Ok(receipt)
    }
}
pub(super) fn provisioning_group_permitted(
    conn: &Connection,
    id: &PrincipalId,
    group: &str,
) -> Result<bool, String> {
    let enabled: bool = sql(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM lifecycle_config)",
        [],
        |r| r.get(0),
    ))?;
    if !enabled {
        return Ok(true);
    }
    sql(conn.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_subjects s JOIN lifecycle_config c ON c.singleton=1 JOIN json_each(s.groups_json) g WHERE s.principal_id=?1 AND s.active=1 AND s.deleted=0 AND c.suspended=0 AND g.value=?2)",params![id.as_str(),group],|r|r.get(0)))
}
/// Read-only pre-initialization probe; old managed databases explicitly remain
/// fenced until migrated. No protocol adapter gets access to this database.
pub fn persisted_lifecycle(state_dir: &Path) -> Result<bool, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = state_dir.join("identity.db");
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("persisted identity unavailable".into()),
    };
    let meta = file
        .metadata()
        .map_err(|_| "persisted identity unavailable")?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7077 != 0 {
        return Err("persisted identity must be privately owned".into());
    }
    let conn = sql(Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ))?;
    if legacy_state(&conn)? {
        return Err("legacy managed identity state requires explicit offline migration".into());
    }
    let exists: bool = sql(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifecycle_config')",
        [],
        |r| r.get(0),
    ))?;
    if !exists {
        return Ok(false);
    }
    sql(
        conn.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_config)", [], |r| {
            r.get(0)
        }),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::identity_lifecycle::SubjectUpdate;
    use serde_json::json;
    #[tokio::test]
    async fn socket_writer_excludes_live_listener_and_recovers_only_owned_stale_socket() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .prefix("oqlc-")
            .tempdir_in(Path::new("/tmp").canonicalize().unwrap())
            .unwrap();
        let config = LifecycleConfig {
            socket_path: dir.path().join("lifecycle.sock"),
            token_file: dir.path().join("unused.token"),
            allowed_adapter_uids: BTreeSet::from([unsafe { libc::geteuid() }]),
            socket_gid: None,
            group_roles: BTreeMap::new(),
        };
        let (listener, endpoint) = bind_endpoint(&config).await.unwrap();
        assert!(
            bind_endpoint(&config)
                .await
                .err()
                .unwrap()
                .contains("already has a writer")
        );
        assert!(
            tokio::net::UnixStream::connect(&config.socket_path)
                .await
                .is_ok()
        );
        drop(listener);
        drop(endpoint);
        let stale = tokio::net::UnixListener::bind(&config.socket_path).unwrap();
        drop(stale);
        let (listener, endpoint) = bind_endpoint(&config).await.unwrap();
        drop(listener);
        drop(endpoint);
        std::fs::write(&config.socket_path, "preserve this non-socket").unwrap();
        assert!(bind_endpoint(&config).await.is_err());
        assert_eq!(
            std::fs::read_to_string(&config.socket_path).unwrap(),
            "preserve this non-socket"
        );
        std::fs::remove_file(&config.socket_path).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(bind_endpoint(&config).await.is_err());
    }
    struct Fixture {
        runtime: Arc<IdentityRuntime>,
        binding: TenantBinding,
        dir: tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_issuer("https://idp.example")
        }
        fn with_issuer(issuer: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config=serde_json::from_value(json!({"issuer":issuer,"client_id":"lifecycle-fixture","required":true,"allowed_subjects":["alice","bob"]})).unwrap();
            let runtime = Arc::new(IdentityRuntime::initialize(config, dir.path()).unwrap());
            let binding = TenantBinding::new(
                opaque_core::tenant::TenantId::parse("tenant-a").unwrap(),
                uuid::Uuid::new_v4(),
            )
            .unwrap();
            runtime
                .store
                .configure_lifecycle(
                    &binding,
                    &runtime.config.issuer,
                    &BTreeMap::from([(
                        "reviewers".into(),
                        BTreeSet::from([Role::Approver, Role::Operator]),
                    )]),
                    &runtime.config.allowed_subjects,
                )
                .unwrap();
            Self {
                runtime,
                binding,
                dir,
            }
        }
        fn batch(&self, revision: u64, active: bool, groups: &[&str]) -> LifecycleBatch {
            LifecycleBatch {
                schema_version: 1,
                binding: self.binding.clone(),
                issuer: self.runtime.config.issuer.clone(),
                revision,
                updates: vec![SubjectUpdate {
                    subject: "alice".into(),
                    active,
                    deleted: false,
                    groups: groups.iter().map(|s| s.to_string()).collect(),
                }],
                suspend: false,
            }
        }
        fn apply(&self, batch: &LifecycleBatch) -> Result<LifecycleReceipt, String> {
            self.runtime
                .store
                .apply_lifecycle(&self.binding, &self.runtime.config.issuer, batch)
        }
        fn principal(&self) -> opaque_core::identity::Principal {
            self.runtime
                .store
                .get_human_by_subject(&self.runtime.config.issuer, "alice")
                .unwrap()
                .unwrap()
        }
    }
    #[test]
    fn scope_revision_and_tombstones_are_authorized_by_core() {
        let f = Fixture::new();
        let batch = f.batch(1, true, &["reviewers"]);
        let mut bad = batch.clone();
        bad.issuer = "https://other.example".into();
        assert!(f.apply(&bad).is_err());
        let mut wrong = batch.clone();
        wrong.binding = TenantBinding::new(
            opaque_core::tenant::TenantId::parse("tenant-b").unwrap(),
            uuid::Uuid::new_v4(),
        )
        .unwrap();
        assert!(f.apply(&wrong).is_err());
        wrong = batch.clone();
        wrong.updates[0].subject = "unadmitted".into();
        assert!(f.apply(&wrong).is_err());
        wrong = batch.clone();
        wrong.revision = 2;
        assert!(f.apply(&wrong).is_err());
        let receipt = f.apply(&batch).unwrap();
        let epoch = f.runtime.store.authority_epoch(&f.principal().id).unwrap();
        assert_eq!(f.apply(&batch).unwrap(), receipt);
        assert_eq!(
            f.runtime.store.authority_epoch(&f.principal().id).unwrap(),
            epoch
        );
        wrong = batch.clone();
        wrong.updates[0].active = false;
        assert!(f.apply(&wrong).is_err());
        let mut deleted = f.batch(2, false, &[]);
        deleted.updates[0].deleted = true;
        f.apply(&deleted).unwrap();
        assert!(f.principal().disabled);
        assert!(f.apply(&f.batch(3, true, &["reviewers"])).is_err());
        assert!(f.apply(&batch).is_err());
    }
    #[test]
    fn removal_regrant_revokes_old_sessions_and_reviewer_epoch() {
        let f = Fixture::new();
        f.apply(&f.batch(1, true, &["reviewers"])).unwrap();
        let p = f.principal();
        let epoch = f
            .runtime
            .reviewer_eligibility(&p.id, Role::Approver)
            .unwrap();
        let revision = f.runtime.store.lifecycle_revision().unwrap();
        let session = f
            .runtime
            .store
            .create_human_session(&p.id, 3600, &f.runtime.config.issuer)
            .unwrap();
        f.apply(&f.batch(2, false, &[])).unwrap();
        f.apply(&f.batch(3, true, &["reviewers"])).unwrap();
        assert!(!f.principal().disabled);
        assert!(
            f.runtime
                .store
                .get_human_session(&session.id)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            f.runtime
                .store
                .create_human_session_at_revision(&p.id, 3600, &f.runtime.config.issuer, revision)
                .is_err()
        );
        let mut called = false;
        assert!(
            f.runtime
                .with_reviewer_authority(&p.id, Role::Approver, epoch, &mut || {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
        assert!(
            f.runtime
                .reviewer_eligibility(&p.id, Role::Approver)
                .unwrap()
                > epoch
        );
    }
    #[test]
    fn dispatch_writer_fence_serializes_removal() {
        let f = Fixture::new();
        f.apply(&f.batch(1, true, &["reviewers"])).unwrap();
        let p = f.principal();
        let epoch = f
            .runtime
            .reviewer_eligibility(&p.id, Role::Approver)
            .unwrap();
        let batch = f.batch(2, false, &[]);
        let runtime = f.runtime.clone();
        let binding = f.binding.clone();
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let mut worker = None;
        f.runtime
            .with_reviewer_authority(&p.id, Role::Approver, epoch, &mut || {
                let runtime = runtime.clone();
                let binding = binding.clone();
                let batch = batch.clone();
                let start_tx = start_tx.clone();
                let done_tx = done_tx.clone();
                worker = Some(std::thread::spawn(move || {
                    start_tx.send(()).unwrap();
                    runtime
                        .store
                        .apply_lifecycle(&binding, &runtime.config.issuer, &batch)
                        .unwrap();
                    done_tx.send(()).unwrap();
                }));
                start_rx.recv().unwrap();
                assert!(
                    done_rx
                        .recv_timeout(std::time::Duration::from_millis(30))
                        .is_err()
                );
                Ok(())
            })
            .unwrap();
        worker.unwrap().join().unwrap();
        assert!(done_rx.recv().is_ok());
        assert!(f.principal().disabled);
    }
    #[test]
    fn managed_admission_and_groups_do_not_trust_stale_login_claims() {
        let f = Fixture::new();
        assert!(
            f.runtime
                .store
                .upsert_human(
                    &f.runtime.config.issuer,
                    "alice",
                    None,
                    None,
                    &BTreeSet::from([Role::Admin])
                )
                .is_err()
        );
        f.apply(&f.batch(1, true, &["reviewers"])).unwrap();
        let p = f.principal();
        assert!(provisioning_group_permitted(&f.runtime.store.lock(), &p.id, "reviewers").unwrap());
        f.apply(&f.batch(2, true, &[])).unwrap();
        assert!(
            !provisioning_group_permitted(&f.runtime.store.lock(), &p.id, "reviewers").unwrap()
        );
        assert!(!f.principal().has_role(Role::Approver));
        f.runtime
            .store
            .configure_lifecycle(
                &f.binding,
                &f.runtime.config.issuer,
                &BTreeMap::new(),
                &["bob".into()],
            )
            .unwrap();
        assert!(f.principal().disabled);
        assert!(f.apply(&f.batch(3, true, &[])).is_err());
    }
    #[test]
    fn suspension_is_durable_and_cannot_be_cleared_by_source() {
        let f = Fixture::new();
        f.apply(&f.batch(1, true, &["reviewers"])).unwrap();
        let mut batch = f.batch(2, false, &[]);
        batch.updates.clear();
        batch.suspend = true;
        let receipt = f.apply(&batch).unwrap();
        assert!(f.principal().disabled);
        assert_eq!(f.apply(&batch).unwrap(), receipt);
        assert!(f.apply(&f.batch(3, true, &["reviewers"])).is_err());
        assert!(
            f.runtime
                .store
                .configure_lifecycle(
                    &f.binding,
                    &f.runtime.config.issuer,
                    &BTreeMap::new(),
                    &f.runtime.config.allowed_subjects
                )
                .is_err()
        );
    }
    #[test]
    fn persisted_managed_state_and_legacy_schema_refuse_silent_downgrade() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!persisted_lifecycle(dir.path()).unwrap());
        assert!(!dir.path().join("identity.db").exists());
        let f = Fixture::new();
        assert!(persisted_lifecycle(f.dir.path()).unwrap());
        f.runtime
            .store
            .lock()
            .execute_batch(
                "CREATE TABLE scim_config(singleton INTEGER);INSERT INTO scim_config VALUES(1);",
            )
            .unwrap();
        assert!(persisted_lifecycle(f.dir.path()).is_err());
        assert!(IdentityStore::open(&f.dir.path().join("identity.db")).is_err());
    }
    #[test]
    fn restart_retains_source_revision_and_current_authority() {
        let f = Fixture::new();
        let batch = f.batch(1, true, &["reviewers"]);
        let receipt = f.apply(&batch).unwrap();
        let store = IdentityStore::open(&f.dir.path().join("identity.db")).unwrap();
        assert_eq!(
            store
                .apply_lifecycle(&f.binding, &f.runtime.config.issuer, &batch)
                .unwrap(),
            receipt
        );
        assert!(
            store
                .apply_lifecycle(&f.binding, "https://wrong.example", &batch)
                .is_err()
        );
        assert!(
            store
                .apply_lifecycle(
                    &f.binding,
                    &f.runtime.config.issuer,
                    &f.batch(0, false, &[])
                )
                .is_err()
        );
    }
    #[tokio::test]
    async fn mock_oidc_lifecycle_change_cancels_pending_login_and_fresh_login_succeeds() {
        use crate::identity::oidc::tests::{mount_discovery, sign_id_token};
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let idp = MockServer::start().await;
        mount_discovery(&idp, &idp.uri()).await;
        let f = Fixture::with_issuer(&idp.uri());
        f.apply(&f.batch(1, true, &["reviewers"])).unwrap();
        for index in 0..2 {
            let attempt = f.runtime.login_start().await.unwrap();
            let url = reqwest::Url::parse(&attempt.auth_url).unwrap();
            let fields = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
            let token = sign_id_token(
                json!({"iss":idp.uri(),"sub":"alice","aud":"lifecycle-fixture","nonce":fields["nonce"],"iat":now_unix(),"exp":now_unix()+600}),
                "test-key-1",
            );
            let _token = Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id_token":token})))
                .mount_as_scoped(&idp)
                .await;
            if index == 0 {
                f.apply(&f.batch(2, false, &[])).unwrap();
                f.apply(&f.batch(3, true, &["reviewers"])).unwrap();
            }
            reqwest::get(format!(
                "{}?code=fixture&state={}",
                fields["redirect_uri"], fields["state"]
            ))
            .await
            .unwrap();
            let outcome = f.runtime.login_status(&attempt.attempt_id);
            if index == 0 {
                assert!(
                    matches!(
                        outcome,
                        Some(crate::identity::login::AttemptOutcome::Failed { .. })
                    ),
                    "{outcome:?}"
                );
                assert!(f.runtime.current_human_principal().is_none());
            } else {
                assert!(
                    matches!(
                        outcome,
                        Some(crate::identity::login::AttemptOutcome::Done { .. })
                    ),
                    "{outcome:?}"
                );
                assert!(f.runtime.current_human_principal().is_some());
            }
        }
    }
}
