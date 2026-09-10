//! Bounded SCIM 2.0 Users/Groups lifecycle service. The ingress credential is
//! tenant-scoped; only sealed configuration maps immutable group IDs to roles.
//! This is a local HTTP service intended behind operator-owned TLS ingress.
use super::{IdentityRuntime, store::IdentityStore};
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use opaque_core::{
    identity::{PrincipalId, PrincipalKind, Role, now_unix, roles_from_string, roles_to_string},
    tenant::TenantBinding,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const MAX_RESOURCES: i64 = 10_000;
const MAX_REQUESTS: i64 = 100_000;
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
CREATE TABLE IF NOT EXISTS scim_config(singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL, issuer TEXT NOT NULL, mapping TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0));
CREATE TABLE IF NOT EXISTS scim_admission(singleton INTEGER PRIMARY KEY CHECK(singleton=1),subjects TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scim_resources(id TEXT PRIMARY KEY, kind TEXT NOT NULL, external_id TEXT NOT NULL, subject TEXT, principal_id TEXT, version INTEGER NOT NULL CHECK(version>0), deleted INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL, UNIQUE(kind,external_id), UNIQUE(subject), UNIQUE(principal_id));
CREATE TABLE IF NOT EXISTS scim_members(group_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY(group_id,user_id));
CREATE TABLE IF NOT EXISTS scim_capacity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),exhausted INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS scim_requests(key TEXT PRIMARY KEY, digest TEXT NOT NULL, status INTEGER NOT NULL, body TEXT NOT NULL, etag TEXT);
CREATE TABLE IF NOT EXISTS scim_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at INTEGER NOT NULL, method TEXT NOT NULL, resource_id TEXT NOT NULL, revision INTEGER NOT NULL, request_digest TEXT NOT NULL);
"#;

pub(super) fn ensure_schema(conn: &Connection) -> Result<(), String> {
    super::provisioning::ensure_schema(conn)?;
    super::persona::ensure_schema(conn)?;
    conn.execute_batch(SCHEMA)
        .map_err(|_| "identity lifecycle schema unavailable".into())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimConfig {
    pub listen: SocketAddr,
    pub token_file: PathBuf,
    #[serde(default)]
    pub group_roles: BTreeMap<String, Vec<String>>,
}
impl ScimConfig {
    fn mapping(&self) -> Result<BTreeMap<String, BTreeSet<Role>>, String> {
        if !self.listen.ip().is_loopback() || self.group_roles.len() > 128 {
            return Err("SCIM requires a loopback listener and at most 128 mapped groups".into());
        }
        self.group_roles
            .iter()
            .map(|(id, roles)| {
                exact(id).map_err(|e| e.detail.to_string())?;
                let roles = roles_from_string(&roles.join(",")).map_err(|e| e.to_string())?;
                Ok((id.clone(), roles))
            })
            .collect()
    }
}

#[derive(Clone)]
struct Service {
    runtime: Arc<IdentityRuntime>,
    tenant: String,
    token_hash: [u8; 32],
}

/// Startup fails closed if the tenant, issuer or credential custody is invalid.
/// The persisted lifecycle boundary cannot be silently removed by deleting config.
pub async fn start(
    config: ScimConfig,
    runtime: Arc<IdentityRuntime>,
    binding: TenantBinding,
    state_dir: &Path,
) -> Result<tokio::task::JoinHandle<()>, String> {
    binding.validate().map_err(|e| e.to_string())?;
    if !runtime.config.required || runtime.config.allowed_subjects.is_empty() {
        return Err("SCIM requires required identity and explicit issuer-subject admission".into());
    }
    if config.token_file.parent() != Some(state_dir) {
        return Err("SCIM credential must be directly inside the broker custody directory".into());
    }
    let mapping = config.mapping()?;
    let token = read_token(&config.token_file)?;
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|_| "SCIM listener unavailable")?;
    runtime.store.configure_lifecycle(
        &binding,
        &runtime.config.issuer,
        &mapping,
        &runtime.config.allowed_subjects,
    )?;
    let service = Service {
        runtime,
        tenant: binding.tenant_id.to_string(),
        token_hash: Sha256::digest(token.as_bytes()).into(),
    };
    let router = Router::new().fallback(handle).with_state(service);
    tracing::info!(address=%listener.local_addr().map_err(|e|e.to_string())?, "SCIM lifecycle listener ready");
    Ok(tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router).await {
            tracing::error!(%error,"SCIM listener stopped");
        }
    }))
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
        .map_err(|_| "SCIM credential unavailable")?;
    let meta = file.metadata().map_err(|_| "SCIM credential unavailable")?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7077 != 0
        || meta.len() > 256
    {
        return Err("SCIM credential must be a private owned regular file".into());
    }
    let mut token = zeroize::Zeroizing::new(String::new());
    file.read_to_string(&mut token)
        .map_err(|_| "SCIM credential unavailable")?;
    if token.len() < 32
        || token.len() > 128
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(
            "SCIM credential must be 32..128 random URL-safe bytes without whitespace".into(),
        );
    }
    Ok(token)
}

#[derive(Debug)]
struct Error {
    status: StatusCode,
    kind: &'static str,
    detail: &'static str,
}
type Result<T, E = Error> = std::result::Result<T, E>;
fn bad(detail: &'static str) -> Error {
    Error {
        status: StatusCode::BAD_REQUEST,
        kind: "invalidValue",
        detail,
    }
}
fn db<T>(value: rusqlite::Result<T>) -> Result<T> {
    value.map_err(|_| Error {
        status: StatusCode::SERVICE_UNAVAILABLE,
        kind: "internalError",
        detail: "identity lifecycle store unavailable",
    })
}
fn conflict(detail: &'static str) -> Error {
    Error {
        status: StatusCode::CONFLICT,
        kind: "uniqueness",
        detail,
    }
}
fn missing() -> Error {
    Error {
        status: StatusCode::NOT_FOUND,
        kind: "invalidValue",
        detail: "resource unavailable",
    }
}
fn exact(v: &str) -> Result<()> {
    if v.is_empty()
        || v.len() > 255
        || v.chars()
            .any(|c| c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'))
    {
        Err(bad("identifiers must be bounded exact strings"))
    } else {
        Ok(())
    }
}
fn uuid(v: &str) -> Result<()> {
    if uuid::Uuid::parse_str(v).is_ok_and(|id| !id.is_nil() && id.to_string() == v) {
        Ok(())
    } else {
        Err(bad("resource IDs must be canonical UUIDs"))
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut r=(self.status, axum::Json(json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":self.status.as_u16().to_string(),"scimType":self.kind,"detail":self.detail}))).into_response();
        secure_headers(&mut r);
        r
    }
}
fn secure_headers(r: &mut Response) {
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    r.headers_mut()
        .insert("content-type", "application/scim+json".parse().unwrap());
    r.headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
}
#[derive(Debug, Clone)]
struct Reply {
    status: u16,
    body: Value,
    etag: Option<String>,
}
impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut r = if self.status == 204 {
            StatusCode::NO_CONTENT.into_response()
        } else {
            (
                StatusCode::from_u16(self.status).unwrap(),
                axum::Json(self.body),
            )
                .into_response()
        };
        if let Some(etag) = self.etag {
            r.headers_mut().insert("etag", etag.parse().unwrap());
        }
        secure_headers(&mut r);
        r
    }
}

async fn handle(State(service): State<Service>, request: Request) -> Response {
    match handle_inner(service, request).await {
        Ok(reply) => reply.into_response(),
        Err(error) => error.into_response(),
    }
}
async fn handle_inner(service: Service, request: Request) -> Result<Reply> {
    let (parts, body) = request.into_parts();
    let auth = parts.headers.get_all("authorization");
    let supplied = auth
        .iter()
        .next()
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let valid = supplied.filter(|s| s.len() <= 128).is_some_and(|s| {
        let actual: [u8; 32] = Sha256::digest(s.as_bytes()).into();
        actual
            .iter()
            .zip(service.token_hash)
            .fold(0u8, |d, (a, b)| d | (a ^ b))
            == 0
    });
    if !valid || auth.iter().count() != 1 || parts.headers.contains_key("origin") {
        return Err(Error {
            status: StatusCode::UNAUTHORIZED,
            kind: "invalidValue",
            detail: "tenant provisioning credential required",
        });
    }
    let prefix = format!("/scim/v2/{}/", service.tenant);
    let path = parts.uri.path().strip_prefix(&prefix).ok_or_else(missing)?;
    let chunks = path.split('/').collect::<Vec<_>>();
    if parts.method == "GET" && path == "ServiceProviderConfig" {
        return Ok(Reply {
            status: 200,
            etag: None,
            body: json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],"patch":{"supported":true},"bulk":{"supported":false,"maxOperations":0,"maxPayloadSize":0},"filter":{"supported":true,"maxResults":100},"changePassword":{"supported":false},"sort":{"supported":false},"etag":{"supported":true},"authenticationSchemes":[{"type":"oauthbearertoken","name":"Tenant provisioning bearer","description":"Operator provisioned tenant credential"}],"urn:opaque:scim:contract:1":{"idempotencyKeyRequired":true,"ifMatchRequired":true,"filters":["externalId eq string","userName eq string"],"userName":"exact OIDC subject","deletion":"permanent tombstone"}}),
        });
    }
    if chunks.is_empty() || chunks.len() > 2 || !matches!(chunks[0], "Users" | "Groups") {
        return Err(missing());
    }
    let kind = chunks[0];
    let id = chunks.get(1).copied();
    if let Some(id) = id {
        uuid(id)?;
    }
    if parts.method == "GET" {
        return service.runtime.store.scim_read(kind, id, parts.uri.query());
    }
    if !matches!(parts.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
        || (parts.method == "POST") != id.is_none()
    {
        return Err(Error {
            status: StatusCode::METHOD_NOT_ALLOWED,
            kind: "invalidValue",
            detail: "unsupported method",
        });
    }
    if parts.uri.query().is_some() {
        return Err(bad("mutation query parameters are unsupported"));
    }
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        to_bytes(body, 128 * 1024),
    )
    .await
    .map_err(|_| bad("request body timeout"))?
    .map_err(|_| bad("request body exceeds bound"))?;
    let value = if parts.method == "DELETE" {
        if !bytes.is_empty() {
            return Err(bad("DELETE has no request body"));
        }
        Value::Null
    } else {
        serde_json::from_slice(&bytes).map_err(|_| bad("invalid JSON request"))?
    };
    service.runtime.store.scim_mutate(
        &service.runtime,
        parts.method.as_str(),
        kind,
        id,
        &parts.headers,
        value,
    )
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct User {
    schemas: Vec<String>,
    external_id: String,
    user_name: String,
    active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Group {
    schemas: Vec<String>,
    external_id: String,
    display_name: String,
    #[serde(default)]
    members: Vec<Member>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Member {
    value: String,
}
fn validate_resource(kind: &str, value: Value) -> Result<Value> {
    if kind == "Users" {
        let u: User = serde_json::from_value(value).map_err(|_| bad("invalid User attributes"))?;
        if u.schemas != [USER] {
            return Err(bad("unsupported User schema"));
        }
        exact(&u.external_id)?;
        exact(&u.user_name)?;
        if let Some(name) = &u.display_name {
            exact(name)?;
        }
        serde_json::to_value(u).map_err(|_| bad("invalid User"))
    } else {
        let mut g: Group =
            serde_json::from_value(value).map_err(|_| bad("invalid Group attributes"))?;
        if g.schemas != [GROUP] {
            return Err(bad("unsupported Group schema"));
        }
        exact(&g.external_id)?;
        exact(&g.display_name)?;
        if g.members.len() > 1000 {
            return Err(bad("too many group members"));
        }
        for m in &g.members {
            uuid(&m.value)?;
        }
        g.members.sort_by(|a, b| a.value.cmp(&b.value));
        g.members.dedup_by(|a, b| a.value == b.value);
        serde_json::to_value(g).map_err(|_| bad("invalid Group"))
    }
}
fn patch(kind: &str, mut prior: Value, value: Value) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Patch {
        schemas: Vec<String>,
        #[serde(rename = "Operations")]
        operations: Vec<Op>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Op {
        op: String,
        path: String,
        #[serde(default)]
        value: Value,
    }
    let patch: Patch = serde_json::from_value(value).map_err(|_| bad("invalid PATCH"))?;
    if patch.schemas != [PATCH] || patch.operations.is_empty() || patch.operations.len() > 32 {
        return Err(bad("invalid PATCH operations"));
    }
    for op in patch.operations {
        match (kind, op.op.to_ascii_lowercase().as_str(), op.path.as_str()) {
            ("Users", "replace", "active" | "displayName") => {
                prior[op.path] = op.value;
            }
            ("Groups", "replace", "members" | "displayName") => {
                prior[op.path] = op.value;
            }
            ("Groups", "add", "members") => {
                let add = op
                    .value
                    .as_array()
                    .ok_or_else(|| bad("members must be an array"))?;
                prior["members"]
                    .as_array_mut()
                    .ok_or_else(|| bad("members unavailable"))?
                    .extend(add.iter().cloned());
            }
            ("Groups", "remove", "members") => {
                prior["members"] = json!([]);
            }
            ("Groups", "remove", path)
                if path.starts_with("members[value eq ") && path.ends_with(']') =>
            {
                let id: String = serde_json::from_str(&path[17..path.len() - 1])
                    .map_err(|_| bad("invalid member selector"))?;
                uuid(&id)?;
                prior["members"]
                    .as_array_mut()
                    .ok_or_else(|| bad("members unavailable"))?
                    .retain(|m| m["value"] != id);
            }
            _ => {
                return Err(Error {
                    status: StatusCode::BAD_REQUEST,
                    kind: "invalidPath",
                    detail: "unsupported PATCH path or operation",
                });
            }
        }
    }
    validate_resource(kind, prior)
}
#[derive(Clone)]
struct Resource {
    id: String,
    kind: String,
    external_id: String,
    subject: Option<String>,
    principal_id: Option<String>,
    version: i64,
    deleted: bool,
    body: Value,
}
fn resource(conn: &Connection, kind: &str, id: &str) -> Result<Resource> {
    db(conn.query_row("SELECT id,kind,external_id,subject,principal_id,version,deleted,body FROM scim_resources WHERE kind=?1 AND id=?2",params![kind,id],|r|{let body:String=r.get(7)?;Ok(Resource{id:r.get(0)?,kind:r.get(1)?,external_id:r.get(2)?,subject:r.get(3)?,principal_id:r.get(4)?,version:r.get(5)?,deleted:r.get(6)?,body:serde_json::from_str(&body).map_err(|_|rusqlite::Error::InvalidQuery)?})}).optional())?.ok_or_else(missing)
}
fn representation(r: &Resource) -> Value {
    let mut body = r.body.clone();
    body["id"] = json!(r.id);
    body["meta"] =
        json!({"resourceType":if r.kind=="Users"{"User"}else{"Group"},"version":etag(r.version)});
    body
}
fn etag(version: i64) -> String {
    format!("W/\"{version}\"")
}
fn invalidate(conn: &Connection, id: &str, now: i64) -> Result<()> {
    db(conn.execute(
        "UPDATE identity_authority_epochs SET epoch=epoch+1 WHERE principal_id=?1",
        [id],
    ))?;
    db(conn.execute(
        "UPDATE human_sessions SET revoked_at=COALESCE(revoked_at,?2) WHERE principal_id=?1",
        params![id, now],
    ))?;
    db(conn.execute("UPDATE delegations SET revoked_at=COALESCE(revoked_at,?2) WHERE sub_principal=?1 OR act_principal=?1 OR approved_by=?1",params![id,now]))?;
    db(conn.execute(
        "UPDATE provisioning_principal_epochs SET epoch=epoch+1 WHERE principal_id=?1",
        [id],
    ))?;
    db(conn.execute("UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,?2) WHERE issuer=?1 OR service=?1",params![id,now]))?;
    db(conn.execute("UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,?2) WHERE recipient=?1 OR parent_id IN(SELECT id FROM provisioning_mandates WHERE issuer=?1 OR service=?1)",params![id,now]))?;
    db(conn.execute("UPDATE persona_snapshots SET revision=revision+1,observed_at=0,issued_at=0,expires_at=0 WHERE principal_id=?1",[id]))?;
    Ok(())
}
fn roles_for(
    conn: &Connection,
    user_id: &str,
    mapping: &BTreeMap<String, BTreeSet<Role>>,
) -> Result<BTreeSet<Role>> {
    let mut stmt=db(conn.prepare("SELECT r.external_id FROM scim_members m JOIN scim_resources r ON r.id=m.group_id WHERE m.user_id=?1 AND r.deleted=0"))?;
    let groups = db(stmt.query_map([user_id], |r| r.get::<_, String>(0)))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| bad("group mappings unavailable"))?;
    Ok(groups
        .iter()
        .filter_map(|g| mapping.get(g))
        .flat_map(|roles| roles.iter().copied())
        .collect())
}
fn refresh_user(
    conn: &Connection,
    id: &str,
    mapping: &BTreeMap<String, BTreeSet<Role>>,
    now: i64,
) -> Result<()> {
    let user = resource(conn, "Users", id)?;
    let principal = user
        .principal_id
        .ok_or_else(|| bad("user binding unavailable"))?;
    let admission: String = db(conn.query_row(
        "SELECT subjects FROM scim_admission WHERE singleton=1",
        [],
        |row| row.get(0),
    ))?;
    let admission: Vec<String> =
        serde_json::from_str(&admission).map_err(|_| bad("admission unavailable"))?;
    let active = !user.deleted
        && user.body["active"] == true
        && user
            .subject
            .as_ref()
            .is_some_and(|subject| admission.contains(subject));
    let roles = if active {
        roles_for(conn, id, mapping)?
    } else {
        BTreeSet::new()
    };
    db(conn.execute(
        "UPDATE principals SET roles=?2,disabled=?3 WHERE id=?1",
        params![principal, roles_to_string(&roles), !active],
    ))?;
    invalidate(conn, &principal, now)
}

impl IdentityStore {
    pub fn authority_epoch(&self, id: &PrincipalId) -> std::result::Result<u64, String> {
        self.lock()
            .query_row(
                "SELECT epoch FROM identity_authority_epochs WHERE principal_id=?1",
                [id.as_str()],
                |r| r.get(0),
            )
            .map_err(|_| "identity authority epoch unavailable".into())
    }
    pub fn lifecycle_revision(&self) -> std::result::Result<i64, String> {
        self.lock()
            .query_row(
                "SELECT revision FROM scim_config WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map(|r| r.unwrap_or(0))
            .map_err(|_| "identity lifecycle unavailable".into())
    }
    #[cfg(test)]
    pub fn lifecycle_permitted(&self, id: &PrincipalId) -> std::result::Result<bool, String> {
        let conn = self.lock();
        lifecycle_permitted(&conn, id.as_str()).map_err(|e| e.detail.into())
    }
    fn configure_lifecycle(
        &self,
        binding: &TenantBinding,
        issuer: &str,
        mapping: &BTreeMap<String, BTreeSet<Role>>,
        admitted_subjects: &[String],
    ) -> std::result::Result<(), String> {
        let mut conn = self.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "lifecycle transaction unavailable")?;
        let capacity_exhausted: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM scim_capacity WHERE exhausted=1)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| "lifecycle capacity unavailable")?;
        if capacity_exhausted {
            return Err("lifecycle capacity exhausted; offline recovery required".into());
        }
        let binding = serde_json::to_string(binding).map_err(|_| "invalid tenant binding")?;
        let mapping_text = serde_json::to_string(mapping).map_err(|_| "invalid role mapping")?;
        let previous: Option<(String, String, String)> = tx
            .query_row(
                "SELECT binding,issuer,mapping FROM scim_config WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "lifecycle config unavailable")?;
        if previous
            .as_ref()
            .is_some_and(|(b, i, _)| b != &binding || i != issuer)
        {
            return Err("lifecycle tenant/issuer cannot be rebound".into());
        }
        let mut admission = admitted_subjects.to_vec();
        admission.sort();
        admission.dedup();
        let admission = serde_json::to_string(&admission).map_err(|_| "invalid admission")?;
        let previous_admission: Option<String> = tx
            .query_row(
                "SELECT subjects FROM scim_admission WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| "admission unavailable")?;
        if previous.as_ref().is_none_or(|(_, _, m)| m != &mapping_text)
            || previous_admission.as_deref() != Some(&admission)
        {
            tx.execute("INSERT INTO scim_admission VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET subjects=excluded.subjects",[&admission]).map_err(|_|"admission unavailable")?;
            tx.execute("INSERT INTO scim_config VALUES(1,?1,?2,?3,1) ON CONFLICT(singleton) DO UPDATE SET mapping=excluded.mapping,revision=revision+1",params![binding,issuer,mapping_text]).map_err(|_|"lifecycle config unavailable")?;
            let ids: Vec<String> = tx
                .prepare("SELECT id FROM scim_resources WHERE kind='Users'")
                .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
                .map_err(|_| "lifecycle users unavailable")?;
            for id in ids {
                refresh_user(&tx, &id, mapping, now_unix()).map_err(|e| e.detail)?;
            }
            tx.execute("UPDATE principals SET disabled=1,roles='' WHERE kind='human' AND NOT EXISTS(SELECT 1 FROM scim_resources r WHERE r.principal_id=principals.id AND r.deleted=0 AND json_extract(r.body,'$.active')=1)",[]).map_err(|_|"unmanaged principal revocation unavailable")?;
            // Activation invalidates old authority for previously unmanaged humans.
            tx.execute(
                "UPDATE human_sessions SET revoked_at=COALESCE(revoked_at,?1)",
                [now_unix()],
            )
            .map_err(|_| "lifecycle session revocation unavailable")?;
            tx.execute("UPDATE delegations SET revoked_at=COALESCE(revoked_at,?1) WHERE sub_principal IN(SELECT id FROM principals WHERE kind='human')",[now_unix()]).map_err(|_|"lifecycle delegation revocation unavailable")?;
        }
        tx.commit()
            .map_err(|_| "lifecycle config commit unavailable".into())
    }
    fn scim_read(&self, kind: &str, id: Option<&str>, query: Option<&str>) -> Result<Reply> {
        let conn = self.lock();
        if let Some(id) = id {
            if query.is_some() {
                return Err(bad("resource query unsupported"));
            }
            let r = resource(&conn, kind, id)?;
            if r.deleted {
                return Err(missing());
            }
            return Ok(Reply {
                status: 200,
                body: representation(&r),
                etag: Some(etag(r.version)),
            });
        }
        let url = reqwest::Url::parse(&format!("http://localhost/?{}", query.unwrap_or_default()))
            .map_err(|_| bad("invalid query"))?;
        let mut start = 1usize;
        let mut count = 100usize;
        let mut filter = None;
        let mut seen = BTreeSet::new();
        for (k, v) in url.query_pairs() {
            if !seen.insert(k.to_string()) {
                return Err(bad("duplicate query parameter"));
            }
            match k.as_ref() {
                "startIndex" => start = v.parse().map_err(|_| bad("invalid startIndex"))?,
                "count" => count = v.parse().map_err(|_| bad("invalid count"))?,
                "filter" => {
                    let (attribute, value) = v
                        .split_once(" eq ")
                        .ok_or_else(|| bad("unsupported filter"))?;
                    if !matches!(attribute, "externalId" | "userName") {
                        return Err(bad("unsupported filter"));
                    }
                    let value: String =
                        serde_json::from_str(value).map_err(|_| bad("invalid filter"))?;
                    filter = Some((attribute.to_string(), value));
                }
                _ => return Err(bad("unsupported query")),
            }
        }
        if start == 0 || start > MAX_RESOURCES as usize || count > 100 {
            return Err(bad("pagination exceeds bounds"));
        }
        let mut statement =
            db(conn
                .prepare("SELECT id FROM scim_resources WHERE kind=?1 AND deleted=0 ORDER BY id"))?;
        let ids = db(statement.query_map([kind], |r| r.get::<_, String>(0)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| bad("resource listing unavailable"))?;
        let mut rows = Vec::new();
        for id in ids {
            let r = resource(&conn, kind, &id)?;
            if filter.as_ref().is_none_or(|(k, v)| r.body[k] == *v) {
                rows.push(representation(&r));
            }
        }
        let total = rows.len();
        let page = rows
            .into_iter()
            .skip(start - 1)
            .take(count)
            .collect::<Vec<_>>();
        Ok(Reply {
            status: 200,
            etag: None,
            body: json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":total,"startIndex":start,"itemsPerPage":page.len(),"Resources":page}),
        })
    }
    fn scim_mutate(
        &self,
        runtime: &IdentityRuntime,
        method: &str,
        kind: &str,
        id: Option<&str>,
        headers: &HeaderMap,
        value: Value,
    ) -> Result<Reply> {
        if headers.get_all("idempotency-key").iter().count() != 1
            || headers.get_all("if-match").iter().count() > 1
        {
            return Err(bad("ambiguous mutation headers"));
        }
        let key = headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| bad("Idempotency-Key required"))?;
        exact(key)?;
        let if_match = headers.get("if-match").and_then(|v| v.to_str().ok());
        let digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    "opaque.scim.mutation.v1",
                    method,
                    kind,
                    id,
                    if_match,
                    &value
                ))
                .map_err(|_| bad("invalid request"))?
            )
        );
        let mut conn = self.lock();
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let prior: Option<(String, u16, String, Option<String>)> = db(tx
            .query_row(
                "SELECT digest,status,body,etag FROM scim_requests WHERE key=?1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional())?;
        if let Some((prior, status, body, etag)) = prior {
            if prior != digest {
                return Err(conflict(
                    "idempotency key already used for different intent",
                ));
            }
            return Ok(Reply {
                status,
                body: serde_json::from_str(&body)
                    .map_err(|_| bad("stored response unavailable"))?,
                etag,
            });
        }
        let count: i64 = db(tx.query_row("SELECT COUNT(*) FROM scim_requests", [], |r| r.get(0)))?;
        if count >= MAX_REQUESTS {
            let exhausted: bool = db(tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM scim_capacity WHERE exhausted=1)",
                [],
                |row| row.get(0),
            ))?;
            if !exhausted {
                let ids: Vec<String> =
                    db(tx.prepare("SELECT id FROM principals WHERE kind='human'"))?
                        .query_map([], |row| row.get(0))
                        .map_err(|_| bad("principals unavailable"))?
                        .collect::<rusqlite::Result<_>>()
                        .map_err(|_| bad("principals unavailable"))?;
                for id in ids {
                    invalidate(&tx, &id, now_unix())?;
                }
                db(tx.execute(
                    "UPDATE principals SET disabled=1,roles='' WHERE kind='human'",
                    [],
                ))?;
                db(tx.execute("UPDATE scim_config SET revision=revision+1", []))?;
                db(tx.execute("INSERT INTO scim_capacity VALUES(1,1)", []))?;
            }
            db(tx.commit())?;
            return Err(Error {
                status: StatusCode::SERVICE_UNAVAILABLE,
                kind: "tooMany",
                detail: "lifecycle retention capacity reached; human authority revoked; offline recovery required",
            });
        }
        let now = now_unix();
        let mapping: String = db(tx.query_row(
            "SELECT mapping FROM scim_config WHERE singleton=1",
            [],
            |r| r.get(0),
        ))?;
        let mapping: BTreeMap<String, BTreeSet<Role>> =
            serde_json::from_str(&mapping).map_err(|_| bad("mapping unavailable"))?;
        let mut r = if let Some(id) = id {
            let r = resource(&tx, kind, id)?;
            if r.deleted {
                return Err(missing());
            }
            if if_match != Some(etag(r.version).as_str()) {
                return Err(Error {
                    status: StatusCode::PRECONDITION_FAILED,
                    kind: "invalidVers",
                    detail: "current If-Match version required",
                });
            }
            r
        } else {
            if if_match.is_some() {
                return Err(bad("POST does not accept If-Match"));
            }
            let body = validate_resource(kind, value.clone())?;
            let external_id = body["externalId"].as_str().unwrap().to_string();
            let subject = if kind == "Users" {
                Some(body["userName"].as_str().unwrap().to_owned())
            } else {
                None
            };
            let count: i64 =
                db(tx.query_row("SELECT COUNT(*) FROM scim_resources", [], |r| r.get(0)))?;
            if count >= MAX_RESOURCES {
                return Err(bad("resource capacity reached"));
            }
            let exists:bool=db(tx.query_row("SELECT EXISTS(SELECT 1 FROM scim_resources WHERE (kind=?1 AND external_id=?2) OR (?3 IS NOT NULL AND subject=?3))",params![kind,external_id,subject],|r|r.get(0)))?;
            if exists {
                return Err(conflict(
                    "external identity already exists, including deleted tombstones",
                ));
            }
            let principal_id = if let Some(subject) = &subject {
                if !runtime.config.allowed_subjects.contains(subject) {
                    return Err(bad("subject is not in trusted issuer admission"));
                }
                let existing: Option<String> = db(tx
                    .query_row(
                        "SELECT id FROM principals WHERE kind='human' AND iss=?1 AND sub=?2",
                        params![runtime.config.issuer, subject],
                        |r| r.get(0),
                    )
                    .optional())?;
                let principal = existing.unwrap_or_else(|| {
                    PrincipalId::generate(&PrincipalKind::Human {
                        iss: runtime.config.issuer.clone(),
                        sub: subject.clone(),
                        email: None,
                        name: None,
                    })
                    .as_str()
                    .to_string()
                });
                db(tx.execute("INSERT OR IGNORE INTO principals(id,kind,iss,sub,roles,created_at,last_seen,disabled) VALUES(?1,'human',?2,?3,'',?4,?4,1)",params![principal,runtime.config.issuer,subject,now]))?;
                Some(principal)
            } else {
                None
            };
            Resource {
                id: uuid::Uuid::new_v4().to_string(),
                kind: kind.to_owned(),
                external_id,
                subject,
                principal_id,
                version: 0,
                deleted: false,
                body,
            }
        };
        let previous_body = r.body.clone();
        let prior_members = if kind == "Groups" {
            r.body["members"].as_array().cloned().unwrap_or_default()
        } else {
            Vec::new()
        };
        if method == "DELETE" {
            r.deleted = true;
        } else if method == "PATCH" {
            r.body = patch(kind, r.body, value)?;
        } else {
            let mut value = value;
            if method == "PUT" {
                let object = value
                    .as_object_mut()
                    .ok_or_else(|| bad("invalid resource"))?;
                if let Some(id) = object.remove("id")
                    && id != r.id
                {
                    return Err(bad("read-only id cannot be changed"));
                }
                if let Some(meta) = object.remove("meta")
                    && meta != representation(&r)["meta"]
                {
                    return Err(bad("read-only metadata cannot be changed"));
                }
            }
            r.body = validate_resource(kind, value)?;
        }
        if r.body["externalId"] != r.external_id
            || r.subject.as_ref().is_some_and(|s| r.body["userName"] != *s)
        {
            return Err(conflict("externalId and userName are immutable"));
        }
        if method != "POST" && method != "DELETE" && r.body == previous_body {
            let reply = Reply {
                status: 200,
                body: representation(&r),
                etag: Some(etag(r.version)),
            };
            db(tx.execute(
                "INSERT INTO scim_requests VALUES(?1,?2,?3,?4,?5)",
                params![
                    key,
                    digest,
                    reply.status,
                    reply.body.to_string(),
                    reply.etag
                ],
            ))?;
            db(tx.commit())?;
            return Ok(reply);
        }
        r.version = r
            .version
            .checked_add(1)
            .ok_or_else(|| bad("resource version exhausted"))?;
        db(tx.execute("INSERT INTO scim_resources(id,kind,external_id,subject,principal_id,version,deleted,body) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET version=excluded.version,deleted=excluded.deleted,body=excluded.body",params![r.id,r.kind,r.external_id,r.subject,r.principal_id,r.version,r.deleted,r.body.to_string()]))?;
        if kind == "Users" {
            refresh_user(&tx, &r.id, &mapping, now)?;
            if r.deleted {
                let group_ids: Vec<String> =
                    db(tx.prepare("SELECT group_id FROM scim_members WHERE user_id=?1"))?
                        .query_map([&r.id], |row| row.get(0))
                        .map_err(|_| bad("members unavailable"))?
                        .collect::<std::result::Result<_, _>>()
                        .map_err(|_| bad("members unavailable"))?;
                for group_id in group_ids {
                    let mut group = resource(&tx, "Groups", &group_id)?;
                    group.body["members"]
                        .as_array_mut()
                        .ok_or_else(|| bad("members unavailable"))?
                        .retain(|m| m["value"] != r.id);
                    let version = group
                        .version
                        .checked_add(1)
                        .ok_or_else(|| bad("group version exhausted"))?;
                    db(tx.execute(
                        "UPDATE scim_resources SET body=?2,version=?3 WHERE id=?1",
                        params![group_id, group.body.to_string(), version],
                    ))?;
                }
                db(tx.execute("DELETE FROM scim_members WHERE user_id=?1", [&r.id]))?;
            }
        } else {
            db(tx.execute("DELETE FROM scim_members WHERE group_id=?1", [&r.id]))?;
            let members = if r.deleted {
                Vec::new()
            } else {
                r.body["members"]
                    .as_array()
                    .cloned()
                    .ok_or_else(|| bad("members unavailable"))?
            };
            for m in &members {
                let user = resource(&tx, "Users", m["value"].as_str().unwrap())?;
                if user.deleted {
                    return Err(bad("deleted group member"));
                }
                db(tx.execute(
                    "INSERT INTO scim_members VALUES(?1,?2)",
                    params![r.id, user.id],
                ))?;
            }
            let affected = prior_members
                .iter()
                .chain(members.iter())
                .filter_map(|m| m["value"].as_str())
                .collect::<BTreeSet<_>>();
            for id in affected {
                refresh_user(&tx, id, &mapping, now)?;
            }
        }
        db(tx.execute(
            "UPDATE scim_config SET revision=revision+1 WHERE singleton=1",
            [],
        ))?;
        let reply = Reply {
            status: if method == "DELETE" {
                204
            } else if method == "POST" {
                201
            } else {
                200
            },
            body: if r.deleted {
                Value::Null
            } else {
                representation(&r)
            },
            etag: Some(etag(r.version)),
        };
        db(tx.execute(
            "INSERT INTO scim_requests VALUES(?1,?2,?3,?4,?5)",
            params![
                key,
                digest,
                reply.status,
                reply.body.to_string(),
                reply.etag
            ],
        ))?;
        db(tx.execute("INSERT INTO scim_events(occurred_at,method,resource_id,revision,request_digest) VALUES(?1,?2,?3,?4,?5)",params![now,method,r.id,r.version,digest]))?;
        db(tx.commit())?;
        drop(conn);
        runtime.emit_audit(
            opaque_core::audit::AuditEvent::new(
                opaque_core::audit::AuditEventKind::IdentityRoleChanged,
            )
            .with_operation("identity.scim.lifecycle")
            .with_outcome("applied")
            .with_detail(format!(
                "resource={} version={} request_digest={digest}",
                r.id, r.version
            )),
        );
        Ok(reply)
    }
}
#[cfg(test)]
fn lifecycle_permitted(conn: &Connection, id: &str) -> Result<bool> {
    let enabled: bool =
        db(conn.query_row("SELECT EXISTS(SELECT 1 FROM scim_config)", [], |r| r.get(0)))?;
    if !enabled {
        return Ok(true);
    }
    db(conn.query_row("SELECT EXISTS(SELECT 1 FROM scim_resources WHERE principal_id=?1 AND deleted=0 AND json_extract(body,'$.active')=1)",[id],|r|r.get(0)))
}

pub(super) fn provisioning_group_permitted(
    conn: &Connection,
    id: &PrincipalId,
    group: &str,
) -> std::result::Result<bool, String> {
    let enabled: bool = conn
        .query_row("SELECT EXISTS(SELECT 1 FROM scim_config)", [], |row| {
            row.get(0)
        })
        .map_err(|_| "lifecycle configuration unavailable")?;
    if !enabled {
        return Ok(true);
    }
    conn.query_row("SELECT EXISTS(SELECT 1 FROM scim_resources u JOIN scim_members m ON m.user_id=u.id JOIN scim_resources g ON g.id=m.group_id WHERE u.principal_id=?1 AND u.deleted=0 AND json_extract(u.body,'$.active')=1 AND g.external_id=?2 AND g.deleted=0)",params![id.as_str(),group],|row|row.get(0)).map_err(|_|"lifecycle group membership unavailable".into())
}

/// Inspect an existing identity database without creating or migrating it.
/// Called before optional identity initialization, so config removal or an
/// invalid optional identity block cannot bypass a persisted lifecycle boundary.
pub fn persisted_lifecycle(state_dir: &Path) -> std::result::Result<bool, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = state_dir.join("identity.db");
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("persisted identity state unavailable".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "persisted identity state unavailable")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7077 != 0
    {
        return Err("persisted identity state must be privately owned".into());
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| "persisted identity state unreadable")?;
    let has_table: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='scim_config')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "persisted identity schema unreadable")?;
    if !has_table {
        return Ok(false);
    }
    conn.query_row("SELECT EXISTS(SELECT 1 FROM scim_config)", [], |row| {
        row.get(0)
    })
    .map_err(|_| "persisted lifecycle state unreadable".into())
}

#[cfg(test)]
mod tests {
    use super::super::{IdentityConfig, store::DelegationRecord};
    use super::*;
    use opaque_core::identity::{AccessMode, Principal};

    struct Fixture {
        runtime: Arc<IdentityRuntime>,
        _dir: tempfile::TempDir,
        binding: TenantBinding,
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_issuer("https://idp.example")
        }
        fn with_issuer(issuer: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let runtime = Arc::new(
                IdentityRuntime::initialize(
                    IdentityConfig {
                        issuer: issuer.into(),
                        client_id: "scim-test".into(),
                        audience: None,
                        redirect_port: None,
                        session_ttl_secs: None,
                        allowed_email_domains: vec![],
                        allowed_subjects: vec!["alice".into(), "bob".into()],
                        required: true,
                        persona: None,
                        service_principals: vec![],
                    },
                    dir.path(),
                )
                .unwrap(),
            );
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
                _dir: dir,
                binding,
            }
        }
        fn apply(
            &self,
            method: &str,
            kind: &str,
            id: Option<&str>,
            key: &str,
            version: Option<&str>,
            value: Value,
        ) -> Result<Reply> {
            let mut headers = HeaderMap::new();
            headers.insert("idempotency-key", key.parse().unwrap());
            if let Some(version) = version {
                headers.insert("if-match", version.parse().unwrap());
            }
            self.runtime
                .store
                .scim_mutate(&self.runtime, method, kind, id, &headers, value)
        }
        fn user(&self, name: &str) -> Reply {
            self.apply("POST", "Users", None, name, None, user(name, true))
                .unwrap()
        }
        fn principal(&self, name: &str) -> Principal {
            self.runtime
                .store
                .get_human_by_subject(&self.runtime.config.issuer, name)
                .unwrap()
                .unwrap()
        }
    }
    fn user(subject: &str, active: bool) -> Value {
        json!({"schemas":[USER],"externalId":format!("external-{subject}"),"userName":subject,"active":active})
    }
    fn group(id: &str, members: &[&str]) -> Value {
        json!({"schemas":[GROUP],"externalId":id,"displayName":"Display only","members":members.iter().map(|id|json!({"value":id})).collect::<Vec<_>>()})
    }

    #[test]
    fn lifecycle_versions_idempotency_and_permanent_tombstones() {
        let f = Fixture::new();
        let created = f.user("alice");
        let id = created.body["id"].as_str().unwrap();
        assert_eq!(
            f.apply("POST", "Users", None, "alice", None, user("alice", true))
                .unwrap()
                .body,
            created.body
        );
        assert_eq!(
            f.apply("POST", "Users", None, "alice", None, user("bob", true))
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        let disabled = f
            .apply(
                "PUT",
                "Users",
                Some(id),
                "disable",
                created.etag.as_deref(),
                user("alice", false),
            )
            .unwrap();
        assert!(!f.runtime.principal_permitted(&f.principal("alice")));
        assert_eq!(
            f.apply(
                "PUT",
                "Users",
                Some(id),
                "out-of-order",
                created.etag.as_deref(),
                user("alice", true)
            )
            .unwrap_err()
            .status,
            StatusCode::PRECONDITION_FAILED
        );
        f.apply(
            "DELETE",
            "Users",
            Some(id),
            "delete",
            disabled.etag.as_deref(),
            Value::Null,
        )
        .unwrap();
        assert_eq!(
            f.apply("POST", "Users", None, "recreate", None, user("alice", true))
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            f.runtime
                .store
                .scim_read("Users", Some(id), None)
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
        // Replayed create returns the original receipt, without restoring state.
        f.apply("POST", "Users", None, "alice", None, user("alice", true))
            .unwrap();
        assert!(!f.runtime.principal_permitted(&f.principal("alice")));
    }

    #[test]
    fn group_removal_revokes_sessions_delegations_reviewer_and_requires_fresh_login() {
        let f = Fixture::new();
        let user = f.user("alice");
        let uid = user.body["id"].as_str().unwrap();
        let g = f
            .apply(
                "POST",
                "Groups",
                None,
                "group",
                None,
                group("reviewers", &[uid]),
            )
            .unwrap();
        let gid = g.body["id"].as_str().unwrap();
        let principal = f.principal("alice");
        assert!(principal.has_role(Role::Approver));
        let epoch = f
            .runtime
            .reviewer_eligibility(&principal.id, Role::Approver)
            .unwrap();
        let session = f
            .runtime
            .store
            .create_human_session(&principal.id, 3600, &f.runtime.config.issuer)
            .unwrap();
        let actor = f.runtime.store.upsert_agent("test-agent").unwrap();
        f.runtime
            .store
            .record_delegation(&DelegationRecord {
                jti: "delegation".into(),
                sub_principal: principal.id.clone(),
                act_principal: actor.id,
                mode: AccessMode::Delegated,
                human_session_id: Some(session.id.clone()),
                approved_by: Some(principal.id.clone()),
                created_at: now_unix(),
                expires_at: now_unix() + 3600,
                revoked_at: None,
            })
            .unwrap();
        let revision = f.runtime.store.lifecycle_revision().unwrap();
        let removed=f.apply("PATCH","Groups",Some(gid),"remove",g.etag.as_deref(),json!({"schemas":[PATCH],"Operations":[{"op":"remove","path":format!("members[value eq \"{uid}\"]")}]})).unwrap();
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
                .get_delegation("delegation")
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            f.runtime
                .reviewer_eligibility(&principal.id, Role::Approver)
                .is_err()
        );
        assert!(
            f.runtime
                .store
                .create_human_session_at_revision(
                    &principal.id,
                    3600,
                    &f.runtime.config.issuer,
                    revision
                )
                .is_err()
        );
        f.apply(
            "PUT",
            "Groups",
            Some(gid),
            "restore",
            removed.etag.as_deref(),
            group("reviewers", &[uid]),
        )
        .unwrap();
        assert!(
            f.runtime
                .reviewer_eligibility(&principal.id, Role::Approver)
                .unwrap()
                > epoch
        );
        assert!(
            f.runtime
                .store
                .get_delegation("delegation")
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            f.runtime
                .store
                .create_human_session(&principal.id, 3600, &f.runtime.config.issuer)
                .is_ok()
        );
    }

    #[test]
    fn mapping_is_external_id_owned_not_display_name_or_payload_roles() {
        let f = Fixture::new();
        let u = f.user("alice");
        let id = u.body["id"].as_str().unwrap();
        let mut malicious = group("unmapped", &[id]);
        malicious["displayName"] = json!("reviewers");
        f.apply("POST", "Groups", None, "unmapped", None, malicious)
            .unwrap();
        assert!(f.principal("alice").roles.is_empty());
        let mut user = user("bob", true);
        user["roles"] = json!(["admin"]);
        assert!(
            f.apply("POST", "Users", None, "role-injection", None, user)
                .is_err()
        );
        let other = TenantBinding::new(
            opaque_core::tenant::TenantId::parse("tenant-b").unwrap(),
            f.binding.broker_id,
        )
        .unwrap();
        assert!(
            f.runtime
                .store
                .configure_lifecycle(
                    &other,
                    &f.runtime.config.issuer,
                    &BTreeMap::new(),
                    &f.runtime.config.allowed_subjects
                )
                .is_err()
        );
        assert!(
            f.runtime
                .store
                .configure_lifecycle(
                    &f.binding,
                    "https://other.example",
                    &BTreeMap::new(),
                    &f.runtime.config.allowed_subjects
                )
                .is_err()
        );
    }

    #[test]
    fn deactivation_reactivation_and_mapping_change_never_revive_authority() {
        let f = Fixture::new();
        let u = f.user("alice");
        let id = u.body["id"].as_str().unwrap();
        f.apply(
            "POST",
            "Groups",
            None,
            "group",
            None,
            group("reviewers", &[id]),
        )
        .unwrap();
        let p = f.principal("alice");
        let session = f
            .runtime
            .store
            .create_human_session(&p.id, 3600, &f.runtime.config.issuer)
            .unwrap();
        let inactive = f
            .apply(
                "PUT",
                "Users",
                Some(id),
                "off",
                u.etag.as_deref(),
                user("alice", false),
            )
            .unwrap();
        f.apply(
            "PUT",
            "Users",
            Some(id),
            "on",
            inactive.etag.as_deref(),
            user("alice", true),
        )
        .unwrap();
        assert!(
            f.runtime
                .store
                .get_human_session(&session.id)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
        f.runtime
            .store
            .configure_lifecycle(
                &f.binding,
                &f.runtime.config.issuer,
                &BTreeMap::new(),
                &f.runtime.config.allowed_subjects,
            )
            .unwrap();
        assert!(f.principal("alice").roles.is_empty());
    }

    #[test]
    fn deletion_removes_group_members_and_changes_group_etag() {
        let f = Fixture::new();
        let u = f.user("alice");
        let uid = u.body["id"].as_str().unwrap();
        let g = f
            .apply(
                "POST",
                "Groups",
                None,
                "group",
                None,
                group("reviewers", &[uid]),
            )
            .unwrap();
        let gid = g.body["id"].as_str().unwrap();
        f.apply(
            "DELETE",
            "Users",
            Some(uid),
            "delete",
            u.etag.as_deref(),
            Value::Null,
        )
        .unwrap();
        let updated = f
            .runtime
            .store
            .scim_read("Groups", Some(gid), None)
            .unwrap();
        assert_eq!(updated.body["members"], json!([]));
        assert_ne!(updated.etag, g.etag);
    }

    #[tokio::test]
    async fn authenticated_tenant_http_is_usable_and_fails_closed() {
        let f = Fixture::new();
        let token = "synthetic_scim_fixture_token_32_bytes_min";
        let state = Service {
            runtime: f.runtime.clone(),
            tenant: "tenant-a".into(),
            token_hash: Sha256::digest(token.as_bytes()).into(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new().fallback(handle).with_state(state);
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let base = format!("http://{address}/scim/v2/tenant-a/Users");
        assert_eq!(client.get(&base).send().await.unwrap().status(), 401);
        assert_eq!(
            client
                .get(format!("http://{address}/scim/v2/tenant-b/Users"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            client
                .get(&base)
                .bearer_auth(token)
                .header("Origin", "https://attacker.example")
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        let response = client
            .post(&base)
            .bearer_auth(token)
            .header("Idempotency-Key", "create")
            .json(&user("alice", true))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let listed: Value = client
            .get(&base)
            .query(&[
                ("filter", "externalId eq \"external-alice\""),
                ("count", "1"),
            ])
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(listed["totalResults"], 1);
        assert_eq!(listed["Resources"].as_array().unwrap().len(), 1);
        assert_eq!(
            client
                .get(&base)
                .query(&[("filter", "active eq true")])
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
        task.abort();
    }

    #[test]
    fn restart_retains_idempotency_tombstones_and_authority_epochs() {
        let f = Fixture::new();
        let u = f.user("alice");
        let id = u.body["id"].as_str().unwrap();
        f.apply(
            "DELETE",
            "Users",
            Some(id),
            "delete",
            u.etag.as_deref(),
            Value::Null,
        )
        .unwrap();
        let p = f.principal("alice");
        let epoch = f.runtime.store.authority_epoch(&p.id).unwrap();
        let reopened = IdentityStore::open(&f._dir.path().join("identity.db")).unwrap();
        assert_eq!(reopened.authority_epoch(&p.id).unwrap(), epoch);
        assert!(!reopened.lifecycle_permitted(&p.id).unwrap());
        assert_eq!(
            reopened
                .scim_mutate(
                    &f.runtime,
                    "POST",
                    "Users",
                    None,
                    &HeaderMap::from_iter([(
                        "idempotency-key".parse().unwrap(),
                        "alice".parse().unwrap()
                    )]),
                    user("alice", true)
                )
                .unwrap()
                .body,
            u.body
        );
        assert!(!reopened.lifecycle_permitted(&p.id).unwrap());
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
        let u = f.user("alice");
        let uid = u.body["id"].as_str().unwrap();
        for index in 0..2 {
            let attempt = f.runtime.login_start().await.unwrap();
            let url = reqwest::Url::parse(&attempt.auth_url).unwrap();
            let fields = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
            let token = sign_id_token(
                json!({"iss":idp.uri(),"sub":"alice","aud":"scim-test","nonce":fields["nonce"],"iat":now_unix(),"exp":now_unix()+600}),
                "test-key-1",
            );
            let _token = Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id_token":token})))
                .mount_as_scoped(&idp)
                .await;
            if index == 0 {
                let disabled = f
                    .apply(
                        "PUT",
                        "Users",
                        Some(uid),
                        "off",
                        u.etag.as_deref(),
                        user("alice", false),
                    )
                    .unwrap();
                f.apply(
                    "PUT",
                    "Users",
                    Some(uid),
                    "on",
                    disabled.etag.as_deref(),
                    user("alice", true),
                )
                .unwrap();
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
    #[test]
    fn capacity_exhaustion_revokes_authority_instead_of_blocking_offboarding_open() {
        let f = Fixture::new();
        f.user("alice");
        let principal = f.principal("alice");
        let session = f
            .runtime
            .store
            .create_human_session(&principal.id, 3600, &f.runtime.config.issuer)
            .unwrap();
        f.runtime.store.lock().execute_batch("WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100000) INSERT INTO scim_requests SELECT 'capacity-'||x,'digest',200,'{}',NULL FROM n;").unwrap();
        assert_eq!(
            f.apply(
                "POST",
                "Users",
                None,
                "new-request",
                None,
                user("bob", true)
            )
            .unwrap_err()
            .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(f.principal("alice").disabled);
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
    fn configured_membership_removal_and_restore_require_fresh_authority() {
        let f = Fixture::new();
        f.user("alice");
        let principal = f.principal("alice");
        let session = f
            .runtime
            .store
            .create_human_session(&principal.id, 3600, &f.runtime.config.issuer)
            .unwrap();
        f.runtime
            .store
            .configure_lifecycle(
                &f.binding,
                &f.runtime.config.issuer,
                &BTreeMap::new(),
                &["bob".into()],
            )
            .unwrap();
        assert!(f.principal("alice").disabled);
        f.runtime
            .store
            .configure_lifecycle(
                &f.binding,
                &f.runtime.config.issuer,
                &BTreeMap::new(),
                &f.runtime.config.allowed_subjects,
            )
            .unwrap();
        assert!(!f.principal("alice").disabled);
        assert!(
            f.runtime
                .store
                .get_human_session(&session.id)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }
    #[test]
    fn persisted_lifecycle_probe_is_read_only_and_independent_of_runtime_config() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!persisted_lifecycle(directory.path()).unwrap());
        assert!(!directory.path().join("identity.db").exists());
        let f = Fixture::new();
        assert!(persisted_lifecycle(f._dir.path()).unwrap());
        assert!(
            f.runtime
                .store
                .upsert_human(
                    &f.runtime.config.issuer,
                    "unmanaged",
                    None,
                    None,
                    &BTreeSet::from([Role::Admin])
                )
                .is_err()
        );
    }
    #[test]
    fn get_put_roundtrip_is_idempotent_and_cannot_mutate_read_only_identity() {
        let f = Fixture::new();
        let created = f.user("alice");
        let id = created.body["id"].as_str().unwrap();
        let principal = f.principal("alice");
        let session = f
            .runtime
            .store
            .create_human_session(&principal.id, 3600, &f.runtime.config.issuer)
            .unwrap();
        let repeated = f
            .apply(
                "PUT",
                "Users",
                Some(id),
                "replace-same",
                created.etag.as_deref(),
                created.body.clone(),
            )
            .unwrap();
        assert_eq!(repeated.etag, created.etag);
        assert!(
            f.runtime
                .store
                .get_human_session(&session.id)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
        let mut changed = created.body.clone();
        changed["id"] = json!(uuid::Uuid::new_v4().to_string());
        assert!(
            f.apply(
                "PUT",
                "Users",
                Some(id),
                "wrong-id",
                created.etag.as_deref(),
                changed
            )
            .is_err()
        );
    }
    #[test]
    fn dispatch_fence_excludes_lifecycle_mutation_and_rejects_stale_reviewer() {
        let f = Fixture::new();
        let created = f.user("alice");
        let uid = created.body["id"].as_str().unwrap().to_owned();
        f.apply(
            "POST",
            "Groups",
            None,
            "reviewers",
            None,
            group("reviewers", &[&uid]),
        )
        .unwrap();
        let principal = f.principal("alice");
        let epoch = f
            .runtime
            .reviewer_eligibility(&principal.id, Role::Approver)
            .unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let runtime = f.runtime.clone();
        let version = created.etag.clone().unwrap();
        let mut worker = None;
        let mut dispatched = false;
        f.runtime
            .with_reviewer_authority(&principal.id, Role::Approver, epoch, &mut || {
                let started_tx = started_tx.clone();
                let done_tx = done_tx.clone();
                let runtime = runtime.clone();
                let version = version.clone();
                let uid = uid.clone();
                worker = Some(std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    let mut headers = HeaderMap::new();
                    headers.insert("idempotency-key", "disable-at-fence".parse().unwrap());
                    headers.insert("if-match", version.parse().unwrap());
                    runtime
                        .store
                        .scim_mutate(
                            &runtime,
                            "PUT",
                            "Users",
                            Some(&uid),
                            &headers,
                            user("alice", false),
                        )
                        .unwrap();
                    done_tx.send(()).unwrap();
                }));
                started_rx.recv().unwrap();
                assert!(
                    done_rx
                        .recv_timeout(std::time::Duration::from_millis(30))
                        .is_err(),
                    "mutation cannot commit inside the fence"
                );
                dispatched = true;
                Ok(())
            })
            .unwrap();
        worker.unwrap().join().unwrap();
        assert!(dispatched);
        assert!(done_rx.recv().is_ok());
        let mut called = false;
        assert!(
            f.runtime
                .with_reviewer_authority(&principal.id, Role::Approver, epoch, &mut || {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
    }
    #[test]
    fn provisioning_requires_current_scim_group_even_when_oidc_groups_are_stale() {
        let f = Fixture::new();
        let u = f.user("alice");
        let uid = u.body["id"].as_str().unwrap();
        let g = f
            .apply(
                "POST",
                "Groups",
                None,
                "g",
                None,
                group("reviewers", &[uid]),
            )
            .unwrap();
        let p = f.principal("alice");
        assert!(provisioning_group_permitted(&f.runtime.store.lock(), &p.id, "reviewers").unwrap());
        f.apply(
            "PUT",
            "Groups",
            Some(g.body["id"].as_str().unwrap()),
            "remove",
            g.etag.as_deref(),
            group("reviewers", &[]),
        )
        .unwrap();
        assert!(
            !provisioning_group_permitted(&f.runtime.store.lock(), &p.id, "reviewers").unwrap()
        );
    }
}
