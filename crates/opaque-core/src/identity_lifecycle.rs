//! Provider-neutral, tenant-bound identity lifecycle replication contract.
//! The source supplies membership observations; the broker maps those observations
//! through trusted admission and role configuration under its dispatch lock.
use crate::tenant::TenantBinding;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectUpdate {
    pub subject: String,
    pub active: bool,
    pub deleted: bool,
    pub groups: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleBatch {
    pub schema_version: u32,
    pub binding: TenantBinding,
    pub issuer: String,
    /// Strictly sequential source revision, starting at one. Only an exact
    /// replay of the last accepted revision is acknowledged again.
    pub revision: u64,
    pub updates: Vec<SubjectUpdate>,
    /// Terminal source-capacity fence. Recovery requires an offline procedure;
    /// a later update cannot clear it or revive consumed authority.
    pub suspend: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleReceipt {
    pub schema_version: u32,
    pub binding: TenantBinding,
    pub issuer: String,
    pub revision: u64,
    pub digest: String,
}
pub const MAX_BATCH_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_BATCH_UPDATES: usize = 4096;

/// One operation per Unix stream: big-endian u32 length followed by JSON.
/// Authenticate the OS peer before exposing the dedicated scoped credential.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    pub credential: String,
    pub batch: LifecycleBatch,
}
impl Drop for LifecycleRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.credential.zeroize();
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleResponse {
    Applied { receipt: LifecycleReceipt },
    Rejected { error: String },
}
pub const MAX_REQUEST_BYTES: usize = MAX_BATCH_BYTES + 256;
pub const MAX_RESPONSE_BYTES: usize = 4096;

/// Every ancestor must be controlled by the broker or root. A root sticky
/// temporary directory cannot replace a broker-owned child and is permitted.
pub fn validate_socket_path(socket: &std::path::Path, broker_uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if !socket.is_absolute() {
        return Err("lifecycle socket path must be absolute".into());
    }
    crate::socket::validate_path_chain(socket).map_err(|_| "unsafe lifecycle socket path")?;
    let parent = socket
        .parent()
        .ok_or("lifecycle socket parent unavailable")?;
    for directory in parent.ancestors() {
        let meta = std::fs::symlink_metadata(directory)
            .map_err(|_| "lifecycle socket parent unavailable")?;
        if !meta.is_dir()
            || (meta.uid() != broker_uid && meta.uid() != 0)
            || (meta.mode() & 0o022 != 0 && !(meta.uid() == 0 && meta.mode() & 0o1000 != 0))
        {
            return Err("unsafe lifecycle socket ancestor".into());
        }
    }
    let meta =
        std::fs::symlink_metadata(parent).map_err(|_| "lifecycle socket parent unavailable")?;
    if meta.uid() != broker_uid || meta.mode() & 0o022 != 0 {
        return Err(
            "lifecycle socket parent must be broker owned without group/other writes".into(),
        );
    }
    Ok(())
}

/// Sends a scoped mutation only to the configured broker UID. There is no TCP
/// fallback: a local user binding a vacant port must never receive this token
/// or impersonate an acknowledgment of revocation.
pub async fn deliver(
    socket: &std::path::Path,
    broker_uid: u32,
    credential: &str,
    batch: &LifecycleBatch,
) -> Result<LifecycleReceipt, String> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        validate_socket_path(socket, broker_uid)?;
        let parent = socket
            .parent()
            .ok_or("lifecycle socket parent unavailable")?;
        let directory =
            std::fs::symlink_metadata(parent).map_err(|_| "lifecycle socket unavailable")?;
        let endpoint =
            std::fs::symlink_metadata(socket).map_err(|_| "lifecycle socket unavailable")?;
        if !directory.is_dir()
            || directory.uid() != broker_uid
            || directory.mode() & 0o022 != 0
            || !endpoint.file_type().is_socket()
            || endpoint.uid() != broker_uid
            || endpoint.mode() & 0o007 != 0
        {
            return Err("lifecycle endpoint custody mismatch".into());
        }
        let mut stream = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|_| "lifecycle connection unavailable")?;
        exchange(&mut stream, broker_uid, credential, batch).await
    })
    .await
    .map_err(|_| "lifecycle delivery timed out")?
}
async fn exchange(
    stream: &mut tokio::net::UnixStream,
    broker_uid: u32,
    credential: &str,
    batch: &LifecycleBatch,
) -> Result<LifecycleReceipt, String> {
    use std::os::fd::AsRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let peer = crate::peer::peer_info_from_fd(stream.as_raw_fd())
        .map_err(|_| "lifecycle peer unavailable")?;
    if peer.uid != broker_uid {
        return Err("lifecycle broker UID mismatch".into());
    }
    if serde_json::to_vec(batch)
        .map_err(|_| "invalid lifecycle batch")?
        .len()
        > MAX_BATCH_BYTES
    {
        return Err("lifecycle batch exceeds bound".into());
    }
    let request = LifecycleRequest {
        credential: credential.to_owned(),
        batch: batch.clone(),
    };
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(&request).map_err(|_| "invalid lifecycle request")?,
    );
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("lifecycle request exceeds bound".into());
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| "lifecycle write unavailable")?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| "lifecycle write unavailable")?;
    let length = stream
        .read_u32()
        .await
        .map_err(|_| "lifecycle response unavailable")? as usize;
    if length == 0 || length > MAX_RESPONSE_BYTES {
        return Err("lifecycle response exceeds bound".into());
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "lifecycle response unavailable")?;
    match serde_json::from_slice(&bytes).map_err(|_| "invalid lifecycle response")? {
        LifecycleResponse::Applied { receipt } => {
            use sha2::{Digest, Sha256};
            let digest = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(batch).map_err(|_| "invalid lifecycle batch")?)
            );
            if receipt.schema_version != 1
                || receipt.binding != batch.binding
                || receipt.issuer != batch.issuer
                || receipt.revision != batch.revision
                || receipt.digest != digest
            {
                return Err("lifecycle receipt does not match pending mutation".into());
            }
            Ok(receipt)
        }
        LifecycleResponse::Rejected { error } => Err(error),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod transport_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn batch() -> LifecycleBatch {
        LifecycleBatch {
            schema_version: 1,
            binding: TenantBinding::new(
                crate::tenant::TenantId::parse("transport-fixture").unwrap(),
                uuid::Uuid::new_v4(),
            )
            .unwrap(),
            issuer: "https://idp.example".into(),
            revision: 2,
            updates: vec![SubjectUpdate {
                subject: "reviewer".into(),
                active: false,
                deleted: false,
                groups: vec![],
            }],
            suspend: false,
        }
    }

    fn receipt(batch: &LifecycleBatch) -> LifecycleReceipt {
        use sha2::{Digest, Sha256};
        LifecycleReceipt {
            schema_version: 1,
            binding: batch.binding.clone(),
            issuer: batch.issuer.clone(),
            revision: batch.revision,
            digest: format!("{:x}", Sha256::digest(serde_json::to_vec(batch).unwrap())),
        }
    }

    fn frame(bytes: &[u8]) -> Vec<u8> {
        let mut result = (bytes.len() as u32).to_be_bytes().to_vec();
        result.extend_from_slice(bytes);
        result
    }

    // A real, custody-checked Unix listener receives exactly one scoped
    // mutation. The responder is synthetic; broker state is tested separately.
    async fn response_over_socket(
        batch: &LifecycleBatch,
        response: Vec<u8>,
    ) -> Result<LifecycleReceipt, String> {
        let dir = tempfile::Builder::new()
            .prefix("oq-lifecycle-")
            .tempdir_in(std::fs::canonicalize("/tmp").unwrap())
            .unwrap();
        let socket = dir.path().join("lifecycle.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let client = deliver(
            &socket,
            unsafe { libc::geteuid() },
            "scoped-fixture-token",
            batch,
        );
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u32().await.unwrap() as usize;
            assert!(length > 0 && length <= MAX_REQUEST_BYTES);
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.unwrap();
            let request: LifecycleRequest = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(request.credential, "scoped-fixture-token");
            assert_eq!(&request.batch, batch);
            for chunk in response.chunks(3) {
                stream.write_all(chunk).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (result, ()) = tokio::join!(client, server);
            result
        })
        .await
        .expect("one exchange must terminate without retry")
    }

    #[tokio::test]
    async fn framed_delivery_requires_every_pending_mutation_receipt_binding() {
        let batch = batch();
        let valid = receipt(&batch);
        for case in 0..8 {
            let mut offered = valid.clone();
            match case {
                0 => {}
                1 => offered.schema_version = 2,
                2 => offered.binding.tenant_id = crate::tenant::TenantId::parse("other").unwrap(),
                3 => offered.binding.broker_id = uuid::Uuid::new_v4(),
                4 => offered.issuer = "https://different.example".into(),
                5 => offered.revision += 1,
                6 => offered.digest = "0".repeat(64),
                7 => offered.binding.schema_version = 2,
                _ => unreachable!(),
            }
            let response =
                serde_json::to_vec(&LifecycleResponse::Applied { receipt: offered }).unwrap();
            let result = response_over_socket(&batch, frame(&response)).await;
            if case == 0 {
                assert_eq!(result.unwrap(), valid);
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    "lifecycle receipt does not match pending mutation",
                    "case {case}"
                );
            }
        }
        let rejected = serde_json::to_vec(&LifecycleResponse::Rejected {
            error: "revision denied".into(),
        })
        .unwrap();
        assert_eq!(
            response_over_socket(&batch, frame(&rejected))
                .await
                .unwrap_err(),
            "revision denied"
        );
    }

    #[tokio::test]
    async fn framed_delivery_rejects_zero_oversized_malformed_and_truncated_responses() {
        let batch = batch();
        let cases = [
            (vec![0, 0, 0, 0], "lifecycle response exceeds bound"),
            (
                ((MAX_RESPONSE_BYTES + 1) as u32).to_be_bytes().to_vec(),
                "lifecycle response exceeds bound",
            ),
            (frame(b"{"), "invalid lifecycle response"),
            (
                frame(br#"{"status":"applied","receipt":null}"#),
                "invalid lifecycle response",
            ),
            (vec![0, 0], "lifecycle response unavailable"),
            (vec![0, 0, 0, 3, b'{'], "lifecycle response unavailable"),
        ];
        for (response, expected) in cases {
            assert_eq!(
                response_over_socket(&batch, response).await.unwrap_err(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn oversized_mutations_and_credentials_send_no_frame_bytes() {
        for oversized_batch in [true, false] {
            let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
            let mut batch = batch();
            let credential = if oversized_batch {
                batch.updates[0].subject = "x".repeat(MAX_BATCH_BYTES);
                "scoped-fixture-token".into()
            } else {
                "x".repeat(MAX_REQUEST_BYTES)
            };
            let result =
                exchange(&mut client, unsafe { libc::geteuid() }, &credential, &batch).await;
            assert_eq!(
                result.unwrap_err(),
                if oversized_batch {
                    "lifecycle batch exceeds bound"
                } else {
                    "lifecycle request exceeds bound"
                }
            );
            drop(client);
            let mut bytes = Vec::new();
            server.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.is_empty());
        }
    }

    #[tokio::test]
    async fn unsafe_socket_custody_denies_delivery_before_credentials_leave() {
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            validate_socket_path(std::path::Path::new("relative.sock"), uid).unwrap_err(),
            "lifecycle socket path must be absolute"
        );
        let dir = tempfile::Builder::new()
            .prefix("oq-custody-")
            .tempdir_in(std::fs::canonicalize("/tmp").unwrap())
            .unwrap();
        let socket = dir.path().join("lifecycle.sock");
        std::fs::write(&socket, b"preserve this file").unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            deliver(&socket, uid, "secret", &batch()).await.unwrap_err(),
            "lifecycle endpoint custody mismatch"
        );
        assert_eq!(std::fs::read(&socket).unwrap(), b"preserve this file");
        std::fs::remove_file(&socket).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o606)).unwrap();
        assert_eq!(
            deliver(&socket, uid, "secret", &batch()).await.unwrap_err(),
            "lifecycle endpoint custody mismatch"
        );
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            deliver(&socket, uid, "secret", &batch())
                .await
                .unwrap_err()
                .contains("unsafe lifecycle")
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[tokio::test]
    async fn wrong_peer_uid_receives_no_credential_or_mutation_bytes() {
        let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
        let batch = LifecycleBatch {
            schema_version: 1,
            binding: TenantBinding::new(
                crate::tenant::TenantId::parse("test").unwrap(),
                uuid::Uuid::new_v4(),
            )
            .unwrap(),
            issuer: "https://idp.example".into(),
            revision: 1,
            updates: vec![],
            suspend: true,
        };
        let error = exchange(
            &mut client,
            unsafe { libc::geteuid() }.wrapping_add(1),
            "never_disclose_this_fixture_credential",
            &batch,
        )
        .await
        .unwrap_err();
        assert!(error.contains("UID mismatch"));
        drop(client);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }
}
