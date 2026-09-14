//! Explicit executable fixture for the official bws command boundary.
use super::client::BitwardenClient;
use std::path::PathBuf;

pub(super) const PROJECT_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub(super) const SECRET_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub(super) const OTHER_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

pub(super) struct Fixture {
    pub dir: tempfile::TempDir,
    pub executable: PathBuf,
    pub client: BitwardenClient,
    pub token: String,
}

impl Fixture {
    pub fn new() -> Self {
        Self::script("")
    }

    /// `prefix` is authored test code, never provider/user content.
    pub fn script(prefix: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let executable = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/bws.sh"
        ));
        // The executable is never opened for writing while tests spawn.
        // Only sidecar data changes, avoiding inherited writer FDs/ETXTBSY.
        // The client clears ambient env, so its disposable token identifies
        // this fixture through the actual credential-delivery boundary.
        let token = format!("disposable-fixture-token:{}", dir.path().to_str().unwrap());
        std::fs::write(dir.path().join("behavior"), prefix).unwrap();
        std::fs::write(
            dir.path().join("projects.json"),
            serde_json::json!([
                {"id": PROJECT_ID,"name":"Production","organizationId":OTHER_ID}
            ])
            .to_string(),
        )
        .unwrap();
        let secret = serde_json::json!({"id":SECRET_ID,"key":"DB_PASSWORD","value":"secret with trailing spaces  \n", "note":"private fixture note", "projectId":PROJECT_ID});
        std::fs::write(
            dir.path().join("secrets.json"),
            serde_json::json!([secret.clone()]).to_string(),
        )
        .unwrap();
        std::fs::write(dir.path().join("secret.json"), secret.to_string()).unwrap();
        let client = BitwardenClient::with_executable(
            "https://api.bitwarden.com",
            "https://identity.bitwarden.com",
            &executable,
        )
        .unwrap();
        Self {
            dir,
            executable,
            client,
            token,
        }
    }

    pub fn recorded_args(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("args")).unwrap()
    }
}
