//! Explicit executable fixture for the official bws command boundary.
use super::client::BitwardenClient;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub(super) const PROJECT_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub(super) const SECRET_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub(super) const OTHER_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
pub(super) const TOKEN: &str = "disposable-fixture-token";

pub(super) struct Fixture {
    pub dir: tempfile::TempDir,
    pub executable: PathBuf,
    pub client: BitwardenClient,
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

impl Fixture {
    pub fn new() -> Self {
        Self::script("")
    }

    /// `prefix` is authored test code, never provider/user content.
    pub fn script(prefix: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("bws-fixture");
        let p = quote(dir.path().to_str().unwrap());
        let script = format!(
            r#"#!/bin/sh
set -eu
printf '%s\n' "$@" >> {p}/args
/bin/cat "$2" > {p}/config
[ "${{BWS_ACCESS_TOKEN-}}" = '{TOKEN}' ] || exit 9
[ -z "${{BWS_SERVER_URL-}}" ] || exit 10
[ -z "${{BWS_CONFIG_FILE-}}" ] || exit 11
[ -z "${{OPAQUE_BWS_PARENT_ONLY-}}" ] || exit 12
{prefix}
case "$9 ${{10}}" in
  'project list') /bin/cat {p}/projects.json ;;
  'secret list') /bin/cat {p}/secrets.json ;;
  'secret get') /bin/cat {p}/secret.json ;;
  *) exit 13 ;;
esac
"#
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
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
        }
    }

    pub fn recorded_args(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("args")).unwrap()
    }
}
