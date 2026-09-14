//! Actual disposable Git repositories, native peer cwd, and bounded metadata
//! faults. No global cwd/config, user repository, transport or credential helper.
use super::*;
use opaque_core::operation::WorkspaceContext;
use std::process::{Child, Stdio};

struct Repository {
    directory: tempfile::TempDir,
    root: PathBuf,
}

impl Repository {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let value = Self { directory, root };
        value.git(&["init", "-q", "-b", "main"]);
        std::fs::write(value.root.join("tracked"), "initial\n").unwrap();
        value.git(&["add", "tracked"]);
        value.git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "initial",
        ]);
        value
    }

    fn git(&self, args: &[&str]) -> String {
        let result = safe_command("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap().trim().to_owned()
    }

    fn claim(&self) -> WorkspaceContext {
        WorkspaceContext {
            repo_root: self.root.canonicalize().unwrap(),
            remote_url: None,
            branch: Some("main".into()),
            head_sha: Some(self.git(&["rev-parse", "HEAD"])),
            dirty: false,
            workspace_verified: false,
        }
    }

    fn unchanged_metadata(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            std::fs::read(self.root.join(".git/config")).unwrap(),
            std::fs::read(self.root.join(".git/index")).unwrap(),
            std::fs::read(self.root.join("tracked")).unwrap(),
        )
    }
}

struct Peer(Child);
impl Peer {
    fn at(path: &std::path::Path) -> Self {
        Self(
            safe_command("/bin/sleep")
                .arg("60")
                .current_dir(path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn identity(&self) -> ClientIdentity {
        ClientIdentity {
            uid: 0,
            gid: 0,
            pid: Some(self.0.id().try_into().unwrap()),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        }
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn workspace_rpc_binds_native_peer_and_sanitizes_verified_remote() {
    let repo = Repository::new();
    repo.git(&[
        "remote",
        "add",
        "origin",
        "https://secret-token@example.invalid/org/repo.git",
    ]);
    let child_dir = repo.root.join("subdir");
    std::fs::create_dir(&child_dir).unwrap();
    let peer = Peer::at(&child_dir);
    let mut claim = repo.claim();
    claim.remote_url = Some("https://secret-token@example.invalid/org/repo.git".into());
    // A client-supplied true value is not proof; native peer and Git are checked.
    claim.workspace_verified = true;
    let before = repo.unchanged_metadata();
    let verified = verified_workspace(&serde_json::json!({"workspace":claim}), &peer.identity())
        .await
        .unwrap()
        .unwrap();
    assert!(verified.workspace_verified);
    assert_eq!(verified.repo_root, repo.root.canonicalize().unwrap());
    assert_eq!(
        verified.remote_url.as_deref(),
        Some("https://example.invalid/org/repo.git")
    );
    assert_eq!(verified.branch.as_deref(), Some("main"));
    assert_eq!(verified.head_sha, claim.head_sha);
    assert!(!verified.dirty);
    assert_eq!(repo.unchanged_metadata(), before);

    let outside = Peer::at(repo.directory.path());
    assert_eq!(
        verified_workspace(&serde_json::json!({"workspace":claim}), &outside.identity())
            .await
            .unwrap_err(),
        "workspace verification failed"
    );
    assert_eq!(repo.unchanged_metadata(), before);
}

#[tokio::test]
async fn workspace_rpc_rejects_missing_peer_and_malformed_claim_before_verification() {
    let repo = Repository::new();
    let peer = Peer::at(&repo.root);
    let mut identity = peer.identity();
    identity.pid = None;
    assert_eq!(
        verified_workspace(&serde_json::json!({"workspace":repo.claim()}), &identity)
            .await
            .unwrap_err(),
        "workspace peer pid is unavailable"
    );
    for value in [
        serde_json::json!(false),
        serde_json::json!("repository"),
        serde_json::json!({"repo_root":3}),
    ] {
        assert_eq!(
            verified_workspace(&serde_json::json!({"workspace":value}), &peer.identity())
                .await
                .unwrap_err(),
            "invalid workspace context"
        );
    }
    for params in [serde_json::json!({}), serde_json::json!({"workspace":null})] {
        assert!(
            verified_workspace(&params, &identity)
                .await
                .unwrap()
                .is_none()
        );
    }
    identity.pid = Some(i32::MAX);
    assert_eq!(
        verified_workspace(&serde_json::json!({"workspace":repo.claim()}), &identity)
            .await
            .unwrap_err(),
        "workspace verification failed"
    );
}

#[test]
fn workspace_rejects_non_repository_and_nested_claimed_toplevel() {
    let repo = Repository::new();
    let mut claim = repo.claim();
    claim.repo_root = repo.directory.path().to_owned();
    assert!(
        verify_workspace_blocking(&claim, None)
            .unwrap_err()
            .ends_with("is not a git repository")
    );
    let subdir = repo.root.join("nested");
    std::fs::create_dir(&subdir).unwrap();
    claim.repo_root = subdir;
    assert!(
        verify_workspace_blocking(&claim, None)
            .unwrap_err()
            .contains("does not match claimed repo_root")
    );
    let peer = Peer::at(repo.directory.path());
    claim = repo.claim();
    assert!(
        verify_workspace_blocking(&claim, peer.identity().pid)
            .unwrap_err()
            .contains("is not within claimed repo_root")
    );
    assert_eq!(
        verify_workspace_blocking(&claim, Some(i32::MAX)).unwrap_err(),
        format!(
            "cannot read cwd for pid {}: workspace verification requires readable cwd",
            i32::MAX
        )
    );
}

#[test]
fn workspace_remote_and_branch_failures_do_not_echo_remote_credentials() {
    let repo = Repository::new();
    let mut claim = repo.claim();
    claim.remote_url = Some("https://claimed-secret@other.invalid/repo".into());
    assert_eq!(
        verify_workspace_blocking(&claim, None).unwrap_err(),
        "git remote get-url origin failed: cannot verify claimed remote_url"
    );
    repo.git(&[
        "remote",
        "add",
        "origin",
        "https://actual-secret@example.invalid/repo",
    ]);
    let error = verify_workspace_blocking(&claim, None).unwrap_err();
    assert_eq!(
        error,
        "claimed remote_url 'https://other.invalid/repo' does not match actual 'https://example.invalid/repo'"
    );
    assert!(!error.contains("secret"));
    claim.remote_url = Some("https://example.invalid/repo".into());
    claim.branch = Some("not-main".into());
    assert_eq!(
        verify_workspace_blocking(&claim, None).unwrap_err(),
        "claimed branch 'not-main' does not match actual 'main'"
    );
    claim.branch = Some("main".into());
    let before = repo.unchanged_metadata();
    verify_workspace_blocking(&claim, None).unwrap();
    assert_eq!(repo.unchanged_metadata(), before);
}

#[test]
fn unborn_workspace_cannot_claim_a_verified_branch_or_head() {
    let repo = Repository::new();
    repo.git(&["checkout", "--orphan", "unborn"]);
    let claim = WorkspaceContext {
        repo_root: repo.root.clone(),
        remote_url: None,
        branch: Some("unborn".into()),
        head_sha: None,
        dirty: true,
        workspace_verified: false,
    };
    assert_eq!(
        verify_workspace_blocking(&claim, None).unwrap_err(),
        "git rev-parse --abbrev-ref HEAD failed: cannot verify claimed branch"
    );
    assert_eq!(
        WorkspaceGitSnapshot::capture(&repo.root).err().unwrap(),
        "workspace metadata cannot be verified safely"
    );
}

#[test]
fn sparse_and_external_config_fail_closed_without_mutating_git_state() {
    let repo = Repository::new();
    for key in [
        "core.sparseCheckout",
        "core.sparseCheckoutCone",
        "index.sparse",
    ] {
        repo.git(&["config", key, "true"]);
        let before = repo.unchanged_metadata();
        assert_eq!(
            WorkspaceGitSnapshot::capture(&repo.root).err().unwrap(),
            "sparse workspaces cannot be verified safely",
            "{key}"
        );
        assert_eq!(repo.unchanged_metadata(), before);
        // Disabled spellings remain safe: the snapshot has a complete index.
        for disabled in ["false", "no", "off", "0"] {
            repo.git(&["config", key, disabled]);
            assert!(
                !WorkspaceGitSnapshot::capture(&repo.root)
                    .unwrap()
                    .is_dirty()
                    .unwrap()
            );
        }
        repo.git(&["config", "--unset", key]);
    }
    for key in ["core.attributesFile", "core.excludesFile"] {
        let external = repo.directory.path().join("outside-config");
        std::fs::write(&external, "tracked filter=untrusted\n").unwrap();
        repo.git(&["config", key, external.to_str().unwrap()]);
        let before = repo.unchanged_metadata();
        assert_eq!(
            WorkspaceGitSnapshot::capture(&repo.root).err().unwrap(),
            "external workspace attribute or exclude files are unsupported"
        );
        assert_eq!(repo.unchanged_metadata(), before);
        assert_eq!(
            std::fs::read(external).unwrap(),
            b"tracked filter=untrusted\n"
        );
        repo.git(&["config", "--unset", key]);
    }
}

#[test]
fn snapshot_rejects_unbounded_and_noncanonical_safe_configuration() {
    let repo = Repository::new();
    for value in ["a".repeat(33), "contains space".into(), "unicodé".into()] {
        repo.git(&["config", "core.checkstat", &value]);
        let before = repo.unchanged_metadata();
        assert_eq!(
            WorkspaceGitSnapshot::capture(&repo.root).err().unwrap(),
            "workspace metadata cannot be verified safely"
        );
        assert_eq!(repo.unchanged_metadata(), before);
    }
    repo.git(&["config", "--unset", "core.checkstat"]);
    // Real Git emits this metadata; the 128 KiB command-output cap is exercised.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(repo.root.join(".git/config"))
        .unwrap();
    use std::io::Write;
    writeln!(file, "[opaque]\nlarge = {}", "x".repeat(129 * 1024)).unwrap();
    drop(file);
    let before = repo.unchanged_metadata();
    assert_eq!(
        WorkspaceGitSnapshot::capture(&repo.root).err().unwrap(),
        "workspace metadata cannot be verified safely"
    );
    assert_eq!(repo.unchanged_metadata(), before);
}

#[test]
fn metadata_copy_rejects_symlinks_directories_and_oversized_files_without_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("destination");
    std::fs::write(&target, b"unchanged").unwrap();
    let source = directory.path().join("source");
    std::fs::write(&source, b"12345").unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert_eq!(
        WorkspaceGitSnapshot::copy_metadata(&link, &target, 5).unwrap_err(),
        "workspace metadata unavailable"
    );
    for path in [&source, directory.path()] {
        assert_eq!(
            WorkspaceGitSnapshot::copy_metadata(path, &target, 4).unwrap_err(),
            "workspace metadata exceeds supported limits"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    }
    WorkspaceGitSnapshot::copy_metadata(&directory.path().join("absent"), &target, 5).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    WorkspaceGitSnapshot::copy_metadata(&source, &target, 5).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"12345");
    assert_eq!(std::fs::read(&source).unwrap(), b"12345");
    assert_eq!(
        WorkspaceGitSnapshot::copy_metadata(&source, &directory.path().join("missing/output"), 5)
            .unwrap_err(),
        "workspace metadata snapshot unavailable"
    );
}

#[test]
fn snapshot_rejects_skip_worktree_and_corrupt_index_without_repairing_original() {
    let repo = Repository::new();
    repo.git(&["update-index", "--skip-worktree", "tracked"]);
    let before = repo.unchanged_metadata();
    assert_eq!(
        WorkspaceGitSnapshot::capture(&repo.root).err().unwrap(),
        "assume-unchanged, split or sparse workspace indexes are unsupported"
    );
    assert_eq!(repo.unchanged_metadata(), before);
    repo.git(&["update-index", "--no-skip-worktree", "tracked"]);
    std::fs::write(repo.root.join(".git/index"), b"not a Git index").unwrap();
    let before = repo.unchanged_metadata();
    assert_eq!(
        WorkspaceGitSnapshot::capture(&repo.root).err().unwrap(),
        "assume-unchanged, split or sparse workspace indexes are unsupported"
    );
    assert_eq!(repo.unchanged_metadata(), before);
}

#[test]
fn snapshot_preserves_executable_symlink_gitlink_and_unmerged_index_entries() {
    let repo = Repository::new();
    let blob = repo.git(&["rev-parse", "HEAD:tracked"]);
    let head = repo.git(&["rev-parse", "HEAD"]);
    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("100755,{blob},executable"),
    ]);
    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("120000,{blob},symlink"),
    ]);
    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{head},submodule"),
    ]);
    let input = repo.directory.path().join("stages");
    std::fs::write(
        &input,
        format!(
            "100644 {blob} 1\tconflict\n100644 {blob} 2\tconflict\n100644 {blob} 3\tconflict\n"
        ),
    )
    .unwrap();
    let result = safe_command("git")
        .arg("-C")
        .arg(&repo.root)
        .args(["update-index", "--index-info"])
        .stdin(std::fs::File::open(input).unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let before = repo.unchanged_metadata();
    let expected = repo.git(&["ls-files", "--stage"]);
    let snapshot = WorkspaceGitSnapshot::capture(&repo.root).unwrap();
    let result = snapshot
        .command()
        .args(["ls-files", "--stage"])
        .workspace_output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), expected);
    assert!(snapshot.is_dirty().unwrap());
    assert_eq!(repo.unchanged_metadata(), before);
}

#[test]
fn snapshot_rejects_unsupported_sha256_repository_without_changing_it() {
    let directory = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let result = safe_command("git")
            .arg("-C")
            .arg(directory.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    };
    git(&["init", "-q", "--object-format=sha256"]);
    git(&[
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--allow-empty",
        "-qm",
        "initial",
    ]);
    let head = git(&["rev-parse", "HEAD"]);
    assert_eq!(head.len(), 65);
    assert_eq!(
        WorkspaceGitSnapshot::capture(directory.path())
            .err()
            .unwrap(),
        "workspace HEAD or object format is unsupported"
    );
    assert_eq!(git(&["rev-parse", "HEAD"]), head);
}

#[test]
fn snapshot_does_not_trust_later_corruption_of_its_private_index() {
    let repo = Repository::new();
    let snapshot = WorkspaceGitSnapshot::capture(&repo.root).unwrap();
    assert!(!snapshot.is_dirty().unwrap());
    let before = repo.unchanged_metadata();
    std::fs::write(snapshot.directory.path().join("index"), b"corrupt snapshot").unwrap();
    assert_eq!(
        snapshot.is_dirty().unwrap_err(),
        "workspace index is unsupported or unavailable"
    );
    assert_eq!(repo.unchanged_metadata(), before);
}
