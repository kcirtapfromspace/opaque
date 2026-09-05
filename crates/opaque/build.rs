use std::process::Command;

fn archive_revision(value: &str) -> Result<&str, &'static str> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("OPAQUE_BUILD_REVISION must be a full lowercase 40-character Git commit SHA");
    }
    Ok(&value[..7])
}

fn main() {
    // A verified source archive has no .git directory. Its build coordinator may
    // supply the full source commit; this is consistency metadata, not attestation.
    println!("cargo:rerun-if-env-changed=OPAQUE_BUILD_REVISION");
    let git_sha = match std::env::var("OPAQUE_BUILD_REVISION") {
        Ok(value) => archive_revision(&value)
            .unwrap_or_else(|message| panic!("{message}"))
            .to_owned(),
        Err(std::env::VarError::NotPresent) => Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("OPAQUE_BUILD_REVISION must be valid ASCII")
        }
    };

    println!("cargo:rustc-env=OPAQUE_GIT_SHA={git_sha}");
    // Rebuild when git HEAD changes (new commits).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/");
}

#[cfg(test)]
mod tests {
    use super::archive_revision;

    #[test]
    fn archive_revision_requires_exact_immutable_commit() {
        assert_eq!(
            archive_revision("190cb16d9c9082f56beb11f4dcee5ace5ba85e34"),
            Ok("190cb16")
        );
        for value in [
            "",
            "HEAD",
            "190cb16",
            &"A".repeat(40),
            &"g".repeat(40),
            &"é".repeat(20),
        ] {
            assert!(archive_revision(value).is_err());
        }
    }
}
