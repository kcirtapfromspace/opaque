#!/usr/bin/env python3
"""Real CLI + opaqued + systemd --user acceptance in an owned Linux container.

Never run on a workstation: require root, the contained image marker and systemd
PID1. Create one unique disposable account; never use an existing user manager.
No service-controller substitution, permissive daemon flags, or provider calls.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opaque", type=Path, required=True)
    parser.add_argument("--opaqued", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--coverage-input", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd"
    assert os.environ.get("container") == "docker", "requires the owned contained image"
    assert Path("/etc/opaque-contained-fixture").read_text().strip() == "opaque-contained-ssh-v1"
    assert not args.output.exists(), "evidence output must be fresh"
    args.output.mkdir(mode=0o700, parents=True)
    binaries = {name: path.resolve(strict=True) for name, path in [("opaque", args.opaque), ("opaqued", args.opaqued)]}
    coverage = None
    coverage_env = {}
    coverage_support = None
    source_root = Path(__file__).resolve().parents[2]
    if args.coverage_input:
        sys.path.insert(0, str(source_root / "scripts"))
        import acceptance_coverage as coverage_support
        coverage = coverage_support.load(args.coverage_input, root=source_root, purpose="service")
        assert all(str(path) == coverage["objects"][label]["path"] for label, path in binaries.items())
        coverage_env = coverage_support.environment(coverage, role="service")
    hashes = {name: hashlib.file_digest(path.open("rb"), "sha256").hexdigest() for name, path in binaries.items()}
    name = "oqsvc" + uuid.uuid4().hex[:12]
    home = Path("/home") / name
    record = {"schema": "opaque.contained-user-service.v1", "status": "running", "binary_sha256": hashes,
              "scope": "real CLI, real daemon and real systemd user manager; no cloud vendor or human approval qualification", "checks": []}
    if coverage:
        record["source_before"] = coverage["source"]
    created = False
    uid = None
    rust_pids = set()

    def command(argv, *, success=True):
        result = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        if success:
            assert result.returncode == 0, (argv, result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
        return result

    def as_user(argv, *, success=True):
        return command(["runuser", "-u", name, "--", "env", "-i", f"HOME={home}",
                        f"XDG_RUNTIME_DIR=/run/user/{uid}", f"PATH={home}/bin:/usr/bin:/bin", "NO_COLOR=1",
                        *(f"{key}={value}" for key, value in coverage_env.items()), *argv], success=success)

    def cli(*argv, success=True):
        pid_file = home / (".cli-pid-" + uuid.uuid4().hex)
        # The shell records its own PID before exec; that exact PID becomes the
        # actual Rust CLI, not the outer runuser process. No source instrumentation
        # is simulated and every observed CLI process must retain LLVM counters.
        result = as_user(["/bin/sh", "-c", 'pid_file=$1; shift; printf "%s\\n" "$$" > "$pid_file"; exec "$@"',
                          "owned-cli", pid_file, home / "bin/opaque", "--yes", *argv], success=False)
        rust_pids.add(int(pid_file.read_text().strip()))
        pid_file.unlink()
        if success:
            assert result.returncode == 0, (argv, result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
        return result

    def state():
        output = as_user(["systemctl", "--user", "show", "opaqued.service", "--property=ActiveState,MainPID,SubState"], success=False)
        return dict(line.split("=", 1) for line in output.stdout.decode().splitlines() if "=" in line)

    def running(previous=None):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            snapshot = state()
            pid = int(snapshot.get("MainPID", "0"))
            if snapshot.get("ActiveState") == "active" and pid > 0 and pid != previous:
                result = cli("ping", success=False)
                if result.returncode == 0:
                    assert Path(f"/proc/{pid}").stat().st_uid == uid
                    rust_pids.add(pid)
                    return pid
            time.sleep(0.05)
        raise AssertionError(("daemon did not become reachable", state()))

    try:
        command(["useradd", "--create-home", "--user-group", "--shell", "/bin/sh", name]); created = True
        uid = pwd.getpwnam(name).pw_uid
        record["fixture_uid"] = uid
        (home / "bin").mkdir(mode=0o700)
        (home / ".opaque").mkdir(mode=0o700)
        for label, source in binaries.items():
            shutil.copy2(source, home / "bin" / label)
        assert hashes == {label: hashlib.file_digest((home / "bin" / label).open("rb"), "sha256").hexdigest() for label in binaries}
        (home / ".opaque/config.toml").write_text("require_seal = true\n")
        command(["chown", "-R", f"{uid}:{pwd.getpwnam(name).pw_gid}", home])
        command(["systemctl", "start", f"user@{uid}.service"])
        if coverage:
            as_user(["systemctl", "--user", "set-environment", *(f"{key}={value}" for key, value in coverage_env.items())])
        cli("setup", "--seal"); cli("setup", "--verify")
        record["checks"].append("real-keyed-seal")
        cli("service", "install")
        unit = home / ".config/systemd/user/opaqued.service"
        assert unit.is_file() and unit.stat().st_uid == uid
        pid1 = running()
        assert as_user(["systemctl", "--user", "is-enabled", "opaqued.service"]).stdout.strip() == b"enabled"
        record["checks"].append("install-enabled-reachable-owned-daemon")
        assert cli("service", "install", success=False).returncode == 1
        cli("service", "stop")
        assert state()["ActiveState"] == "inactive" and state()["MainPID"] == "0"
        assert not Path(f"/proc/{pid1}").exists()
        record["checks"].append("stop-reaped-daemon")
        cli("service", "start"); pid2 = running(previous=pid1)
        cli("service", "restart"); pid3 = running(previous=pid2)
        assert not Path(f"/proc/{pid2}").exists()
        record["checks"].append("start-and-restart-new-reachable-pids")
        assert str(pid3).encode() in cli("service", "status").stdout
        cli("service", "uninstall")
        assert not unit.exists() and not Path(f"/proc/{pid3}").exists()
        assert as_user(["systemctl", "--user", "is-enabled", "opaqued.service"], success=False).returncode != 0
        assert state().get("MainPID", "0") == "0"
        record["checks"].append("uninstall-disabled-removed-and-reaped")
        # The actual systemctl must report a missing user-manager connection as
        # failure. Stop only this fixture's manager; a failed install retains its
        # unit file and must not print completed installation.
        if coverage:
            as_user(["systemctl", "--user", "unset-environment", *coverage_env])
        command(["systemctl", "stop", f"user@{uid}.service"])
        rejected = cli("service", "install", success=False)
        assert rejected.returncode == 1 and unit.is_file()
        assert b"installed and started" not in rejected.stdout
        record["checks"].append("actual-systemctl-unavailable-manager-denied")
        assert hashes == {label: hashlib.file_digest(path.open("rb"), "sha256").hexdigest() for label, path in binaries.items()}
        assert hashes == {label: hashlib.file_digest((home / "bin" / label).open("rb"), "sha256").hexdigest() for label in binaries}
        record["rust_process_ids"] = sorted(rust_pids)
        if coverage:
            import synthesized_suite
            record["source_after"] = synthesized_suite.source_snapshot(source_root)
            assert record["source_after"] == record["source_before"], "source changed during service acceptance"
            record["coverage"] = {"input_sha256": coverage["_input_sha256"],
                                  "profiles": coverage_support.profiles(coverage, roles={"service"}, process_ids=rust_pids)}
        record["status"] = "passed"
    finally:
        cleanup = []
        if created:
            assert pwd.getpwnam(name).pw_uid == uid and home == Path(pwd.getpwnam(name).pw_dir)
            if uid is not None:
                if coverage:
                    as_user(["systemctl", "--user", "unset-environment", *coverage_env], success=False)
                command(["systemctl", "stop", f"user@{uid}.service"], success=False)
                command(["systemctl", "stop", f"user-runtime-dir@{uid}.service"], success=False)
            removed = command(["userdel", "--remove", name], success=False)
            if removed.returncode != 0 or home.exists():
                cleanup.append("owned_user_cleanup_failed")
            try:
                pwd.getpwnam(name)
                cleanup.append("owned_user_remained")
            except KeyError:
                pass
        if record["status"] != "passed":
            record["status"] = "failed"
        record["cleanup_errors"] = cleanup
        if cleanup:
            record["status"] = "failed"
        (args.output / "report.json").write_text(json.dumps(record, indent=2) + "\n")
        assert not cleanup, cleanup
    print(json.dumps(record))


if __name__ == "__main__":
    main()
