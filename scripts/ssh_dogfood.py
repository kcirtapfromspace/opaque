#!/usr/bin/env python3
"""Exercise real OpenSSH command/session controls on disposable private hosts.

No native approval, broker grant, production identity or real service is claimed.
Only this run's named containers/network are removed. Keys/logs stay in /tmp.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/bounded-ssh"
DB = "/var/lib/opaque-ssh/grants.sqlite"
GUARD = ["/usr/bin/python3", "-I", "/opt/opaque-ssh/host_guard.py"]
COMMAND = "opaque-service-health"


def run(argv, *, check=True, timeout=45):
    result = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{argv[0]} exited {result.returncode}: {result.stderr[-3000:]}")
    return result


class Fixture:
    def __init__(self, image, directory):
        self.image, self.directory = image, directory
        self.prefix = "opaque-ssh-" + uuid.uuid4().hex[:12]
        self.network = self.prefix + "-net"
        self.a, self.b = self.prefix + "-a", self.prefix + "-b"
        self.client, self.foreign = self.prefix + "-client", self.prefix + "-foreign"
        # Track intended resources before any possibly ambiguous Docker reply.
        self.containers = [self.client, self.foreign, self.a, self.b]
        self.results = []
        self.runtime = {}

    def docker(self, *args, **kwargs):
        return run(["docker", *args], **kwargs)

    def copy(self, path, target, destination):
        self.docker("cp", path, f"{target}:{destination}")

    def inside(self, target, *args, **kwargs):
        return self.docker("exec", target, *args, **kwargs)

    def setup(self):
        self.runtime["image_id"] = self.docker("image", "inspect", "--format", "{{.Id}}", self.image).stdout.strip()
        for name in ["ca", "client_key"]:
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.directory / name])
        self.docker("network", "create", "--internal", self.network)
        for name in [self.client, self.foreign]:
            self.docker("run", "-d", "--name", name, "--network", self.network,
                        "--entrypoint", "/bin/sleep", self.image, "infinity")
            self.copy(self.directory / "client_key", name, "/client/key")
            self.inside(name, "chown", "7382:7382", "/client/key")
            self.inside(name, "chmod", "600", "/client/key")
        self.client_ip = json.loads(self.docker("inspect", self.client).stdout)[0]["NetworkSettings"]["Networks"][self.network]["IPAddress"]
        self.runtime["openssh_version"] = self.inside(self.client, "ssh", "-V").stderr.strip()
        for name, host in [(self.a, "fixture-a"), (self.b, "fixture-b")]:
            self.docker("create", "--name", name, "--network", self.network,
                        "--network-alias", host, "--env", f"FIXTURE_HOST={host}", self.image)
            self.copy(self.directory / "ca.pub", name, "/etc/opaque-ssh/ca.pub")
            self.docker("start", name)
            self.ready(name)
        known = self.directory / "known_hosts"
        known.write_text("".join(
            f"[{host}]:2222 " + self.inside(name, "cat", "/etc/opaque-ssh/host_key.pub").stdout
            for name, host in [(self.a, "fixture-a"), (self.b, "fixture-b")]
        ))
        for name in [self.client, self.foreign]:
            self.copy(known, name, "/client/known_hosts")
            self.inside(name, "chmod", "644", "/client/known_hosts")
        wrong_known = self.directory / "wrong_known_hosts"
        wrong_known.write_text("[fixture-a]:2222 " + self.inside(self.b, "cat", "/etc/opaque-ssh/host_key.pub").stdout)
        self.copy(wrong_known, self.client, "/client/wrong_known_hosts")
        self.inside(self.client, "chmod", "644", "/client/wrong_known_hosts")

    def ready(self, name):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            result = self.inside(name, "/usr/bin/python3", "-c",
                                "import socket; s=socket.create_connection(('127.0.0.1',2222),.2); s.close()", check=False)
            if result.returncode == 0:
                return
            time.sleep(.1)
        raise RuntimeError("SSH host failed readiness: " + self.docker("logs", name, check=False).stderr[-2500:])

    def issue(self, *, principal="opaque-fixture-a-health", lifetime=120,
              max_seconds=5, expired_cert=False, forced=True, force_override=None):
        grant = str(uuid.uuid4())
        now = int(time.time())
        self.inside(self.a, *GUARD, "grant", "--db", DB, "--id", grant,
                    "--host", "fixture-a", "--principal", "opaque-fixture-a-health",
                    "--expires-at", str(now + lifetime), "--max-seconds", str(max_seconds))
        public = self.directory / f"{grant}.pub"
        shutil.copyfile(self.directory / "client_key.pub", public)
        end = now - 1 if expired_cert else now + lifetime
        command = force_override or f"/usr/bin/python3 -I /opt/opaque-ssh/host_guard.py enter {grant}"
        argv = ["ssh-keygen", "-q", "-s", self.directory / "ca", "-I", grant,
                "-z", str(uuid.uuid4().int % (2**63)), "-n", principal,
                "-V", f"0x{now-60:x}:0x{end:x}", "-O", "clear",
                "-O", f"source-address={self.client_ip}/32"]
        if forced:
            argv.extend(["-O", f"force-command={command}"])
        run([*argv, public])
        for name in [self.client, self.foreign]:
            self.copy(public.with_name(f"{grant}-cert.pub"), name, f"/client/{grant}-cert.pub")
            self.inside(name, "chmod", "644", f"/client/{grant}-cert.pub")
        return grant

    def ssh(self, grant, *, command=COMMAND, host="fixture-a", user="opaque", options=(), foreign=False):
        argv = ["docker", "exec", "--user", "7382:7382", self.foreign if foreign else self.client,
                "ssh", *options, "-F", "/dev/null", "-p", "2222", "-i", "/client/key",
                "-o", f"CertificateFile=/client/{grant}-cert.pub",
                "-o", "UserKnownHostsFile=/client/known_hosts", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "ConnectTimeout=5",
                "-o", "ControlMaster=no", "-o", "ControlPath=none", f"{user}@{host}"]
        if command:
            argv.append(command)
        return run(argv, check=False, timeout=20)

    def reads(self):
        return int(self.inside(self.a, "/usr/bin/python3", "-c",
                   "from pathlib import Path; p=Path('/var/lib/opaque-ssh/reads'); print(p.read_text() if p.exists() else 0)").stdout)

    def check(self, name, condition):
        if not condition:
            raise AssertionError(name)
        self.results.append(name)
        print(f"PASS {name}", flush=True)

    def deny(self, name, grant, **kwargs):
        before = self.reads()
        response = self.ssh(grant, **kwargs)
        self.check(name, response.returncode != 0 and self.reads() == before)

    def revoke(self, grant):
        self.inside(self.a, *GUARD, "revoke", "--db", DB, "--id", grant)

    def no_probe(self, reason):
        code = """from pathlib import Path
count = 0
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        count += b'/opt/opaque-ssh/health_probe.py' in path.read_bytes().split(b'\\0')
    except (FileNotFoundError, ProcessLookupError):
        pass
print(count)
"""
        count = self.inside(self.a, "/usr/bin/python3", "-c", code).stdout.strip()
        self.check(f"no health probe remains after {reason}", count == "0")

    def exercise(self):
        grant = self.issue()
        before = self.reads()
        response = self.ssh(grant)
        if response.returncode:
            raise RuntimeError(f"allowed SSH failed: {response.stdout[-2000:]} {response.stderr[-2000:]}")
        body = json.loads(response.stdout)
        self.check("one fixed health read and bound receipt", body["status"] == "completed"
                   and body["result"] == {"service": "fixture-api", "status": "ok", "version": "1"}
                   and body["receipt"]["grant_id"] == grant and body["receipt"]["host"] == "fixture-a"
                   and body["receipt"]["principal"] == "opaque-fixture-a-health"
                   and self.reads() == before + 1)
        self.deny("replay denied without a second read", grant)
        self.docker("restart", self.a)
        self.ready(self.a)
        self.deny("replay remains denied after host restart", grant)

        unused = self.issue()
        for command in ["id", COMMAND + "; id", "", "sftp"]:
            self.deny(f"foreign command/shell denied: {command!r}", unused, command=command)
        self.deny("SFTP subsystem denied", unused, command="sftp", options=("-s",))
        # OpenSSH may continue a permitted command after refusing its PTY.
        # Require an observed PTY rejection and prove it cannot open a shell.
        before = self.reads()
        pty = self.ssh(unused, command="", options=("-tt",))
        self.check("PTY allocation and interactive shell denied", pty.returncode != 0
                   and "PTY allocation request failed" in pty.stderr and self.reads() == before)
        self.deny("TCP forwarding denied", unused, command="", options=("-N", "-R", "0:127.0.0.1:8080", "-o", "ExitOnForwardFailure=yes"))
        before = self.reads()
        start = time.monotonic()
        no_channel = self.ssh(unused, command="", options=("-N", "-v"))
        self.check("authenticated connection without a channel is closed", no_channel.returncode != 0
                   and "Authenticated to fixture-a" in no_channel.stderr
                   and self.reads() == before and time.monotonic() - start < 6)
        self.deny("foreign login user denied", unused, user="root")
        self.deny("foreign host principal denied", unused, host="fixture-b")
        self.deny("foreign source address denied", unused, foreign=True)
        before = self.reads()
        wrong_pin = self.ssh(unused, options=("-o", "UserKnownHostsFile=/client/wrong_known_hosts",))
        self.check("wrong pinned host key denied", wrong_pin.returncode != 0
                   and "REMOTE HOST IDENTIFICATION HAS CHANGED" in wrong_pin.stderr and self.reads() == before)
        self.deny("foreign certificate principal denied", self.issue(principal="opaque-fixture-b-health"))
        self.deny("expired certificate denied", self.issue(expired_cert=True))
        self.deny("certificate force-command cannot override host command", self.issue(force_override="/usr/bin/id"))
        # The host command remains mandatory even if a CA omits the certificate option.
        self.deny("host enforces command when certificate omits it", self.issue(forced=False), command="id")
        revoked = self.issue()
        self.revoke(revoked)
        self.deny("revoked grant denied", revoked)
        self.check("denied requests did not consume valid grant", self.ssh(unused).returncode == 0)

        concurrent = self.issue()
        before = self.reads()
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.ssh(concurrent), range(6)))
        self.check("six concurrent sessions consume exactly one allowance",
                   sum(r.returncode == 0 for r in results) == 1 and self.reads() == before + 1)

        self.inside(self.a, "touch", "/var/lib/opaque-ssh/hang")
        timed = self.issue(max_seconds=1)
        before = self.reads()
        start = time.monotonic()
        response = self.ssh(timed)
        timed_body = json.loads(response.stdout)
        self.check("active command duration enforced without output release", response.returncode != 0
                   and timed_body["status"] == "timeout" and "result" not in timed_body
                   and timed_body["receipt"]["grant_id"] == timed
                   and timed_body["receipt"]["result_code"] == "duration_exceeded"
                   and self.reads() == before + 1 and time.monotonic() - start < 4)
        self.no_probe("duration timeout")
        self.deny("timed-out allowance cannot be replayed", timed)

        expiring = self.issue(lifetime=4, max_seconds=10)
        before = self.reads()
        start = time.monotonic()
        response = self.ssh(expiring)
        expiry_body = json.loads(response.stdout)
        self.check("expiry terminates an already authenticated operation", response.returncode != 0
                   and expiry_body["status"] == "expired" and "result" not in expiry_body
                   and expiry_body["receipt"]["grant_id"] == expiring
                   and expiry_body["receipt"]["result_code"] == "expired" and self.reads() == before + 1
                   and time.monotonic() - start < 6)
        self.no_probe("expiry")

        active = self.issue(max_seconds=10)
        before = self.reads()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(self.ssh, active)
            deadline = time.monotonic() + 5
            while self.reads() == before and time.monotonic() < deadline:
                time.sleep(.05)
            self.check("revocation test reached the fixed source", self.reads() == before + 1)
            start = time.monotonic()
            self.revoke(active)
            response = result.result(timeout=4)
        revoked_body = json.loads(response.stdout)
        self.check("revocation terminates active work without output release", response.returncode != 0
                   and revoked_body["status"] == "revoked" and "result" not in revoked_body
                   and revoked_body["receipt"]["grant_id"] == active
                   and revoked_body["receipt"]["result_code"] == "revoked"
                   and time.monotonic() - start < 3)
        self.inside(self.a, "rm", "/var/lib/opaque-ssh/hang")
        # The probe, rather than the already accepted source request, must be gone.
        self.no_probe("revocation")

    def cleanup(self):
        errors = []
        for name in reversed(self.containers):
            try:
                logs = self.docker("logs", name, check=False, timeout=10)
                (self.directory / f"{name}.log").write_text(logs.stdout + logs.stderr)
            except (OSError, subprocess.TimeoutExpired) as error:
                errors.append(f"log capture failed for {name}: {type(error).__name__}")
            try:
                removal = self.docker("rm", "-f", name, check=False, timeout=15)
                if removal.returncode and "No such container" not in removal.stderr:
                    errors.append(f"container removal failed: {name}")
            except (OSError, subprocess.TimeoutExpired) as error:
                errors.append(f"container removal failed for {name}: {type(error).__name__}")
        try:
            removal = self.docker("network", "rm", self.network, check=False, timeout=15)
            if removal.returncode and "not found" not in removal.stderr:
                errors.append(f"network removal failed: {self.network}")
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append(f"network removal failed: {type(error).__name__}")
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="opaque-ssh-dogfood:local")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix="opaque-ssh-"))
    print(f"Private temporary state: {directory}", flush=True)
    if not args.skip_build:
        build = run(["docker", "build", "-t", args.image, EXAMPLE], check=False, timeout=300)
        (directory / "build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(f"Docker build failed; see {directory / 'build.log'}")
    fixture = Fixture(args.image, directory)
    source_files = [Path(__file__).resolve(), *sorted(EXAMPLE.glob("*.py")), EXAMPLE / "Dockerfile"]
    source_hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in source_files}
    passed = False
    try:
        fixture.setup()
        fixture.exercise()
        passed = True
    finally:
        cleanup_errors = fixture.cleanup()
        report = {"schema_version": 1, "passed": passed and not cleanup_errors, "checks": fixture.results,
                  "cleanup_errors": cleanup_errors,
                  "runtime": fixture.runtime, "source_sha256": source_hashes,
                  "approval": "fixture_operator_only", "source": "synthetic-local-health",
                  "broker_integrated": False, "production_identity": False}
        (directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if cleanup_errors:
        raise RuntimeError(f"Cleanup needs attention; see {directory / 'result.json'}")
    print(f"{len(fixture.results)} checks passed. Evidence: {directory / 'result.json'}", flush=True)


if __name__ == "__main__":
    main()
