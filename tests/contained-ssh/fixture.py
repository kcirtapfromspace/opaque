#!/usr/bin/env python3
"""Provision only the marked disposable systemd image used by run.py.

All authority is generated at runtime. No test control endpoint is added to the
product: this root fixture configures the installed host package and reads its
SQLite ledger independently. The broker uses real TLS, Vault, SSH and guard IPC.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
STATE = Path("/var/lib/opaque-contained")
HOST = Path("/etc/opaque-ssh")
ROLE = "contained-health"
UNITS = ("opaque-ssh-sshd", "opaque-ssh-control", "opaque-ssh-guard",
         "opaque-contained-health", "opaque-contained-vault")
SPEC = importlib.util.spec_from_file_location("contained_processes", Path(__file__).with_name("processes.py"))
PROCESSES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROCESSES)


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def command(*args, check=True):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    require(not check or result.returncode == 0, "fixture command failed: " + Path(args[0]).name)
    return result


def prerequisite():
    require(os.geteuid() == 0, "contained fixture requires root")
    require(Path("/etc/opaque-contained-fixture").read_text() == "opaque-contained-ssh-v1\n",
            "run only inside the dedicated disposable fixture image")
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "systemd must be PID 1")
    for tool in ("vault", "systemctl", "ssh-keygen", "getent"):
        require(shutil.which(tool), "missing fixture executable")
    require(command("getent", "passwd", "opaque").stdout.split(b":")[2] == b"7382",
            "actual host NSS account required")


def write(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = value if isinstance(value, bytes) else value.encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    path.chmod(mode)
    return path


def api(path, body=None, *, token=None):
    raw = None if body is None else json.dumps(body).encode()
    request = Request("https://127.0.0.1:8200/v1/" + path, raw,
                      headers={"Content-Type": "application/json", "X-Vault-Token": token or ""})
    context = ssl.create_default_context(cafile=str(STATE / "vault-ca.pem"))
    try:
        with urlopen(request, context=context, timeout=4) as response:
            data = response.read(65537)
            require(len(data) <= 65536, "Vault fixture response too large")
            return response.status, json.loads(data) if data else {}
    except HTTPError as error:
        return error.code, {}


def wait_for(check, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, ValueError, URLError):
            pass
        time.sleep(0.05)
    raise RuntimeError("contained service readiness deadline")


def unit(name, body):
    write(Path("/etc/systemd/system") / (name + ".service"), body, 0o644)


def ssh_digest(public):
    return hashlib.sha256(base64.b64decode(public.split()[1], validate=True)).hexdigest()


def prepare(output, grant_key):
    # These paths belong exclusively to the marked disposable image. Refuse to
    # reset a running fixture, including one started by another test process.
    descriptor = os.open(STATE / "active", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as marker:
        marker.write(str(os.getpid()))
    token = secrets.token_urlsafe(32)
    write(STATE / "vault.env", "VAULT_DEV_ROOT_TOKEN_ID=" + token + "\n")
    unit("opaque-contained-vault", """[Service]
Type=simple
EnvironmentFile=/var/lib/opaque-contained/vault.env
ExecStart=/usr/local/bin/vault server -dev -dev-tls -dev-tls-cert-dir=/var/lib/opaque-contained -dev-listen-address=127.0.0.1:8200
UMask=0077
KillMode=control-group
TimeoutStopSec=5
""")
    command("systemctl", "daemon-reload")
    command("systemctl", "start", "opaque-contained-vault")
    wait_for(lambda: (STATE / "vault-ca.pem").exists() and api("sys/health")[0] == 200)
    for path, body in (
        ("sys/mounts/ssh", {"type": "ssh"}),
        ("ssh/config/ca", {"generate_signing_key": True, "key_type": "ssh-ed25519"}),
        ("ssh/roles/" + ROLE, {
            "key_type": "ca", "allow_user_certificates": True, "allow_host_certificates": False,
            "allowed_users": ROLE, "default_user": ROLE, "allow_user_key_ids": True,
            "allowed_extensions": "", "default_extensions": {},
            "allowed_critical_options": "force-command,source-address", "default_critical_options": {},
            "ttl": "60s", "max_ttl": "300s", "not_before_duration": "1s"}),
        ("sys/policies/acl/contained-signer", {
            "policy": 'path "ssh/sign/contained-health" { capabilities = ["update"] }'}),
    ):
        require(api(path, body, token=token)[0] in (200, 204), "Vault provisioning failed")
    status, response = api("auth/token/create", {
        "policies": ["contained-signer"], "no_default_policy": True,
        "ttl": "15m", "explicit_max_ttl": "15m"}, token=token)
    require(status == 200, "restricted Vault signer unavailable")
    write(output / "signer-token", response["auth"]["client_token"])
    status, response = api("ssh/config/ca", token=token)
    require(status == 200, "Vault SSH CA unavailable")
    ca_public = response["data"]["public_key"]
    require(api("sys/mounts/forbidden", {"type": "kv"},
                token=(output / "signer-token").read_text())[0] == 403,
            "restricted signer unexpectedly owns Vault administration")
    require(api("sys/audit/contained", {"type": "file", "options": {"file_path": str(STATE / "vault-audit.jsonl"), "log_raw": "false"}}, token=token)[0] in (200, 204), "Vault audit unavailable")
    broker_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    write(grant_key, broker_key.private_bytes(serialization.Encoding.Raw,
          serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    os.chown(grant_key, 7581, 7581)
    write(STATE / "broker-public", broker_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
    write(STATE / "receipt-public", receipt_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
    write(HOST / "receipt.key", receipt_key.private_bytes(serialization.Encoding.Raw,
          serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(HOST / "host_key"))
    host_public = (HOST / "host_key.pub").read_text()
    write(HOST / "ca.pub", ca_public, 0o644)
    write(HOST / "tls.pem", (STATE / "vault-cert.pem").read_bytes())
    write(HOST / "tls.key", (STATE / "vault-key.pem").read_bytes())
    profile = {
        "profile_id": ROLE, "destination_host": "127.0.0.1", "destination_port": 2222,
        "host_public_key": host_public, "host_key_sha256": ssh_digest(host_public),
        "principal": ROLE, "login_user": "opaque", "source_address": "127.0.0.1",
        "max_session_secs": 5,
        "health_contract": {"service": "contained-api", "version": "1", "host": "127.0.0.1",
                            "port": 8080, "path": "/ready/health"},
        "vault_url": "https://127.0.0.1:8200/", "vault_mount": "ssh", "vault_role": ROLE,
        "vault_token_ref": "env:OPAQUE_CONTAINED_VAULT_TOKEN", "vault_ca_public_key": ca_public,
        "vault_ca_sha256": ssh_digest(ca_public), "control_url": "https://127.0.0.1:8443/",
        "tls_ca_pem": (STATE / "vault-ca.pem").read_text(),
        "receipt_public_key_hex": receipt_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        "grant_signing_key_path": str(grant_key), "allow_loopback_http": False,
    }
    write(output / "profile.json", json.dumps(profile, sort_keys=True))
    write(STATE / "reads", "0")


def host_ready():
    request = Request("https://127.0.0.1:8443/v1/ssh-control", b"{}",
                      headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, context=ssl.create_default_context(cafile=str(STATE / "vault-ca.pem")), timeout=1):
            return False
    except HTTPError as error:
        if error.code != 403:
            return False
    with socket.create_connection(("127.0.0.1", 2222), timeout=1) as peer:
        return peer.recv(256).startswith(b"SSH-2.0-")


def configure(task_path):
    spec = importlib.util.spec_from_file_location("contained_render", ROOT / "packaging/ssh-host/render_host_config.py")
    render = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(render)
    task = json.loads(task_path.read_bytes())
    action = task["manifest"]["actions"][0]
    config = render.render(task, (STATE / "broker-public").read_text(),
                           str(HOST / "receipt.key"), str(HOST / "tls.pem"), str(HOST / "tls.key"),
                           "127.0.0.1", 8443)
    command("sh", str(ROOT / "packaging/ssh-host/install.sh"))
    write(HOST / "broker.json", json.dumps(config, sort_keys=True))
    write(HOST / "health.json", json.dumps(action["health_contract"]), 0o644)
    write(HOST / "principals", ROLE + "\n", 0o644)
    write(HOST / "sshd_config", (ROOT / "packaging/ssh-host/sshd_config.example").read_text()
          .replace("192.0.2.10", "127.0.0.1"))
    write(Path("/opt/opaque-contained-health.py"), Path(__file__).with_name("health.py").read_bytes(), 0o644)
    write(Path("/opt/opaque-contained-processes.py"), Path(__file__).with_name("processes.py").read_bytes(), 0o644)
    unit("opaque-contained-health", """[Service]
Type=simple
ExecStart=/usr/bin/python3 -I /opt/opaque-contained-health.py
UMask=0077
KillMode=control-group
TimeoutStopSec=5
""")
    command("systemctl", "daemon-reload")
    command("systemctl", "start", "opaque-contained-health", "opaque-ssh-guard", "opaque-ssh-control", "opaque-ssh-sshd")
    wait_for(lambda: command("systemctl", "is-active", *UNITS, check=False).stdout.splitlines() == [b"active"] * len(UNITS))
    wait_for(host_ready)
    # Verify installation bytes, rather than assuming a unit name identifies
    # the canonical source under test.
    for name in ("host_config", "health_probe", "principal_hook", "host_guard", "broker_control", "host_daemon"):
        require((Path("/opt/opaque-ssh") / (name + ".py")).read_bytes() ==
                (ROOT / "packaging/ssh-host" / (name + ".py")).read_bytes(), "installed source drift")


def observations():
    require(not (STATE / "observation-error").exists(), "actual probe identity observation failed")
    path = STATE / "probe-observations.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def snapshot():
    ledger = Path("/var/lib/opaque-ssh/grants.sqlite")
    with sqlite3.connect("file:" + str(ledger) + "?mode=ro", uri=True) as database:
        database.row_factory = sqlite3.Row
        database.execute("BEGIN")
        ledger_rows = {table: [dict(row) for row in database.execute(f"SELECT * FROM {table} ORDER BY {key}")]
                       for table, key in (("grants", "id"), ("receipts", "sequence"),
                                          ("broker_authority", "grant_id"), ("broker_nonces", "nonce"))}
    recorded = observations()
    sign_requests = sum(event.get("type") == "request" and event.get("request", {}).get("path") == "ssh/sign/" + ROLE
                        for line in (STATE / "vault-audit.jsonl").read_text().splitlines()
                        if (event := json.loads(line)))
    return {"reads": int((STATE / "reads").read_text()), "vault_sign_requests": sign_requests,
            "grants": ledger_rows["grants"], "ledger": ledger_rows,
            "receipts": [json.loads(row["receipt"]) for row in ledger_rows["receipts"]],
            "probe_observations": recorded, "guard_idle": PROCESSES.guard_idle(recorded)}


def replay_host(task_path):
    action = json.loads(task_path.read_bytes())["manifest"]["actions"][0]
    before = snapshot()
    result = subprocess.run(["setpriv", "--reuid=7382", "--regid=7382", "--clear-groups",
                             "--bounding-set=-all", "/usr/bin/python3", "-I",
                             "/opt/opaque-ssh/host_guard.py", "enter", action["grant_id"]],
                            env={"SSH_ORIGINAL_COMMAND": "opaque-service-health", "PATH": "/usr/bin:/bin"},
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    require(result.returncode == 1, "consumed host grant accepted replay")
    envelope = json.loads(result.stdout)
    raw = base64.b64decode(envelope["payload"], validate=True)
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex((STATE / "receipt-public").read_text()))
    public.verify(bytes.fromhex(envelope["signature"]), b"opaque.ssh-receipt.v1\0" + raw)
    receipt = json.loads(raw)
    require(receipt["manifest"] == action and receipt["response"]["status"] == "denied",
            "host replay denial lost its signed authority binding")
    after = snapshot()
    for field in ("reads", "vault_sign_requests", "grants", "probe_observations"):
        require(after[field] == before[field], "host replay changed one-use execution evidence")
    for table in ("grants", "broker_authority", "broker_nonces"):
        require(after["ledger"][table] == before["ledger"][table], "host replay mutated authority ledger")
    previous = before["ledger"]["receipts"]
    current = after["ledger"]["receipts"]
    require(len(current) == len(previous) + 1 and current[:-1] == previous,
            "host replay did not append exactly one denial")
    appended = json.loads(current[-1]["receipt"])
    signed = dict(receipt["response"]["receipt"])
    require(signed.pop("sequence") == current[-1]["sequence"] and signed == appended
            and appended["status"] == "denied" and appended["grant_id"] == action["grant_id"],
            "new durable denial differs from signed host response")
    require(after["guard_idle"], "host replay left a descendant process")


def cleanup():
    # Capture the complete owned service cgroups before stopping them. Command
    # line changes or a reparented descendant cannot hide from these checks.
    states = [PROCESSES.unit_state(name) for name in UNITS]
    captured = [identity for state in states if state["ControlGroup"]
                for identity in PROCESSES.cgroup_members(state["ControlGroup"])]
    path = STATE / "probe-observations.jsonl"
    if path.exists():
        captured += [identity for line in path.read_text().splitlines()
                     for identity in json.loads(line)["members"]]
    command("systemctl", "stop", *UNITS, check=False)
    def stopped():
        current = [PROCESSES.unit_state(name) for name in UNITS]
        return (all(state["ActiveState"] in ("inactive", "failed") and state["MainPID"] == 0 for state in current)
                and all(not PROCESSES.cgroup_members(state["ControlGroup"]) for state in states if state["ControlGroup"])
                and PROCESSES.gone(captured))
    wait_for(stopped)
    for directory in (HOST, Path("/var/lib/opaque-ssh"), STATE):
        if directory.exists():
            shutil.rmtree(directory)
    STATE.mkdir(mode=0o700)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "configure", "snapshot", "stall", "crash-guard", "replay-host", "cleanup"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--grant-key", type=Path)
    parser.add_argument("--task", type=Path)
    args = parser.parse_args()
    prerequisite()
    if args.action == "prepare":
        require(args.output and args.grant_key, "prepare paths required")
        try:
            prepare(args.output, args.grant_key)
        except BaseException:
            # A rejected second caller must not clean another active fixture.
            if (STATE / "active").exists() and (STATE / "active").read_text() == str(os.getpid()):
                cleanup()
            raise
    elif args.action == "configure":
        require(args.task, "planned task required")
        configure(args.task)
    elif args.action == "replay-host":
        require(args.task, "planned task required")
        replay_host(args.task)
    elif args.action == "snapshot":
        print(json.dumps(snapshot(), sort_keys=True))
    elif args.action == "stall":
        write(STATE / "stall", "1")
    elif args.action == "crash-guard":
        # Kill the actual supervisor while a real fixed probe is in flight.
        # Its systemd restart and kernel parent-death cleanup remain enabled.
        recorded = observations()
        require(len(recorded) == 1, "expected exactly one observed real probe")
        live = PROCESSES.observe_probe()
        require(PROCESSES.same_identity(recorded[0]["probe"], live["probe"]), "observed probe changed before crash")
        pid = live["guard"]["pid"]
        os.kill(pid, signal.SIGKILL)
        wait_for(lambda: PROCESSES.guard_idle(recorded, restarted=True)
                 and all(grant["state"] != "reserved" for grant in snapshot()["grants"]))
    else:
        cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Avoid tracebacks or API bodies containing ephemeral credentials.
        print("Contained fixture failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=__import__("sys").stderr)
        raise SystemExit(1)
