#!/usr/bin/env python3
"""Real Vault CA + OpenSSH + signed host authority in disposable local containers.

Uses fresh synthetic keys/tokens/data only. This exercises the broker/host wire
contract, not a native human approval or a production Vault/host connection.
Runtime keys stay in a private temporary directory; only named run resources
are removed. No host Docker socket, home, or production credential is mounted.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/bounded-ssh"
SPEC = importlib.util.spec_from_file_location("ssh_control_fixture", EXAMPLE / "broker_control.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
ROLE = "fixture-health"
MOUNT = "ssh-client-signer"


def run(argv, *, check=True, timeout=60):
    result = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"fixture subprocess {Path(str(argv[0])).name} {argv[1]} failed with exit {result.returncode}")
    return result


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http(url, body=None, *, token=None, context=None, method=None):
    handlers = [ProxyHandler({}), NoRedirect()]
    if context:
        handlers.append(HTTPSHandler(context=context))
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    data = None
    if body is not None:
        data = CONTROL.canonical_json(body)
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with build_opener(*handlers).open(request, timeout=5) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError("fixture response exceeded limit")
            return response.status, CONTROL.strict_json(raw) if raw else {}
    except HTTPError as error:
        # Do not expose provider error bodies, including token endpoint replies.
        return error.code, {}


def local_ports(count):
    sockets = []
    try:
        for _ in range(count):
            connection = socket.socket()
            connection.bind(("127.0.0.1", 0))
            sockets.append(connection)
        return [connection.getsockname()[1] for connection in sockets]
    finally:
        for connection in sockets:
            connection.close()


class Fixture:
    def __init__(self, image, vault_image, directory):
        self.image, self.vault_image, self.directory = image, vault_image, directory
        self.prefix = "opaque-vault-ssh-" + uuid.uuid4().hex[:10]
        self.network = self.prefix + "-net"
        self.host, self.client, self.foreign, self.vault = [self.prefix + "-" + name for name in ("host", "client", "foreign", "vault")]
        self.containers = [self.host, self.client, self.foreign, self.vault]
        self.results, self.runtime = [], {}
        self.broker_key, self.receipt_key = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
        self.root_token = secrets.token_urlsafe(32)
        self.signer_token = None

    def docker(self, *args, **kwargs):
        return run(["docker", *args], **kwargs)

    def inside(self, target, *args, **kwargs):
        return self.docker("exec", target, *args, **kwargs)

    def check(self, name, passed):
        self.results.append({"name": name, "passed": bool(passed)})
        if not passed:
            raise AssertionError(name)

    def write(self, name, data):
        path = self.directory / name
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        path.chmod(0o600)
        return path

    def copy(self, path, target, destination):
        # Explicit archive ownership avoids host UID preservation by Docker
        # Desktop when seeding a stopped container's trusted configuration.
        archive = io.BytesIO()
        raw = Path(path).read_bytes()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            entry = tarfile.TarInfo(Path(destination).name)
            entry.uid = entry.gid = 0
            entry.mode, entry.size = 0o600, len(raw)
            tar.addfile(entry, io.BytesIO(raw))
        copied = subprocess.run(["docker", "cp", "-a", "-", f"{target}:{Path(destination).parent}"],
                                input=archive.getvalue(), capture_output=True, timeout=30)
        if copied.returncode:
            raise RuntimeError("fixture file seeding failed")

    def vault_api(self, path, body=None, *, signer=False, method=None):
        return http(self.vault_url + "/v1/" + path, body, token=self.signer_token if signer else self.root_token, method=method)

    def configure_vault(self):
        for path, body in ((f"sys/mounts/{MOUNT}", {"type": "ssh"}),
                           (f"{MOUNT}/config/ca", {"generate_signing_key": True, "key_type": "ssh-ed25519"})):
            status, _ = self.vault_api(path, body)
            self.check("Vault setup " + path, status in {200, 204})
        status, data = self.vault_api(f"{MOUNT}/config/ca")
        self.check("Vault generated a public CA key", status == 200 and data.get("data", {}).get("public_key", "").startswith("ssh-ed25519 "))
        self.ca = self.write("vault-ca.pub", data["data"]["public_key"])
        role = {
            "key_type": "ca", "allow_user_certificates": True, "allow_host_certificates": False,
            "allowed_users": "opaque-fixture-a-health", "default_user": "opaque-fixture-a-health",
            "allow_user_key_ids": True, "allowed_extensions": "", "default_extensions": {},
            "allowed_critical_options": "force-command,source-address", "default_critical_options": {},
            "ttl": "60s", "max_ttl": "300s", "not_before_duration": "1s",
        }
        status, _ = self.vault_api(f"{MOUNT}/roles/{ROLE}", role)
        self.check("Vault role restricts principal lifetime and extensions", status in {200, 204})
        policy = f'path "{MOUNT}/sign/{ROLE}" {{ capabilities = ["update"] }}'
        status, _ = self.vault_api("sys/policies/acl/opaque-fixture-signer", {"policy": policy})
        self.check("Vault signer policy is one role endpoint", status in {200, 204})
        status, data = self.vault_api("auth/token/create", {"policies": ["opaque-fixture-signer"],
                                                          "no_default_policy": True, "ttl": "15m", "explicit_max_ttl": "15m"})
        self.check("Vault issued separate restricted signer token", status == 200 and isinstance(data.get("auth", {}).get("client_token"), str))
        self.signer_token = data["auth"]["client_token"]

    def setup(self):
        self.runtime["setup_stage"] = "image metadata"
        self.runtime["fixture_image_id"] = self.docker("image", "inspect", "--format", "{{.Id}}", self.image).stdout.strip()
        self.runtime["vault_image_id"] = self.docker("image", "inspect", "--format", "{{.Id}}", self.vault_image).stdout.strip()
        # Explicit IPAM is required for Docker's static per-container addresses.
        # Docker refuses overlap; never alter an existing network to make room.
        subnet = f"10.231.{secrets.randbelow(254) + 1}.0/24"
        self.runtime["setup_stage"] = "network creation"
        # Docker Desktop suppresses published ports on an internal network.
        # This disposable bridge exposes service ports only on host loopback;
        # the fixture makes no outbound-network isolation claim.
        self.docker("network", "create", "--subnet", subnet, self.network)
        self.runtime["network_scope"] = "disposable bridge; service ports published only on literal host loopback; no egress-isolation claim"
        subnet = self.docker("network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", self.network).stdout.strip()
        address = ipaddress.ip_network(subnet)
        self.gateway_ip = str(address[1])
        # Explicitly assigned free ports remain stable across Docker restarts.
        # Any intervening bind collision makes Docker fail without replacing it.
        vault_port, control_port, ssh_port = local_ports(3)
        self.host_ip, self.client_ip, self.foreign_ip, self.vault_ip = [str(address[number]) for number in (10, 20, 21, 30)]
        envfile = self.write("vault-dev.env", f"VAULT_DEV_ROOT_TOKEN_ID={self.root_token}\nVAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200\n")
        self.runtime["setup_stage"] = "Vault container"
        self.docker("run", "-d", "--name", self.vault, "--network", self.network, "--ip", self.vault_ip,
                    "--cap-add", "IPC_LOCK", "--env-file", envfile, "-p", f"127.0.0.1:{vault_port}:8200", self.vault_image, "server", "-dev")
        published = self.docker("port", self.vault, "8200/tcp", check=False)
        if published.returncode:
            logs = self.docker("logs", self.vault, check=False)
            self.write("vault-startup.log", (logs.stdout + logs.stderr).replace(self.root_token, "[fixture token redacted]"))
            self.runtime["vault_container_state"] = self.docker("inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", self.vault).stdout.strip()
            raise RuntimeError("Vault fixture has no published loopback port")
        self.vault_url = "http://" + published.stdout.strip()
        self.runtime["setup_stage"] = "Vault readiness"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                status, _ = http(self.vault_url + "/v1/sys/health")
                if status == 200:
                    break
            except (URLError, OSError):
                pass
            time.sleep(.1)
        else:
            logs = self.docker("logs", self.vault, check=False)
            self.write("vault-startup.log", (logs.stdout + logs.stderr).replace(self.root_token, "[fixture token redacted]"))
            raise RuntimeError("Vault fixture failed readiness")
        self.runtime["vault_version"] = self.inside(self.vault, "vault", "version").stdout.strip()
        self.configure_vault()
        for target, ip in ((self.client, self.client_ip), (self.foreign, self.foreign_ip)):
            self.docker("run", "-d", "--name", target, "--network", self.network, "--ip", ip,
                        "--entrypoint", "/bin/sleep", self.image, "infinity")
        for name in ("host_key", "client_key", "wrong_key"):
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.directory / name])
        self.runtime["openssh_version"] = self.inside(self.client, "ssh", "-V").stderr.strip()
        self.action = {
            "operation": "ssh.service_health", "tenant": {"schema_version": 1, "tenant_id": "synthetic-vault-a", "broker_id": str(uuid.uuid4())},
            "subject": "hum_" + "a" * 32, "delegation_id": "fixture-session-1", "workload_uid": 1000,
            "profile_id": ROLE, "profile_sha256": hashlib.sha256(b"opaque-vault-fixture-profile-v1").hexdigest(),
            "destination_host": self.host_ip, "destination_port": 2222,
            "host_key_sha256": CONTROL.openssh_sha256((self.directory / "host_key.pub").read_bytes()),
            "vault_role": ROLE, "vault_ca_sha256": CONTROL.openssh_sha256(self.ca.read_bytes()),
            "vault_token_ref": "env:VAULT_SIGNER_TOKEN", "principal": "opaque-fixture-a-health", "login_user": "opaque",
            "source_address": self.client_ip, "command": "opaque-service-health", "max_session_secs": 5, "grant_id": str(uuid.uuid4()),
        }
        config = {field: self.action[field] for field in CONTROL.PINNED_FIELDS}
        config.update(broker_public_key_hex=self.broker_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
                      receipt_private_key_path="/etc/opaque-ssh/receipt.key", max_session_secs=10,
                      tls_cert_path="/etc/opaque-ssh/tls.pem", tls_key_path="/etc/opaque-ssh/tls.key")
        self.config = config
        config_path = self.write("broker.json", CONTROL.canonical_json(config))
        self.write("receipt.key", self.receipt_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "opaque-ssh-fixture")])
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "opaque-ssh-fixture-tls-ca")])
        now = datetime.now(timezone.utc)
        tls_ca = (x509.CertificateBuilder().subject_name(ca_subject).issuer_name(ca_subject).public_key(ca_key.public_key())
                  .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                  .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                  .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                               data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                               crl_sign=True, encipher_only=False, decipher_only=False), critical=True).sign(ca_key, hashes.SHA256()))
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_subject).public_key(tls_key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                       .not_valid_after(now + timedelta(days=1)).add_extension(x509.SubjectAlternativeName([
                           x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address(self.host_ip))]), critical=False)
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_key, hashes.SHA256()))
        self.write("tls-ca.pem", tls_ca.public_bytes(serialization.Encoding.PEM))
        self.write("tls.pem", certificate.public_bytes(serialization.Encoding.PEM))
        self.write("tls.key", tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.tls_context = ssl.create_default_context(cafile=str(self.directory / "tls-ca.pem"))
        self.docker("create", "--name", self.host, "--network", self.network, "--ip", self.host_ip,
                    "--env", "FIXTURE_HOST=fixture-a", "-p", f"127.0.0.1:{control_port}:8443", "-p", f"127.0.0.1:{ssh_port}:2222", self.image)
        for name, destination in (("vault-ca.pub", "ca.pub"), ("host_key", "host_key"), ("host_key.pub", "host_key.pub"),
                                  ("broker.json", "broker.json"), ("receipt.key", "receipt.key"), ("tls.pem", "tls.pem"), ("tls.key", "tls.key")):
            self.copy(self.directory / name, self.host, "/etc/opaque-ssh/" + destination)
        self.docker("start", self.host)
        self.control_url = "https://" + self.docker("port", self.host, "8443/tcp").stdout.strip() + "/v1/ssh-control"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if http(self.control_url, {}, context=self.tls_context)[0] == 403:
                    break
            except (URLError, OSError):
                pass
            time.sleep(.1)
        else:
            # Host logs stay private, and may be inspected locally after failure.
            logs = self.docker("logs", self.host, check=False)
            self.write("host-startup.log", logs.stdout + logs.stderr)
            raise RuntimeError("signed SSH host failed readiness")
        known = self.write("known_hosts", f"[{self.host_ip}]:2222 " + (self.directory / "host_key.pub").read_text())
        wrong_known = self.write("wrong_known_hosts", f"[{self.host_ip}]:2222 " + (self.directory / "wrong_key.pub").read_text())
        for target in (self.client, self.foreign):
            for name, path in (("key", self.directory / "client_key"), ("wrong_key", self.directory / "wrong_key"),
                               ("known_hosts", known), ("wrong_known_hosts", wrong_known)):
                self.copy(path, target, "/client/" + name)
            self.inside(target, "chown", "-R", "7382:7382", "/client")
            self.inside(target, "chmod", "600", "/client/key", "/client/wrong_key")
            self.inside(target, "chmod", "644", "/client/known_hosts", "/client/wrong_known_hosts")

    def signed_control(self, action, expires_at, verb="grant"):
        message = {"action": verb, "manifest": action, "expires_at": expires_at,
                   "issued_at": int(time.time()), "nonce": str(uuid.uuid4())}
        raw = CONTROL.canonical_json(message)
        return {"payload": base64.b64encode(raw).decode(), "signature": self.broker_key.sign(CONTROL.CONTROL_DOMAIN + raw).hex()}

    def control(self, envelope):
        return http(self.control_url, envelope, context=self.tls_context)

    def receipt(self, envelope, action, expires_at):
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise AssertionError("missing signed host evidence")
        payload = base64.b64decode(envelope["payload"], validate=True)
        self.receipt_key.public_key().verify(bytes.fromhex(envelope["signature"]), CONTROL.RECEIPT_DOMAIN + payload)
        result = CONTROL.strict_json(payload)
        if result["manifest"] != action or result["expires_at"] != expires_at:
            raise AssertionError("host evidence changed the approved authority")
        return result["response"]

    def sign_certificate(self, action, *, ttl=60, change=None, public_name="client_key.pub"):
        payload = {"public_key": (self.directory / public_name).read_text(), "valid_principals": action["principal"],
                   "key_id": action["grant_id"], "cert_type": "user", "ttl": f"{ttl}s", "extensions": {},
                   "critical_options": {"source-address": action["source_address"] + "/32",
                                        "force-command": f"/usr/bin/python3 -I /opt/opaque-ssh/host_guard.py enter {action['grant_id']}"}}
        if change:
            payload.update(change)
        return self.vault_api(f"{MOUNT}/sign/{ROLE}", payload, signer=True)

    def grant(self, *, ttl=60, duration=5, admit=True):
        action = copy.deepcopy(self.action)
        action.update(grant_id=str(uuid.uuid4()), max_session_secs=duration)
        expires_at = int(time.time()) + ttl
        envelope = self.signed_control(action, expires_at)
        if admit:
            status, ack = self.control(envelope)
            self.check("signed host grant admitted", status == 200 and self.receipt(ack, action, expires_at)["status"] == "granted")
        status, signed = self.sign_certificate(action, ttl=ttl)
        self.check("Vault signed a bounded user certificate", status == 200 and "signed_key" in signed.get("data", {}))
        path = self.write(action["grant_id"] + "-cert.pub", signed["data"]["signed_key"])
        for target in (self.client, self.foreign):
            self.copy(path, target, "/client/" + path.name)
            self.inside(target, "chmod", "644", "/client/" + path.name)
        return action, expires_at, envelope

    def ssh(self, action, *, target=None, command="opaque-service-health", key="key", known="known_hosts", extra=()):
        return self.inside(target or self.client, "runuser", "-u", "opaque", "--", "ssh", "-F", "/dev/null",
                           "-p", "2222", "-i", "/client/" + key, "-o", "CertificateFile=/client/" + action["grant_id"] + "-cert.pub",
                           "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                           "-o", "UserKnownHostsFile=/client/" + known, "-o", "GlobalKnownHostsFile=/dev/null",
                           "-o", "ConnectTimeout=3", "-o", "LogLevel=ERROR", "-o", "ClearAllForwardings=yes",
                           *extra, "opaque@" + self.host_ip, command, check=False, timeout=20)

    def reads(self):
        return int(self.inside(self.host, "python3", "-c",
                              "from pathlib import Path; p=Path('/var/lib/opaque-ssh/reads'); print(p.read_text() if p.exists() else 0)").stdout)

    def deny_ssh(self, name, action, **kwargs):
        before = self.reads()
        result = self.ssh(action, **kwargs)
        self.check(name, result.returncode != 0 and self.reads() == before)
        return result

    def exercise(self):
        self.check("unsigned host grant denied", self.control({"manifest": self.action})[0] == 403)
        action, expiry, envelope = self.grant()
        self.check("control nonce replay denied", self.control(envelope)[0] == 403)
        tampered = copy.deepcopy(envelope)
        changed = CONTROL.strict_json(base64.b64decode(tampered["payload"]))
        changed["manifest"]["command"] = "id"
        tampered["payload"] = base64.b64encode(CONTROL.canonical_json(changed)).decode()
        self.check("tampered signed control denied", self.control(tampered)[0] == 403)
        foreign = copy.deepcopy(action)
        foreign["tenant"]["tenant_id"] = "synthetic-vault-b"
        foreign["grant_id"] = str(uuid.uuid4())
        self.check("signed foreign tenant denied", self.control(self.signed_control(foreign, expiry))[0] == 403)
        before = self.reads()
        response = self.ssh(action)
        result = self.receipt(CONTROL.strict_json(response.stdout), action, expiry)
        self.check("Vault certificate performs one fixed source read", response.returncode == 0 and result["status"] == "completed" and self.reads() == before + 1)
        self.check("host signs exact complete output hash", hashlib.sha256(result["output_text"].encode()).hexdigest() == result["receipt"]["output_sha256"]
                   and json.loads(result["output_text"]) == result["result"])
        signed_envelope = CONTROL.strict_json(response.stdout)
        payload = base64.b64decode(signed_envelope["payload"])
        try:
            self.receipt_key.public_key().verify(bytes.fromhex(signed_envelope["signature"]), CONTROL.RECEIPT_DOMAIN + payload + b" ")
        except InvalidSignature:
            self.check("tampered host result signature denied", True)
        else:
            self.check("tampered host result signature denied", False)
        self.deny_ssh("single-use SSH replay denied", action)
        usable, usable_expiry, _ = self.grant()
        self.deny_ssh("foreign source address denied", usable, target=self.foreign)
        self.deny_ssh("wrong client private key denied", usable, key="wrong_key")
        self.deny_ssh("wrong pinned host key denied", usable, known="wrong_known_hosts")
        self.deny_ssh("alternate command denied", usable, command="id")
        pty = self.deny_ssh("PTY cannot open interactive shell", usable, command="", extra=("-tt",))
        self.check("server explicitly rejects PTY allocation", "PTY allocation request failed" in pty.stderr)
        # Prove these denials left the intended one-use authorization available.
        permitted = self.ssh(usable)
        self.check("denied channels do not consume valid grant", self.receipt(CONTROL.strict_json(permitted.stdout), usable, usable_expiry)["status"] == "completed")
        no_grant, _, _ = self.grant(admit=False)
        self.deny_ssh("Vault certificate alone grants no operation authority", no_grant)
        expired, _, _ = self.grant(ttl=2)
        time.sleep(2.1)
        self.deny_ssh("expired Vault certificate denied", expired)
        for name, change in (("foreign principal", {"valid_principals": "opaque-fixture-b-health"}),
                             ("excess TTL", {"ttl": "301s"}), ("PTY extension", {"extensions": {"permit-pty": ""}}),
                             ("host certificate", {"cert_type": "host"})):
            status, _ = self.sign_certificate(self.action, change=change)
            self.check("Vault rejects " + name, status in {400, 403})
        for name, path, body in (("other signing role", f"{MOUNT}/sign/other-role", {}),
                                 ("role mutation", f"{MOUNT}/roles/{ROLE}", {"allowed_users": "*"}),
                                 ("CA mutation", f"{MOUNT}/config/ca", {"generate_signing_key": True})):
            self.check("scoped signer cannot request " + name, self.vault_api(path, body, signer=True)[0] == 403)
        active, active_expiry, _ = self.grant(duration=10)
        self.inside(self.host, "touch", "/var/lib/opaque-ssh/hang")
        before = self.reads()
        with ThreadPoolExecutor() as executor:
            running = executor.submit(self.ssh, active)
            deadline = time.monotonic() + 5
            while self.reads() == before and time.monotonic() < deadline:
                time.sleep(.05)
            self.check("active revocation reached the fixed source", self.reads() == before + 1)
            status, ack = self.control(self.signed_control(active, active_expiry, "revoke"))
            self.check("signed revocation admitted", status == 200 and self.receipt(ack, active, active_expiry)["status"] == "revoked")
            outcome = running.result(timeout=3)
        result = self.receipt(CONTROL.strict_json(outcome.stdout), active, active_expiry)
        self.check("active revocation terminates work and suppresses output", outcome.returncode != 0 and result["status"] == "revoked"
                   and "output_text" not in result and "result" not in result)
        self.inside(self.host, "rm", "/var/lib/opaque-ssh/hang")
        self.docker("restart", self.host)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if self.control({})[0] == 403:
                    break
            except (URLError, OSError):
                pass
            time.sleep(.1)
        else:
            raise RuntimeError("host control did not recover after restart")
        self.deny_ssh("host restart cannot restore consumed allowance", action)
        self.check("control replay survives host restart", self.control(envelope)[0] == 403)

    def cleanup(self):
        failures = []
        for name in self.containers:
            try:
                if self.docker("container", "inspect", name, check=False).returncode == 0:
                    if self.docker("rm", "-f", name, check=False).returncode:
                        failures.append("container cleanup failed")
            except (OSError, subprocess.TimeoutExpired):
                failures.append("container cleanup unavailable")
        try:
            if self.docker("network", "inspect", self.network, check=False).returncode == 0:
                if self.docker("network", "rm", self.network, check=False).returncode:
                    failures.append("network cleanup failed")
        except (OSError, subprocess.TimeoutExpired):
            failures.append("network cleanup unavailable")
        return failures

    def native_rust_check(self):
        """Validate the real Rust executor against this same disposable Vault/host."""
        ssh_port = int(self.docker("port", self.host, "2222/tcp").stdout.strip().rsplit(":", 1)[1])
        # Observe the source address of Docker's native loopback port forward.
        # A banner-only SSH connection starts no channel and reads no source.
        with socket.create_connection(("127.0.0.1", ssh_port), timeout=3) as connection:
            connection.sendall(b"SSH-2.0-opaque_native_source_probe\r\n")
        time.sleep(.2)
        logs = self.docker("logs", self.host)
        addresses = re.findall(r"Connection from ([0-9a-fA-F:.]+) port [0-9]+", logs.stdout + logs.stderr)
        if not addresses:
            raise RuntimeError("native SSH source address could not be observed")
        source_address = str(ipaddress.ip_address(addresses[-1]))
        self.runtime["native_source_address"] = source_address
        grant_key = self.write("broker-signing.key", self.broker_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).resolve()
        profile = {
            "tenant": self.action["tenant"], "profile_id": ROLE,
            "destination_host": "127.0.0.1", "destination_port": ssh_port,
            "host_public_key": (self.directory / "host_key.pub").read_text(), "host_key_sha256": self.action["host_key_sha256"],
            "principal": self.action["principal"], "login_user": "opaque", "source_address": source_address, "max_session_secs": 5,
            "vault_url": self.vault_url + "/", "vault_mount": MOUNT, "vault_role": ROLE,
            "vault_token_ref": "env:OPAQUE_SSH_VAULT_TOKEN", "vault_ca_public_key": self.ca.read_text(),
            "vault_ca_sha256": self.action["vault_ca_sha256"], "control_url": self.control_url.removesuffix("v1/ssh-control"),
            "tls_ca_pem": (self.directory / "tls-ca.pem").read_text(),
            "receipt_public_key_hex": self.receipt_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
            "grant_signing_key_path": str(grant_key), "allow_loopback_http": True,
        }
        profile_path = self.write("rust-profile.json", CONTROL.canonical_json(profile)).resolve()
        prepare_path = (self.directory / "rust-profile-digest.json").resolve()
        result_path = (self.directory / "rust-result.json").resolve()
        env = os.environ.copy()
        env.update(OPAQUE_SSH_LIVE_PROFILE=str(profile_path), OPAQUE_SSH_LIVE_PREPARE=str(prepare_path),
                   OPAQUE_SSH_VAULT_TOKEN=self.signer_token, OPAQUE_SSH_LIVE_RESULT=str(result_path))
        command = ["cargo", "test", "--locked", "-p", "opaque-bounded-work", "--lib", "ssh::tests::live_vault_host_execution", "--", "--ignored", "--exact"]
        prepared = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        self.write("rust-prepare.log", prepared.stdout + prepared.stderr)
        self.check("Rust validates exact profile key custody and pins", prepared.returncode == 0 and prepare_path.exists())
        digest = CONTROL.strict_json(prepare_path.read_bytes())["profile_sha256"]
        self.config.update({field: profile[field] for field in CONTROL.PINNED_FIELDS if field in profile})
        self.config["profile_sha256"] = digest
        self.copy(self.write("broker-native.json", CONTROL.canonical_json(self.config)), self.host, "/etc/opaque-ssh/broker.json")
        self.docker("restart", self.host)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if self.control({})[0] == 403:
                    break
            except (URLError, OSError):
                pass
            time.sleep(.1)
        else:
            raise RuntimeError("native broker host failed readiness")
        env.pop("OPAQUE_SSH_LIVE_PREPARE")
        before = self.reads()
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        self.write("rust-execution.log", completed.stdout + completed.stderr)
        self.runtime["native_source_reads"] = self.reads() - before
        logs = self.docker("logs", self.host, check=False)
        self.write("native-host.log", logs.stdout + logs.stderr)
        self.check("Rust executor uses Vault certificate and verifies host receipt", completed.returncode == 0 and result_path.exists())
        self.check("Rust execution and replay perform exactly one source read", self.reads() == before + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="opaque-ssh-control-validation:20260905")
    parser.add_argument("--vault-image", default="hashicorp/vault:1.21")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--skip-rust-check", action="store_true", help="explicitly skip the real Rust executor integration phase")
    args = parser.parse_args()
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix="opaque-vault-ssh-"))
    fixture = Fixture(args.image, args.vault_image, directory)
    error = None
    try:
        if not args.no_build:
            run(["docker", "build", "-t", args.image, EXAMPLE], timeout=300)
        if run(["docker", "image", "inspect", args.vault_image], check=False).returncode:
            run(["docker", "pull", args.vault_image], timeout=300)
        fixture.setup()
        fixture.exercise()
        if not args.skip_rust_check:
            fixture.native_rust_check()
    except Exception as failure:
        # Stable local assertion names are safe; raw Docker/HTTP errors are not.
        error = str(failure) if isinstance(failure, (AssertionError, RuntimeError)) else type(failure).__name__
    finally:
        cleanup_failures = fixture.cleanup()
    report = {"schema_version": 1, "passed": error is None and not cleanup_failures,
              "checks": fixture.results, "runtime": fixture.runtime, "error": error,
              "cleanup_failures": cleanup_failures, "source": "synthetic-local-health",
              "authority": "fixture-broker-signing-key; no native approval ceremony",
              "ca": "Vault-generated; CA private key remains inside disposable Vault",
              "production_connection": False,
              "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in [Path(__file__).resolve(), *sorted(EXAMPLE.glob("*.py")), EXAMPLE / "Dockerfile"]}}
    (directory / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps({"passed": report["passed"], "checks": len(fixture.results), "evidence": str(directory / "result.json"),
                      "error": error, "cleanup_failures": cleanup_failures}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
