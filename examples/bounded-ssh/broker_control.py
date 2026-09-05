#!/usr/bin/env python3
"""Verify broker-approved fixed grants and sign host evidence; never issue SSH keys.

The separate Vault CA authenticates SSH certificates. This control plane admits
only an exact signed broker manifest into the existing single-use host ledger.
It cannot approve work, choose commands, or obtain Vault/source credentials.
"""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import threading
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CONFIG_PATH = "/etc/opaque-ssh/broker.json"
MAX_MESSAGE = 24 * 1024
CONTROL_DOMAIN = b"opaque.ssh-control.v1\0"
RECEIPT_DOMAIN = b"opaque.ssh-receipt.v1\0"
PINNED_FIELDS = {
    "tenant", "profile_id", "profile_sha256", "destination_host", "destination_port",
    "host_key_sha256", "principal", "login_user", "source_address", "vault_role",
    "vault_ca_sha256", "vault_token_ref",
}
ACTION_FIELDS = PINNED_FIELDS | {
    "operation", "subject", "delegation_id", "workload_uid", "command", "max_session_secs", "grant_id",
}
CONFIG_FIELDS = PINNED_FIELDS | {
    "broker_public_key_hex", "receipt_private_key_path", "max_session_secs", "tls_cert_path", "tls_key_path",
}


def strict_json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite number")

    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=constant)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
        raise ValueError("canonical nonnil UUID required")


def canonical_ip(value):
    if not isinstance(value, str):
        raise ValueError("canonical IP required")
    address = ipaddress.ip_address(value)
    if str(address) != value or address.is_unspecified or address.is_multicast:
        raise ValueError("canonical IP required")


def validate_action(action):
    if not isinstance(action, dict) or not ACTION_FIELDS <= set(action) or set(action) - ACTION_FIELDS - {"workload_exe_sha256"}:
        raise ValueError("invalid action fields")
    tenant = action["tenant"]
    if (not isinstance(tenant, dict) or set(tenant) != {"schema_version", "tenant_id", "broker_id"}
            or type(tenant["schema_version"]) is not int or tenant["schema_version"] != 1
            or not isinstance(tenant["tenant_id"], str)
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?", tenant["tenant_id"])):
        raise ValueError("invalid tenant binding")
    canonical_uuid(tenant["broker_id"])
    for field in ("profile_id", "principal", "login_user", "vault_role"):
        if not isinstance(action[field], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", action[field]):
            raise ValueError("invalid label")
    for field in ("profile_sha256", "host_key_sha256", "vault_ca_sha256", "workload_exe_sha256"):
        if field in action and (not isinstance(action[field], str) or not re.fullmatch(r"[a-f0-9]{64}", action[field])):
            raise ValueError("invalid digest")
    if not isinstance(action["subject"], str) or not re.fullmatch(r"(?:hum|agt|svc)_[a-f0-9]{32}", action["subject"]):
        raise ValueError("invalid principal identity")
    if not isinstance(action["delegation_id"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", action["delegation_id"]):
        raise ValueError("invalid delegation")
    if (not isinstance(action["vault_token_ref"], str) or not 1 <= len(action["vault_token_ref"]) <= 1024
            or any(ord(char) < 33 or ord(char) > 126 for char in action["vault_token_ref"])):
        raise ValueError("invalid credential reference")
    if (action["operation"] != "ssh.service_health" or action["command"] != "opaque-service-health"
            or action["login_user"] == "root"
            or type(action["destination_port"]) is not int or not 1 <= action["destination_port"] <= 65535
            or type(action["workload_uid"]) is not int or not 0 <= action["workload_uid"] < 2**32 - 1
            or type(action["max_session_secs"]) is not int or not 1 <= action["max_session_secs"] <= 30):
        raise ValueError("invalid fixed operation")
    canonical_ip(action["destination_host"])
    canonical_ip(action["source_address"])
    canonical_uuid(action["grant_id"])


def protected_bytes(path, limit, *, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & (0o077 if private else 0o022) or metadata.st_size > limit):
            raise ValueError("host control files require root custody")
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError("host control file is too large")
        return data


def openssh_sha256(raw):
    parts = raw.decode("ascii").strip().split()
    if len(parts) not in {2, 3} or parts[0] not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"}:
        raise ValueError("invalid pinned SSH public key")
    blob = base64.b64decode(parts[1], validate=True)
    return hashlib.sha256(blob).hexdigest()


def load_config(path=CONFIG_PATH):
    config = strict_json(protected_bytes(path, MAX_MESSAGE))
    if not isinstance(config, dict) or set(config) != CONFIG_FIELDS:
        raise ValueError("invalid broker host configuration")
    if (not isinstance(config["broker_public_key_hex"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", config["broker_public_key_hex"])):
        raise ValueError("invalid broker verification key")
    for field in ("receipt_private_key_path", "tls_cert_path", "tls_key_path"):
        if not isinstance(config[field], str) or not Path(config[field]).is_absolute():
            raise ValueError("host key path must be absolute")
    # Config and mounted CA must agree before any broker admission is possible.
    if config["vault_ca_sha256"] != openssh_sha256(protected_bytes("/etc/opaque-ssh/ca.pub", 8192)):
        raise ValueError("mounted Vault CA does not match the configured key")
    if config["host_key_sha256"] != openssh_sha256(protected_bytes("/etc/opaque-ssh/host_key.pub", 8192)):
        raise ValueError("host key does not match the configured key")
    seed = protected_bytes(config["receipt_private_key_path"], 32, private=True)
    if len(seed) != 32:
        raise ValueError("receipt signing seed must be 32 bytes")
    protected_bytes(config["tls_key_path"], 16384, private=True)
    protected_bytes(config["tls_cert_path"], 16384)
    return config, Ed25519PrivateKey.from_private_bytes(seed)


class BrokerControl:
    def __init__(self, ledger, config, receipt_key, host, principal, *, clock=time.time):
        self.ledger, self.config, self.receipt_key = ledger, config, receipt_key
        self.host, self.principal, self.clock = host, principal, clock
        if config["principal"] != principal or config["login_user"] != "opaque":
            raise ValueError("control profile does not match the local SSH account")
        if type(config["max_session_secs"]) is not int or not 1 <= config["max_session_secs"] <= 30:
            raise ValueError("invalid host session limit")
        self.broker_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(config["broker_public_key_hex"]))
        with ledger.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS broker_authority (
                    grant_id TEXT PRIMARY KEY REFERENCES grants(id),
                    manifest TEXT NOT NULL, expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS broker_nonces (
                    nonce TEXT PRIMARY KEY, payload_sha256 TEXT NOT NULL
                );
            """)

    def verify(self, envelope):
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError("invalid signed envelope")
        if (not isinstance(envelope["payload"], str) or not 1 <= len(envelope["payload"]) <= MAX_MESSAGE
                or not isinstance(envelope["signature"], str) or not re.fullmatch(r"[a-f0-9]{128}", envelope["signature"])):
            raise ValueError("invalid signed envelope")
        payload = base64.b64decode(envelope["payload"], validate=True)
        if base64.b64encode(payload).decode() != envelope["payload"]:
            raise ValueError("noncanonical envelope encoding")
        self.broker_key.verify(bytes.fromhex(envelope["signature"]), CONTROL_DOMAIN + payload)
        # No JSON is interpreted or ledger modified before signature verification.
        message = strict_json(payload)
        if not isinstance(message, dict) or set(message) != {"action", "manifest", "expires_at", "issued_at", "nonce"}:
            raise ValueError("invalid control fields")
        action = message["manifest"]
        validate_action(action)
        now = self.clock()
        if (not isinstance(message["action"], str) or message["action"] not in {"grant", "revoke"}
                or type(message["expires_at"]) is not int or type(message["issued_at"]) is not int
                or not now - 30 <= message["issued_at"] <= now + 5
                or not message["issued_at"] < message["expires_at"] <= message["issued_at"] + 300
                or message["expires_at"] <= now):
            raise ValueError("expired or invalid broker control")
        canonical_uuid(message["nonce"])
        if (any(action[field] != self.config[field] for field in PINNED_FIELDS)
                or action["max_session_secs"] > self.config["max_session_secs"]):
            raise ValueError("broker manifest is outside the host profile")
        return message, hashlib.sha256(payload).hexdigest()

    def sign(self, manifest, expires_at, response):
        payload = canonical_json({"manifest": manifest, "expires_at": expires_at, "response": response})
        return {"payload": base64.b64encode(payload).decode(),
                "signature": self.receipt_key.sign(RECEIPT_DOMAIN + payload).hex()}

    def apply(self, envelope):
        message, digest = self.verify(envelope)
        action = message["manifest"]
        manifest = canonical_json(action).decode()
        with self.ledger.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Ledger expiry is checked again after waiting for its writer lock.
            if message["expires_at"] <= self.clock():
                raise ValueError("broker authority expired while awaiting admission")
            db.execute("INSERT INTO broker_nonces(nonce,payload_sha256) VALUES(?,?)", (message["nonce"], digest))
            if message["action"] == "grant":
                db.execute("INSERT INTO grants(id,host,principal,expires_at,max_seconds) VALUES(?,?,?,?,?)",
                           (action["grant_id"], self.host, self.principal, message["expires_at"], action["max_session_secs"]))
                db.execute("INSERT INTO broker_authority(grant_id,manifest,expires_at) VALUES(?,?,?)",
                           (action["grant_id"], manifest, message["expires_at"]))
                status = "granted"
            else:
                row = db.execute("SELECT manifest,expires_at FROM broker_authority WHERE grant_id=?", (action["grant_id"],)).fetchone()
                if row is None:
                    # Cancellation can overtake a grant that is still in flight.
                    # Persist its exact authority as an already-revoked grant,
                    # atomically with the authority row and nonce. A later grant
                    # then collides with this UUID instead of creating permission.
                    # Keeping the normal grants row also preserves foreign-key
                    # integrity and lets the host return authenticated denial.
                    db.execute("INSERT INTO grants(id,host,principal,expires_at,max_seconds,revoked) VALUES(?,?,?,?,?,1)",
                               (action["grant_id"], self.host, self.principal, message["expires_at"], action["max_session_secs"]))
                    db.execute("INSERT INTO broker_authority(grant_id,manifest,expires_at) VALUES(?,?,?)",
                               (action["grant_id"], manifest, message["expires_at"]))
                else:
                    if row["manifest"] != manifest or row["expires_at"] != message["expires_at"]:
                        raise ValueError("revocation does not match the admitted manifest")
                    if db.execute("UPDATE grants SET revoked=1 WHERE id=?", (action["grant_id"],)).rowcount != 1:
                        raise ValueError("missing host reservation")
                status = "revoked"
            db.commit()
        return self.sign(action, message["expires_at"], {"status": status})

    def authority(self, identifier):
        with self.ledger.connect() as db:
            row = db.execute("SELECT manifest,expires_at FROM broker_authority WHERE grant_id=?", (identifier,)).fetchone()
        return (strict_json(row["manifest"]), row["expires_at"]) if row else None


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, control):
        self.control, self.slots = control, threading.BoundedSemaphore(8)
        super().__init__(address, ControlHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class ControlHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(2)
        if isinstance(self.request, ssl.SSLSocket):
            # Handshake occurs only after the server allocates a bounded worker.
            self.request.do_handshake()
        super().setup()

    def log_message(self, *_args):
        pass

    def do_POST(self):
        status, result = 403, {"error": "broker_control_denied"}
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (self.path != "/v1/ssh-control" or len(lengths) != 1 or not lengths[0].isdigit()
                    or not 0 < int(lengths[0]) <= MAX_MESSAGE or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get_content_type() != "application/json"):
                raise ValueError("invalid control request")
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError("incomplete control request")
            result = self.server.control.apply(strict_json(raw))
            status = 200
        except (ValueError, InvalidSignature, OSError, sqlite3.Error, RecursionError):
            pass
        body = canonical_json(result)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--principal", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("broker control requires root")
    os.umask(0o077)
    config, receipt_key = load_config()
    spec = importlib.util.spec_from_file_location("opaque_host_guard", Path(__file__).with_name("host_guard.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    control = BrokerControl(module.Ledger(args.db), config, receipt_key, args.host, args.principal)
    server = ControlServer(("0.0.0.0", 8443), control)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(config["tls_cert_path"], config["tls_key_path"])
    server.socket = tls.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.serve_forever()


if __name__ == "__main__":
    main()
