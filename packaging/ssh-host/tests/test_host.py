"""Local protocol checks. No SSH daemon, root changes or real service is used."""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load("host_guard")
control = load("broker_control")
probe = load("health_probe")
config_module = load("host_config")
renderer = load("render_host_config")
CONTRACT = {"service": "payments-api", "version": "2026.09.1", "host": "127.0.0.1", "port": 9000, "path": "/ready/health"}


class HostProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = guard.Ledger(Path(self.temp.name) / "grants.db")
        self.broker_key = Ed25519PrivateKey.generate()
        self.receipt_key = Ed25519PrivateKey.generate()
        self.now = int(time.time())
        self.action = {
            "tenant": {"schema_version": 1, "tenant_id": "test-tenant", "broker_id": str(uuid.uuid4())},
            "profile_id": "payments-health", "profile_sha256": "a" * 64,
            "destination_host": "192.0.2.1", "destination_port": 22,
            "host_key_sha256": "b" * 64, "principal": "payments-health", "login_user": "opaque",
            "source_address": "192.0.2.2", "vault_role": "payments-health", "vault_ca_sha256": "c" * 64,
            "vault_token_ref": "env:TEST_VAULT_TOKEN", "operation": "ssh.service_health",
            "subject": "hum_" + "1" * 32, "delegation_id": "test-session", "workload_uid": os.getuid(),
            "command": "opaque-service-health", "max_session_secs": 2, "grant_id": str(uuid.uuid4()),
            "health_contract": copy.deepcopy(CONTRACT),
        }
        self.config = {key: copy.deepcopy(self.action[key]) for key in control.PINNED_FIELDS}
        self.config.update({"max_session_secs": 2, "broker_public_key_hex": self.broker_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()})
        self.control = control.BrokerControl(self.ledger, self.config, self.receipt_key, "payments-host", "payments-health")

    def envelope(self, action=None, verb="grant", expiry=None):
        message = {"action": verb, "manifest": action or self.action,
                   "expires_at": self.now + 60 if expiry is None else expiry,
                   "issued_at": self.now, "nonce": str(uuid.uuid4())}
        payload = control.canonical_json(message)
        return {"payload": base64.b64encode(payload).decode(), "signature": self.broker_key.sign(control.CONTROL_DOMAIN + payload).hex()}

    def response(self, signed):
        payload = base64.b64decode(signed["payload"])
        self.receipt_key.public_key().verify(bytes.fromhex(signed["signature"]), control.RECEIPT_DOMAIN + payload)
        decoded = json.loads(payload)
        self.assertEqual(decoded["manifest"], self.action)
        self.assertEqual(decoded["expires_at"], self.now + 60)
        return decoded["response"]

    def test_host_configuration_renderer_pins_actual_planned_action(self):
        rendered = renderer.render({"task": {"manifest": {"schema_version": 4, "actions": [self.action]}}}, self.config["broker_public_key_hex"], "/etc/opaque-ssh/receipt.key", "/etc/opaque-ssh/control.crt", "/etc/opaque-ssh/control.key", "192.0.2.1", 8443)
        self.assertEqual(set(rendered), control.CONFIG_FIELDS)
        self.assertEqual(rendered["health_contract"], CONTRACT)
        self.assertEqual(rendered["profile_sha256"], self.action["profile_sha256"])
        with self.assertRaises(ValueError):
            renderer.render({"manifest": {"schema_version": 4, "actions": []}}, self.config["broker_public_key_hex"], "/receipt", "/cert", "/key", "192.0.2.1", 8443)

    def test_signed_admission_and_consumed_replay(self):
        envelope = self.envelope()
        self.assertEqual(self.response(self.control.apply(envelope))["status"], "granted")
        with self.assertRaises(sqlite3.IntegrityError):
            self.control.apply(envelope)
        with self.assertRaises(sqlite3.IntegrityError):
            self.control.apply(self.envelope())
        claim, denial = self.ledger.reserve(self.action["grant_id"], "payments-host", "payments-health")
        self.assertIsNone(denial)
        _, denial = self.ledger.reserve(self.action["grant_id"], "payments-host", "payments-health")
        self.assertEqual(denial["receipt"]["result_code"], "already_used")
        self.ledger.recover()
        response = self.ledger.finish(claim, "completed", "ok", b"{}", True, {})
        self.assertEqual(response["status"], "unknown")
        self.assertNotIn("output_text", response)

    def test_signed_contract_tamper_and_expiry_rejected_before_admission(self):
        for field, value in [("service", "billing-api"), ("version", "2026.09.2"), ("host", "::1"), ("port", 9001), ("path", "/health")]:
            changed = copy.deepcopy(self.action)
            changed["health_contract"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.control.apply(self.envelope(changed))
        with self.assertRaises(ValueError):
            self.control.apply(self.envelope(expiry=self.now - 1))
        changed = self.envelope()
        changed["signature"] = "0" * 128
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises(InvalidSignature):
            self.control.apply(changed)
        with self.ledger.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM grants").fetchone()[0], 0)

    def test_revoke_overtakes_grant_and_cannot_be_refunded(self):
        self.assertEqual(self.response(self.control.apply(self.envelope(verb="revoke")))["status"], "revoked")
        with self.assertRaises(sqlite3.IntegrityError):
            self.control.apply(self.envelope())
        _, denial = self.ledger.reserve(self.action["grant_id"], "payments-host", "payments-health")
        self.assertEqual(denial["receipt"]["result_code"], "revoked")

    def test_guard_passes_bounded_contract_and_returns_signed_real_named_health(self):
        self.control.apply(self.envelope())
        command = (sys.executable, "-I", "-c", "import json,sys;c=json.load(sys.stdin);print(json.dumps({'service':c['service'],'status':'ok','version':c['version']}))")
        instance = guard.Guard(self.ledger, "payments-host", "payments-health", os.getuid(), gid=os.getgid(), probe_argv=command, broker=self.control)
        with patch.object(control.host_config, "load_health", return_value=copy.deepcopy(CONTRACT)):
            response = self.response(instance.run(self.action["grant_id"]))
        self.assertEqual(response["status"], "completed")
        self.assertEqual(json.loads(response["output_text"])["service"], "payments-api")
        self.assertEqual(self.response(instance.run(self.action["grant_id"]))["receipt"]["result_code"], "already_used")

    def test_host_configuration_drift_consumes_claim_before_probe_and_blocks_network(self):
        self.control.apply(self.envelope())
        instance = guard.Guard(self.ledger, "payments-host", "payments-health", os.getuid(), gid=os.getgid(), broker=self.control)
        changed = CONTRACT | {"port": 9001}
        with patch.object(control.host_config, "load_health", return_value=changed), patch.object(guard.subprocess, "Popen") as spawn:
            self.assertEqual(self.response(instance.run(self.action["grant_id"]))["status"], "failed")
            spawn.assert_not_called()
        with patch.object(probe.host_config, "load_health", return_value=changed), patch.object(probe.http.client, "HTTPConnection") as network:
            with self.assertRaises(ValueError):
                probe.execute(CONTRACT)
            network.assert_not_called()

    def test_release_fence_suppresses_success_after_revocation(self):
        self.control.apply(self.envelope())
        claim, _ = self.ledger.reserve(self.action["grant_id"], "payments-host", "payments-health")
        self.control.apply(self.envelope(verb="revoke"))
        response = self.ledger.finish(claim, "completed", "ok", b"sensitive-probe-bytes", True, {}, include_output_text=True)
        self.assertEqual(response["status"], "revoked")
        self.assertNotIn("output_text", response)
        self.assertNotIn("result", response)

    def test_expired_claim_is_denied_and_failed_attempt_is_not_refunded(self):
        self.control.apply(self.envelope())
        with self.ledger.connect() as db:
            db.execute("UPDATE grants SET expires_at=?", (self.now - 1,))
        _, response = self.ledger.reserve(self.action["grant_id"], "payments-host", "payments-health")
        self.assertEqual(response["receipt"]["result_code"], "expired")

    def test_contract_rejects_url_injection_unknown_fields_and_duplicate_json(self):
        for field, value in [("host", "localhost"), ("host", "169.254.169.254"), ("host", []), ("port", True), ("port", 0), ("path", "/../metadata"), ("path", "//health"), ("path", "/health?token=x"), ("path", "/%68ealth"), ("service", "api;id")]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                config_module.validate_contract(CONTRACT | {field: value})
        with self.assertRaises(ValueError):
            config_module.validate_contract(CONTRACT | {"headers": {}})
        with self.assertRaises(ValueError):
            config_module.strict_json('{"port":1,"port":2}')
        with self.assertRaises(ValueError):
            config_module.protected_bytes(Path(self.temp.name) / "not-present", 100)

    def test_actual_http_probe_uses_only_approved_path_and_checks_service_and_version(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            value = {"service": "payments-api", "status": "ok", "version": "2026.09.1"}
            status = 200
            def do_GET(self):
                requests.append(self.path)
                body = json.dumps(self.value).encode()
                self.send_response(self.status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Location", "/must-not-follow")
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            contract = CONTRACT | {"port": server.server_port}
            with patch.object(probe.host_config, "load_health", return_value=contract):
                self.assertEqual(probe.execute(contract), Handler.value)
                Handler.value = Handler.value | {"version": "other"}
                with self.assertRaises(ValueError):
                    probe.execute(contract)
                Handler.status = 302
                with self.assertRaises(ValueError):
                    probe.execute(contract)
            self.assertEqual(requests, [CONTRACT["path"]] * 3)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == "__main__":
    unittest.main()
