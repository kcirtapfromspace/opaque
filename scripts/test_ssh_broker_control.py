"""Signed broker-to-host authority tests; only disposable keys and local ledgers."""
import base64
import concurrent.futures
import copy
import hashlib
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
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/bounded-ssh"


def module(name):
    spec = importlib.util.spec_from_file_location("opaque_test_" + name, EXAMPLE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


control_module, guard_module = module("broker_control"), module("host_guard")


class BrokerControlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger = guard_module.Ledger(Path(self.temporary.name) / "grants.sqlite")
        self.broker_key, self.receipt_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.action = {
            "operation": "ssh.service_health",
            "tenant": {"schema_version": 1, "tenant_id": "tenant-a", "broker_id": str(uuid.uuid4())},
            "subject": "hum_" + "a" * 32, "delegation_id": "session-1", "workload_uid": 1000,
            "profile_id": "fixture-health", "profile_sha256": "a" * 64,
            "destination_host": "192.0.2.1", "destination_port": 2222, "host_key_sha256": "b" * 64,
            "vault_role": "fixture-health", "vault_ca_sha256": "c" * 64, "vault_token_ref": "env:VAULT_SIGNER_TOKEN",
            "principal": "opaque-fixture-a-health", "login_user": "opaque", "source_address": "192.0.2.2",
            "command": "opaque-service-health", "max_session_secs": 5, "grant_id": str(uuid.uuid4()),
        }
        self.config = {field: copy.deepcopy(self.action[field]) for field in control_module.PINNED_FIELDS}
        self.config.update(max_session_secs=10, broker_public_key_hex=self.broker_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
        self.control = self.new_control()
        self.expires_at = int(time.time()) + 60

    def new_control(self):
        return control_module.BrokerControl(self.ledger, self.config, self.receipt_key, "fixture-a", self.action["principal"])

    def message(self, action="grant", **fields):
        return {"action": action, "manifest": copy.deepcopy(self.action), "expires_at": self.expires_at,
                "issued_at": int(time.time()), "nonce": str(uuid.uuid4())} | fields

    def signed(self, message, key=None, *, raw=None):
        raw = control_module.canonical_json(message) if raw is None else raw
        return {"payload": base64.b64encode(raw).decode(),
                "signature": (key or self.broker_key).sign(control_module.CONTROL_DOMAIN + raw).hex()}

    def verify_receipt(self, envelope):
        self.assertEqual(set(envelope), {"payload", "signature"})
        payload = base64.b64decode(envelope["payload"], validate=True)
        self.receipt_key.public_key().verify(bytes.fromhex(envelope["signature"]), control_module.RECEIPT_DOMAIN + payload)
        result = control_module.strict_json(payload)
        self.assertEqual(result["manifest"], self.action)
        self.assertEqual(result["expires_at"], self.expires_at)
        return result["response"]

    def counts(self):
        with self.ledger.connect() as db:
            return [db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                    for table in ("grants", "broker_authority", "broker_nonces")]

    def guard(self, code='print(\'{"service":"fixture-api","status":"ok"}\')'):
        return guard_module.Guard(self.ledger, "fixture-a", self.action["principal"], os.geteuid(),
                                  gid=os.getegid(), probe_argv=(sys.executable, "-I", "-c", code), broker=self.control)

    def test_unsigned_wrong_signer_tampered_and_duplicate_json_have_no_authority(self):
        message = self.message()
        envelope = self.signed(message)
        tampered = copy.deepcopy(envelope)
        changed = copy.deepcopy(message)
        changed["manifest"]["command"] = "id"
        tampered["payload"] = base64.b64encode(control_module.canonical_json(changed)).decode()
        for offered in (message, self.signed(message, Ed25519PrivateKey.generate()), tampered,
                        self.signed(message, raw=b'{"action":"grant","action":"revoke"}')):
            with self.assertRaises((ValueError, InvalidSignature)):
                self.control.apply(offered)
        self.assertEqual(self.counts(), [0, 0, 0])

    def test_signed_cross_tenant_and_destination_profile_changes_fail_before_grant(self):
        for field in control_module.PINNED_FIELDS:
            with self.subTest(field=field):
                message = self.message()
                if field == "tenant":
                    message["manifest"][field]["tenant_id"] = "tenant-b"
                elif field == "destination_port":
                    message["manifest"][field] = 22
                elif field in {"destination_host", "source_address"}:
                    message["manifest"][field] = "192.0.2.9"
                elif field.endswith("sha256"):
                    message["manifest"][field] = "f" * 64
                else:
                    message["manifest"][field] = "other-value"
                with self.assertRaises(ValueError):
                    self.control.apply(self.signed(message))
                self.assertEqual(self.counts(), [0, 0, 0])

    def test_signed_general_command_expiry_and_duration_are_rejected(self):
        for edit in (lambda m: m["manifest"].update(command="id"),
                     lambda m: m["manifest"].update(max_session_secs=11),
                     lambda m: m["manifest"].update(argv=["sh"]),
                     lambda m: m.update(expires_at=int(time.time()) - 1),
                     lambda m: m.update(expires_at=int(time.time()) + 301),
                     lambda m: m.update(issued_at=int(time.time()) - 31),
                     lambda m: m.update(issued_at=int(time.time()) + 6),
                     lambda m: m.update(issued_at=True), lambda m: m.update(action=[])):
            message = self.message()
            edit(message)
            with self.assertRaises(ValueError):
                self.control.apply(self.signed(message))
        self.assertEqual(self.counts(), [0, 0, 0])

    def test_grant_ack_replay_and_restart_keep_one_immutable_allowance(self):
        envelope = self.signed(self.message())
        self.assertEqual(self.verify_receipt(self.control.apply(envelope)), {"status": "granted"})
        for offered in (envelope, self.signed(self.message())):
            with self.assertRaises(sqlite3.IntegrityError):
                self.new_control().apply(offered)
        self.assertEqual(self.counts(), [1, 1, 1], "failed duplicate grant must roll back its nonce")
        response = self.verify_receipt(self.guard().run(self.action["grant_id"]))
        self.assertEqual(response["status"], "completed")
        denied = self.verify_receipt(self.guard().run(self.action["grant_id"]))
        self.assertEqual(denied["receipt"]["result_code"], "already_used")

    def test_signed_result_hashes_exact_output_and_stores_no_plaintext(self):
        self.control.apply(self.signed(self.message()))
        response = self.verify_receipt(self.guard().run(self.action["grant_id"]))
        self.assertEqual(response["status"], "completed")
        self.assertEqual(hashlib.sha256(response["output_text"].encode()).hexdigest(), response["receipt"]["output_sha256"])
        self.assertEqual(json.loads(response["output_text"]), response["result"])
        with self.ledger.connect() as db:
            receipt = db.execute("SELECT receipt FROM receipts").fetchone()[0]
        self.assertNotIn("fixture-api", receipt)
        self.assertNotIn("output_text", receipt)
        with self.assertRaises(InvalidSignature):
            self.broker_key.public_key().verify(bytes.fromhex(self.control.sign(self.action, self.expires_at, response)["signature"]), b"wrong-domain")

    def test_operator_only_grant_cannot_execute_in_broker_mode(self):
        self.ledger.grant(self.action["grant_id"], "fixture-a", self.action["principal"], self.expires_at, 5)
        with mock.patch.object(guard_module.subprocess, "Popen") as spawn:
            response = self.guard().run(self.action["grant_id"])
        self.assertEqual(response["error"], "broker_authority_required")
        spawn.assert_not_called()

    def test_revoke_requires_full_manifest_and_updates_active_guard(self):
        self.control.apply(self.signed(self.message()))
        changed = self.message("revoke")
        changed["manifest"]["subject"] = "hum_" + "b" * 32
        with self.assertRaises(ValueError):
            self.control.apply(self.signed(changed))
        marker = Path(self.temporary.name) / "probe-started"
        code = f'import time; print(\'{{"private":"held-output"}}\', flush=True); open({str(marker)!r},"w").close(); time.sleep(10)'
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.guard(code).run, self.action["grant_id"])
            deadline = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(marker.exists())
            self.assertEqual(self.verify_receipt(self.control.apply(self.signed(self.message("revoke")))), {"status": "revoked"})
            response = self.verify_receipt(future.result(timeout=1))
        self.assertEqual(response["status"], "revoked")
        self.assertNotIn("output_text", response)
        self.assertNotIn("result", response)
        self.assertNotIn("held-output", json.dumps(response))

    def test_revoke_before_grant_persists_exact_tombstone_across_restart(self):
        delayed_grant = self.signed(self.message())
        revocation = self.signed(self.message("revoke"))
        self.assertEqual(self.verify_receipt(self.control.apply(revocation)), {"status": "revoked"})
        self.assertEqual(self.counts(), [1, 1, 1])
        restarted = self.new_control()
        self.assertEqual(restarted.authority(self.action["grant_id"]), (self.action, self.expires_at))
        with self.ledger.connect() as db:
            tombstone = db.execute("SELECT * FROM grants WHERE id=?", (self.action["grant_id"],)).fetchone()
            self.assertEqual(tombstone["revoked"], 1)
            self.assertIsNone(tombstone["reservation"])
            self.assertIsNone(tombstone["started_at"])
        for offered in (delayed_grant, self.signed(self.message()), revocation):
            with self.assertRaises(sqlite3.IntegrityError):
                restarted.apply(offered)
            self.assertEqual(self.counts(), [1, 1, 1], "failed late admission or replay must roll back its nonce")
        # A freshly signed retry is idempotent; replay of an envelope is still
        # rejected by the existing nonce contract.
        self.assertEqual(self.verify_receipt(restarted.apply(self.signed(self.message("revoke")))), {"status": "revoked"})
        self.assertEqual(self.counts(), [1, 1, 2])
        with mock.patch.object(guard_module.subprocess, "Popen") as spawn:
            response = self.verify_receipt(self.guard().run(self.action["grant_id"]))
        self.assertEqual(response["receipt"]["result_code"], "revoked")
        self.assertNotIn("output_text", response)
        spawn.assert_not_called()

    def test_revoked_tombstone_cannot_change_subject_session_workload_duration_or_expiry(self):
        self.control.apply(self.signed(self.message("revoke")))
        edits = (
            lambda m: m["manifest"].update(subject="hum_" + "b" * 32),
            lambda m: m["manifest"].update(delegation_id="other-session"),
            lambda m: m["manifest"].update(workload_uid=1001),
            lambda m: m["manifest"].update(workload_exe_sha256="d" * 64),
            lambda m: m["manifest"].update(max_session_secs=6),
            lambda m: m.update(expires_at=self.expires_at + 1),
        )
        for operation in ("grant", "revoke"):
            for edit in edits:
                with self.subTest(operation=operation, edit=edit):
                    message = self.message(operation)
                    edit(message)
                    with self.assertRaises((ValueError, sqlite3.IntegrityError)):
                        self.new_control().apply(self.signed(message))
                    self.assertEqual(self.counts(), [1, 1, 1])
                    self.assertEqual(self.control.authority(self.action["grant_id"]), (self.action, self.expires_at))
        with self.ledger.connect() as db:
            self.assertEqual(db.execute("SELECT revoked FROM grants").fetchone()[0], 1)

    def test_revocation_overtakes_already_verified_inflight_grant(self):
        verified, deliver_grant = threading.Event(), threading.Event()
        original_verify = self.control.verify

        def pause_grant_after_verification(envelope):
            result = original_verify(envelope)
            if result[0]["action"] == "grant":
                verified.set()
                if not deliver_grant.wait(timeout=2):
                    raise TimeoutError("test did not deliver the pending grant")
            return result

        with mock.patch.object(self.control, "verify", side_effect=pause_grant_after_verification):
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(self.control.apply, self.signed(self.message()))
                try:
                    self.assertTrue(verified.wait(timeout=2))
                    self.assertEqual(self.verify_receipt(self.new_control().apply(self.signed(self.message("revoke")))),
                                     {"status": "revoked"})
                finally:
                    deliver_grant.set()
                with self.assertRaises(sqlite3.IntegrityError):
                    future.result(timeout=2)
        self.assertEqual(self.counts(), [1, 1, 1])
        with mock.patch.object(guard_module.subprocess, "Popen") as spawn:
            response = self.verify_receipt(self.guard().run(self.action["grant_id"]))
        self.assertEqual(response["receipt"]["result_code"], "revoked")
        spawn.assert_not_called()

    def test_http_denies_unsigned_and_replayed_request(self):
        server = control_module.ControlServer(("127.0.0.1", 0), self.control)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def post(value):
            return urlopen(Request(f"http://127.0.0.1:{server.server_port}/v1/ssh-control",
                                   data=control_module.canonical_json(value), headers={"Content-Type": "application/json"}), timeout=2)
        try:
            with self.assertRaises(HTTPError) as denied:
                post(self.message())
            self.assertEqual(denied.exception.code, 403)
            self.assertEqual(self.counts(), [0, 0, 0])
            envelope = self.signed(self.message())
            with post(envelope) as response:
                self.assertEqual(self.verify_receipt(json.load(response))["status"], "granted")
            with self.assertRaises(HTTPError) as replay:
                post(envelope)
            self.assertEqual(replay.exception.code, 403)
            self.assertEqual(self.counts(), [1, 1, 1])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
