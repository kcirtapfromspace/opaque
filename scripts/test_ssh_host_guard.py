#!/usr/bin/env python3
"""Tests for the isolated SSH fixture guard. Uses temporary ledgers only."""

import concurrent.futures
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid


SOURCE = Path(__file__).resolve().parents[1] / "examples/bounded-ssh/host_guard.py"
SPEC = importlib.util.spec_from_file_location("ssh_host_guard", SOURCE)
guard_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard_module)


class HostGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger = guard_module.Ledger(Path(self.temporary.name) / "grants.sqlite")

    def grant(self, *, host="fixture-a", principal="opaque-fixture-a-health", ttl=30, duration=5):
        identifier = str(uuid.uuid4())
        self.ledger.grant(identifier, host, principal, int(time.time()) + ttl, duration)
        return identifier

    def guard(self, code='print(\'{"ok":true}\')', *, host="fixture-a", principal="opaque-fixture-a-health"):
        return guard_module.Guard(self.ledger, host, principal, os.geteuid(), gid=os.getegid(),
                                  probe_argv=(sys.executable, "-I", "-c", code))

    def receipts(self, identifier):
        with self.ledger.connect() as db:
            return [json.loads(row["receipt"]) for row in
                    db.execute("SELECT receipt FROM receipts WHERE grant_id=? ORDER BY sequence", (identifier,))]

    def wait_reserved(self, identifier):
        until = time.monotonic() + 2
        while time.monotonic() < until:
            with self.ledger.connect() as db:
                state = db.execute("SELECT state FROM grants WHERE id=?", (identifier,)).fetchone()["state"]
            if state == "reserved":
                return
            time.sleep(0.01)
        self.fail("operation never reserved grant")

    def test_success_receipt_hash_and_scrubbed_environment(self):
        identifier = self.grant()
        code = 'import json, os; print(json.dumps({"cwd":os.getcwd(),"env":dict(os.environ)}))'
        with mock.patch.dict(os.environ, {"OPAQUE_FIXTURE_SECRET": "never-forward-me"}):
            response = self.guard(code).run(identifier)
        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["result"]["cwd"], "/")
        self.assertNotIn("OPAQUE_FIXTURE_SECRET", response["result"]["env"])
        receipt = response["receipt"]
        self.assertEqual(receipt["host"], "fixture-a")
        self.assertEqual(receipt["principal"], "opaque-fixture-a-health")
        self.assertEqual(receipt["operation"], "opaque-service-health")
        # Hash is of the exact probe bytes, including the newline.
        raw = (json.dumps(response["result"]) + "\n").encode()
        self.assertEqual(receipt["output_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(self.receipts(identifier)), 1)
        self.assertNotIn("result", self.receipts(identifier)[0])

    def test_concurrent_single_use_has_one_host_side_effect(self):
        identifier = self.grant()
        marker = Path(self.temporary.name) / "executions"
        code = f'import time; open({str(marker)!r}, "a").write("1"); time.sleep(.2); print(\'{{"ok":true}}\')'
        barrier = threading.Barrier(8)
        guard = self.guard(code)

        def attempt():
            barrier.wait()
            return guard.run(identifier)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            responses = list(executor.map(lambda _: attempt(), range(8)))
        self.assertEqual(marker.read_text(), "1")
        self.assertEqual(sum(reply["status"] == "completed" for reply in responses), 1)
        self.assertEqual(sum(reply["receipt"]["result_code"] == "already_used" for reply in responses), 7)

    def test_host_and_principal_mismatch_do_not_execute_or_consume(self):
        for override in ({"host": "fixture-b"}, {"principal": "opaque-other-health"}):
            with self.subTest(override=override):
                identifier = self.grant()
                denied = self.guard(**override).run(identifier)
                self.assertEqual(denied["receipt"]["result_code"], "destination_mismatch")
                self.assertNotIn("result", denied)
                self.assertEqual(self.guard().run(identifier)["status"], "completed")

    def test_revoked_and_expired_grants_never_spawn(self):
        revoked, expired = self.grant(), self.grant()
        self.ledger.revoke(revoked)
        with self.ledger.connect() as db:
            db.execute("UPDATE grants SET expires_at=? WHERE id=?", (int(time.time()) - 1, expired))
        with mock.patch.object(guard_module.subprocess, "Popen") as spawn:
            for identifier, expected in ((revoked, "revoked"), (expired, "expired")):
                response = self.guard().run(identifier)
                self.assertEqual(response["receipt"]["result_code"], expected)
                self.assertNotIn("result", response)
        spawn.assert_not_called()

    def test_active_revocation_kills_and_suppresses_buffered_result(self):
        identifier = self.grant()
        marker = Path(self.temporary.name) / "started"
        code = f'import time; print(\'{{"private":"buffered"}}\', flush=True); open({str(marker)!r},"w").close(); time.sleep(10)'
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.guard(code).run, identifier)
            self.wait_reserved(identifier)
            until = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < until:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            started = time.monotonic()
            self.ledger.revoke(identifier)
            response = future.result(timeout=1)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(response["status"], "revoked")
        self.assertNotIn("result", response)
        self.assertNotIn("buffered", json.dumps(self.receipts(identifier)))
        self.assertEqual(self.guard().run(identifier)["receipt"]["result_code"], "revoked")

    def test_active_expiry_and_duration_are_hard_deadlines(self):
        for ttl, duration, status in ((2, 5, "expired"), (30, 1, "timeout")):
            with self.subTest(status=status):
                identifier = self.grant(ttl=ttl, duration=duration)
                started = time.monotonic()
                response = self.guard('import time; print(\'{"ok":true}\',flush=True); time.sleep(10)').run(identifier)
                self.assertEqual(response["status"], status)
                self.assertNotIn("result", response)
                self.assertLess(time.monotonic() - started, min(ttl, duration) + 0.5)

    def test_deadline_kills_descendants_of_fixed_operation(self):
        identifier = self.grant(duration=1)
        ready, leaked = (Path(self.temporary.name) / name for name in ("child-ready", "child-leaked"))
        child = f'import time; open({str(ready)!r},"w").close(); time.sleep(1.7); open({str(leaked)!r},"w").close()'
        parent = f'import subprocess, sys, time; subprocess.Popen([sys.executable,"-I","-c",{child!r}]); time.sleep(10)'
        response = self.guard(parent).run(identifier)
        self.assertEqual(response["status"], "timeout")
        self.assertTrue(ready.exists(), "descendant must have started for this test to be meaningful")
        time.sleep(0.9)
        self.assertFalse(leaked.exists(), "descendant escaped operation process-group termination")

    @unittest.skipUnless(sys.platform == "linux", "Linux parent-death signal")
    def test_probe_dies_when_guard_process_is_killed(self):
        ready = Path(self.temporary.name) / "probe-ready"
        child_pid_file = Path(self.temporary.name) / "probe-pid"
        probe = SOURCE.with_name("health_probe.py")
        child_code = (f'import runpy,time; runpy.run_path({str(probe)!r})["arm_parent_death_signal"](); '
                      f'open({str(ready)!r},"w").close(); time.sleep(10)')
        parent_code = (f'import subprocess,sys,time,pathlib; child=subprocess.Popen([sys.executable,"-I","-c",{child_code!r}]); '
                       f'\nwhile not pathlib.Path({str(ready)!r}).exists(): time.sleep(.01)'
                       f'\npathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); time.sleep(10)')
        parent = subprocess.Popen([sys.executable, "-I", "-c", parent_code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child_pid = None
        try:
            until = time.monotonic() + 2
            while not child_pid_file.exists() and time.monotonic() < until:
                time.sleep(0.01)
            self.assertTrue(child_pid_file.exists(), "probe must arm its parent-death signal")
            child_pid = int(child_pid_file.read_text())
            parent.kill()
            parent.wait(timeout=1)
            until = time.monotonic() + 0.5
            running = True
            while running and time.monotonic() < until:
                process_state = Path(f"/proc/{child_pid}/stat")
                try:
                    running = process_state.read_text().rsplit(")", 1)[1].split()[0] != "Z"
                except FileNotFoundError:
                    running = False
                if running:
                    time.sleep(0.01)
            self.assertFalse(running, "orphaned probe survived its supervising process")
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait()
            if child_pid is not None:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(child_pid, 9)
                with contextlib.suppress(ChildProcessError):
                    os.waitpid(child_pid, os.WNOHANG)

    def test_busy_ledger_cancels_operation_within_deadline(self):
        identifier = self.grant(duration=1)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.guard("import time; time.sleep(10)").run, identifier)
            self.wait_reserved(identifier)
            with self.ledger.connect() as db:
                db.execute("BEGIN EXCLUSIVE")
                time.sleep(0.2)
                # Failure closed while SQLite is unavailable; final receipt
                # waits until this controlled test releases its writer lock.
                db.rollback()
            response = future.result(timeout=1)
        self.assertEqual(response["status"], "failed")
        self.assertEqual(response["receipt"]["result_code"], "guard_error")

    def test_restart_reservations_remain_unknown_and_unusable(self):
        identifier = self.grant()
        claim, denial = self.ledger.reserve(identifier, "fixture-a", "opaque-fixture-a-health")
        self.assertIsNone(denial)
        restarted = guard_module.Ledger(self.ledger.path)
        restarted.recover()
        with restarted.connect() as db:
            self.assertEqual(db.execute("SELECT state FROM grants WHERE id=?", (identifier,)).fetchone()["state"], "unknown")
        self.assertEqual(self.receipts(identifier)[0]["result_code"], "restart_unknown")
        self.assertEqual(self.guard().run(identifier)["receipt"]["result_code"], "already_used")
        stale_result = restarted.finish(claim, "completed", "ok", b'{}', True, {})
        self.assertEqual(stale_result["status"], "unknown")
        self.assertNotIn("result", stale_result)

    def test_failed_and_oversized_probe_cannot_refund_reservation(self):
        for code, reason in (("print('x'*5000)", "output_limit"),
                             ("print('not json')", "invalid_probe_json"),
                             ("print('NaN')", "invalid_probe_json"),
                             ("raise SystemExit(9)", "probe_failed")):
            with self.subTest(reason=reason):
                identifier = self.grant()
                response = self.guard(code).run(identifier)
                self.assertEqual(response["receipt"]["result_code"], reason)
                self.assertNotIn("result", response)
                self.assertLessEqual(response["receipt"]["output_bytes"], guard_module.MAX_OUTPUT + 1)
                self.assertEqual(self.guard().run(identifier)["receipt"]["result_code"], "already_used")

    def test_late_revoke_and_expiry_checked_before_result_release(self):
        for action in ("revoke", "expire"):
            with self.subTest(action=action):
                identifier = self.grant()
                claim, _ = self.ledger.reserve(identifier, "fixture-a", "opaque-fixture-a-health")
                if action == "revoke":
                    self.ledger.revoke(identifier)
                else:
                    with self.ledger.connect() as db:
                        db.execute("UPDATE grants SET expires_at=0 WHERE id=?", (identifier,))
                response = self.ledger.finish(claim, "completed", "ok", b'{}', True, {})
                self.assertEqual(response["status"], "revoked" if action == "revoke" else "expired")
                self.assertNotIn("result", response)

    def test_grant_constraints_and_immutable_id(self):
        identifier = self.grant()
        for expiry, duration in ((int(time.time()) - 1, 5), (int(time.time()) + 302, 5),
                                 (int(time.time()) + 10, 0), (int(time.time()) + 10, 31)):
            with self.assertRaises(ValueError):
                self.ledger.grant(str(uuid.uuid4()), "fixture-a", "opaque-fixture-a-health", expiry, duration)
        with self.assertRaises(guard_module.sqlite3.IntegrityError):
            self.ledger.grant(identifier, "fixture-a", "opaque-fixture-a-health", int(time.time()) + 30, 5)

    def test_forced_command_rejects_shell_argv_and_tty_before_socket(self):
        for environment in ({}, {"SSH_ORIGINAL_COMMAND": "sh"},
                            {"SSH_ORIGINAL_COMMAND": "opaque-service-health --url http://elsewhere"},
                            {"SSH_ORIGINAL_COMMAND": "opaque-service-health", "SSH_TTY": "/dev/pts/0"}):
            with self.subTest(environment=environment), mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch.object(guard_module.socket, "socket") as connect, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(guard_module.enter(str(uuid.uuid4())), 1)
                connect.assert_not_called()

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux peer credentials integration")
    def test_socket_checks_peer_and_rejects_client_policy_fields(self):
        guard = self.guard()
        for expected_uid, request, error in ((os.geteuid() + 1, {"grant_id": self.grant()}, "peer_identity"),
                                             (os.geteuid(), {"grant_id": self.grant(), "command": "id"}, "invalid_request_or_guard_failure")):
            local, remote = socket.socketpair()
            slots = threading.BoundedSemaphore(1)
            slots.acquire()
            thread = threading.Thread(target=guard_module.handle, args=(local, guard, slots), kwargs={"peer_uid": expected_uid})
            remote.sendall(json.dumps(request).encode() + b"\n")
            thread.start()
            try:
                response = guard_module.read_message(remote, guard_module.MAX_REPLY)
                self.assertEqual(response["error"], error)
            finally:
                remote.close()
                thread.join(timeout=2)
            self.assertTrue(slots.acquire(blocking=False))


if __name__ == "__main__":
    unittest.main()
