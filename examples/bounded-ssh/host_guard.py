#!/usr/bin/env python3
"""Root-owned, single-operation SSH fixture guard; this is not an approval broker.

The unprivileged SSH account can submit only a grant UUID over a Unix socket.
Host policy, executable, principal, and operating-system identity are local
configuration. SQLite reservations survive crashes and are never refunded.
"""

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid


OPERATION = "opaque-service-health"
SOCKET_PATH = "/run/opaque-ssh/guard.sock"
PROBE_ARGV = ("/usr/bin/python3", "-I", "/opt/opaque-ssh/health_probe.py")
MAX_OUTPUT = 4096
MAX_REQUEST = 256
MAX_REPLY = 16384
POLL_SECONDS = 0.05


def grant_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("grant ID must be a canonical UUID")
    return value


def policy_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value):
        raise ValueError("invalid host or principal")
    return value


class Ledger:
    def __init__(self, path):
        self.path = os.fspath(path)
        # The fixture CLI runs as root with umask 077. No secrets or probe output
        # are persisted; receipts contain only fixed metadata and an output hash.
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS grants (
                    id TEXT PRIMARY KEY, host TEXT NOT NULL, principal TEXT NOT NULL,
                    expires_at INTEGER NOT NULL, max_seconds INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'granted', reservation TEXT,
                    started_at REAL
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL,
                    receipt TEXT NOT NULL
                );
            """)

    @contextlib.contextmanager
    def connect(self, timeout=2):
        db = sqlite3.connect(self.path, timeout=timeout, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
            yield db
        finally:
            db.close()

    def grant(self, identifier, host, principal, expires_at, max_seconds):
        identifier, host, principal = grant_id(identifier), policy_name(host), policy_name(principal)
        if type(expires_at) is not int or not time.time() < expires_at <= time.time() + 300:
            raise ValueError("grant expiry must be in the next 300 seconds")
        if type(max_seconds) is not int or not 1 <= max_seconds <= 30:
            raise ValueError("max seconds must be between 1 and 30")
        with self.connect() as db:
            db.execute("INSERT INTO grants(id,host,principal,expires_at,max_seconds) VALUES(?,?,?,?,?)",
                       (identifier, host, principal, expires_at, max_seconds))

    def revoke(self, identifier):
        with self.connect() as db:
            result = db.execute("UPDATE grants SET revoked=1 WHERE id=?", (grant_id(identifier),))
            if result.rowcount != 1:
                raise ValueError("unknown grant")

    @staticmethod
    def receipt(db, identifier, host, principal, status, code, started, output=b"", complete=True):
        receipt = {
            "grant_id": identifier, "host": host, "principal": principal,
            "operation": OPERATION, "status": status, "result_code": code,
            "started_at": started, "finished_at": time.time(),
            "output_sha256": hashlib.sha256(output).hexdigest(),
            "output_bytes": len(output), "output_complete": complete,
        }
        cursor = db.execute("INSERT INTO receipts(grant_id,receipt) VALUES(?,?)",
                            (identifier, json.dumps(receipt, sort_keys=True)))
        receipt["sequence"] = cursor.lastrowid
        return {"status": status, "receipt": receipt}

    def recover(self):
        """Called only with the exclusive server lock held on process startup."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute("SELECT * FROM grants WHERE state='reserved'").fetchall():
                self.receipt(db, row["id"], row["host"], row["principal"], "unknown",
                             "restart_unknown", row["started_at"], complete=False)
            db.execute("UPDATE grants SET state='unknown' WHERE state='reserved'")
            db.commit()

    def reserve(self, identifier, host, principal):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM grants WHERE id=?", (identifier,)).fetchone()
            code = None
            if row is None:
                code = "unknown_grant"
            elif row["host"] != host or row["principal"] != principal:
                code = "destination_mismatch"
            elif row["revoked"]:
                code = "revoked"
            elif row["expires_at"] <= time.time():
                code = "expired"
            elif row["state"] != "granted":
                code = "already_used"
            if code:
                result = self.receipt(db, identifier, host, principal, "denied", code, time.time())
                db.commit()
                return None, result
            reservation = str(uuid.uuid4())
            started = time.time()
            db.execute("UPDATE grants SET state='reserved',reservation=?,started_at=? WHERE id=?",
                       (reservation, started, identifier))
            db.commit()
            return dict(row) | {"reservation": reservation, "started_at": started}, None

    def cancellation(self, claim):
        with self.connect(timeout=0.025) as db:
            row = db.execute("SELECT revoked,state,reservation FROM grants WHERE id=?", (claim["id"],)).fetchone()
        if row is None or row["state"] != "reserved" or row["reservation"] != claim["reservation"]:
            return "unknown"
        if row["revoked"]:
            return "revoked"
        if time.time() >= claim["expires_at"]:
            return "expired"
        return None

    def finish(self, claim, status, code, output, complete, result=None, *, include_output_text=False):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM grants WHERE id=?", (claim["id"],)).fetchone()
            # Recheck at the output-release decision, under the same lock as
            # revoke. A stale child can never finish a recovered reservation.
            if row is None or row["state"] != "reserved" or row["reservation"] != claim["reservation"]:
                status, code, result = "unknown", "reservation_lost", None
            else:
                if row["revoked"]:
                    status, code, result = "revoked", "revoked", None
                elif time.time() >= row["expires_at"]:
                    status, code, result = "expired", "expired", None
                db.execute("UPDATE grants SET state='completed' WHERE id=?", (claim["id"],))
            response = self.receipt(db, claim["id"], claim["host"], claim["principal"], status, code,
                                    claim["started_at"], output, complete)
            if status == "completed":
                response["result"] = result
                if include_output_text:
                    # Exact bytes are returned only inside broker-authenticated
                    # evidence; receipt storage still contains just the digest.
                    response["output_text"] = output.decode("utf-8")
            db.commit()
            return response


class Guard:
    def __init__(self, ledger, host, principal, uid=7382, *, probe_argv=PROBE_ARGV, gid=None, broker=None):
        self.ledger = ledger
        self.host, self.principal = policy_name(host), policy_name(principal)
        self.uid, self.gid = uid, uid if gid is None else gid
        # Test injection is Python-only. The command-line protocol cannot change
        # the executable, arguments, identity, environment, or destination.
        self.probe_argv = tuple(probe_argv)
        self.broker = broker

    def run(self, identifier):
        identifier = grant_id(identifier)
        authority = self.broker.authority(identifier) if self.broker else None
        if self.broker and authority is None:
            return {"status": "denied", "error": "broker_authority_required"}
        def wrap(response):
            return self.broker.sign(*authority, response) if authority else response
        claim, denial = self.ledger.reserve(identifier, self.host, self.principal)
        if denial:
            return wrap(denial)
        deadline = time.monotonic() + min(claim["max_seconds"], max(0, claim["expires_at"] - time.time()))
        process, selector = None, selectors.DefaultSelector()
        output = bytearray()
        status, code, complete, result = "failed", "spawn_failed", False, None
        try:
            identity = {}
            if os.geteuid() == 0:
                identity = {"user": self.uid, "group": self.gid, "extra_groups": []}
            elif self.uid != os.geteuid() or self.gid != os.getegid():
                raise PermissionError("cannot switch operation identity")
            cancellation = self.ledger.cancellation(claim)
            if cancellation:
                status, code = cancellation, cancellation
            else:
                process = subprocess.Popen(
                    self.probe_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    start_new_session=True, close_fds=True, **identity,
                )
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                eof = False
                while True:
                    cancellation = self.ledger.cancellation(claim)
                    if cancellation:
                        status, code = cancellation, cancellation
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        status, code = "timeout", "duration_exceeded"
                        break
                    for key, _ in selector.select(min(POLL_SECONDS, remaining)):
                        chunk = os.read(key.fileobj.fileno(), MAX_OUTPUT + 1 - len(output))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            eof = True
                        output.extend(chunk)
                    if len(output) > MAX_OUTPUT:
                        status, code = "failed", "output_limit"
                        break
                    returncode = process.poll()
                    if eof and returncode is not None:
                        complete = True
                        if returncode != 0:
                            status, code = "failed", "probe_failed"
                        else:
                            try:
                                result = json.loads(output, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                                status, code = "completed", "ok"
                            except (ValueError, UnicodeError, RecursionError):
                                status, code = "failed", "invalid_probe_json"
                        break
        except (OSError, sqlite3.Error):
            status, code = "failed", "guard_error" if process else "spawn_failed"
        finally:
            selector.close()
            if process is not None:
                # The complete process group is terminated on every outcome,
                # including when a child outlives the fixed operation's parent.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                process.stdout.close()
        return wrap(self.ledger.finish(claim, status, code, bytes(output), complete, result,
                                      include_output_text=authority is not None))


def read_message(connection, limit):
    data = bytearray()
    while len(data) <= limit:
        chunk = connection.recv(min(1024, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in data:
            if data.index(b"\n") != len(data) - 1:
                raise ValueError("trailing protocol data")
            break
    if len(data) > limit or not data.endswith(b"\n"):
        raise ValueError("invalid message length or framing")
    return json.loads(data)


def handle(connection, guard, slots, *, peer_uid=None):
    try:
        connection.settimeout(1)
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", credentials)
        if uid != (guard.uid if peer_uid is None else peer_uid):
            response = {"status": "denied", "error": "peer_identity"}
        else:
            request = read_message(connection, MAX_REQUEST)
            if not isinstance(request, dict) or set(request) != {"grant_id"}:
                raise ValueError("only a grant ID is accepted")
            response = guard.run(grant_id(request["grant_id"]))
        connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")
    except (ValueError, OSError, sqlite3.Error, RecursionError):
        with contextlib.suppress(OSError):
            connection.sendall(b'{"status":"denied","error":"invalid_request_or_guard_failure"}\n')
    finally:
        connection.close()
        slots.release()


def serve(guard, socket_path):
    # Avoid a second server interpreting a live reservation as a crashed one.
    lock_fd = os.open(guard.ledger.path + ".serve.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        guard.ledger.recover()
        if os.path.lexists(socket_path):
            if not stat.S_ISSOCK(os.lstat(socket_path).st_mode):
                raise ValueError("socket path already exists and is not a socket")
            os.unlink(socket_path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(socket_path)
            os.chown(socket_path, 0, guard.gid)
            os.chmod(socket_path, 0o660)
            server.listen(8)
            slots = threading.BoundedSemaphore(8)
            while True:
                connection, _ = server.accept()
                if not slots.acquire(blocking=False):
                    connection.close()
                    continue
                threading.Thread(target=handle, args=(connection, guard, slots), daemon=True).start()


def enter(identifier):
    identifier = grant_id(identifier)
    if os.environ.get("SSH_ORIGINAL_COMMAND") != OPERATION or os.environ.get("SSH_TTY"):
        print(json.dumps({"status": "denied", "error": "command_or_session_policy"}))
        return 1
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(35)
            connection.connect(SOCKET_PATH)
            connection.sendall(json.dumps({"grant_id": identifier}).encode() + b"\n")
            response = read_message(connection, MAX_REPLY)
        # The unprivileged dispatcher forwards signed bytes unchanged. Only the
        # broker verifies the host signature and treats a result as evidence.
        status = response.get("status") if isinstance(response, dict) else None
        if isinstance(response, dict) and set(response) == {"payload", "signature"}:
            import base64
            payload = json.loads(base64.b64decode(response["payload"], validate=True))
            if not isinstance(payload, dict) or not isinstance(payload.get("response"), dict):
                raise ValueError("invalid signed guard response")
            status = payload["response"].get("status")
        if status not in {
            "completed", "denied", "revoked", "expired", "timeout", "failed", "unknown"
        }:
            raise ValueError("invalid guard response")
        print(json.dumps(response, sort_keys=True))
        return 0 if status == "completed" else 1
    except (ValueError, OSError, RecursionError):
        print(json.dumps({"status": "denied", "error": "guard_unavailable"}))
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    grant = commands.add_parser("grant")
    grant.add_argument("--db", required=True)
    grant.add_argument("--id", required=True)
    grant.add_argument("--host", required=True)
    grant.add_argument("--principal", required=True)
    grant.add_argument("--expires-at", required=True, type=int)
    grant.add_argument("--max-seconds", required=True, type=int)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--db", required=True)
    revoke.add_argument("--id", required=True)
    server = commands.add_parser("serve")
    server.add_argument("--db", required=True)
    server.add_argument("--socket", required=True)
    server.add_argument("--host", required=True)
    server.add_argument("--principal", required=True)
    server.add_argument("--uid", type=int, default=7382)
    entry = commands.add_parser("enter")
    entry.add_argument("id")
    args = parser.parse_args(argv)
    try:
        if args.command == "enter":
            return enter(args.id)
        if os.geteuid() != 0:
            raise ValueError("fixture control plane requires root")
        os.umask(0o077)
        if os.path.lexists(args.db):
            metadata = os.lstat(args.db)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
                raise ValueError("ledger must be a root-owned regular file with mode 0600")
        ledger = Ledger(args.db)
        if args.command == "grant":
            ledger.grant(args.id, args.host, args.principal, args.expires_at, args.max_seconds)
            print(json.dumps({"status": "granted", "grant_id": args.id}))
        elif args.command == "revoke":
            ledger.revoke(args.id)
            print(json.dumps({"status": "revoked", "grant_id": args.id}))
        else:
            if args.uid <= 0:
                raise ValueError("operation UID must be unprivileged")
            broker = None
            if Path("/etc/opaque-ssh/broker.json").exists():
                spec = importlib.util.spec_from_file_location("opaque_broker_control", Path(__file__).with_name("broker_control.py"))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                config, receipt_key = module.load_config()
                broker = module.BrokerControl(ledger, config, receipt_key, args.host, args.principal)
            serve(Guard(ledger, args.host, args.principal, args.uid, broker=broker), args.socket)
        return 0
    except (ValueError, OSError, sqlite3.Error):
        print(json.dumps({"status": "denied", "error": "invalid_control_plane_request"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
