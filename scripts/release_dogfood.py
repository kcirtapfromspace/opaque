#!/usr/bin/env python3
"""Disposable, separately custodied staging-release dogfood (Python stdlib + Docker).

The automated signer exercises the real workstation protocol but is explicitly
TEST APPROVAL. Native mode uses opaque-approver's complete review ceremony.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
RUST_IMAGE = "rust:1.95.0-slim-bookworm"
RUNTIME_IMAGE = "debian:bookworm-slim"
# Already distributed as a Python runtime; no MCP server is started. Override
# --python-image to use another operator-reviewed image containing python3.
PYTHON_IMAGE = "mcp/fetch@sha256:0b2e4fb020b591dcc9f49aac11e2380b3820f0a097e7d370a5227ed8bbe5118c"
# These names mirror the private live example, but every provider request in
# this runner still goes to its disposable loopback server.
REPO = "kcirtapfromspace/opaque-dogfood"
REPOSITORY_ID = 1357845081
WORKFLOW_ID = 17001
WORKFLOW_PATH = ".github/workflows/opaque-staging-release.yml"
BRANCH = "main"
COMMIT = "a" * 40
IMAGE_REPOSITORY = "ghcr.io/kcirtapfromspace/opaque-dogfood"
IMAGE_DIGEST = "sha256:" + "b" * 64
TOKEN = "opaque-release-disposable-fixture-token"
PROVIDER_PORT = 18901
APPROVAL_PORT = 18902
SOCKET = "/run/opaque/opaqued.sock"
BROKER_STATE = "/var/lib/opaque"


def dump(path: Path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def execute(command, *, check=True, input=None, timeout=90, text=True, **kwargs):
    result = subprocess.run(command, input=input, text=text, capture_output=True, timeout=timeout, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"Command failed: {shlex.join(map(str, command[:7]))}\n{result.stderr[-5000:]}")
    return result


def public_task(payload):
    result = payload.get("result", payload)
    return result.get("task", result)


def port_available(port):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock = threading.Lock()
        self.workflow = (self.directory / "workflow.yml").read_bytes()
        super().__init__(("127.0.0.1", PROVIDER_PORT), FixtureHandler)

    def records(self):
        path = self.directory / "dispatches.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def control(self):
        return json.loads((self.directory / "control.json").read_text())


class FixtureHandler(BaseHTTPRequestHandler):
    server: FixtureServer

    def log_message(self, *_args):
        pass

    def reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authenticated(self):
        return self.headers.get("Authorization") == "Bearer " + TOKEN

    def do_GET(self):
        if not self.authenticated():
            return self.reply(401, {"message": "disposable fixture token required"})
        url = urlparse(self.path)
        path = unquote(url.path)
        prefix = f"/repos/{REPO}"
        repo = {"id": REPOSITORY_ID, "full_name": REPO}
        if path.lower() == prefix.lower():
            return self.reply(200, repo)
        if path in (prefix + "/actions/workflows/" + WORKFLOW_PATH.rsplit("/", 1)[1], prefix + f"/actions/workflows/{WORKFLOW_ID}"):
            return self.reply(200, {"id": WORKFLOW_ID, "path": WORKFLOW_PATH, "state": "active"})
        if path == prefix + "/branches/" + BRANCH:
            return self.reply(200, {"name": BRANCH, "protected": True, "commit": {"sha": COMMIT}})
        if path == prefix + "/contents/" + WORKFLOW_PATH and parse_qs(url.query) == {"ref": [COMMIT]}:
            return self.reply(200, {"type": "file", "path": WORKFLOW_PATH, "encoding": "base64", "content": base64.b64encode(self.server.workflow).decode()})
        if path.startswith(prefix + "/actions/runs/"):
            try:
                run_id = int(path.rsplit("/", 1)[1])
                record = self.server.records()[run_id - 80001]
                assert run_id >= 80001
            except (ValueError, IndexError, AssertionError):
                return self.reply(404, {"message": "unknown run"})
            mode = self.server.control().get("observation", "pending")
            inputs = record["body"]["inputs"]
            return self.reply(200, {
                "id": run_id, "workflow_id": WORKFLOW_ID, "repository": repo, "head_repository": repo,
                "head_sha": COMMIT, "head_branch": BRANCH, "event": "workflow_dispatch",
                "display_title": "opaque-staging:" + inputs["opaque_task_id"] + ":" + inputs["opaque_manifest_digest"],
                "status": "in_progress" if mode in ("pending", "running") else "completed",
                "conclusion": None if mode in ("pending", "running") else ("failure" if mode == "failed" else "success"),
                "run_attempt": 2 if mode == "rerun" else 1,
            })
        if path == prefix + f"/actions/workflows/{WORKFLOW_ID}/runs":
            query = parse_qs(url.query)
            if any(query.get(key) != [value] for key, value in {"event": "workflow_dispatch", "branch": BRANCH, "head_sha": COMMIT, "per_page": "100"}.items()):
                return self.reply(400, {"message": "exact correlation filters required"})
            mode = self.server.control().get("observation", "pending")
            runs = []
            for index, record in enumerate(self.server.records(), 1):
                inputs = record["body"]["inputs"]
                if mode == "pending":
                    continue
                run = {
                    "id": 80000 + index, "workflow_id": WORKFLOW_ID, "repository": repo, "head_repository": repo,
                    "head_sha": COMMIT, "head_branch": BRANCH, "event": "workflow_dispatch",
                    "display_title": "opaque-staging:" + inputs["opaque_task_id"] + ":" + inputs["opaque_manifest_digest"],
                    "status": "in_progress" if mode == "running" else "completed",
                    "conclusion": None if mode == "running" else ("failure" if mode == "failed" else "success"),
                    "run_attempt": 2 if mode == "rerun" else 1,
                }
                runs.append(run)
                if mode == "ambiguous":
                    runs.append(dict(run, id=90000 + index))
            if query.get("page", ["1"]) != ["1"]:
                runs = []
            return self.reply(200, {"total_count": len(runs), "workflow_runs": runs})
        return self.reply(404, {"message": "unknown fixture route"})

    def do_POST(self):
        if not self.authenticated():
            return self.reply(401, {"message": "disposable fixture token required"})
        expected = f"/repos/{REPO}/actions/workflows/{WORKFLOW_ID}/dispatches"
        if unquote(urlparse(self.path).path) != expected:
            return self.reply(404, {"message": "unknown fixture dispatch target"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                raise ValueError("body length")
            body = json.loads(self.rfile.read(length))
            inputs = body["inputs"]
            if set(body) != {"ref", "inputs"} or body["ref"] != BRANCH:
                raise ValueError("dispatch shape")
            exact = {"approved_commit_sha": COMMIT, "image_repository": IMAGE_REPOSITORY, "image_digest": IMAGE_DIGEST, "environment": "staging"}
            if set(inputs) != set(exact) | {"opaque_task_id", "opaque_manifest_digest"}:
                raise ValueError("arbitrary inputs")
            if any(inputs[key] != value for key, value in exact.items()):
                raise ValueError("immutable authority mismatch")
            if not re.fullmatch(r"[0-9a-f-]{36}", inputs["opaque_task_id"]) or not re.fullmatch(r"[0-9a-f]{64}", inputs["opaque_manifest_digest"]):
                raise ValueError("correlation identity")
        except (ValueError, KeyError, TypeError):
            return self.reply(400, {"message": "invalid fixed release contract"})
        with self.server.lock:
            settings = self.server.control()
            code = 500 if settings.get("fault") else (204 if settings.get("legacy") else 200)
            run_id = 80001 + len(self.server.records())
            with (self.server.directory / "dispatches.jsonl").open("a") as out:
                out.write(json.dumps({"status": code, "body": body}) + "\n")
        if code == 204:
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif code == 200:
            self.reply(code, {"workflow_run_id": run_id})
        else:
            self.reply(code, {"message": "fixture uncertain response; run may exist"})


class RelayHandler(BaseHTTPRequestHandler):
    """Stream a loopback dashboard through a host-loopback Docker publication."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def relay(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.web_port, timeout=60)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16384:
                self.send_error(413)
                return
            body = self.rfile.read(length) if length else None
            headers = {key: value for key, value in self.headers.items() if key.lower() not in ("connection", "transfer-encoding")}
            connection.request(self.command, self.path, body, headers)
            response = connection.getresponse()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ("connection", "transfer-encoding"):
                    self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            while chunk := response.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        finally:
            self.close_connection = True
            connection.close()

    do_GET = relay
    do_POST = relay


def fixture_main(args):
    fixture = FixtureServer(args.directory)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    relay = ThreadingHTTPServer(("0.0.0.0", args.relay_port), RelayHandler)
    relay.web_port = args.web_port
    relay.serve_forever()


def signed_fields(fields):
    content = bytearray()
    for field in fields:
        value = field.encode() if isinstance(field, str) else field
        content.extend(struct.pack("<I", len(value)))
        content.extend(value)
    return hashlib.sha256(content).digest()


class TestSigner:
    """Disposable fixture only. Never imported or called by opaque-approver."""
    def __init__(self, directory, broker_port, fingerprint, openssl):
        self.directory = Path(directory)
        self.port = broker_port
        self.fingerprint = fingerprint
        self.openssl = openssl
        self.public_key = (self.directory / "public-key.txt").read_text().strip()
        self.identity = None
        self.broker_id = None
        self.seen = set()

    def request(self, path, body=None, authenticated=True):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=context, timeout=8)
        connection.connect()
        actual = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if actual != self.fingerprint:
            connection.close()
            raise RuntimeError("Pinned broker TLS certificate changed")
        headers = {}
        if authenticated:
            headers = {"Authorization": "Bearer " + self.identity["token"], "X-Opaque-Device": self.identity["device_id"]}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request("POST" if body is not None else "GET", path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        if not 200 <= response.status < 300:
            raise RuntimeError(f"Pinned broker request {path} returned {response.status}")
        return json.loads(raw) if raw else {}

    def sign(self, message):
        input_path = self.directory / "challenge.bin"
        input_path.write_bytes(message)
        input_path.chmod(0o600)
        result = execute([self.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.directory / "test-key.pem"), "-in", str(input_path)], text=False)
        input_path.unlink()
        if len(result.stdout) != 64:
            raise RuntimeError("Expected an Ed25519 signature")
        return result.stdout.hex()

    def validate_challenge(self, challenge):
        now = int(time.time())
        if challenge["schema_version"] != 1 or challenge["broker_id"] != self.broker_id:
            raise RuntimeError("Wrong broker or challenge version")
        if not challenge["created_at"] <= now < challenge["expires_at"] or not 0 < challenge["expires_at"] - challenge["created_at"] <= 300:
            raise RuntimeError("Expired or invalid approval window")
        if not re.fullmatch("[0-9a-f]{64}", challenge["nonce"]):
            raise RuntimeError("Invalid broker nonce")

    def enroll(self):
        challenge = self.request("/workstation/enrollment/challenge", {"public_key_hex": self.public_key}, authenticated=False)
        self.broker_id = challenge["broker_id"]
        self.validate_challenge(challenge)
        if challenge["public_key_hex"] != self.public_key:
            raise RuntimeError("Enrollment public key mismatch")
        fields = ["opaque.workstation-enrollment.v1", self.broker_id, self.public_key, challenge["nonce"], struct.pack("<q", challenge["created_at"]), struct.pack("<q", challenge["expires_at"])]
        self.identity = self.request("/workstation/enrollment/complete", {"public_key_hex": self.public_key, "nonce": challenge["nonce"], "signature": self.sign(signed_fields(fields))}, authenticated=False)
        if self.identity["server_id"] != self.broker_id:
            raise RuntimeError("Enrollment broker identity changed")
        dump(self.directory / "test-enrollment.json", self.identity)
        (self.directory / "broker-id.txt").write_text(self.broker_id + "\n")

    def approve_pending(self):
        pending = self.request("/workstation/approvals/pending")
        for item in pending.get("approvals", []):
            challenge = item.get("challenge", item)
            approval_id = challenge["approval_id"]
            if approval_id in self.seen:
                continue
            review = self.request("/workstation/approvals/" + approval_id)
            if review["challenge"] != challenge:
                raise RuntimeError("Pending challenge changed before full review")
            challenge = review["challenge"]
            self.validate_challenge(challenge)
            if challenge["operation"] != "github.release_manifest":
                raise RuntimeError("Test signer accepts only fixture staging releases")
            if hashlib.sha256(review["review_text"].encode()).hexdigest() != challenge["content_hash"]:
                raise RuntimeError("Full review hash mismatch")
            if any(value not in review["review_text"] for value in (REPO, IMAGE_REPOSITORY, IMAGE_DIGEST, COMMIT, "staging")):
                raise RuntimeError("Test review is missing the fixed fixture authority")
            fields = ["opaque.workstation-decision.v1", self.broker_id, approval_id, challenge["request_id"], challenge["operation"], challenge["content_hash"], challenge["nonce"], struct.pack("<q", challenge["created_at"]), struct.pack("<q", challenge["expires_at"]), "approve"]
            self.request("/workstation/approvals/" + approval_id + "/respond", {"device_id": self.identity["device_id"], "decision": "approve", "signature": self.sign(signed_fields(fields))})
            self.seen.add(approval_id)
            with (self.directory / "test-approvals.jsonl").open("a") as output:
                output.write(json.dumps({"approval_id": approval_id, "content_hash": challenge["content_hash"], "mode": "insecure_test"}) + "\n")


def signer_main(args):
    signer = TestSigner(args.directory, args.port, args.fingerprint, args.openssl)
    signer.enroll()
    print("TEST SIGNER ready. No human consent is requested.", flush=True)
    while True:
        try:
            signer.approve_pending()
        except (OSError, http.client.HTTPException):
            # A broker restart can interrupt transport; no decision is replayed.
            time.sleep(1)
        time.sleep(0.25)


class ReleaseDogfood:
    def __init__(self, args):
        self.args = args
        self.directory = (args.data_dir or Path(tempfile.mkdtemp(prefix="orf-", dir="/tmp"))).expanduser().resolve()
        marker = self.directory / ".opaque-release-dogfood.json"
        if self.directory == (Path.home() / ".opaque").resolve():
            raise RuntimeError("Choose a disposable directory, not ~/.opaque")
        if self.directory.exists() and any(self.directory.iterdir()) and not marker.exists():
            raise RuntimeError("Data directory must be empty or marked as a release fixture")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        previous = json.loads(marker.read_text()) if marker.exists() else {}
        if previous and previous.get("native") != args.native:
            raise RuntimeError("Use a fresh directory when changing native/test signing mode")
        self.prefix = previous.get("prefix", "opaque-release-" + hashlib.sha256(str(self.directory).encode()).hexdigest()[:12])
        dump(marker, {"prefix": self.prefix, "native": args.native, "simulation": True})
        self.fixture_dir = self.directory / "fixture"
        self.signer_dir = self.directory / "approver"
        self.bin_dir = self.directory / "bin"
        self.input_dir = self.directory / "input"
        for directory in (self.fixture_dir, self.signer_dir, self.bin_dir, self.input_dir):
            directory.mkdir(exist_ok=True, mode=0o700)
        # Only these public fixture inputs are mounted inside an unprivileged
        # provider/client container. Approver custody is never mounted there.
        for directory in (self.fixture_dir, self.bin_dir, self.input_dir):
            directory.chmod(0o755)
        self.clean_env = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR") if key in os.environ}
        self.signer = None
        self.logs = []
        self.container_names = []
        self.task_id = None
        self.workstation_port = args.approval_port
        self.openssl = shutil.which("openssl")
        if not self.openssl:
            raise RuntimeError("OpenSSL with Ed25519 support is required for a disposable signer")
        port_available(args.port)
        port_available(args.approval_port)
        self.control()
        (self.directory / "cleanup.txt").write_text(shlex.join(["docker", "volume", "rm", self.prefix + "-state", self.prefix + "-socket"]) + "\n")

    def docker(self, *args, **kwargs):
        return execute(["docker", *map(str, args)], **kwargs)

    def control(self, *, observation="pending", fault=False, legacy=False):
        # Atomic replacement keeps the fixture's concurrent GETs consistent.
        path = self.fixture_dir / "control.next"
        dump(path, {"observation": observation, "fault": fault, "legacy": legacy})
        path.chmod(0o644)
        path.replace(self.fixture_dir / "control.json")

    def count_dispatches(self):
        path = self.fixture_dir / "dispatches.jsonl"
        return len(path.read_text().splitlines()) if path.exists() else 0

    def build(self):
        self.docker("version", "--format", "{{.Server.Version}}")
        for image in (RUST_IMAGE, RUNTIME_IMAGE, self.args.python_image):
            self.docker("image", "inspect", image)
        if not self.args.no_build:
            print("Building Linux broker/client/dashboard/MCP in the pinned Rust container…", flush=True)
            command = ["docker", "run", "--rm", "-v", f"{ROOT}:/work:ro", "-v", "opaque-linux-target:/ctarget", "-v", "opaque-linux-cargo-registry:/usr/local/cargo/registry", "-v", "opaque-linux-rustup:/usr/local/rustup", "-e", "CARGO_TARGET_DIR=/ctarget", "-e", "CARGO_INCREMENTAL=0", "-w", "/work", RUST_IMAGE, "cargo", "build", "--locked", "-p", "opaqued", "-p", "opaque", "-p", "opaque-web", "-p", "opaque-mcp"]
            subprocess.run(command, check=True, cwd=ROOT)
        self.docker("run", "--rm", "-v", "opaque-linux-target:/ctarget:ro", "-v", f"{self.bin_dir}:/out", RUNTIME_IMAGE, "sh", "-c", "cp /ctarget/debug/opaqued /ctarget/debug/opaque /ctarget/debug/opaque-web /ctarget/debug/opaque-mcp /out/ && chmod 755 /out/*")
        if self.args.native and not all((ROOT / "target/debug" / name).exists()
                                        for name in ("opaque-approver", "opaque-approve-helper")):
            raise RuntimeError("Build native opaque-approver and opaque-approve-helper first")

    def prepare(self):
        workflow_path = ROOT / "examples/staging-release/opaque-staging-release.workflow.yml"
        if not workflow_path.exists():
            raise RuntimeError(f"Reviewed workflow contract missing: {workflow_path}")
        workflow = workflow_path.read_bytes()
        (self.fixture_dir / "workflow.yml").write_bytes(workflow)
        (self.fixture_dir / "workflow.yml").chmod(0o644)
        workflow_sha = hashlib.sha256(workflow).hexdigest()
        if self.args.native:
            key_path = self.signer_dir / "public-key.txt"
            if not key_path.exists():
                result = execute([str(ROOT / "target/debug/opaque-approver"), "init", "--state-dir", str(self.signer_dir), "--name", "Release dogfood workstation"], env=self.clean_env)
                (self.directory / "approver-init.txt").write_text(result.stdout)
                public = json.loads(result.stdout).get("public_key_hex", "")
                if not re.fullmatch("[0-9a-f]{64}", public):
                    raise RuntimeError("Native approver init did not return a public key")
                key_path.write_text(public + "\n")
            public_key = key_path.read_text().strip()
        else:
            key = self.signer_dir / "test-key.pem"
            if not key.exists():
                execute([self.openssl, "genpkey", "-algorithm", "Ed25519", "-out", str(key)], env=self.clean_env)
                key.chmod(0o600)
            public = execute([self.openssl, "pkey", "-in", str(key), "-pubout", "-outform", "DER"], text=False, env=self.clean_env).stdout
            if len(public) != 44 or public[:12].hex() != "302a300506032b6570032100":
                raise RuntimeError("Unexpected Ed25519 public key encoding")
            public_key = public[-32:].hex()
            (self.signer_dir / "public-key.txt").write_text(public_key + "\n")
        config = f'''# DISPOSABLE RELEASE FIXTURE. No production credentials.
data_dir = "{BROKER_STATE}"
enable_task_grants = true
require_seal = true
enforce_agent_sessions = false
approval_backend = "native"
workstation_test_mode = {str(not self.args.native).lower()}
workstation_approvers = [{{ public_key_hex = "{public_key}", name = "{'Native workstation' if self.args.native else 'TEST SIGNER - no human consent'}" }}]
[trust_domain]
enforce = true
socket_group = "7999"
socket_path = "{SOCKET}"
[approval]
server_bind = "0.0.0.0:{APPROVAL_PORT}"
timeout_secs = 180
'''
        for operation in ("github.release_manifest", "github.dispatch_staging_workflow"):
            config += f'''
[[rules]]
name = "disposable-{operation}"
operation_pattern = "{operation}"
allow = true
client_types = ["agent", "human"]
[rules.approval]
require = "always"
factors = ["paired_workstation"]
lease_ttl = 0
'''
        config += '''
[[rules]]
name = "disposable-release-observation"
operation_pattern = "github.observe_staging_workflow"
allow = true
client_types = ["agent", "human"]
[rules.approval]
require = "never"
factors = []
lease_ttl = 0
'''
        (self.input_dir / "config.toml").write_text(config)
        (self.input_dir / "config.toml").chmod(0o644)
        action = {"operation": "github.dispatch_staging_workflow", "repo": REPO, "workflow_path": WORKFLOW_PATH, "workflow_ref": BRANCH, "image_repository": IMAGE_REPOSITORY, "image_digest": IMAGE_DIGEST, "environment": "staging"}
        dump(self.input_dir / "manifest.json", {"schema_version": 2, "title": "Opaque staging: one reviewed immutable artifact", "expires_in_secs": 3600, "actions": [action]})
        (self.input_dir / "manifest.json").chmod(0o644)
        self.provider_env = {
            "OPAQUE_CONFIG": BROKER_STATE + "/config.toml", "OPAQUE_DOGFOOD_LOOPBACK": "1", "OPAQUE_GITHUB_API_URL": f"http://127.0.0.1:{PROVIDER_PORT}",
            "OPAQUE_GITHUB_TOKEN_REF": "env:OPAQUE_RELEASE_FIXTURE_TOKEN", "OPAQUE_RELEASE_FIXTURE_TOKEN": TOKEN,
            "OPAQUE_STAGING_REPO": REPO, "OPAQUE_STAGING_WORKFLOW_PATH": WORKFLOW_PATH, "OPAQUE_STAGING_WORKFLOW_SHA256": workflow_sha,
            "OPAQUE_STAGING_IMAGE_REPOSITORY": IMAGE_REPOSITORY, "OPAQUE_STAGING_REF": BRANCH, "RUST_LOG": "info",
        }

    def bootstrap(self):
        for name in ("state", "socket"):
            self.docker("volume", "create", self.prefix + "-" + name)
        script = '''set -eu
install -d -o 7381 -g 7381 -m 0700 /var/lib/opaque
install -d -o 7381 -g 7999 -m 0750 /run/opaque
install -o 7381 -g 7381 -m 0600 /input/config.toml /var/lib/opaque/config.toml
setpriv --reuid=7381 --regid=7381 --clear-groups /opt/opaque/opaque setup --seal
'''
        self.docker("run", "--rm", "--network", "none", "-v", self.prefix + "-state:" + BROKER_STATE, "-v", self.prefix + "-socket:/run/opaque", "-v", f"{self.bin_dir}:/opt/opaque:ro", "-v", f"{self.input_dir}:/input:ro", "-e", "OPAQUE_CONFIG=" + BROKER_STATE + "/config.toml", RUNTIME_IMAGE, "sh", "-c", script)

    def run_container(self, name, options, image, command):
        full_name = self.prefix + "-" + name
        self.docker("run", "-d", "--name", full_name, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", *options, image, *command)
        self.container_names.append(full_name)
        return full_name

    def start(self):
        self.fixture_name = self.run_container("fixture", ["--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "-p", f"127.0.0.1:{self.workstation_port}:{APPROVAL_PORT}", "-p", f"127.0.0.1:{self.args.port}:{self.args.port + 1}", "-v", f"{self.fixture_dir}:/fixture", "-v", f"{Path(__file__).resolve()}:/release_dogfood.py:ro", "--entrypoint", "python3"], self.args.python_image, ["/release_dogfood.py", "_fixture", "--directory", "/fixture", "--web-port", str(self.args.port), "--relay-port", str(self.args.port + 1)])
        options = ["--user", "7381:7381", "--group-add", "7999", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "--network", "container:" + self.fixture_name, "-v", self.prefix + "-state:" + BROKER_STATE, "-v", self.prefix + "-socket:/run/opaque", "-v", f"{self.bin_dir}:/opt/opaque:ro"]
        for key, value in self.provider_env.items():
            options.extend(["-e", key + "=" + value])
        self.broker_name = self.run_container("broker", options, RUNTIME_IMAGE, ["/opt/opaque/opaqued"])
        self.agent_name = self.run_container("agent", ["--user", "7382:7382", "--group-add", "7999", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "--network", "container:" + self.fixture_name, "-v", self.prefix + "-socket:/run/opaque", "-v", f"{self.bin_dir}:/opt/opaque:ro", "-v", f"{self.input_dir / 'manifest.json'}:/input/manifest.json:ro", "-e", "OPAQUE_SOCK=" + SOCKET, "-w", "/tmp"], RUNTIME_IMAGE, ["sleep", "infinity"])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = self.docker("exec", self.agent_name, "/opt/opaque/opaque", "--socket", SOCKET, "--json", "ping", check=False)
            if result.returncode == 0:
                break
            if self.docker("inspect", self.broker_name, "--format", "{{.State.Running}}").stdout.strip() != "true":
                raise RuntimeError("Broker exited:\n" + self.docker("logs", self.broker_name).stdout[-5000:])
            time.sleep(0.25)
        else:
            raise RuntimeError("Isolated broker did not become ready")
        self.docker("exec", "-d", self.agent_name, "/opt/opaque/opaque-web", "--data-dir", "/tmp/web", "--socket", SOCKET, "--port", str(self.args.port))
        certificate = self.docker("exec", self.broker_name, "cat", BROKER_STATE + "/approval_server.cert", text=False).stdout
        self.fingerprint = hashlib.sha256(certificate).hexdigest()
        (self.directory / "broker-tls-fingerprint.txt").write_text(self.fingerprint + "\n")
        # Fetch only public enrollment metadata after checking the operator-pinned
        # certificate. No broker private key or provider token leaves custody.
        probe = TestSigner(self.signer_dir, self.workstation_port, self.fingerprint, self.openssl)
        challenge = probe.request("/workstation/enrollment/challenge", {"public_key_hex": probe.public_key}, authenticated=False)
        self.broker_id = challenge["broker_id"]
        (self.directory / "broker-id.txt").write_text(self.broker_id + "\n")
        if self.args.native:
            execute([str(ROOT / "target/debug/opaque-approver"), "enroll", "--state-dir", str(self.signer_dir), "--broker", f"https://127.0.0.1:{self.workstation_port}", "--broker-id", self.broker_id, "--tls-fingerprint", self.fingerprint], env=self.clean_env)
        else:
            log = (self.signer_dir / "test-signer.log").open("a")
            self.logs.append(log)
            self.signer = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_signer", "--directory", str(self.signer_dir), "--port", str(self.workstation_port), "--fingerprint", self.fingerprint, "--openssl", self.openssl], cwd=self.signer_dir, env=self.clean_env, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 15
            while not (self.signer_dir / "test-enrollment.json").exists():
                self.ensure_signer()
                if time.monotonic() > deadline:
                    raise RuntimeError("Test signer enrollment timed out")
                time.sleep(0.1)

    def ensure_signer(self):
        if self.signer and self.signer.poll() is not None:
            raise RuntimeError("Test signer failed:\n" + (self.signer_dir / "test-signer.log").read_text()[-4000:])

    def cli(self, *args, allow_error=False):
        result = self.docker("exec", self.agent_name, "/opt/opaque/opaque", "--socket", SOCKET, "--json", *map(str, args), check=False, timeout=220)
        self.ensure_signer()
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError("CLI returned no JSON:\n" + result.stderr[-3000:]) from None
        if not allow_error and (result.returncode or payload.get("error")):
            raise RuntimeError("CLI request failed: " + json.dumps(payload))
        return payload, result.returncode

    def task(self, *args, **kwargs):
        payload, status = self.cli("task", *args, **kwargs)
        return public_task(payload), status

    def assert_custody(self):
        script = '''set -eu
[ "$(id -u)" = 7382 ]
[ ! -e /var/lib/opaque ]
[ ! -e /approver ]
[ ! -e /var/run/docker.sock ]
[ "$(stat -c '%a %u %g' /run/opaque)" = '750 7381 7999' ]
[ "$(stat -c '%a %u %g' /run/opaque/opaqued.sock)" = '660 7381 7999' ]
[ "$(stat -c '%a %u %g' /run/opaque/daemon.token)" = '640 7381 7999' ]
! env | grep -E 'OPAQUE_RELEASE_FIXTURE_TOKEN|OPAQUE_GITHUB|OPAQUE_STAGING|WORKSTATION'
'''
        self.docker("exec", self.agent_name, "sh", "-c", script)
        denied = self.docker("exec", self.broker_name, "/opt/opaque/opaque", "--socket", SOCKET, "--json", "ping", check=False)
        assert denied.returncode != 0, "Broker's own UID was allowed as a client"
        version, _ = self.cli("version")
        data = version.get("result", version)
        assert data["trust_domain_enforced"] is True
        assert data["workstation_test_mode"] is (not self.args.native)
        assert data["approval_backend"] == "native"
        dump(self.directory / "custody-evidence.json", {"broker_uid": 7381, "agent_uid": 7382, "socket_gid": 7999, "custody_not_mounted_in_agent": True, "signer_not_mounted_in_broker_or_agent": True, "broker_uid_client_denied": True, "version": data})

    def validate_receipt(self, task):
        assert re.fullmatch("[0-9a-f]{64}", task["manifest_digest"])
        assert task["manifest"]["schema_version"] == 2
        assert len(task["slots"]) == 1
        action = task["manifest"]["actions"][0]
        assert action == task["slots"][0]["action"]
        assert action["repo"] == REPO and action["repository_id"] == REPOSITORY_ID
        assert action["workflow_id"] == WORKFLOW_ID and action["workflow_path"] == WORKFLOW_PATH
        assert action["approved_commit_sha"] == COMMIT and action["image_digest"] == IMAGE_DIGEST
        assert action["image_repository"] == IMAGE_REPOSITORY and action["environment"] == "staging"
        assert action["github_token_ref"] == "env:OPAQUE_RELEASE_FIXTURE_TOKEN"
        assert action["workflow_sha256"] == hashlib.sha256((self.fixture_dir / "workflow.yml").read_bytes()).hexdigest()
        assert TOKEN not in json.dumps(task)
        if task["approved_at"] is not None:
            assert task["approval_mode"] == ("paired_workstation" if self.args.native else "insecure_test")

    def native_check(self):
        """Open real human review, then verify its bounded fixture effect."""
        if not self.args.native:
            raise RuntimeError("Native walkthrough requires native workstation mode")
        self.assert_custody()
        self.control(observation="succeeded")
        baseline = self.count_dispatches()
        planned, _ = self.task("plan", "--manifest", "/input/manifest.json")
        self.task_id = planned["id"]
        command = ["docker", "exec", self.agent_name, "/opt/opaque/opaque",
                   "--socket", SOCKET, "--json", "task", "run", self.task_id]
        approver = str(ROOT / "target/debug/opaque-approver")
        started = time.monotonic()
        print("NATIVE HUMAN REVIEW: one disposable provider dispatch. "
              "Review the full document and authenticate in the native window. "
              "No real GitHub operation or cluster change will occur.", flush=True)
        # File-backed output avoids pipe deadlocks while the operator reviews.
        with (self.directory / "native-task.json").open("w+") as output, \
             (self.directory / "native-task.stderr").open("w") as errors:
            process = subprocess.Popen(command, stdout=output, stderr=errors)
            try:
                deadline = time.monotonic() + 30
                while True:
                    pending = execute([approver, "list", "--state-dir", str(self.signer_dir)],
                                      env=self.clean_env)
                    approvals = json.loads(pending.stdout)
                    matches = [item for item in approvals
                               if item["operation"] == "github.release_manifest"]
                    if len(matches) == 1:
                        approval_id = matches[0]["approval_id"]
                        break
                    if len(matches) > 1:
                        raise RuntimeError("Multiple pending reviews; refusing to choose one")
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("Native approval did not become pending")
                    time.sleep(0.25)
                review = execute([approver, "review", "--state-dir", str(self.signer_dir),
                                  "--approval-id", approval_id],
                                 env=self.clean_env, timeout=200, check=False)
                (self.directory / "native-review.log").write_text(review.stdout + review.stderr)
                status = process.wait(timeout=30)
                output.seek(0)
                payload = json.load(output)
                completed = public_task(payload)
                if review.returncode or status or payload.get("error"):
                    dump(self.directory / "native-review-evidence.json", {
                        "passed": False, "task_id": self.task_id,
                        "dispatches": self.count_dispatches() - baseline,
                        "reason": "native_review_or_task_did_not_complete",
                    })
                    raise RuntimeError("Native review/task did not complete; inspect the retained "
                                       "native review log. No human-approval success is claimed.")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        self.validate_receipt(completed)
        validate_native_completion(completed, self.count_dispatches() - baseline)
        observed, _ = self.task("reconcile", self.task_id)
        self.validate_receipt(observed)
        if observed["release_observation"]["state"] != "succeeded":
            raise RuntimeError("Native-approved fixture workflow did not reconcile successfully")
        _, denied = self.task("run", self.task_id, allow_error=True)
        if not denied or self.count_dispatches() != baseline + 1:
            raise RuntimeError("Native-approved task replay was not bounded to one dispatch")
        self.docker("restart", self.broker_name)
        deadline = time.monotonic() + 20
        while True:
            try:
                self.cli("ping")
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Broker did not recover after native walkthrough restart")
                time.sleep(0.25)
        restored, _ = self.task("show", self.task_id)
        self.validate_receipt(restored)
        validate_native_completion(restored, self.count_dispatches() - baseline)
        if restored["slots"] != observed["slots"] or restored["release_observation"] != observed["release_observation"]:
            raise RuntimeError("Native approval receipt changed across broker restart")
        _, denied = self.task("run", self.task_id, allow_error=True)
        if not denied or self.count_dispatches() != baseline + 1:
            raise RuntimeError("Restart replenished native-approved dispatch authority")
        self.check_mcp(restored)
        self.check_web(restored)
        dump(self.directory / "native-approved-receipt.json", restored)
        dump(self.directory / "native-review-evidence.json", {
            "passed": True, "task_id": self.task_id, "approval_id": approval_id,
            "approval_mode": restored["approval_mode"], "dispatches": 1,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "replay_denied": True, "restart_preserved_receipt": True,
            "provider": "disposable_loopback_fixture", "live_github": False,
            "biometric_attestation": False,
        })
        print("NATIVE CHECK PASSED: paired-workstation human review; one fixture dispatch; "
              "reconciliation, replay denial, restart, MCP and dashboard verified.", flush=True)

    def check(self):
        if self.args.native:
            raise RuntimeError("--check uses a TEST SIGNER. Use --serve --native for human approval.")
        self.assert_custody()
        baseline = self.count_dispatches()
        self.control(legacy=True)
        task, _ = self.task("plan", "--manifest", "/input/manifest.json")
        self.validate_receipt(task)
        self.task_id = task["id"]
        completed, _ = self.task("run", self.task_id)
        self.validate_receipt(completed)
        assert completed["state"] == "completed" and completed["slots"][0]["state"] == "api_accepted"
        assert self.count_dispatches() == baseline + 1
        _, denied = self.task("run", self.task_id, allow_error=True)
        assert denied and self.count_dispatches() == baseline + 1
        observations = []
        for state in ("pending", "running", "failed", "succeeded", "rerun"):
            self.control(observation=state, legacy=True)
            receipt, exit_status = self.task("reconcile", self.task_id, allow_error=True)
            assert bool(exit_status) == (state in ("failed", "ambiguous", "rerun"))
            self.validate_receipt(receipt)
            expected = "ambiguous" if state == "rerun" else state
            assert receipt["release_observation"]["state"] == expected, receipt
            assert receipt["slots"] == completed["slots"], "Reconciliation changed dispatch authority"
            assert self.count_dispatches() == baseline + 1, "Read-only reconciliation dispatched work"
            observations.append(receipt["release_observation"])
        completed = receipt
        assert completed["release_observation"]["code"] == "external_rerun_observed"
        self.control(observation="succeeded")
        sticky, sticky_status = self.task("reconcile", self.task_id, allow_error=True)
        assert sticky_status and sticky["release_observation"] == completed["release_observation"], "Ambiguous evidence was erased"
        dump(self.directory / "legacy-rerun-receipt.json", completed)
        self.control(observation="succeeded", fault=True)
        unknown, _ = self.task("plan", "--manifest", "/input/manifest.json")
        unknown, status = self.task("run", unknown["id"], allow_error=True)
        self.validate_receipt(unknown)
        assert status and unknown["slots"][0]["state"] == "unknown"
        assert self.count_dispatches() == baseline + 2
        unknown, _ = self.task("reconcile", unknown["id"])
        assert unknown["release_observation"]["state"] == "succeeded"
        assert unknown["slots"][0]["state"] == "unknown", "Workflow evidence erased uncertain dispatch receipt"
        _, denied = self.task("run", unknown["id"], allow_error=True)
        assert denied and self.count_dispatches() == baseline + 2
        dump(self.directory / "unknown-dispatch-receipt.json", unknown)
        self.docker("restart", self.broker_name)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                self.cli("ping")
                break
            except RuntimeError:
                time.sleep(0.25)
        for saved in (completed, unknown):
            restored, _ = self.task("show", saved["id"])
            self.validate_receipt(restored)
            assert restored["slots"] == saved["slots"]
            assert restored["release_observation"] == saved["release_observation"]
            _, denied = self.task("run", saved["id"], allow_error=True)
            assert denied
        assert self.count_dispatches() == baseline + 2
        self.control(observation="running")
        direct, _ = self.task("plan", "--manifest", "/input/manifest.json")
        direct, _ = self.task("run", direct["id"])
        assert direct["slots"][0]["outcome"]["provider_run_id"] > 0
        direct, _ = self.task("reconcile", direct["id"])
        assert direct["release_observation"]["state"] == "running"
        assert direct["release_observation"]["correlation"] == "dispatch_response"
        self.control(observation="succeeded")
        direct, _ = self.task("reconcile", direct["id"])
        assert direct["release_observation"]["state"] == "succeeded"
        assert self.count_dispatches() == baseline + 3
        dump(self.directory / "direct-run-receipt.json", direct)
        self.control(observation="ambiguous", legacy=True)
        duplicate, _ = self.task("plan", "--manifest", "/input/manifest.json")
        duplicate, _ = self.task("run", duplicate["id"])
        duplicate, duplicate_status = self.task("reconcile", duplicate["id"], allow_error=True)
        assert duplicate_status and duplicate["release_observation"]["code"] == "run_correlation_ambiguous"
        observations.append(duplicate["release_observation"])
        dump(self.directory / "ambiguous-receipt.json", duplicate)
        dump(self.directory / "observation-evidence.json", observations)
        self.control(observation="succeeded")
        assert self.count_dispatches() == baseline + 4
        self.check_mcp(direct)
        self.check_web(direct)
        print("CHECK PASSED: enforced container custody; pinned TLS enrollment; signed TEST APPROVAL; four bounded tasks; direct run ID and legacy correlation; six workflow observations; replay denial; unknown dispatch; restart and MCP reconciliation.", flush=True)

    def check_mcp(self, completed):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "release-dogfood", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "opaque_task_reconcile", "arguments": {"task_id": completed["id"]}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "opaque_task_run", "arguments": {"task_id": completed["id"]}}},
        ]
        before = self.count_dispatches()
        result = self.docker("exec", "-i", self.agent_name, "/opt/opaque/opaque-mcp", input="\n".join(json.dumps(message) for message in messages) + "\n")
        replies = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        by_id = {reply["id"]: reply for reply in replies if "id" in reply}
        assert "opaque_task_reconcile" in {tool["name"] for tool in by_id[2]["result"]["tools"]}
        assert not by_id[3]["result"].get("isError", False), by_id[3]
        assert by_id[4]["result"]["isError"] is True
        assert self.count_dispatches() == before
        assert TOKEN not in result.stdout
        dump(self.directory / "mcp-evidence.json", replies)

    def check_web(self, completed):
        token = self.docker("exec", self.agent_name, "cat", "/tmp/web/web.token").stdout.strip()
        def request(path, *, authenticated=True, origin=None, method="GET"):
            connection = http.client.HTTPConnection("127.0.0.1", self.args.port, timeout=50)
            headers = {"Authorization": "Bearer " + token} if authenticated else {}
            if origin:
                headers["Origin"] = origin
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            status = response.status
            raw = response.read()
            connection.close()
            return status, json.loads(raw) if raw.startswith(b"{") else None
        status, health = request("/api/status")
        assert status == 200 and health["mode"] == "live"
        assert health["trust_domain_enforced"] is True
        assert health["workstation_test_mode"] is (not self.args.native)
        status, tasks = request("/api/tasks")
        assert status == 200 and completed["id"] in {task["id"] for task in tasks["tasks"]}
        before = self.count_dispatches()
        endpoint = "/api/tasks/" + completed["id"] + "/reconcile"
        assert request(endpoint, authenticated=False, method="POST")[0] == 401
        assert request(endpoint, origin="https://untrusted.example", method="POST")[0] == 403
        status, receipt = request(endpoint, method="POST")
        assert status == 200 and receipt["task"]["release_observation"]["state"] == "succeeded"
        assert receipt["task"]["slots"] == completed["slots"]
        assert self.count_dispatches() == before
        dump(self.directory / "dashboard-evidence.json", {"status": health, "task_id": completed["id"], "reconcile_authenticated": True, "cross_origin_rejected": True, "no_extra_dispatch": True})

    def serve(self):
        self.control(observation="succeeded")
        planned, _ = self.task("plan", "--manifest", "/input/manifest.json")
        self.task_id = planned["id"]
        mode = "NATIVE WORKSTATION REVIEW" if self.args.native else "TEST SIGNER — NO HUMAN CONSENT"
        print(f"\n{mode}\nDisposable loopback providers. No real GitHub or cluster changes.\nDashboard: http://127.0.0.1:{self.args.port}\nState: {self.directory}\nBroker container: {self.broker_name}\nAgent container: {self.agent_name}\nBroker socket inside agent: {SOCKET}\nPlanned task: {self.task_id}", flush=True)
        print("Run task: " + shlex.join(["docker", "exec", self.agent_name, "/opt/opaque/opaque", "--socket", SOCKET, "task", "run", self.task_id]), flush=True)
        print("MCP: " + shlex.join(["docker", "exec", "-i", self.agent_name, "/opt/opaque/opaque-mcp"]), flush=True)
        if self.args.native:
            print("Review pending approvals: " + shlex.join([str(ROOT / "target/debug/opaque-approver"), "list", "--state-dir", str(self.signer_dir)]), flush=True)
            print("Review one: opaque-approver review --state-dir " + shlex.quote(str(self.signer_dir)) + " --approval-id ID", flush=True)
        print("Ctrl-C stops these fixture containers; state volumes are retained. Cleanup command is saved in cleanup.txt.", flush=True)
        while True:
            self.ensure_signer()
            time.sleep(1)

    def close(self):
        if self.signer and self.signer.poll() is None:
            self.signer.terminate()
            self.signer.wait(timeout=5)
        for name in reversed(self.container_names):
            log = self.docker("logs", name, check=False)
            (self.directory / (name.rsplit("-", 1)[-1] + ".log")).write_text(log.stdout + log.stderr)
            self.docker("rm", "-f", name, check=False)
        for log in self.logs:
            log.close()
        cleanup = ["docker", "volume", "rm", self.prefix + "-state", self.prefix + "-socket"]
        (self.directory / "cleanup.txt").write_text(shlex.join(cleanup) + "\n")


def validate_native_completion(task, dispatches):
    """Test approval or a nominal CLI success cannot satisfy the human gate."""
    if task.get("approval_mode") != "paired_workstation" or task.get("approved_at") is None:
        raise RuntimeError("Receipt lacks a completed native workstation approval")
    slots = task.get("slots", [])
    if task.get("state") != "completed" or len(slots) != 1 or slots[0].get("state") != "api_accepted":
        raise RuntimeError("Native-approved task did not record exactly one accepted slot")
    if dispatches != 1:
        raise RuntimeError("Expected exactly one native-approved fixture dispatch")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("_fixture", "_signer"):
        mode = sys.argv[1]
        parser = argparse.ArgumentParser()
        parser.add_argument("--directory", required=True)
        if mode == "_fixture":
            parser.add_argument("--web-port", type=int, required=True)
            parser.add_argument("--relay-port", type=int, required=True)
            fixture_main(parser.parse_args(sys.argv[2:]))
        else:
            parser.add_argument("--port", type=int, required=True)
            parser.add_argument("--fingerprint", required=True)
            parser.add_argument("--openssl", required=True)
            signer_main(parser.parse_args(sys.argv[2:]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Run the disposable automated signed-protocol check (default)")
    mode.add_argument("--serve", action="store_true", help="Keep isolated broker, agent, providers, and dashboard running")
    mode.add_argument("--native-check", action="store_true", help="Open human native review, verify one fixture dispatch and replay/restart, then clean up")
    parser.add_argument("--native", action="store_true", help="Use the native host workstation reviewer with --serve (implied by --native-check)")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--port", type=int, default=19393)
    parser.add_argument("--approval-port", type=int, default=19443)
    parser.add_argument("--no-build", action="store_true", help="Copy existing Linux binaries from opaque-linux-target")
    parser.add_argument("--python-image", default=PYTHON_IMAGE)
    args = parser.parse_args()
    if args.native_check:
        args.native = True
    if not 1 <= args.port < 65535 or not 1 <= args.approval_port <= 65535 or args.port == args.approval_port or {args.port, args.port + 1} & {PROVIDER_PORT, APPROVAL_PORT}:
        parser.error("Choose distinct valid dashboard/approval ports outside internal fixture ports 18901/18902")
    if args.native and not (args.serve or args.native_check):
        parser.error("--native requires --serve or --native-check; automated --check records TEST APPROVAL")
    environment = None
    try:
        environment = ReleaseDogfood(args)
        print("Isolated release fixture: " + str(environment.directory), flush=True)
        environment.build()
        environment.prepare()
        environment.bootstrap()
        environment.start()
        if args.native_check:
            environment.native_check()
        elif args.serve:
            environment.assert_custody()
            environment.serve()
        else:
            environment.check()
    except KeyboardInterrupt:
        pass
    except (RuntimeError, subprocess.SubprocessError, OSError, AssertionError) as error:
        print("RELEASE DOGFOOD FAILED: " + str(error), file=sys.stderr)
        return 1
    finally:
        if environment:
            environment.close()
            print("Retained fixture evidence: " + str(environment.directory), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
