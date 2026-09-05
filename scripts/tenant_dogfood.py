#!/usr/bin/env python3
"""Two disposable tenant brokers, real OIDC/delegation, and bounded inference.

Docker containers share a kernel. The issuer/model/signer are explicit fixtures,
not human consent, a private data source, GPU inference, or microVM attestation.
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
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import release_dogfood as shared

ROOT = shared.ROOT
SOCKET = shared.SOCKET
STATE = shared.BROKER_STATE
MODEL_PORT = 18911
IDP_PORT = 18912
APPROVAL_PORT = 18913
CANARY_PORT = 18914
CANARY_BODY = b"opaque-disposable-network-canary-v1\n"
TEMPLATE = "opaque-fixture-template-v1"
BUILD = "opaque-fixture-v1"
SOURCE_ID = "opaque-public-receipts-v1"
HUMAN_EXE = "/usr/local/bin/python3.12"
PROMPT_IDS = ["receipt_summary", "uncertainty_check", "next_safe_step"]


def sha(value):
    return hashlib.sha256(value).hexdigest()


def dump(path, value, mode=0o600):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".next")
    temporary.write_text(json.dumps(value, separators=(",", ":")) + "\n")
    temporary.chmod(mode)
    temporary.replace(path)


def rpc(message):
    """Actual framed daemon protocol, running with the selected client's UID."""
    def read_exact(connection, length):
        data = b""
        while len(data) < length:
            chunk = connection.recv(length - len(data))
            if not chunk:
                raise ConnectionError("broker closed the connection")
            data += chunk
        return data
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(210)
            connection.connect(SOCKET)
            handshake = {"handshake": "v1", "daemon_token": message.get("daemon_token") or Path("/run/opaque/daemon.token").read_text().strip()}
            if message.get("session_token"):
                handshake["session_token"] = message["session_token"]
            for frame in [handshake, {"id": 1, "method": message["method"], "params": message.get("params", {})}]:
                raw = json.dumps(frame).encode()
                connection.sendall(struct.pack(">I", len(raw)) + raw)
            length = struct.unpack(">I", read_exact(connection, 4))[0]
            if length > 1024 * 1024:
                raise ValueError("oversized daemon response")
            return json.loads(read_exact(connection, length))
    except (OSError, ValueError, ConnectionError) as error:
        return {"error": {"code": "transport_denied", "message": type(error).__name__}}


class LoopbackRelay(socketserver.ThreadingTCPServer):
    """Host UI transport through Docker stdio; tenant networks stay internal.

    Approval TLS passes through untouched and is pinned by the signer. This
    relay never receives a Docker socket inside a container.
    """
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port, container, destination):
        self.container, self.destination = container, destination
        super().__init__(("127.0.0.1", port), RelayConnection)


class RelayConnection(socketserver.BaseRequestHandler):
    def handle(self):
        process = subprocess.Popen(["docker", "exec", "-i", self.server.container, "python3", "/scripts/tenant_dogfood.py", "_tunnel", str(self.server.destination)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.request.settimeout(60)
        def incoming():
            try:
                while chunk := self.request.recv(65536):
                    process.stdin.write(chunk)
                    process.stdin.flush()
            except (OSError, ValueError):
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        threading.Thread(target=incoming, daemon=True).start()
        try:
            while chunk := process.stdout.read1(65536):
                self.request.sendall(chunk)
        except OSError:
            pass
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, directory, port):
        self.directory = Path(directory)
        self.profile = json.loads((self.directory / "profile.json").read_text())
        self.prompts = json.loads((self.directory / "prompts.json").read_text())
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", port), FixtureHandler)


class NetworkCanaryHandler(BaseHTTPRequestHandler):
    """Public reachability control with no model, identity or data capability."""
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(CANARY_BODY)))
        self.end_headers()
        self.wfile.write(CANARY_BODY)


class FixtureHandler(BaseHTTPRequestHandler):
    server: FixtureServer

    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        profile = self.server.profile
        path = urlparse(self.path).path
        issuer = f"http://127.0.0.1:{IDP_PORT}"
        responses = {
            "/health": {"status": "ok"},
            "/props": {"model_path": profile["model_path"], "build_info": BUILD, "chat_template": TEMPLATE, "total_slots": 1, "default_generation_settings": {"n_ctx": 2048}},
            "/v1/models": {"data": [{"id": profile["model_id"]}]},
            "/.well-known/openid-configuration": {"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"},
        }
        if path == "/jwks":
            return self.reply(200, json.loads((self.server.directory / "jwks.json").read_text()))
        return self.reply(200, responses[path]) if path in responses else self.reply(404, {"error": "unknown_fixture_route"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 32768:
            return self.reply(413, {"error": "bounded_body_required"})
        raw = self.rfile.read(length)
        path = urlparse(self.path).path
        if path == "/token":
            body = parse_qs(raw.decode())
            control = json.loads((self.server.directory / "login.json").read_text())
            verifier = body.get("code_verifier", [""])[0]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            if any(body.get(key) != [value] for key, value in {"grant_type": "authorization_code", "code": control["code"], "redirect_uri": control["redirect_uri"], "client_id": control["client_id"]}.items()) or challenge != control["code_challenge"]:
                return self.reply(400, {"error": "invalid_fixture_code_or_pkce"})
            return self.reply(200, {"access_token": "unused-fixture-access-token", "token_type": "Bearer", "id_token": control["id_token"]})
        try:
            body = json.loads(raw)
            if path == "/apply-template":
                messages = body["messages"]
                if set(body) != {"messages"} or len(messages) != 1 or set(messages[0]) != {"role", "content"} or messages[0]["role"] != "user":
                    raise ValueError("template shape")
                ordinal = self.server.prompts.index(messages[0]["content"]) + 1
                return self.reply(200, {"prompt": f"fixture:{ordinal}:" + messages[0]["content"]})
            if path == "/tokenize":
                ordinal = int(body["content"].split(":", 2)[1])
                if ordinal not in [1, 2, 3]:
                    raise ValueError("tokenizer ordinal")
                expected = {"content": f"fixture:{ordinal}:" + self.server.prompts[ordinal - 1], "add_special": False, "parse_special": True, "with_pieces": False}
                if body != expected:
                    raise ValueError("tokenizer shape")
                return self.reply(200, {"tokens": [ordinal, 11, 12]})
            if path != "/completion":
                return self.reply(404, {"error": "unknown_fixture_route"})
            ordinal = body["prompt"][0]
            expected = {"model": self.server.profile["model_id"], "prompt": [ordinal, 11, 12], "n_predict": 96, "n_cmpl": 1, "temperature": 0.0, "seed": 0, "samplers": ["temperature"], "cache_prompt": False, "stream": False, "return_tokens": True, "ignore_eos": False, "n_probs": 0, "n_cache_reuse": 0, "stop": [], "lora": []}
            if ordinal not in [1, 2, 3] or body != expected:
                raise ValueError("fixed completion contract")
        except (ValueError, KeyError, TypeError, IndexError):
            return self.reply(400, {"error": "invalid_fixed_fixture_request"})
        with self.server.lock:
            control = json.loads((self.server.directory / "control.json").read_text())
            status = 500 if control.get("fault") else 200
            with (self.server.directory / "completions.jsonl").open("a") as output:
                output.write(json.dumps({"ordinal": ordinal, "status": status, "tenant": self.server.profile["tenant_id"], "body": body}) + "\n")
        if status != 200:
            return self.reply(status, {"error": "uncertain_fixture_outcome"})
        output = f"Synthetic {self.server.profile['tenant_id']} result {ordinal}. Workflow evidence does not prove service health."
        return self.reply(200, {"content": output, "model": self.server.profile["model_id"], "stop": True, "truncated": False, "stop_type": "eos", "tokens_evaluated": 3, "tokens_predicted": 8, "tokens": list(range(8)), "generation_settings": {"n_predict": 96}})


class TenantSigner(shared.TestSigner):
    def approve_pending(self):
        tenant = (self.directory / "tenant.txt").read_text().strip()
        for challenge in self.request("/workstation/approvals/pending").get("approvals", []):
            approval_id = challenge["approval_id"]
            if approval_id in self.seen:
                continue
            review = self.request("/workstation/approvals/" + approval_id)
            if review["challenge"] != challenge or sha(review["review_text"].encode()) != challenge["content_hash"]:
                raise RuntimeError("Approval review changed")
            self.validate_challenge(challenge)
            operation = challenge["operation"]
            if operation not in ("inference.fixed_manifest", "agent_session_start"):
                raise RuntimeError("Test signer refuses unrelated operation")
            if operation == "inference.fixed_manifest" and tenant not in review["review_text"]:
                raise RuntimeError("Inference review lacks tenant binding")
            fields = ["opaque.workstation-decision.v1", self.broker_id, approval_id, challenge["request_id"], operation, challenge["content_hash"], challenge["nonce"], struct.pack("<q", challenge["created_at"]), struct.pack("<q", challenge["expires_at"]), "approve"]
            self.request("/workstation/approvals/" + approval_id + "/respond", {"device_id": self.identity["device_id"], "decision": "approve", "signature": self.sign(shared.signed_fields(fields))})
            self.seen.add(approval_id)
            with (self.directory / "test-approvals.jsonl").open("a") as output:
                output.write(json.dumps({"approval_id": approval_id, "operation": operation, "mode": "insecure_test"}) + "\n")


class Tenant(shared.ReleaseDogfood):
    def __init__(self, args, directory, index):
        self.args = args
        self.directory = directory / f"tenant-{index}"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.tenant_id = f"synthetic-{'a' if index == 0 else 'b'}"
        self.prefix = "opaque-tenant-" + sha(str(self.directory).encode())[:12]
        self.port = args.port + index * 2
        self.workstation_port = args.approval_port + index
        self.broker_uid, self.agent_uid, self.socket_gid = 7481 + index * 10, 7482 + index * 10, 7981 + index
        self.fixture_dir, self.signer_dir, self.input_dir = [self.directory / name for name in ["fixture", "approver", "input"]]
        self.bin_dir = directory / "bin"
        for path in [self.fixture_dir, self.signer_dir, self.input_dir, self.bin_dir]:
            path.mkdir(mode=0o700, exist_ok=True)
        for path in [self.fixture_dir, self.input_dir, self.bin_dir]:
            path.chmod(0o755)
        self.clean_env = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR") if key in os.environ}
        self.clean_env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.openssl = shutil.which("openssl")
        if not self.openssl:
            raise RuntimeError("OpenSSL is required for disposable signed fixtures")
        self.logs, self.container_names, self.networks = [], [], []
        self.relays = []
        self.signer = None
        self.session = None
        self.task_id = None
        self.ptrace = False
        for port in [self.port, self.workstation_port]:
            shared.port_available(port)

    def control(self, fault=False):
        dump(self.fixture_dir / "control.json", {"fault": fault}, 0o644)

    def build(self):
        self.docker("version", "--format", "{{.Server.Version}}")
        for image in [shared.RUST_IMAGE, shared.RUNTIME_IMAGE, self.args.python_image]:
            self.docker("image", "inspect", image)
        if not self.args.no_build:
            print("Building Linux tenant binaries with incremental cache disabled…", flush=True)
            command = ["docker", "run", "--rm", "-v", f"{ROOT}:/work:ro", "-v", "opaque-linux-target:/ctarget", "-v", "opaque-linux-cargo-registry:/usr/local/cargo/registry", "-v", "opaque-linux-rustup:/usr/local/rustup", "-e", "CARGO_TARGET_DIR=/ctarget", "-e", "CARGO_INCREMENTAL=0", "-w", "/work", shared.RUST_IMAGE, "cargo", "build", "--locked", "-p", "opaqued", "-p", "opaque", "-p", "opaque-web", "-p", "opaque-mcp"]
            subprocess.run(command, check=True, cwd=ROOT)
        original = self.args.no_build
        try:
            self.args.no_build = True
            super().build()
        finally:
            self.args.no_build = original
        digests = {}
        for name in ["opaqued", "opaque", "opaque-web", "opaque-mcp"]:
            with (self.bin_dir / name).open("rb") as binary:
                digests[name] = hashlib.file_digest(binary, "sha256").hexdigest()
        dump(self.directory.parent / "binary-digests.json", digests)

    def count_dispatches(self):
        path = self.fixture_dir / "completions.jsonl"
        return len(path.read_text().splitlines()) if path.exists() else 0

    def prepare(self):
        source = (ROOT / "crates/opaque-core/src/inference.rs").read_text()
        prompts = []
        for name in PROMPT_IDS:
            match = re.search(r'"' + name + r'"\s*=>\s*Some\(\s*("(?:[^"\\]|\\.)*")\s*,?\s*\)', source)
            if not match:
                raise RuntimeError("Cannot extract the compiled public fixture prompts")
            prompts.append(json.loads(match.group(1)))
        snapshot = sha(json.dumps(prompts, separators=(",", ":")).encode())
        profile = {"tenant_id": self.tenant_id, "model_id": self.tenant_id + "-fixture-model", "model_path": "/models/synthetic.gguf"}
        dump(self.fixture_dir / "profile.json", profile, 0o644)
        dump(self.fixture_dir / "prompts.json", prompts, 0o644)
        shutil.copyfile(ROOT / "crates/opaqued/tests/fixtures/test_idp_jwks.json", self.fixture_dir / "jwks.json")
        (self.fixture_dir / "jwks.json").chmod(0o644)
        self.control()
        key = self.signer_dir / "test-key.pem"
        if not key.exists():
            shared.execute([self.openssl, "genpkey", "-algorithm", "Ed25519", "-out", str(key)], env=self.clean_env)
            key.chmod(0o600)
        public = shared.execute([self.openssl, "pkey", "-in", str(key), "-pubout", "-outform", "DER"], env=self.clean_env, text=False).stdout
        if len(public) != 44 or public[:12].hex() != "302a300506032b6570032100":
            raise RuntimeError("Unexpected signer key encoding")
        (self.signer_dir / "public-key.txt").write_text(public[-32:].hex() + "\n")
        (self.signer_dir / "tenant.txt").write_text(self.tenant_id + "\n")
        config = f'''# DISPOSABLE TEST ISSUER, MODEL AND SIGNER. No private tenant data.
data_dir = "{STATE}"
enable_task_grants = true
require_seal = true
enforce_agent_sessions = true
approval_backend = "native"
workstation_test_mode = true
workstation_approvers = [{{public_key_hex = "{public[-32:].hex()}", name = "TEST SIGNER - no human consent"}}]
[[known_human_clients]]
name = "Disposable OIDC login driver"
exe_path = "{HUMAN_EXE}"
[tenant]
id = "{self.tenant_id}"
[trust_domain]
enforce = true
socket_group = "{self.socket_gid}"
socket_path = "{SOCKET}"
[approval]
server_bind = "0.0.0.0:{APPROVAL_PORT}"
timeout_secs = 180
session_factor = "paired_workstation"
[identity]
issuer = "http://127.0.0.1:{IDP_PORT}"
client_id = "opaque-{self.tenant_id}"
required = true
session_ttl_secs = 3600
allowed_email_domains = ["example.invalid"]
allowed_subjects = ["fixture-subject-{self.tenant_id}"]
[inference]
profile_id = "{self.tenant_id}-public-demo"
api_url = "http://127.0.0.1:{MODEL_PORT}"
model_id = "{profile['model_id']}"
model_path = "{profile['model_path']}"
model_artifact_sha256 = "{sha((self.tenant_id + '-disposable-model-artifact').encode())}"
chat_template_sha256 = "{sha(TEMPLATE.encode())}"
server_build = "{BUILD}"
service_uid = "00000000-0000-4000-8000-{self.broker_uid:012d}"
source_id = "{SOURCE_ID}"
source_snapshot_sha256 = "{snapshot}"
allow_loopback_http = true
'''
        for operation in ["inference.fixed_manifest", "inference.fixed_completion"]:
            config += f'''\n[[rules]]
name = "fixture-{operation}"
operation_pattern = "{operation}"
allow = true
client_types = ["agent", "human"]
[rules.approval]
require = "always"
factors = ["paired_workstation"]
lease_ttl = 0
[rules.identity]
require_principal = true
roles = ["operator"]
'''
            if operation == "inference.fixed_completion":
                config += f'''[rules.target]
fields = {{ tenant_id = "{self.tenant_id}", source_id = "{SOURCE_ID}", model_id = "{profile['model_id']}" }}
'''
        (self.input_dir / "config.toml").write_text(config)
        (self.input_dir / "config.toml").chmod(0o644)

    def bootstrap(self):
        for kind in ["state", "socket"]:
            self.docker("volume", "create", self.prefix + "-" + kind)
        script = f'''set -eu
install -d -o {self.broker_uid} -g {self.broker_uid} -m 0700 {STATE}
install -d -o {self.broker_uid} -g {self.socket_gid} -m 0750 /run/opaque
install -o {self.broker_uid} -g {self.broker_uid} -m 0600 /input/config.toml {STATE}/config.toml
setpriv --reuid={self.broker_uid} --regid={self.broker_uid} --clear-groups /opt/opaque/opaque setup --seal
'''
        self.docker("run", "--rm", "--network", "none", "-v", self.prefix + "-state:" + STATE, "-v", self.prefix + "-socket:/run/opaque", "-v", f"{self.bin_dir}:/opt/opaque:ro", "-v", f"{self.input_dir}:/input:ro", "-e", "OPAQUE_CONFIG=" + STATE + "/config.toml", shared.RUNTIME_IMAGE, "sh", "-c", script)

    def mounts(self):
        return ["-v", f"{Path(__file__).resolve()}:/scripts/tenant_dogfood.py:ro", "-v", f"{ROOT / 'scripts/release_dogfood.py'}:/scripts/release_dogfood.py:ro"]

    def start_broker(self):
        options = ["--user", "0:0" if self.ptrace else f"{self.broker_uid}:{self.broker_uid}", "--group-add", str(self.socket_gid), "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "--network", "container:" + self.fixture_name, "-v", self.prefix + "-state:" + STATE, "-v", self.prefix + "-socket:/run/opaque", "-v", f"{self.bin_dir}:/opt/opaque:ro", "-e", "OPAQUE_CONFIG=" + STATE + "/config.toml", "-e", "RUST_LOG=info"]
        command = ["/opt/opaque/opaqued"]
        if self.ptrace:
            for capability in ["SETUID", "SETGID", "SETPCAP", "SYS_PTRACE"]:
                options += ["--cap-add", capability]
            command = ["setpriv", f"--reuid={self.broker_uid}", f"--regid={self.broker_uid}", f"--groups={self.socket_gid}", "--bounding-set=-all,+sys_ptrace", "--inh-caps=+sys_ptrace", "--ambient-caps=+sys_ptrace", *command]
        self.broker_name = self.run_container("broker", options, shared.RUNTIME_IMAGE, command)
        self.human_name = self.run_container("human", ["--user", f"{self.agent_uid}:{self.agent_uid}", "--group-add", str(self.socket_gid), "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "--network", "none", "--pid", "container:" + self.broker_name, "-v", self.prefix + "-socket:/run/opaque", *self.mounts(), "--entrypoint", "sleep"], self.args.python_image, ["infinity"])

    def call(self, method, params=None, *, human=False, session=True, token=None, daemon_token=None, allow_error=False):
        message = {"method": method, "params": params or {}}
        if token is not None:
            message["session_token"] = token
        elif session and self.session and not human:
            message["session_token"] = self.session["session_token"]
        if daemon_token is not None:
            message["daemon_token"] = daemon_token
        result = self.docker("exec", "-i", self.human_name if human else self.agent_name, "python3", "/scripts/tenant_dogfood.py", "_rpc", input=json.dumps(message), check=False, timeout=220)
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError("Fixture RPC returned no JSON: " + result.stderr[-1000:]) from None
        if payload.get("error") and not allow_error:
            raise RuntimeError(method + ": " + json.dumps(payload["error"]))
        return payload

    def start(self):
        for label in ["provider-net", "agent-net"]:
            name = self.prefix + "-" + label
            self.docker("network", "create", "--internal", name)
            self.networks.append(name)
        self.fixture_name = self.run_container("fixture", ["--user", f"{os.getuid()}:{os.getgid()}", "--network", self.networks[0], "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "-v", f"{self.fixture_dir}:/fixture", *self.mounts(), "--entrypoint", "python3"], self.args.python_image, ["/scripts/tenant_dogfood.py", "_fixture"])
        self.agent_name = self.run_container("agent", ["--user", f"{self.agent_uid}:{self.agent_uid}", "--group-add", str(self.socket_gid), "--network", self.networks[1], "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "-v", self.prefix + "-socket:/run/opaque", "-v", f"{self.bin_dir}:/opt/opaque:ro", *self.mounts(), "-e", "OPAQUE_SOCK=" + SOCKET, "-w", "/tmp", "--entrypoint", "sleep"], self.args.python_image, ["infinity"])
        for port, container, destination in [(self.workstation_port, self.fixture_name, APPROVAL_PORT), (self.port, self.agent_name, self.port)]:
            relay = LoopbackRelay(port, container, destination)
            self.relays.append(relay)
            threading.Thread(target=relay.serve_forever, daemon=True).start()
        self.start_broker()
        self.wait_ready()
        who = self.call("whoami", human=True, allow_error=True).get("result", {})
        if who.get("client_type") != "human":
            # Cross-UID /proc/exe requires ptrace inspection on Linux. This cap
            # sees only broker + fixture human processes, never host/agent PIDs.
            for name in [self.human_name, self.broker_name]:
                self.docker("rm", "-f", name)
                self.container_names.remove(name)
            self.ptrace = True
            self.start_broker()
            self.wait_ready()
            who = self.call("whoami", human=True, allow_error=True).get("result", {})
        if who.get("client_type") != "human":
            actual = self.docker("exec", self.human_name, "python3", "-c", 'import os; print(os.readlink("/proc/self/exe"))').stdout.strip()
            capabilities = self.docker("exec", self.broker_name, "sh", "-c", "grep '^Cap' /proc/1/status").stdout.strip()
            raise RuntimeError("Fixture human executable was not classified as human; actual=" + actual + "; broker=" + capabilities)
        certificate = self.docker("exec", "--user", str(self.broker_uid), self.broker_name, "cat", STATE + "/approval_server.cert", text=False).stdout
        self.fingerprint = sha(certificate)
        log = (self.signer_dir / "test-signer.log").open("a")
        self.logs.append(log)
        enrollment = self.signer_dir / "test-enrollment.json"
        enrollment.unlink(missing_ok=True)
        self.signer = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_signer", "--directory", str(self.signer_dir), "--port", str(self.workstation_port), "--fingerprint", self.fingerprint, "--openssl", self.openssl], cwd=self.signer_dir, env=self.clean_env, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 15
        while not enrollment.exists():
            self.ensure_signer()
            if time.monotonic() > deadline:
                raise RuntimeError("Test signer enrollment timed out")
            time.sleep(0.1)
        self.approval_broker_id = (self.signer_dir / "broker-id.txt").read_text().strip()
        self.broker_id = None

    def wait_ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            response = self.docker("exec", self.agent_name, "test", "-S", SOCKET, check=False)
            if self.docker("inspect", self.broker_name, "--format", "{{.State.Running}}").stdout.strip() != "true":
                raise RuntimeError("Tenant broker exited: " + self.docker("logs", self.broker_name).stdout[-3000:])
            if response.returncode == 0:
                # A persistent socket inode can outlive a killed broker. Once
                # human inspection is enabled, require a working handshake.
                if not self.ptrace or not self.call("ping", human=True, allow_error=True).get("error"):
                    return
            time.sleep(0.2)
        raise RuntimeError("Tenant broker not ready")

    def sign_id_token(self, claims):
        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
        signing = (encode({"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}) + "." + encode(claims)).encode()
        signature = shared.execute([self.openssl, "dgst", "-sha256", "-sign", str(ROOT / "crates/opaqued/tests/fixtures/test_rsa_key.pem")], input=signing, text=False, env=self.clean_env).stdout
        return signing.decode() + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")

    def login(self, invalid=False, foreign=False):
        start = self.call("identity.login_start", human=True)["result"]
        query = {key: value[0] for key, value in parse_qs(urlparse(start["auth_url"]).query).items()}
        claims = {"iss": f"http://127.0.0.1:{IDP_PORT}", "aud": "opaque-" + self.tenant_id, "sub": "foreign-fixture-subject" if foreign else "fixture-subject-" + self.tenant_id, "email": self.tenant_id + "@example.invalid", "name": "Synthetic tenant login", "nonce": "wrong-nonce" if invalid else query["nonce"], "iat": int(time.time()), "exp": int(time.time()) + 600}
        code = "disposable-code-" + sha(start["attempt_id"].encode())[:12]
        dump(self.fixture_dir / "login.json", {"id_token": self.sign_id_token(claims), "code": code, "client_id": query["client_id"], "redirect_uri": query["redirect_uri"], "code_challenge": query["code_challenge"]}, 0o644)
        callback = query["redirect_uri"] + "?" + urlencode({"code": code, "state": query["state"]})
        self.docker("exec", "-i", self.fixture_name, "python3", "/scripts/tenant_dogfood.py", "_callback", input=callback, check=False)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            status = self.call("identity.login_status", {"attempt_id": start["attempt_id"]}, human=True)["result"]
            if status["status"] != "pending":
                assert (status["status"] == "complete") is (not invalid and not foreign), status
                return status
            time.sleep(0.1)
        raise RuntimeError("OIDC callback did not complete")

    def delegate(self):
        self.session = self.call("agent_session_start", {"label": "tenant-dogfood-agent", "reason": "disposable synthetic fixture", "ttl_secs": 3600}, human=True)["result"]
        assert self.session["mode"] == "delegated" and self.session["session_token"].startswith("opqd1.")
        self.docker("exec", "-i", self.agent_name, "python3", "/scripts/tenant_dogfood.py", "_session", input=json.dumps(self.session))

    def start_web(self):
        self.docker("exec", "-d", self.agent_name, "python3", "/scripts/tenant_dogfood.py", "_web", "--port", self.port)

    def cli_request(self, *args):
        result = self.docker("exec", self.agent_name, "python3", "/scripts/tenant_dogfood.py", "_cli", "--json", *args, check=False, timeout=210)
        try:
            return json.loads(result.stdout), result.returncode
        except ValueError:
            raise RuntimeError("Tenant CLI returned no JSON: " + result.stderr[-1500:]) from None

    def assert_custody(self, other):
        script = f'''set -eu
[ "$(id -u)" = {self.agent_uid} ]
[ ! -e {STATE} ]
[ ! -e /approver ]
[ ! -e /fixture ]
[ ! -e /var/run/docker.sock ]
[ "$(stat -c '%a %u %g' /run/opaque)" = '750 {self.broker_uid} {self.socket_gid}' ]
[ "$(stat -c '%a %u %g' /run/opaque/opaqued.sock)" = '660 {self.broker_uid} {self.socket_gid}' ]
[ "$(stat -c '%a %u %g' /run/opaque/daemon.token)" = '640 {self.broker_uid} {self.socket_gid}' ]
'''
        self.docker("exec", self.agent_name, "sh", "-c", script)
        inspect = json.loads(self.docker("inspect", self.agent_name).stdout)[0]
        assert inspect["HostConfig"]["Privileged"] is False
        assert not inspect["HostConfig"]["PidMode"]
        assert inspect["HostConfig"]["ReadonlyRootfs"] is True
        mounts = [m["Source"] for m in inspect["Mounts"]]
        assert all(other.prefix not in m and str(other.directory) not in m for m in mounts)
        for network in self.networks:
            assert json.loads(self.docker("network", "inspect", network).stdout)[0]["Internal"] is True
        targets = []
        for tenant in [self, other]:
            settings = json.loads(self.docker("inspect", tenant.fixture_name).stdout)[0]["NetworkSettings"]
            ip = next(iter(settings["Networks"].values()))["IPAddress"]
            targets.append([ip, CANARY_PORT])
        # The model binds loopback. A reachable eth0 canary supplies the
        # positive control needed to test the Docker network boundary itself.
        own_url = f"http://{targets[0][0]}:{CANARY_PORT}/"
        positive = self.docker("exec", "-i", self.fixture_name, "python3", "/scripts/tenant_dogfood.py", "_canary_probe", input=json.dumps(own_url))
        assert json.loads(positive.stdout) == {"status": 200, "body": CANARY_BODY.decode()}
        result = self.docker("exec", "-i", self.agent_name, "python3", "/scripts/tenant_dogfood.py", "_network_probe", input=json.dumps(targets))
        assert json.loads(result.stdout) == [False, False], "Agent reached a tenant provider directly"
        broker_inspect = json.loads(self.docker("inspect", self.broker_name).stdout)[0]
        fixture_inspect = json.loads(self.docker("inspect", self.fixture_name).stdout)[0]
        assert broker_inspect["HostConfig"]["NetworkMode"] == "container:" + fixture_inspect["Id"]
        dump(self.directory / "network-canary-evidence.json", {"tenant": self.tenant_id, "canary_bind": "0.0.0.0", "port": CANARY_PORT, "provider_namespace_positive_control": json.loads(positive.stdout), "broker_shares_provider_network_namespace": True, "agent_targets": targets, "agent_connected": json.loads(result.stdout)})
        version = self.call("version")["result"]
        assert version["trust_domain_enforced"] is True and version["workstation_test_mode"] is True
        status = self.docker("exec", self.broker_name, "cat", "/proc/1/status").stdout
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        assert fields["Uid"].split() == [str(self.broker_uid)] * 4
        assert int(fields["CapEff"].strip(), 16) == (0x80000 if self.ptrace else 0)
        dump(self.directory / "custody-evidence.json", {"tenant": self.tenant_id, "broker_uid": self.broker_uid, "agent_uid": self.agent_uid, "socket_gid": self.socket_gid, "agent_provider_network_denied": True, "other_tenant_mounts_absent": True, "agent_private_pid_namespace": True, "broker_human_metadata_ptrace_cap": self.ptrace, "broker_effective_capabilities": fields["CapEff"].strip(), "runtime": "Docker shared-kernel containers", "version": version})

    def dashboard_check(self, expected_id):
        deadline = time.monotonic() + 15
        while True:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=3) as response:
                    html = response.read().decode()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("Tenant dashboard did not start")
                time.sleep(0.2)
        match = re.search(r'<meta name="opaque-auth-token" content="([^"]+)"', html)
        if not match:
            raise RuntimeError("Dashboard did not provide its authentication bootstrap")
        token = match.group(1)
        def request(path, credential=token):
            headers = {"Authorization": "Bearer " + credential} if credential else {}
            try:
                with urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{self.port}" + path, headers=headers), timeout=5) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, None
        assert request("/api/tasks", None)[0] == 401
        status, result = request("/api/tasks")
        assert status == 200 and expected_id in {t["id"] for t in result["tasks"]}
        assert all(t["manifest"]["actions"][0]["tenant"]["tenant_id"] == self.tenant_id for t in result["tasks"])
        status, health = request("/api/status")
        assert status == 200 and health["mode"] == "live" and health["workstation_test_mode"]
        dump(self.directory / "dashboard-evidence.json", {"tenant": self.tenant_id, "own_task_visible": True, "anonymous_api_denied": True, "test_approval_banner": True})

    def mcp_check(self):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "tenant-fixture", "version": "1"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "opaque_task_get", "arguments": {"task_id": self.task_id}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "opaque_task_run", "arguments": {"task_id": self.task_id}}},
        ]
        result = self.docker("exec", "-i", self.agent_name, "python3", "/scripts/tenant_dogfood.py", "_mcp", input="".join(json.dumps(m) + "\n" for m in messages), check=False, timeout=30)
        responses = {m["id"]: m for m in map(json.loads, result.stdout.splitlines()) if "id" in m}
        assert not responses[3]["result"].get("isError")
        assert responses[4]["result"]["isError"] is True
        assert self.count_dispatches() == 4
        dump(self.directory / "mcp-evidence.json", responses)

    def restart_check(self):
        before = self.count_dispatches()
        for name in [self.human_name, self.broker_name]:
            self.docker("rm", "-f", name)
            self.container_names.remove(name)
        self.start_broker()
        self.wait_ready()
        self.login()
        self.delegate()
        receipt = self.call("task_get", {"task_id": self.task_id})["result"]["task"]
        self.assert_receipt(receipt, True)
        assert self.call("task_run", {"task_id": self.task_id}, allow_error=True).get("error")
        assert self.count_dispatches() == before
        # Restart only this fixture web process so it captures the new session.
        self.docker("exec", self.agent_name, "python3", "/scripts/tenant_dogfood.py", "_restart_web", "--port", self.port)
        dump(self.directory / "restart-evidence.json", {"tenant": self.tenant_id, "receipt_persisted": True, "broker_binding": self.broker_id, "no_extra_completion": True})

    def plan(self):
        task = self.call("task_plan_inference", {"title": self.tenant_id + ": three fixed public completions", "expires_in_secs": 600})["result"]["task"]
        binding = task["manifest"]["actions"][0]["tenant"]
        assert binding["tenant_id"] == self.tenant_id
        if self.broker_id is not None:
            assert binding["broker_id"] == self.broker_id
        self.broker_id = binding["broker_id"]
        return task

    def assert_receipt(self, receipt, completed):
        assert receipt["manifest"]["schema_version"] == 3
        assert re.fullmatch("[0-9a-f]{64}", receipt["manifest_digest"])
        assert len(receipt["slots"]) == 3
        assert receipt["approval_mode"] == "insecure_test"
        for slot in receipt["slots"]:
            action = slot["action"]
            assert action["tenant"]["tenant_id"] == self.tenant_id
            assert action["tenant"]["broker_id"] == self.broker_id
            if completed:
                evidence = slot["outcome"]["inference_receipt"]
                assert slot["reserved_at"] is not None and slot["state"] == "api_accepted"
                assert evidence["code"] == "completion_observed"
                assert evidence["reserved_output_tokens"] == 96 and evidence["observed_output_tokens"] == 8
                assert sha(evidence["output_text"].encode()) == evidence["output_sha256"]
                assert self.tenant_id in evidence["output_text"]

    def close(self):
        for relay in self.relays:
            relay.shutdown()
            relay.server_close()
        super().close()
        for name in reversed(self.networks):
            self.docker("network", "rm", name, check=False)


def internal_mode():
    mode = sys.argv[1]
    if mode == "_rpc":
        print(json.dumps(rpc(json.load(sys.stdin))))
    elif mode == "_fixture":
        for port in [MODEL_PORT, IDP_PORT]:
            server = FixtureServer("/fixture", port)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        canary = ThreadingHTTPServer(("0.0.0.0", CANARY_PORT), NetworkCanaryHandler)
        threading.Thread(target=canary.serve_forever, daemon=True).start()
        threading.Event().wait()
    elif mode == "_callback":
        try:
            with urllib.request.urlopen(sys.stdin.read(), timeout=15) as response:
                print(response.status)
        except urllib.error.HTTPError as error:
            print(error.code)
    elif mode == "_session":
        dump("/tmp/tenant-session.json", json.load(sys.stdin))
    elif mode == "_network_probe":
        results = []
        for address in json.load(sys.stdin):
            with socket.socket() as connection:
                connection.settimeout(1)
                results.append(connection.connect_ex(tuple(address)) == 0)
        print(json.dumps(results))
    elif mode == "_canary_probe":
        with urllib.request.urlopen(json.load(sys.stdin), timeout=3) as response:
            print(json.dumps({"status": response.status, "body": response.read(1024).decode()}))
    elif mode == "_tunnel":
        with socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=10) as connection:
            connection.settimeout(60)
            def incoming():
                try:
                    while chunk := sys.stdin.buffer.read1(65536):
                        connection.sendall(chunk)
                except OSError:
                    pass
                finally:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            threading.Thread(target=incoming, daemon=True).start()
            try:
                while chunk := connection.recv(65536):
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
            except OSError:
                pass
    elif mode in ("_mcp", "_cli"):
        session = json.loads(Path("/tmp/tenant-session.json").read_text())
        environment = dict(os.environ, OPAQUE_SESSION_TOKEN=session["session_token"], OPAQUE_AGENT_WRAPPED="1")
        binary = "opaque-mcp" if mode == "_mcp" else "opaque"
        os.execve("/opt/opaque/" + binary, [binary, *([] if mode == "_mcp" else sys.argv[2:])], environment)
    elif mode == "_restart_web":
        pidfile = Path("/tmp/web.pid")
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 8
        while True:
            with socket.socket() as probe:
                listening = probe.connect_ex(("127.0.0.1", int(sys.argv[3]))) == 0
            if not listening:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Previous fixture dashboard listener did not stop")
            time.sleep(0.05)
        subprocess.Popen([sys.executable, "-B", "/scripts/tenant_dogfood.py", "_web", "--port", sys.argv[3]], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif mode in ("_web", "_relay"):
        port = int(sys.argv[3])
        if mode == "_web":
            Path("/tmp/web.pid").write_text(str(os.getpid()))
            session = json.loads(Path("/tmp/tenant-session.json").read_text())
            environment = dict(os.environ, OPAQUE_SESSION_TOKEN=session["session_token"], OPAQUE_AGENT_WRAPPED="1")
            os.execve("/opt/opaque/opaque-web", ["opaque-web", "--data-dir", "/tmp/web", "--socket", SOCKET, "--port", str(port)], environment)
        relay = ThreadingHTTPServer(("0.0.0.0", port + 1), shared.RelayHandler)
        relay.web_port = port
        relay.serve_forever()
    elif mode == "_signer":
        parser = argparse.ArgumentParser()
        for name in ["directory", "fingerprint", "openssl"]:
            parser.add_argument("--" + name, required=True)
        parser.add_argument("--port", type=int, required=True)
        args = parser.parse_args(sys.argv[2:])
        signer = TenantSigner(args.directory, args.port, args.fingerprint, args.openssl)
        signer.enroll()
        print("TEST SIGNER ready; no human consent.", flush=True)
        while True:
            try:
                signer.approve_pending()
            except (OSError, http.client.HTTPException):
                time.sleep(1)
            time.sleep(0.2)


def check(tenants):
    for tenant in tenants:
        assert tenant.call("identity.login_start", session=False, allow_error=True).get("error"), "Untrusted agent started human login"
        assert tenant.call("task_plan_inference", session=False, allow_error=True).get("error"), "Anonymous tenant inference allowed"
        tenant.login(invalid=True)
        tenant.login(foreign=True)
        tenant.login()
        tenant.delegate()
        tenant.start_web()
        planned = tenant.plan()
        tenant.task_id = planned["id"]
        response, exit_status = tenant.cli_request("task", "run", planned["id"])
        assert exit_status == 0, response
        completed = shared.public_task(response)
        tenant.assert_receipt(completed, True)
        assert tenant.count_dispatches() == 3
        _, replay_status = tenant.cli_request("task", "run", planned["id"])
        assert replay_status != 0
        assert tenant.count_dispatches() == 3, "Fourth completion reached provider"
        dump(tenant.directory / "completed-receipt.json", completed)
        for field, value in [("profile_sha256", "a" * 64), ("source_snapshot_sha256", "b" * 64), ("model_id", "wrong-model")]:
            manifest = json.loads(json.dumps(completed["manifest"]))
            manifest["actions"][0][field] = value
            assert tenant.call("task_plan", {"manifest": manifest}, allow_error=True).get("error"), field
        tenant.control(fault=True)
        unknown_plan = tenant.plan()
        unknown_response = tenant.call("task_run", {"task_id": unknown_plan["id"]}, allow_error=True)
        unknown = unknown_response.get("result", {}).get("task") or tenant.call("task_get", {"task_id": unknown_plan["id"]})["result"]["task"]
        tenant.assert_receipt(unknown, False)
        assert unknown["slots"][0]["state"] == "unknown"
        assert sum(s["reserved_at"] is not None for s in unknown["slots"]) == 1
        assert tenant.count_dispatches() == 4
        tenant.call("task_run", {"task_id": unknown["id"]}, allow_error=True)
        assert tenant.count_dispatches() == 4, "Unknown completion retried"
        dump(tenant.directory / "unknown-receipt.json", unknown)
        tenant.control()
    first, second = tenants
    for tenant, other in [(first, second), (second, first)]:
        assert tenant.call("task_get", {"task_id": other.task_id}, allow_error=True).get("error")
        assert tenant.call("task_list", token=other.session["session_token"], allow_error=True).get("error")
        assert tenant.call("task_list", daemon_token="0" * 64, allow_error=True).get("error")
        manifest = json.loads((other.directory / "completed-receipt.json").read_text())["manifest"]
        assert tenant.call("task_plan", {"manifest": manifest}, allow_error=True).get("error")
        manifest = json.loads((tenant.directory / "completed-receipt.json").read_text())["manifest"]
        manifest["actions"][0]["tenant"]["broker_id"] = other.broker_id
        assert tenant.call("task_plan", {"manifest": manifest}, allow_error=True).get("error")
        assert tenant.count_dispatches() == 4
        tenant.assert_custody(other)
        tenant.mcp_check()
        tenant.restart_check()
        tenant.dashboard_check(tenant.task_id)
    print("PASS: two OIDC logins/delegations; three bounded completions each; replay, unknown retry, forged scopes and cross-broker delegation denied.", flush=True)


def main():
    if len(sys.argv) > 1 and sys.argv[1].startswith("_"):
        internal_mode()
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Run assertions and stop (default)")
    parser.add_argument("--serve", action="store_true", help="Run assertions then retain the two dashboards")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--port", type=int, default=19394)
    parser.add_argument("--approval-port", type=int, default=19444)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--python-image", default=shared.PYTHON_IMAGE)
    args = parser.parse_args()
    args.native = False
    if not 1024 <= args.port <= 65532 or not 1024 <= args.approval_port <= 65534 or {args.port, args.port + 2} & {args.approval_port, args.approval_port + 1}:
        parser.error("Choose distinct valid loopback dashboard/approval ports")
    directory = (args.data_dir or Path(tempfile.mkdtemp(prefix="otf-", dir="/tmp"))).expanduser().resolve()
    if directory.exists() and any(directory.iterdir()):
        parser.error("Use a fresh disposable data directory for an independent check")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    minimum_gib = 2 if args.no_build else 8
    if shutil.disk_usage(directory).free < minimum_gib * 1024 ** 3:
        parser.error(f"Less than {minimum_gib} GiB available for generated build/fixture files; free disposable build space first")
    tenants = []
    failed = False
    try:
        print("Tenant fixture state: " + str(directory), flush=True)
        tenants = [Tenant(args, directory, index) for index in [0, 1]]
        tenants[0].build()
        for tenant in tenants:
            tenant.prepare()
            tenant.bootstrap()
            tenant.start()
        check(tenants)
        dump(directory / "summary.json", {"result": "passed", "runtime": "Docker shared-kernel containers", "approval": "insecure_test", "identity": "real OIDC/delegation protocol with disposable issuer", "live_gpu_requests": 0, "tenants": [{"tenant_id": tenant.tenant_id, "broker_id": tenant.broker_id, "approval_broker_id": tenant.approval_broker_id, "completed_task_id": tenant.task_id, "completion_requests": tenant.count_dispatches(), "dashboard": f"http://127.0.0.1:{tenant.port}", "agent_container": tenant.agent_name} for tenant in tenants]})
        if args.serve:
            for tenant in tenants:
                planned = tenant.plan()
                print(f"{tenant.tenant_id}: http://127.0.0.1:{tenant.port} · planned {planned['id']} · agent {tenant.agent_name}", flush=True)
                print("Run: " + shlex.join(["docker", "exec", tenant.agent_name, "python3", "/scripts/tenant_dogfood.py", "_cli", "task", "run", planned["id"]]), flush=True)
            print("TEST ISSUER / TEST SIGNER / MODEL STUB. No human consent or live GPU execution. Ctrl-C stops these fixtures.", flush=True)
            while True:
                for tenant in tenants:
                    tenant.ensure_signer()
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    except (RuntimeError, OSError, subprocess.SubprocessError, AssertionError, KeyError) as error:
        failed = True
        print("TENANT DOGFOOD FAILED: " + str(error), file=sys.stderr)
        return 1
    finally:
        for tenant in reversed(tenants):
            tenant.close()
        if failed and (directory / "bin").is_dir():
            shutil.rmtree(directory / "bin")
        print("Retained evidence: " + str(directory), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
