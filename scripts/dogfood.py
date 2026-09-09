#!/usr/bin/env python3
"""Run the real Opaque stack against local GitHub/Vault fixtures (stdlib only)."""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
REPOS = ["kcirtapfromspace/opaque", "kcirtapfromspace/no_drake_in_the_house", "Nereus-Data/admachina"]
# Curve25519's standard base point is a valid recipient public key. This fixture
# validates sealed-box wire shape, not decryption or GitHub storage semantics.
PUBLIC_KEY = base64.b64encode(bytes([9]) + bytes(31)).decode()
GH_TOKEN = "opaque-dogfood-fixture-github-token"
VAULT_TOKEN = "opaque-dogfood-fixture-vault-token"
FIELDS = {f"REPO_{i}_{kind}": f"OPAQUE_FAKE_ONLY_{i}_{kind}_v1" for i in range(1, 4) for kind in ("APP", "WORKER")}


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state_dir: Path):
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.state_dir = state_dir
        self.lock = threading.Lock()
        self.writes: list[dict] = []
        self.fail_next = False


class FixtureHandler(BaseHTTPRequestHandler):
    server: FixtureServer

    def log_message(self, *_args):
        pass

    def reply(self, code, value):
        data = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        path = unquote(url.path)
        if path == "/v1/kv/data/dogfood":
            if self.headers.get("X-Vault-Token") != VAULT_TOKEN:
                return self.reply(403, {"errors": ["fixture token required"]})
            if parse_qs(url.query) != {"version": ["1"]}:
                return self.reply(400, {"errors": ["only pinned version 1 exists"]})
            return self.reply(200, {"data": {"data": FIELDS, "metadata": {"version": 1, "destroyed": False, "deletion_time": ""}}})
        if self.headers.get("Authorization") != "Bearer " + GH_TOKEN:
            return self.reply(401, {"message": "fixture token required"})
        for index, repo in enumerate(REPOS, 1):
            if path.lower() == f"/repos/{repo}".lower():
                return self.reply(200, {"id": 90000 + index, "full_name": repo})
            if path.lower() == f"/repos/{repo}/actions/secrets/public-key".lower():
                return self.reply(200, {"key_id": "dogfood-key-v1", "key": PUBLIC_KEY})
        self.reply(404, {"message": "unknown fixture route"})

    def do_PUT(self):
        if self.headers.get("Authorization") != "Bearer " + GH_TOKEN:
            return self.reply(401, {"message": "fixture token required"})
        path = unquote(urlparse(self.path).path)
        known = any(path.lower().startswith(f"/repos/{repo}/actions/secrets/".lower()) for repo in REPOS)
        if not known:
            return self.reply(404, {"message": "unknown fixture target"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length < 65536:
                raise ValueError("invalid body length")
            raw = self.rfile.read(length)
            body = json.loads(raw)
            encrypted = base64.b64decode(body["encrypted_value"], validate=True)
            if body.get("key_id") != "dogfood-key-v1" or len(encrypted) < 49:
                raise ValueError("invalid sealed value")
            if any(value.encode() in raw for value in FIELDS.values()):
                raise ValueError("plaintext in provider payload")
        except (ValueError, KeyError, TypeError):
            return self.reply(400, {"message": "expected encrypted fixture value"})
        with self.server.lock:
            fault = self.server.fail_next
            self.server.fail_next = False
            receipt = {"path": path, "status": 500 if fault else 201, "ciphertext_bytes": len(encrypted)}
            self.server.writes.append(receipt)
            with (self.server.state_dir / "fixture-writes.jsonl").open("a") as out:
                out.write(json.dumps(receipt) + "\n")
        # A 500 intentionally does not establish whether storage happened.
        self.reply(500 if fault else 201, {"message": "simulated uncertain response"} if fault else {})


class Dogfood:
    def __init__(self, args):
        self.args = args
        directory = args.data_dir or Path(tempfile.mkdtemp(prefix="odf-", dir="/tmp"))
        self.directory = directory.expanduser().resolve()
        if self.directory == (Path.home() / ".opaque").resolve():
            raise RuntimeError("Use an isolated directory, not ~/.opaque.")
        marker = self.directory / ".opaque-dogfood.json"
        if self.directory.exists() and any(self.directory.iterdir()) and not marker.exists():
            raise RuntimeError("Data directory is not empty or marked as an Opaque dogfood environment.")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        marker.write_text(json.dumps({"simulation": True, "repos": REPOS}))
        self.socket = self.directory / "run/opaqued.sock"
        if len(str(self.socket).encode()) >= 100:
            raise RuntimeError("Use a shorter data directory for the macOS Unix socket limit.")
        self.fixture = FixtureServer(self.directory)
        self.base_url = f"http://127.0.0.1:{self.fixture.server_port}"
        self.thread = threading.Thread(target=self.fixture.serve_forever, daemon=True)
        self.processes = []
        self.logs = []
        self.http = build_opener(ProxyHandler({}))
        self.env = os.environ.copy()
        # No production credential reaches these fixtures. No global HOME change.
        for key in list(self.env):
            if key.startswith("OPAQUE_"):
                del self.env[key]
        self.env.update({
            "OPAQUE_CONFIG": str(self.directory / "config.toml"),
            "OPAQUE_SOCK": str(self.socket),
            "OPAQUE_DOGFOOD_LOOPBACK": "1",
            "OPAQUE_GITHUB_API_URL": self.base_url,
            "OPAQUE_VAULT_URL": self.base_url,
            "OPAQUE_GITHUB_TOKEN_REF": "env:OPAQUE_DOGFOOD_GH_TOKEN",
            "OPAQUE_VAULT_TOKEN_REF": "env:OPAQUE_DOGFOOD_VAULT_TOKEN",
            "OPAQUE_DOGFOOD_GH_TOKEN": GH_TOKEN,
            "OPAQUE_DOGFOOD_VAULT_TOKEN": VAULT_TOKEN,
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "RUST_LOG": "info",
        })
        if not args.native:
            self.env["OPAQUE_INSECURE_AUTO_APPROVE"] = "1"
        backend = "native" if args.native else "insecure_auto_approve"
        config = f'''# LOCAL SIMULATION ONLY. Generated by scripts/dogfood.py.
data_dir = {json.dumps(str(self.directory))}
enable_task_grants = true
approval_backend = "{backend}"
enforce_agent_sessions = false
require_seal = false
'''
        for operation in ["github.publish_manifest", "github.set_actions_secret"]:
            config += f'''
[[rules]]
name = "dogfood-{operation}"
operation_pattern = "{operation}"
allow = true
client_types = ["agent", "human"]
[rules.approval]
require = "always"
factors = ["local_bio"]
lease_ttl = 0
'''
        (self.directory / "config.toml").write_text(config)
        self.actions = [
            {"repo": repo, "secret_name": f"OPAQUE_DOGFOOD_{kind}", "value_ref": f"vault:kv/data/dogfood?version=1#REPO_{index}_{kind}"}
            for index, repo in enumerate(REPOS, 1) for kind in ("APP", "WORKER")
        ]
        self.manifest = self.write_manifest("manifest.json", "Dogfood: six fixed writes across our three repos", self.actions)
        self.daemon = None
        self.task_id = None

    def write_manifest(self, filename, title, actions):
        path = self.directory / filename
        path.write_text(json.dumps({"schema_version": 1, "title": title, "expires_in_secs": 3600, "actions": actions}, indent=2) + "\n")
        return path

    def start_process(self, name, command):
        log = (self.directory / (name + ".log")).open("a")
        self.logs.append(log)
        process = subprocess.Popen(command, cwd=ROOT, env=self.env, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    def cli(self, *args, allow_error=False):
        command = [str(ROOT / "target/debug/opaque"), "--socket", str(self.socket), "--json", *map(str, args)]
        result = subprocess.run(command, cwd=ROOT, env=self.env, text=True, capture_output=True, timeout=180 if self.args.native else 45)
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError(f"CLI did not return JSON: {result.stderr[-2000:]} {result.stdout[-2000:]}") from None
        if not allow_error and (result.returncode or payload.get("error")):
            raise RuntimeError(f"CLI {' '.join(map(str,args))} failed: {json.dumps(payload)}")
        return payload, result.returncode

    @staticmethod
    def task(payload):
        result = payload.get("result", payload)
        return result.get("task", result)

    def start_daemon(self):
        self.daemon = self.start_process("opaqued", [str(ROOT / "target/debug/opaqued"), "--allow-unsealed"])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.daemon.poll() is not None:
                raise RuntimeError("Daemon exited. " + (self.directory / "opaqued.log").read_text()[-3500:])
            if self.socket.exists():
                try:
                    self.cli("ping")
                    return
                except (RuntimeError, OSError):
                    pass
            time.sleep(0.1)
        raise RuntimeError("Timed out waiting for isolated daemon.")

    @staticmethod
    def stop_process(process):
        if process and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)

    def validate_receipt(self, task):
        if task.get("approved_at") is not None:
            expected_mode = "native" if self.args.native else "insecure_test"
            assert task.get("approval_mode") == expected_mode, "Receipt lost its native/test approval provenance"
        assert re.fullmatch(r"[0-9a-f]{64}", task["manifest_digest"]), "Public manifest digest was lost or malformed"
        assert task["manifest"]["github_api_url"] == self.base_url
        assert task["manifest"]["vault_api_url"] == self.base_url
        for action in task["manifest"]["actions"]:
            assert re.fullmatch(r"vault:kv/data/dogfood\?version=1#REPO_[123]_(APP|WORKER)", action["value_ref"]), "Pinned source reference changed"
            assert action["github_token_ref"] == "env:OPAQUE_DOGFOOD_GH_TOKEN", "Credential reference changed"
            assert action["repo"] in REPOS and action["repository_id"] in (90001, 90002, 90003)
        assert [slot["action"] for slot in task["slots"]] == task["manifest"]["actions"]
        serialized = json.dumps(task)
        assert not any(value in serialized for value in [*FIELDS.values(), GH_TOKEN, VAULT_TOKEN]), "Plaintext fixture secret in receipt"
        return task

    def plan(self, manifest):
        return self.validate_receipt(self.task(self.cli("task", "plan", "--manifest", manifest)[0]))

    def check(self):
        task = self.plan(self.manifest)
        self.task_id = task["id"]
        result = self.task(self.cli("task", "run", self.task_id)[0])
        self.validate_receipt(result)
        assert result["state"] == "completed", result
        assert len(result["slots"]) == 6 and all(slot["state"] == "api_accepted" for slot in result["slots"]), result
        assert len(self.fixture.writes) == 6, self.fixture.writes
        self.assert_no_replay(self.task_id)
        action = dict(self.actions[0], secret_name="OPAQUE_DOGFOOD_UNKNOWN")
        fault_manifest = self.write_manifest("manifest-unknown.json", "Dogfood: uncertain provider receipt", [action])
        fault = self.plan(fault_manifest)
        self.fixture.fail_next = True
        result = self.task(self.cli("task", "run", fault["id"], allow_error=True)[0])
        self.validate_receipt(result)
        assert result["slots"][0]["state"] == "unknown", result
        assert len(self.fixture.writes) == 7
        self.assert_no_replay(fault["id"])
        self.stop_process(self.daemon)
        self.start_daemon()
        for task_id in (self.task_id, fault["id"]):
            self.validate_receipt(self.task(self.cli("task", "show", task_id)[0]))
            self.assert_no_replay(task_id)
        assert len(self.fixture.writes) == 7
        self.check_mcp()

    def check_mcp(self):
        # Agent transport receives a small ordinary process environment and the
        # explicit fixture socket. Provider endpoints and credentials stay in
        # the daemon environment, never in the MCP agent process.
        agent_env = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR") if key in os.environ}
        agent_env["OPAQUE_SOCK"] = str(self.socket)
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "opaque-dogfood-check", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "opaque_task_get", "arguments": {"task_id": self.task_id}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "opaque_task_list", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "opaque_task_run", "arguments": {"task_id": self.task_id}}},
        ]
        before = len(self.fixture.writes)
        with (self.directory / "opaque-mcp.log").open("a") as log:
            process = subprocess.run(
                [str(ROOT / "target/debug/opaque-mcp")], cwd=ROOT, env=agent_env,
                input="\n".join(json.dumps(message) for message in messages) + "\n",
                text=True, stdout=subprocess.PIPE, stderr=log, timeout=45,
            )
        assert process.returncode == 0, "MCP process failed; inspect opaque-mcp.log"
        responses = {response["id"]: response for response in (json.loads(line) for line in process.stdout.splitlines() if line.strip())}
        assert set(responses) == {1, 2, 3, 4, 5}, "MCP did not answer every request"
        assert all("error" not in response for response in responses.values()), responses
        tools = {tool["name"] for tool in responses[2]["result"]["tools"]}
        assert {"opaque_task_plan", "opaque_task_run", "opaque_task_get", "opaque_task_list", "opaque_task_revoke"} <= tools
        for request_id in (3, 4):
            assert responses[request_id]["result"].get("isError") is not True
        record = json.loads(responses[3]["result"]["content"][0]["text"])["task"]
        self.validate_receipt(record)
        assert record["id"] == self.task_id and record["state"] == "completed"
        listed = json.loads(responses[4]["result"]["content"][0]["text"])["tasks"]
        assert any(task["id"] == self.task_id for task in listed)
        assert responses[5]["result"]["isError"] is True, "MCP replay must surface a tool error"
        assert len(self.fixture.writes) == before, "MCP replay dispatched another provider write"
        assert not any(value in process.stdout for value in [*FIELDS.values(), GH_TOKEN, VAULT_TOKEN]), "MCP exposed a fixture secret"
        (self.directory / "mcp-responses.json").write_text(json.dumps(responses, indent=2) + "\n")

    def assert_no_replay(self, task_id):
        before = len(self.fixture.writes)
        payload, code = self.cli("task", "run", task_id, allow_error=True)
        assert code != 0 or payload.get("error"), "Replay unexpectedly succeeded"
        assert len(self.fixture.writes) == before, "Replay dispatched another provider write"

    def dashboard(self, path):
        token = (self.directory / "web.token").read_text().strip()
        request = Request(f"http://127.0.0.1:{self.args.port}" + path, headers={"Authorization": "Bearer " + token})
        with self.http.open(request, timeout=10) as response:
            return json.load(response)

    def wait_dashboard(self, process):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Dashboard exited. " + (self.directory / "opaque-web.log").read_text()[-2000:])
            try:
                status = self.dashboard("/api/status")
                if status["mode"] == "live":
                    expected_backend = "native" if self.args.native else "insecure_auto_approve"
                    assert status["approval_backend"] == expected_backend, "Dashboard must identify the active approval backend"
                    assert status["task_grants_enabled"] is True
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
        raise RuntimeError("Dashboard did not connect to the isolated daemon.")

    def run(self):
        self.thread.start()
        self.start_daemon()
        port = self.args.port
        web = self.start_process("opaque-web", [str(ROOT / "target/debug/opaque-web"), "--data-dir", str(self.directory), "--port", str(port)])
        self.wait_dashboard(web)
        if self.args.serve:
            self.task_id = self.plan(self.manifest)["id"]
        else:
            self.check()
        visible = self.dashboard("/api/tasks")["tasks"]
        assert any(task["id"] == self.task_id for task in visible), "Task missing from scoped dashboard API"
        if not self.args.serve:
            print("PASS: six encrypted writes; replay denied; uncertain outcome charged; receipts survive daemon restart; scoped dashboard and MCP reads work; MCP replay denied; no extra writes.", flush=True)
        cli = shlex.join([str(ROOT / "target/debug/opaque"), "--socket", str(self.socket)])
        print(f"\nLOCAL SIMULATION — providers at {self.base_url}; approval backend: {'native' if self.args.native else 'insecure auto-approve (simulation only)'}")
        print(f"State: {self.directory}\nManifest: {self.manifest}")
        if self.args.serve:
            print(f"Dashboard: http://127.0.0.1:{port}")
            print(f"\nInspect: {cli} task show {self.task_id}\nList:    {cli} task list")
            print(f"Run:     {cli} task run {self.task_id}")
            mcp = shlex.join(["env", "-u", "OPAQUE_SESSION_TOKEN", "OPAQUE_SOCK=" + str(self.socket), str(ROOT / "target/debug/opaque-mcp")])
            print(f"MCP:     {mcp}")
            print("\nKeep this terminal open. Ctrl-C stops all local fixture processes. State and receipts remain for inspection.", flush=True)
            while True:
                if any(process.poll() is not None for process in self.processes[-2:]):
                    raise RuntimeError("A local service exited; inspect the logs in the state directory.")
                time.sleep(0.5)
        else:
            print("Check complete; local services are stopping. For interactive use: python3 scripts/dogfood.py --serve")

    def close(self):
        for process in reversed(self.processes):
            self.stop_process(process)
        for log in self.logs:
            log.close()
        if self.thread.is_alive():
            self.fixture.shutdown()
        self.fixture.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Run end-to-end assertions and stop (default).")
    mode.add_argument("--serve", action="store_true", help="Leave an isolated dashboard and planned task ready to use.")
    parser.add_argument("--native", action="store_true", help="Use real OS approval prompts against local fixtures; never auto-approve.")
    parser.add_argument("--data-dir", type=Path, help="Empty or previously marked isolated directory (default: new short /tmp directory).")
    parser.add_argument("--port", type=int, default=7382, help="Local dashboard port (default: 7382).")
    parser.add_argument("--no-build", action="store_true", help="Use current target/debug binaries.")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    if not args.no_build:
        build = ["cargo", "build", "-p", "opaque", "-p", "opaqued", "-p", "opaque-web", "-p", "opaque-mcp"]
        if args.native:
            build += ["-p", "opaque-approve-helper"]
        subprocess.run(build, cwd=ROOT, check=True)
    session = None
    try:
        session = Dogfood(args)
        session.run()
    except KeyboardInterrupt:
        print("\nStopped local dogfood services.")
    except Exception as error:
        print(f"Dogfood failed: {error}", file=sys.stderr)
        if session:
            print(f"Inspect logs and manifests in {session.directory}", file=sys.stderr)
        return 1
    finally:
        if session:
            session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
