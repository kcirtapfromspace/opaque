#!/usr/bin/env python3
"""Two-customer OAuth/MCP metrics chat with disposable rolling event sources.

Native processes share this host and UID. This fixture does not demonstrate
microVM isolation, real customer data, production OAuth, or human approval.
"""
from __future__ import annotations

import argparse
import base64
from collections import deque
import hashlib
import hmac
import html
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlencode, urlparse

ROOT = Path(__file__).resolve().parents[1]
TEST_KEY = ROOT / "crates/opaqued/tests/fixtures/test_rsa_key.pem"
TEST_JWKS = ROOT / "crates/opaqued/tests/fixtures/test_idp_jwks.json"
METRICS = ["requests_per_second", "error_rate_percent", "p95_latency_ms", "active_sessions"]
SCOPES = ["metrics:read", "metrics:stream", "metrics:explain", *("metrics:metric:" + name for name in METRICS)]


def dump(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".next")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def signed_token(claims, openssl="openssl", header=None):
    header = header or {"alg": "RS256", "typ": "at+jwt", "kid": "test-key-1"}
    content = encode(json.dumps(header, separators=(",", ":")).encode()) + "." + encode(json.dumps(claims, separators=(",", ":")).encode())
    signature = subprocess.run([openssl, "dgst", "-sha256", "-sign", str(TEST_KEY)], input=content.encode(), capture_output=True, check=True).stdout
    return content + "." + encode(signature)


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        # URLs, authorization headers and token bodies must not reach logs.
        pass

    def reply(self, status, value, content_type="application/json", headers=None):
        body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        for key, item in (headers or {}).items():
            self.send_header(key, item)
        self.end_headers()
        self.wfile.write(body)

    def body(self, maximum=8192):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("invalid body") from None
        if not 0 < length <= maximum:
            raise ValueError("invalid body size")
        return self.rfile.read(length)


class RollingSource(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, tenant, index, credential, directory):
        self.tenant, self.index, self.credential = tenant, index, credential
        self.directory = Path(directory)
        self.events = deque()
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.sequence = self.generated = self.queries = self.denied = 0
        self.started_at = time.time()
        super().__init__(("127.0.0.1", port), SourceHandler)
        threading.Thread(target=self.produce, daemon=True).start()

    def produce(self):
        while not self.stop.is_set():
            control = self.directory / "control.json"
            if control.exists() and json.loads(control.read_text()).get("paused") is True:
                self.stop.wait(.25)
                continue
            now = time.time()
            with self.lock:
                self.sequence += 1
                for ordinal in range(2 + (self.sequence + self.index) % 6):
                    self.generated += 1
                    self.events.append((now, 35 + self.index * 41 + (self.generated * 17) % 190, self.generated % (13 + self.index * 3) == 0, self.generated % (19 + self.index * 5)))
                while self.events and self.events[0][0] < now - 360:
                    self.events.popleft()
            self.stop.wait(.25)

    def aggregate(self, names, window):
        now = time.time()
        with self.lock:
            events = [event for event in self.events if event[0] >= now - window]
            self.queries += 1
            times = sorted(event[1] for event in events)
            values = {"requests_per_second": len(events) / window,
                      "error_rate_percent": 100 * sum(event[2] for event in events) / len(events) if events else 0,
                      "p95_latency_ms": times[max(0, math.ceil(len(times) * .95) - 1)] if times else 0,
                      "active_sessions": len({event[3] for event in events})}
            result = {"tenant_id": self.tenant, "window_secs": window, "as_of": int(now), "watermark": int(events[-1][0]) if events else 0, "metrics": [{"name": name, "value": values[name], "count": len(events)} for name in names]}
            evidence = {"tenant_id": self.tenant, "generated_events": self.generated, "aggregate_queries": self.queries, "denied_requests": self.denied, "last_as_of": result["as_of"], "last_watermark": result["watermark"], "last_window_secs": window, "source_started_at": int(self.started_at), "window_coverage_secs": min(window, max(0, int(now-self.started_at))), "window_partial": now-self.started_at < window, "last_metric_names": names, "raw_rows_exposed": False}
            dump(self.directory / "source-evidence.json", evidence)
            with (self.directory / "queries.jsonl").open("a") as output:
                output.write(json.dumps({"query": self.queries, "as_of": result["as_of"], "watermark": result["watermark"], "window_secs": window, "metrics": names, "sample_count": len(events)}) + "\n")
            return result


class SourceHandler(QuietHandler):
    server: RollingSource

    def do_GET(self):
        self.reply(200 if self.path == "/health" else 404, {"status": "ok", "source": "disposable rolling synthetic events"} if self.path == "/health" else {"error": "not_found"})

    def do_POST(self):
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + self.server.credential):
            with self.server.lock:
                self.server.denied += 1
            return self.reply(401, {"error": "source_credential_required"})
        if self.path != "/v1/metrics/query":
            return self.reply(404, {"error": "not_found"})
        try:
            request = json.loads(self.body())
            if not isinstance(request, dict) or set(request) != {"metrics", "window_secs"}:
                raise ValueError("exact query required")
            names, window = request["metrics"], request["window_secs"]
            if not isinstance(names, list) or not 1 <= len(names) <= len(METRICS) or not all(isinstance(name, str) and name in METRICS for name in names) or len(set(names)) != len(names) or type(window) is not int or not 1 <= window <= 300:
                raise ValueError("invalid aggregate scope")
        except (ValueError, TypeError):
            return self.reply(400, {"error": "bounded_named_aggregates_only"})
        return self.reply(200, self.server.aggregate(names, window))


class FixtureIssuer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, clients, directory, openssl):
        self.origin = f"http://127.0.0.1:{port}"
        self.clients = {client["client_id"]: client for client in clients}
        self.directory, self.openssl = Path(directory), openssl
        self.pending, self.codes, self.lock = {}, {}, threading.Lock()
        self.completed = 0
        super().__init__(("127.0.0.1", port), IssuerHandler)

    def claims(self, client, scopes):
        now = int(time.time())
        return {"iss": self.origin, "aud": client["resource"], "sub": client["subject"], "client_id": client["client_id"], "tenant_id": client["tenant_id"], "scope": " ".join(scopes), "jti": secrets.token_hex(16), "iat": now, "nbf": now, "exp": now + 900}


class IssuerHandler(QuietHandler):
    server: FixtureIssuer

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            return self.reply(200, {"issuer": self.server.origin, "authorization_endpoint": self.server.origin + "/authorize", "token_endpoint": self.server.origin + "/token", "jwks_uri": self.server.origin + "/jwks", "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"], "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"], "scopes_supported": SCOPES})
        if parsed.path == "/jwks":
            return self.reply(200, json.loads(TEST_JWKS.read_text()))
        if parsed.path != "/authorize":
            return self.reply(404, {"error": "not_found"})
        try:
            raw = parse_qs(parsed.query, strict_parsing=True)
            if any(len(value) != 1 for value in raw.values()):
                raise ValueError("duplicate parameters")
            query = {key: value[0] for key, value in raw.items()}
            allowed = {"response_type", "client_id", "redirect_uri", "resource", "scope", "state", "code_challenge", "code_challenge_method"}
            if set(query) != allowed:
                raise ValueError("exact authorization profile required")
            client = self.server.clients[query["client_id"]]
            scopes = query["scope"].split()
            if query["response_type"] != "code" or query["redirect_uri"] != client["redirect_uri"] or query["resource"] != client["resource"] or query["code_challenge_method"] != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", query["code_challenge"]) or not 16 <= len(query["state"]) <= 256 or not scopes or len(set(scopes)) != len(scopes) or not set(scopes) <= set(client["scopes"]):
                raise ValueError("authorization binding mismatch")
        except (ValueError, KeyError):
            return self.reply(400, {"error": "invalid_fixture_authorization_request"})
        ticket = secrets.token_urlsafe(32)
        with self.server.lock:
            self.server.pending = {key: value for key, value in self.server.pending.items() if value["expires"] > time.time()}
            if len(self.server.pending) >= 128:
                return self.reply(429, {"error": "fixture_pending_limit"})
            self.server.pending[ticket] = {"query": query, "expires": time.time() + 120}
        customer = html.escape(client["display_name"])
        text = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Opaque test sign-in</title><style>body{{background:#0d1117;color:#e5e9e4;font:16px/1.65 'Avenir Next',sans-serif;max-width:560px;margin:12vh auto;padding:24px}}small{{color:#edc27e;letter-spacing:.1em}}h1{{font-size:32px;font-weight:500;line-height:1.2}}p{{color:#a1ada9}}button{{background:#c2e77b;color:#0d1117;border:0;padding:14px 18px;font:inherit;cursor:pointer}}code{{font-size:12px;overflow-wrap:anywhere}}</style><small>DISPOSABLE OAUTH FIXTURE</small><h1>Continue as {customer}</h1><p>This test issuer creates a 15-minute customer-scoped access token. No real account, password, customer data, or human approval is involved.</p><p>Customer: <code>{html.escape(client['tenant_id'])}</code><br>Allowed scopes: <code>{html.escape(query['scope'])}</code></p><form method="post" action="/authorize"><input type="hidden" name="ticket" value="{ticket}"><button type="submit">Continue as test customer</button></form></html>'''
        # Browsers enforce form-action through the redirect chain. Permit only
        # this operator-registered callback origin, never an unvalidated query.
        callback = urlparse(client["redirect_uri"])
        callback_origin = callback.scheme + "://" + callback.netloc
        self.reply(200, text, "text/html; charset=utf-8", {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' " + callback_origin + "; frame-ancestors 'none'; base-uri 'none'"})

    def do_POST(self):
        if self.path not in ("/authorize", "/token"):
            return self.reply(404, {"error": "not_found"})
        try:
            raw = parse_qs(self.body().decode(), strict_parsing=True)
            if any(len(value) != 1 for value in raw.values()):
                raise ValueError("duplicate parameters")
            form = {key: value[0] for key, value in raw.items()}
        except (ValueError, UnicodeError):
            return self.reply(400, {"error": "invalid_fixture_form"})
        if self.path == "/authorize":
            if self.headers.get("Origin") != self.server.origin or set(form) != {"ticket"}:
                return self.reply(403, {"error": "fixture_origin_required"})
            with self.server.lock:
                pending = self.server.pending.pop(form["ticket"], None)
                if not pending or pending["expires"] <= time.time():
                    return self.reply(400, {"error": "fixture_signin_expired"})
                code = secrets.token_urlsafe(32)
                self.server.codes[code] = pending
            query = pending["query"]
            return self.reply(303, "", "text/plain", {"Location": query["redirect_uri"] + "?" + urlencode({"code": code, "state": query["state"]})})
        required = {"grant_type", "code", "client_id", "redirect_uri", "resource", "code_verifier"}
        if set(form) != required or form["grant_type"] != "authorization_code":
            return self.reply(400, {"error": "exact_fixture_token_exchange_required"})
        with self.server.lock:
            pending = self.server.codes.get(form["code"])
            if not pending or pending["expires"] <= time.time():
                return self.reply(400, {"error": "invalid_grant"})
            query = pending["query"]
            verifier = form["code_verifier"]
            valid = re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) and encode(hashlib.sha256(verifier.encode()).digest()) == query["code_challenge"]
            if not valid or any(form[key] != query[key] for key in ("client_id", "redirect_uri", "resource")):
                return self.reply(400, {"error": "invalid_grant"})
            del self.server.codes[form["code"]]
            self.server.completed += 1
            dump(self.server.directory / "issuer-evidence.json", {"completed_exchanges": self.server.completed, "pkce": "S256", "token_type": "at+jwt RS256", "registered_customer_clients": len(self.server.clients), "test_issuer": True, "token_logging": False})
        client = self.server.clients[query["client_id"]]
        token = signed_token(self.server.claims(client, query["scope"].split()), self.server.openssl)
        return self.reply(200, {"access_token": token, "token_type": "Bearer", "expires_in": 900, "scope": query["scope"]})


def internal_mode(args):
    config = json.loads(args.config.read_text())
    if args.internal == "source":
        server = RollingSource(config["port"], config["tenant_id"], config["index"], os.environ["OPAQUE_FIXTURE_SOURCE_KEY"], args.config.parent)
    else:
        server = FixtureIssuer(config["port"], config["clients"], args.config.parent, config["openssl"])
    server.serve_forever()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def http(url, *, body=None, headers=None, opener=None, timeout=60):
    headers = dict(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode()
    request = urllib.request.Request(url, data=body, headers=headers)
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()


def sse_events(raw):
    events = []
    for frame in raw.decode().replace("\r\n", "\n").split("\n\n"):
        lines = frame.splitlines()
        event = next((line[6:].strip() for line in lines if line.startswith("event:")), "message")
        data = "\n".join(line[5:].lstrip() for line in lines if line.startswith("data:"))
        if data:
            events.append({"event": event, "data": json.loads(data)})
    return events


class ChatFixture:
    def __init__(self, args, directory):
        self.args, self.directory = args, directory
        self.processes, self.logs, self.gateways, self.clients = [], [], [], []
        self.keys = [secrets.token_urlsafe(32), secrets.token_urlsafe(32)]
        self.env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "TMPDIR") if key in os.environ}
        self.env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
        self.openssl = shutil.which("openssl")
        if not self.openssl:
            raise RuntimeError("OpenSSL is required for the disposable OAuth issuer")
        self.issuer = f"http://127.0.0.1:{args.issuer_port}"
        self.binary = ROOT / "target/debug/opaque-metrics"
        self.configs = []
        for port in [args.port, args.port + 1, args.issuer_port, args.source_port, args.source_port + 1]:
            with socket.socket() as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", port))

    def spawn(self, name, command, extra_env=None):
        log = (self.directory / (name + ".log")).open("ab")
        self.logs.append(log)
        process = subprocess.Popen(command, env=dict(self.env, **(extra_env or {})), cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    def wait(self, url, process, expected=200):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Fixture process exited; inspect retained process log")
            try:
                if http(url, timeout=1)[0] == expected:
                    return
            except OSError:
                pass
            time.sleep(.1)
        raise RuntimeError("Fixture listener was not ready within its startup deadline")

    def prepare(self):
        if not self.args.no_build:
            subprocess.run(["cargo", "build", "--locked", "-p", "opaque-metrics"], cwd=ROOT, env=dict(self.env, CARGO_INCREMENTAL="0"), check=True)
        if not self.binary.is_file():
            raise RuntimeError("Build the opaque-metrics native binary before --no-build")
        public_key = subprocess.run([self.openssl, "pkey", "-in", str(TEST_KEY), "-pubout"], capture_output=True, text=True, check=True).stdout
        for index, suffix in enumerate(["a", "b"]):
            tenant = "synthetic-" + suffix
            origin = f"http://127.0.0.1:{self.args.port + index}"
            metrics = METRICS if index == 0 else METRICS[:2]
            scopes = ["metrics:read", "metrics:stream", "metrics:explain", *("metrics:metric:" + name for name in metrics)]
            directory = self.directory / tenant
            directory.mkdir(mode=0o700)
            source_dir = directory / "source"
            source_dir.mkdir(mode=0o700)
            client = {"client_id": "opaque-chat-" + suffix, "tenant_id": tenant, "subject": "analyst-" + suffix, "display_name": "Customer " + suffix.upper(), "resource": origin + "/mcp", "redirect_uri": origin + "/auth/callback", "scopes": scopes}
            self.clients.append(client)
            dump(source_dir / "config.json", {"port": self.args.source_port + index, "tenant_id": tenant, "index": index})
            config = {"bind": f"127.0.0.1:{self.args.port + index}", "public_origin": origin, "tenant_id": tenant, "customer_name": client["display_name"], "state_dir": str(directory / "gateway-state"), "auth": {"issuer": self.issuer, "resource_audience": client["resource"], "public_key_pem": public_key, "admissions": [{"tenant_id": tenant, "subject": client["subject"], "scopes": scopes}], "revoked_jtis": ["fixture-revoked"], "allow_loopback_http": True}, "oauth": {"authorization_endpoint": self.issuer + "/authorize", "token_endpoint": self.issuer + "/token", "client_id": client["client_id"], "scopes": scopes}, "source": {"tenant_id": tenant, "source_id": "rolling-events-" + suffix, "base_url": f"http://127.0.0.1:{self.args.source_port + index}", "credential_env": "OPAQUE_METRICS_SOURCE_KEY", "allowed_metrics": metrics, "max_window_secs": 300, "max_staleness_secs": 5, "allow_loopback_http": True}, "model": {"kind": "fixture"}, "fixture_mode": True}
            self.configs.append(config)
            dump(directory / "gateway.json", config)
        issuer_dir = self.directory / "issuer"
        issuer_dir.mkdir(mode=0o700)
        dump(issuer_dir / "config.json", {"port": self.args.issuer_port, "clients": self.clients, "openssl": self.openssl})
        dump(self.directory / "binary-digest.json", {"opaque-metrics": hashlib.sha256(self.binary.read_bytes()).hexdigest()})

    def start_gateway(self, index):
        config = self.configs[index]
        process = self.spawn("gateway-" + str(index), [str(self.binary), "--config", str(self.directory / config["tenant_id"] / "gateway.json")], {"OPAQUE_METRICS_SOURCE_KEY": self.keys[index]})
        self.wait(config["public_origin"] + "/api/session", process, 401)
        if len(self.gateways) > index:
            self.gateways[index] = process
        else:
            self.gateways.append(process)

    def start(self):
        issuer = self.spawn("issuer", [sys.executable, "-B", str(Path(__file__).resolve()), "--internal", "issuer", "--config", str(self.directory / "issuer/config.json")])
        self.wait(self.issuer + "/.well-known/oauth-authorization-server", issuer)
        for index, config in enumerate(self.configs):
            path = self.directory / config["tenant_id"] / "source/config.json"
            source = self.spawn("source-" + str(index), [sys.executable, "-B", str(Path(__file__).resolve()), "--internal", "source", "--config", str(path)], {"OPAQUE_FIXTURE_SOURCE_KEY": self.keys[index]})
            self.wait(config["source"]["base_url"] + "/health", source)
            self.start_gateway(index)

    def browser_login(self, index):
        jar = CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar), NoRedirect())
        origin = self.configs[index]["public_origin"]
        status, headers, _ = http(origin + "/auth/login", opener=opener)
        assert status in (302, 303, 307), "Login must redirect to registered issuer"
        authorization = headers["Location"]
        assert authorization.startswith(self.issuer + "/authorize?")
        status, authorization_headers, body = http(authorization, opener=opener)
        assert status == 200 and b"DISPOSABLE OAUTH FIXTURE" in body
        form_policy = authorization_headers["Content-Security-Policy"].split("form-action ", 1)[1].split(";", 1)[0]
        assert form_policy == "'self' " + origin, "Fixture sign-in form must permit only its registered callback origin"
        ticket = re.search(rb'name="ticket" value="([^"]+)"', body).group(1).decode()
        status, headers, _ = http(self.issuer + "/authorize", body=urlencode({"ticket": ticket}), headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": self.issuer}, opener=opener)
        assert status == 303
        callback = headers["Location"]
        assert callback.startswith(origin + "/auth/callback?")
        status, headers, _ = http(callback, opener=opener)
        assert status in (302, 303), "OAuth callback must establish the scoped session"
        cookies = headers.get_all("Set-Cookie", [])
        assert any("HttpOnly" in cookie and "SameSite=" in cookie for cookie in cookies)
        status, _, raw = http(origin + "/api/session", opener=opener)
        session = json.loads(raw)
        assert status == 200 and session["customer"]["id"] == self.clients[index]["tenant_id"]
        assert {metric["id"] for metric in session["allowed_metrics"]} == set(self.configs[index]["source"]["allowed_metrics"])
        assert "token" not in json.dumps(session).lower()
        return opener, session

    def token(self, index, changes=None, header=None):
        client = self.clients[index]
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": client["resource"], "sub": client["subject"], "client_id": client["client_id"], "tenant_id": client["tenant_id"], "scope": " ".join(client["scopes"]), "jti": secrets.token_hex(16), "iat": now, "nbf": now, "exp": now + 900}
        claims.update(changes or {})
        return signed_token(claims, self.openssl, header)

    def mcp(self, index, token, arguments=None, method="tools/call"):
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {"name": "opaque_metrics_query", "arguments": arguments or {"metrics": ["requests_per_second"], "window_secs": 60}}}
        return http(self.configs[index]["public_origin"] + "/mcp", body=request, headers={"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"})

    def counts(self):
        values = []
        for client in self.clients:
            path = self.directory / client["tenant_id"] / "source/queries.jsonl"
            values.append(len(path.read_text().splitlines()) if path.exists() else 0)
        return values

    def revoke_during_stream(self, index):
        origin = self.configs[index]["public_origin"]
        opener, _ = self.browser_login(index)
        request = urllib.request.Request(origin + "/api/chat", data=json.dumps({"message": "Watch my request rate live"}).encode(), headers={"Content-Type": "application/json", "Origin": origin, "Accept": "text/event-stream"})
        with opener.open(request, timeout=30) as response:
            first = b""
            while True:
                line = response.readline()
                if not line:
                    raise AssertionError("No observation arrived before stream revocation")
                first += line
                if line in (b"\n", b"\r\n") and any(item["event"] == "result" for item in sse_events(first)):
                    break
            before = self.counts()
            status, _, _ = http(origin + "/auth/logout", body=b"", headers={"Origin": origin}, opener=opener)
            assert status in (200, 204, 303)
            events = sse_events(first + response.read())
        assert any(item["event"] == "error" and item["data"]["code"] == "auth_expired" for item in events)
        assert all(item["data"]["sequence"] == 1 for item in events if item["event"] == "result")
        assert self.counts() == before, "Revoked stream made a new source query"
        dump(self.directory / self.clients[index]["tenant_id"] / "revoked-stream-evidence.json", events)
        return {"stream_revocation_stopped_future_queries": True, "source_counts_after_first_snapshot": before}

    def check(self):
        evidence = {"runtime": "native shared-host processes", "issuer": "disposable OAuth code + PKCE fixture", "model": "deterministic test parser", "negative_checks": [], "customers": []}
        for index in [0, 1]:
            origin = self.configs[index]["public_origin"]
            opener, session = self.browser_login(index)
            token = self.token(index)
            status, _, raw = self.mcp(index, token)
            result = json.loads(raw)
            assert status == 200 and result["result"]["isError"] is False
            assert result["result"]["structuredContent"]["tenant_id"] == self.clients[index]["tenant_id"]
            before = self.counts()
            source_url = self.configs[index]["source"]["base_url"] + "/v1/metrics/query"
            source_query = {"metrics": ["requests_per_second"], "window_secs": 60}
            for name, credential in [("missing_source_key", None), ("other_customer_source_key", self.keys[1-index]), ("customer_access_token_at_source", token)]:
                headers = {"Authorization": "Bearer " + credential} if credential else {}
                status, _, _ = http(source_url, body=source_query, headers=headers)
                assert status == 401, "Unrelated source credential was accepted"
                evidence["negative_checks"].append({"customer": index, "case": name, "status": status})
            assert self.counts() == before, "Rejected source credential reached aggregate computation"
            now = int(time.time())
            tokens = {"wrong_tenant": self.token(index, {"tenant_id": self.clients[1-index]["tenant_id"]}), "wrong_audience": self.token(index, {"aud": self.clients[1-index]["resource"]}), "expired": self.token(index, {"iat": now-60, "nbf": now-60, "exp": now-1}), "revoked": self.token(index, {"jti": "fixture-revoked"}), "id_token_type": self.token(index, header={"alg": "RS256", "typ": "JWT"}), "read_scope_missing": self.token(index, {"scope": "metrics:explain"})}
            tampered = token.split(".")
            claims = json.loads(base64.urlsafe_b64decode(tampered[1] + "=" * (-len(tampered[1]) % 4)))
            claims["tenant_id"] = self.clients[1-index]["tenant_id"]
            tampered[1] = encode(json.dumps(claims).encode())
            tokens["tampered_payload"] = ".".join(tampered)
            for name, probe in tokens.items():
                status, _, _ = self.mcp(index, probe)
                assert status in (401, 403), name + " was accepted"
                evidence["negative_checks"].append({"customer": index, "case": name, "status": status})
            for extra in [{"tenant_id": self.clients[1-index]["tenant_id"]}, {"sql": "SELECT * FROM private"}, {"source_url": "http://127.0.0.1:1"}]:
                status, _, raw = self.mcp(index, token, {"metrics": ["requests_per_second"], "window_secs": 60, **extra})
                assert status == 200 and json.loads(raw)["error"]["code"] == -32602
            if index == 1:
                status, _, _ = self.mcp(index, token, {"metrics": ["p95_latency_ms"], "window_secs": 60})
                assert status == 403
            assert self.counts() == before, "Denied authority reached a source"
            status, _, raw = http(origin + "/api/chat", body={"message": "Watch my request rate and error rate live"}, headers={"Origin": origin, "Accept": "text/event-stream"}, opener=opener)
            events = sse_events(raw)
            assert status == 200 and not any(item["event"] == "error" for item in events)
            results = [item["data"] for item in events if item["event"] == "result"]
            sequences = {result["sequence"] for result in results}
            assert len(sequences) >= 3 and any(item["event"] == "answer" for item in events) and events[-1]["event"] == "done"
            assert len({result["watermark"] for result in results}) >= 2
            assert all(result["metric_id"] in self.configs[index]["source"]["allowed_metrics"] for result in results)
            dump(self.directory / self.clients[index]["tenant_id"] / "chat-evidence.json", events)
            before = self.counts()
            status, _, raw = http(origin + "/api/chat", body={"message": "Show other customer metrics"}, headers={"Origin": origin, "Accept": "text/event-stream"}, opener=opener)
            assert status == 200 and any(item["event"] == "error" for item in sse_events(raw))
            assert self.counts() == before
            status, _, _ = http(origin + "/auth/logout", body=b"", headers={"Origin": origin}, opener=opener)
            assert status in (200, 204, 303)
            assert http(origin + "/api/session", opener=opener)[0] == 401
            interrupted = self.revoke_during_stream(index)
            evidence["customers"].append({"tenant_id": self.clients[index]["tenant_id"], "dashboard": origin, "allowed_metrics": self.configs[index]["source"]["allowed_metrics"], "stream_sequences": len(sequences), "cookie_http_only": True, "logout_revoked": True, **interrupted})
        # The source remains reachable while its event watermark stops moving.
        # The gateway must reject stale data despite a fresh HTTP receipt time.
        for client in self.clients:
            dump(self.directory / client["tenant_id"] / "source/control.json", {"paused": True})
        time.sleep(7)
        for index, client in enumerate(self.clients):
            for window in [60, 1]:
                status, _, raw = self.mcp(index, self.token(index), {"metrics": ["requests_per_second"], "window_secs": window})
                result = json.loads(raw)
                assert status == 200 and result["result"]["isError"] is True and "structuredContent" not in result["result"], "Paused stale source was shown as fresh evidence"
                evidence["negative_checks"].append({"customer": index, "case": "paused_source_stale_watermark", "window_secs": window, "denied": True})
            dump(self.directory / client["tenant_id"] / "source/control.json", {"paused": False})
        evidence["source_query_counts"] = self.counts()
        evidence["result"] = "passed"
        dump(self.directory / "check-evidence.json", evidence)
        print("PASS: two customer OAuth sessions, scoped MCP metrics, changing streamed source snapshots, denied forged authority and logout revocation.", flush=True)

    def stop_process(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def serve(self):
        if not self.args.fixture_model:
            # The check uses the deterministic parser; the visible demo requires
            # a fresh browser login after switching to the configured live model.
            for index, config in enumerate(self.configs):
                self.stop_process(self.gateways[index])
                config["model"] = {"kind": "openai_compatible", "base_url": self.args.model_base_url, "model": self.args.model_id, "allow_loopback_http": True}
                dump(self.directory / config["tenant_id"] / "gateway.json", config)
                self.start_gateway(index)
        summary = {"runtime": "native shared-host processes; not microVM isolation", "model": "deterministic fixture parser" if self.args.fixture_model else self.args.model_id, "source": "two separate synthetic rolling event processes", "oauth": "disposable issuer with 15-minute access tokens", "check_evidence": str(self.directory / "check-evidence.json"), "customers": [{"tenant_id": config["tenant_id"], "dashboard": config["public_origin"], "pid": self.gateways[index].pid, "source_id": config["source"]["source_id"], "allowed_metrics": config["source"]["allowed_metrics"]} for index, config in enumerate(self.configs)]}
        dump(self.directory / "live-summary.json", summary)
        for config in self.configs:
            print(config["customer_name"] + ": " + config["public_origin"] + " · Sign in through the labeled test issuer", flush=True)
        print("Synthetic metric sources / test OAuth issuer / shared-host processes. Ctrl-C stops only this fixture.", flush=True)
        while True:
            if any(process.poll() is not None for process in self.processes if process in self.gateways or process.args[0] == sys.executable):
                raise RuntimeError("A live fixture child exited; evidence is retained")
            time.sleep(1)

    def close(self):
        for process in reversed(self.processes):
            self.stop_process(process)
        for log in self.logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal", choices=["source", "issuer"])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--fixture-model", action="store_true", help="Use an explicit deterministic test parser instead of Gemma for --serve")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--port", type=int, default=19400)
    parser.add_argument("--issuer-port", type=int, default=19402)
    parser.add_argument("--source-port", type=int, default=19403)
    parser.add_argument("--model-base-url", default="http://127.0.0.1:19680/")
    parser.add_argument("--model-id", default="gemma-4-E2B-it-Q3_K_M.gguf")
    args = parser.parse_args()
    if args.internal:
        internal_mode(args)
        return 0
    ports = [args.port, args.port+1, args.issuer_port, args.source_port, args.source_port+1]
    if len(set(ports)) != 5 or any(not 1024 <= port <= 65535 for port in ports):
        parser.error("Choose five distinct unprivileged local ports")
    directory = (args.data_dir or Path(tempfile.mkdtemp(prefix="omf-", dir="/tmp"))).expanduser().resolve()
    if directory.exists() and any(directory.iterdir()):
        parser.error("Use a fresh disposable data directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    fixture = None
    try:
        print("Metrics chat state: " + str(directory), flush=True)
        fixture = ChatFixture(args, directory)
        fixture.prepare()
        fixture.start()
        fixture.check()
        if args.serve:
            fixture.serve()
    except KeyboardInterrupt:
        pass
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError, KeyError, ValueError) as error:
        print("METRICS CHAT FAILED: " + str(error), file=sys.stderr)
        return 1
    finally:
        if fixture:
            fixture.close()
        print("Retained evidence: " + str(directory), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
