#!/usr/bin/env python3
"""Disposable synthetic metrics workspace. No visitor code or production credentials."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlsplit
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("metrics_fixture", ROOT / "scripts/metrics_chat_dogfood.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
CREDIT_SPEC = importlib.util.spec_from_file_location("credit_source", Path(__file__).with_name("credit_source.py"))
credit = importlib.util.module_from_spec(CREDIT_SPEC)
CREDIT_SPEC.loader.exec_module(credit)
PROFILE_SPEC = importlib.util.spec_from_file_location("opaque_demo_model_profiles", Path(__file__).with_name("model_profiles.py"))
profiles = importlib.util.module_from_spec(PROFILE_SPEC)
PROFILE_SPEC.loader.exec_module(profiles)

PERSONAS = ("customer_analyst", "engineer", "support")
CONTROL_PATHS = {"/api/demo/persona", "/api/organization/sharing"}
TASK_PATHS = {"/api/work-task/approve", "/api/work-task/execute", "/api/work-task/revoke"}
APPROVAL_PATHS = {"/api/work-task/approval/start", "/api/work-task/approval/finish"}
TASK_RESPONSE_PATHS = TASK_PATHS | APPROVAL_PATHS | {"/api/work-task", "/api/work-task/approval"}
APPROVAL_ENV = ("OPAQUE_DEMO_APPROVAL_ORIGIN", "OPAQUE_DEMO_OAUTH_PROVIDER", "OPAQUE_DEMO_OAUTH_ISSUER", "OPAQUE_DEMO_OAUTH_CLIENT_ID",
                "OPAQUE_DEMO_OAUTH_CLIENT_SECRET", "OPAQUE_DEMO_OAUTH_REDIRECT_URI")


def task_body(value):
    """A task reference can confirm reviewed work; it cannot select new work."""
    if (not isinstance(value, dict) or set(value) != {"task_id", "manifest_sha256"}
            or not isinstance(value["task_id"], str)
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["task_id"])
            or not isinstance(value["manifest_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["manifest_sha256"])):
        raise ValueError("bounded task reference required")
    return value


def approval_body(path, value):
    """Forward proof for an existing task, never caller-selected authority."""
    if not isinstance(value, dict):
        raise ValueError("object required")
    task_body({key: value.get(key) for key in ("task_id", "manifest_sha256")})
    required = {"task_id", "manifest_sha256"}
    if path == "/api/work-task/approval/start":
        if set(value) != required | {"method"} or value["method"] not in ("passkey", "oauth"):
            raise ValueError("invalid approval method")
    else:
        required.add("transaction_id")
        transaction = value.get("transaction_id")
        if not isinstance(transaction, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", transaction):
            raise ValueError("invalid approval transaction")
        if set(value) == required | {"credential"}:
            if not isinstance(value["credential"], dict):
                raise ValueError("invalid approval credential")
        elif set(value) == required | {"code", "state"}:
            code, state = value["code"], value["state"]
            if (not isinstance(code, str) or not 0 < len(code.encode()) <= 4096
                    or any(ord(ch) <= 32 or ord(ch) == 127 for ch in code)
                    or not isinstance(state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", state)):
                raise ValueError("invalid approval OAuth response")
        else:
            raise ValueError("invalid approval proof")
    return value


def control_body(path, value):
    """Only fixed demo controls, never identity, endpoint or scope authority."""
    if not isinstance(value, dict):
        raise ValueError("object required")
    if path == "/api/demo/persona":
        selected = value.get("persona_id")
        if selected not in PERSONAS:
            raise ValueError("invalid demo persona")
        if selected == "support":
            reason = value.get("reason")
            if (set(value) != {"persona_id", "reason"} or not isinstance(reason, str)
                    or len(reason.strip()) < 8 or len(reason.encode()) > 240
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in reason)):
                raise ValueError("bounded support reason required")
        elif set(value) != {"persona_id"}:
            raise ValueError("invalid demo persona")
    elif path == "/api/organization/sharing":
        if set(value) != {"enabled"} or type(value["enabled"]) is not bool:
            raise ValueError("invalid question sharing")
    else:
        raise ValueError("invalid control route")
    return value


def organization_clients(config, origin):
    metrics = ["metrics:read", "metrics:stream", "metrics:explain",
               *("metrics:metric:" + name for name in credit.ALLOWED_METRICS),
               "portfolio:read", *("portfolio:measure:" + name for name in credit.PORTFOLIO_MEASURES)]
    members, clients = [], []
    for persona, subject, suffix in (("customer_analyst", "portfolio-analyst", "analyst"),
                                     ("engineer", "product-engineer", "engineer"),
                                     ("support", "customer-support", "support")):
        scopes = ["organization:activity:read"]
        if persona != "engineer":
            scopes += [scope for scope in metrics if persona != "support" or scope != "metrics:stream"]
        client_id = "demo-" + config["lease_id"] + "-" + suffix
        members.append({"subject": subject, "persona_id": persona, "oauth_client_id": client_id})
        clients.append({"client_id": client_id, "tenant_id": config["tenant_id"], "subject": subject,
                        "display_name": "Harborlight Credit Union", "resource": origin + "/mcp",
                        "redirect_uri": origin + "/auth/callback", "scopes": scopes})
    organization = {"id": "northstar-" + config["lease_id"], "display_name": "Northstar Financial Systems",
                    "members": members, "other_customer": {"id": "cedar-" + config["lease_id"],
                                                            "display_name": "Cedar Community Bank"}}
    return clients, organization


class LeaseIssuer(fixture.FixtureIssuer):
    def claims(self, client, scopes):
        claims = super().claims(client, scopes)
        claims["exp"] = min(claims["exp"], self.lease_expires_at_ms // 1000)
        return claims


def configuration(env):
    lease = env["OPAQUE_DEMO_LEASE_ID"]
    tenant = env["OPAQUE_DEMO_TENANT_ID"]
    secret = env["OPAQUE_DEMO_PROXY_SECRET"]
    generation = int(env["OPAQUE_DEMO_GENERATION"])
    expires = int(env["OPAQUE_DEMO_EXPIRES_AT_MS"])
    if not re.fullmatch(r"[a-f0-9]{32}", lease) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", tenant):
        raise ValueError("invalid lease identity")
    if generation < 1 or not re.fullmatch(r"[a-f0-9]{64,128}", secret):
        raise ValueError("invalid lease authority")
    if not 0 < expires - int(time.time()*1000) <= 900_000:
        raise ValueError("lease deadline is not bounded")
    selected, model = profiles.runtime_binding(
        env.get("OPAQUE_DEMO_MODEL_PROFILE", profiles.LEGACY_PROFILE_ID),
        env["OPAQUE_DEMO_MODEL_URL"], env["OPAQUE_DEMO_MODEL_ID"],
        env.get("OPAQUE_DEMO_MODEL_TEST_ORIGIN"))
    approval_env = {name: env[name] for name in APPROVAL_ENV if env.get(name)}
    if "OPAQUE_DEMO_APPROVAL_ORIGIN" in approval_env:
        origin = urlsplit(approval_env["OPAQUE_DEMO_APPROVAL_ORIGIN"])
        if (not origin.hostname or origin.username or origin.password or origin.path or origin.query or origin.fragment
                or (origin.scheme != "https" and not (origin.scheme == "http" and origin.hostname in {"127.0.0.1", "localhost"}))):
            raise ValueError("invalid approval public origin")
    return {"lease_id":lease,"tenant_id":tenant,"generation":generation,"expires_at":expires,"secret":secret,
            "model":model,"model_id":selected.model,"model_profile":selected.profile_id,"approval_env":approval_env}


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def bounded_body(self, limit):
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            raise ValueError("exact content length required")
        length = int(self.headers["Content-Length"])
        if not 0 < length <= limit:
            raise ValueError("request too large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("incomplete body")
        return body


class Runtime:
    def __init__(self, config, directory):
        self.config, self.directory = config, Path(directory)
        self.lock = threading.Lock()
        self.identity_lock = threading.Lock()
        self.active_requests = self.model_requests = self.model_unknown = 0
        self.ready = False
        self.cookie = ""
        self.persona_cookies = {}
        self.persona = "customer_analyst"
        self.gateway = None
        self.servers = []

    def expired(self):
        return int(time.time()*1000) >= self.config["expires_at"]

    def health(self):
        with self.lock:
            return {"ready":self.ready and not self.expired() and self.gateway.poll() is None,
                    "lease_id":self.config["lease_id"],"generation":self.config["generation"],
                    "model_profile":self.config["model_profile"],"model_id":self.config["model_id"],
                    "model_url":self.config["model"].geturl(),
                    "expires_at":self.config["expires_at"],"active_requests":self.active_requests,
                    "model_requests_in_flight":self.model_requests + self.model_unknown,
                    "model_execution_uncertain":bool(self.model_unknown)}

    def start(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = self.directory / "issuer-private.pem"
        public = self.directory / "issuer-public.pem"
        subprocess.run(["openssl","genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out",str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        subprocess.run(["openssl","pkey","-in",str(key),"-pubout","-out",str(public)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        fixture.TEST_KEY = key
        modulus = subprocess.run(["openssl","rsa","-pubin","-in",str(public),"-modulus","-noout"],capture_output=True,check=True,text=True).stdout.strip().split("=",1)[1]
        jwks = self.directory / "jwks.json"
        fixture.dump(jwks,{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"test-key-1","n":fixture.encode(bytes.fromhex(modulus)),"e":"AQAB"}]})
        fixture.TEST_JWKS = jwks
        origin, issuer = "http://127.0.0.1:8081", "http://127.0.0.1:8082"
        names = list(credit.ALLOWED_METRICS)
        clients, organization = organization_clients(self.config, origin)
        client, scopes = clients[0], clients[0]["scopes"]
        fixture.SCOPES = sorted({scope for c in clients for scope in c["scopes"]})
        for name in ("source", "issuer"):
            (self.directory/name).mkdir(mode=0o700)
        source_secret = secrets.token_urlsafe(32)
        source = credit.CreditSource(8083,self.config["tenant_id"],source_secret,self.directory/"source")
        auth = LeaseIssuer(8082,clients,self.directory/"issuer","openssl")
        auth.lease_expires_at_ms = self.config["expires_at"]
        bridge = ThreadingHTTPServer(("127.0.0.1",8084),ModelBridge)
        bridge.runtime = self
        self.servers = [source,auth,bridge]
        for server in self.servers:
            threading.Thread(target=server.serve_forever,daemon=True).start()
        config = {"bind":"127.0.0.1:8081","public_origin":origin,"tenant_id":self.config["tenant_id"],"customer_name":client["display_name"],"experience":"credit_portfolio","state_dir":str(self.directory/"gateway"),"auth":{"issuer":issuer,"resource_audience":client["resource"],"public_key_pem":public.read_text(),"admissions":[{"tenant_id":client["tenant_id"],"subject":client["subject"],"client_id":client["client_id"],"scopes":scopes}],"allow_loopback_http":True},"oauth":{"authorization_endpoint":issuer+"/authorize","token_endpoint":issuer+"/token","client_id":client["client_id"],"scopes":scopes},"source":{"tenant_id":client["tenant_id"],"source_id":"loan-application-stream-"+self.config["lease_id"][:8],"base_url":"http://127.0.0.1:8083","credential_env":"OPAQUE_METRICS_SOURCE_KEY","allowed_metrics":names,"max_window_secs":300,"max_staleness_secs":5,"allow_loopback_http":True},"model":{"kind":"openai_compatible","base_url":"http://127.0.0.1:8084/","model":self.config["model_id"],"allow_loopback_http":True},"fixture_mode":True}
        config["source"]["allowed_portfolio_measures"] = list(credit.PORTFOLIO_MEASURES)
        path = self.directory/"gateway.json"
        config["auth"]["admissions"] = [{"tenant_id": c["tenant_id"], "subject": c["subject"],
                                          "client_id": c["client_id"], "scopes": c["scopes"]} for c in clients]
        config["organization_demo"] = organization
        fixture.dump(path,config)
        binary = os.environ.get("OPAQUE_METRICS_BINARY", "/opt/opaque/bin/opaque-metrics")
        self.gateway = subprocess.Popen([binary,"--config",str(path)],env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),"OPAQUE_METRICS_SOURCE_KEY":source_secret,**self.config["approval_env"]},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if self.gateway.poll() is not None:
                raise RuntimeError("gateway startup failed")
            try:
                if fixture.http(origin+"/api/session",timeout=1)[0]==401:
                    break
            except OSError:
                pass
            time.sleep(.1)
        else:
            raise RuntimeError("gateway startup deadline")
        # Each preauthorized demo persona completes its own PKCE exchange.
        # These cookies and signed identities remain inside the runtime.
        for persona, configured_client in zip(PERSONAS, clients):
            self.persona_cookies[persona] = self.login_persona(persona, configured_client, origin, issuer)
        self.cookie = self.persona_cookies["customer_analyst"]
        self.ready=True

    def login_persona(self, persona, client, origin, issuer):
        jar=CookieJar()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar),fixture.NoRedirect())
        status,headers,_=fixture.http(origin+"/auth/login?"+urlencode({"persona_id": persona}),opener=opener)
        if status not in (302,303,307) or not headers["Location"].startswith(issuer+"/authorize?"):
            raise RuntimeError("demo authorization did not start")
        status,_,body=fixture.http(headers["Location"],opener=opener)
        ticket=re.search(rb'name="ticket" value="([^"]+)"',body)
        if status!=200 or not ticket:
            raise RuntimeError("demo authorization challenge failed")
        status,headers,_=fixture.http(issuer+"/authorize",body=urlencode({"ticket":ticket.group(1).decode()}),headers={"Content-Type":"application/x-www-form-urlencoded","Origin":issuer},opener=opener)
        if status!=303 or not headers["Location"].startswith(origin+"/auth/callback?"):
            raise RuntimeError("demo callback binding failed")
        status,_,_=fixture.http(headers["Location"],opener=opener)
        status,_,body=fixture.http(origin+"/api/session",opener=opener)
        session = json.loads(body) if status == 200 else {}
        if (status!=200 or session.get("customer",{}).get("id")!=self.config["tenant_id"]
                or session.get("subject",{}).get("id") != client["subject"]):
            raise RuntimeError("demo customer binding failed")
        cookie="; ".join(cookie.name+"="+cookie.value for cookie in jar if cookie.name == "opaque_metrics_8081")
        if not cookie:
            raise RuntimeError("no private gateway session")
        return cookie

    def stop(self):
        self.ready=False
        if self.gateway is not None and self.gateway.poll() is None:
            self.gateway.terminate()
            try:
                self.gateway.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.gateway.kill()
        for server in self.servers:
            server.shutdown()


class ModelBridge(QuietHandler):
    def do_POST(self):
        runtime=self.server.runtime
        if self.path!="/v1/chat/completions" or runtime.expired():
            return self.reply(403,{"error":"model_route_unavailable"})
        try:
            body=self.bounded_body(32768)
            value=json.loads(body)
            if not isinstance(value,dict) or value.get("model") != runtime.config["model_id"]:
                raise ValueError("model does not match lease profile")
        except (ValueError,OSError):
            return self.reply(400,{"error":"invalid_model_request"})
        with runtime.lock:
            if runtime.model_requests or runtime.model_unknown:
                return self.reply(409,{"error":"model_execution_busy_or_unknown"})
            runtime.model_requests+=1
        complete=False
        connection=None
        try:
            model=runtime.config["model"]
            connection=http.client.HTTPConnection(model.hostname,model.port or 80,timeout=55)
            connection.request("POST","/v1/chat/completions",body=body,headers={"Content-Type":"application/json"})
            response=connection.getresponse()
            result=response.read(32769)
            if len(result)>32768 or not response.isclosed() or response.length not in (None, 0):
                raise ValueError("model response too large or incomplete")
            complete=True
            self.send_response(response.status)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(result)))
            self.end_headers()
            self.wfile.write(result)
        except (OSError,ValueError,http.client.HTTPException):
            try:
                self.reply(502,{"error":"model_execution_uncertain"})
            except OSError:
                pass
        finally:
            if connection:
                connection.close()
            with runtime.lock:
                runtime.model_requests-=1
                if not complete:
                    runtime.model_unknown+=1


class Proxy(QuietHandler):
    def do_GET(self):
        self.proxy()

    def do_POST(self):
        self.proxy()

    def control_proxy(self, runtime, target, body, value):
        # A failed or overlapping activation cannot leave a browser-selected
        # cookie paired with a different gateway persona.
        with runtime.identity_lock:
            if not runtime.ready or runtime.expired():
                return self.reply(410, {"error": "demo_expired"})
            with runtime.lock:
                if runtime.active_requests or runtime.model_requests or runtime.model_unknown:
                    return self.reply(409, {"error": "request_in_progress"})
            selected = value["persona_id"] if target == "/api/demo/persona" else runtime.persona
            cookie = runtime.persona_cookies.get(selected)
            if not cookie:
                return self.reply(503, {"error": "demo_identity_unavailable"})
            connection = http.client.HTTPConnection("127.0.0.1", 8081, timeout=15)
            stage = "connect"
            try:
                connection.request("POST", target, body=body, headers={"Cookie": cookie,
                    "Origin": "http://127.0.0.1:8081", "Content-Type": "application/json", "Accept": "application/json"})
                response = connection.getresponse()
                stage = "read"
                chunks, size = [], 0
                while True:
                    chunk = response.read1(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > 65536:
                        raise ValueError("control response too large")
                # Python 3.11 read1 leaves a fully consumed Content-Length
                # response open. Finalize it without accepting extra bytes.
                if response.read(1):
                    raise ValueError("unexpected control response bytes")
                if not response.isclosed() or response.length not in (None, 0):
                    raise ValueError("incomplete control response")
                stage = "decode"
                data = json.loads(b"".join(chunks))
                if not isinstance(data, dict):
                    raise ValueError("invalid control response")
                if response.status >= 500 or 300 <= response.status < 400:
                    raise ValueError("control outcome unavailable")
                if response.status == 200 and target == "/api/demo/persona":
                    runtime.persona, runtime.cookie = selected, cookie
                status = response.status
            except (OSError, ValueError, http.client.HTTPException) as failure:
                # The gateway may have accepted the change. Do not continue
                # under an assumed identity after an ambiguous response.
                runtime.ready = False
                status, data = 503, {"error": "demo_identity_unavailable"}
                print(json.dumps({"event": "demo_control_unavailable", "stage": stage,
                                  "error_type": type(failure).__name__}), flush=True)
            finally:
                connection.close()
            self.reply(status, data)

    def proxy(self):
        runtime=self.server.runtime
        headers=self.headers.get_all("Authorization",[])
        if len(headers)!=1 or not hmac.compare_digest(headers[0],"Bearer "+runtime.config["secret"]):
            return self.reply(401,{"error":"runtime_authority_required"})
        if self.command=="GET" and self.path=="/health":
            return self.reply(200,runtime.health())
        paths={("GET","/workspace"):"/",("GET","/api/session"):"/api/session",("POST","/api/chat"):"/api/chat",
               ("GET","/api/organization/activity"):"/api/organization/activity",
               ("GET","/api/work-task"):"/api/work-task",
               ("GET","/api/work-task/approval"):"/api/work-task/approval",
               **{("POST", path): path for path in CONTROL_PATHS | TASK_PATHS | APPROVAL_PATHS}}
        target=paths.get((self.command,self.path))
        if target is None:
            return self.reply(404,{"error":"unsupported_demo_route"})
        if not runtime.ready or runtime.expired():
            return self.reply(410,{"error":"demo_expired"})
        body=None
        if self.command=="POST":
            try:
                body=self.bounded_body(16384 if target == "/api/work-task/approval/finish" else 4096)
                value=json.loads(body)
                if target in CONTROL_PATHS:
                    control_body(target, value)
                elif target in TASK_PATHS:
                    task_body(value)
                elif target in APPROVAL_PATHS:
                    approval_body(target, value)
                elif not isinstance(value,dict) or set(value)!={"message"} or not isinstance(value["message"],str) or not 0<len(value["message"].encode())<=2000:
                    raise ValueError("bounded question required")
            except (ValueError,TypeError,OSError):
                return self.reply(400,{"error":"bounded_approval_request_required" if target in APPROVAL_PATHS else "bounded_task_reference_required" if target in TASK_PATHS else "bounded_question_required"})
        if target in CONTROL_PATHS:
            return self.control_proxy(runtime, target, body, value)
        with runtime.identity_lock:
            if not runtime.ready or runtime.expired():
                return self.reply(410, {"error": "demo_expired"})
            cookie = runtime.cookie
            with runtime.lock:
                if target=="/api/chat" and (runtime.active_requests or runtime.model_unknown):
                    return self.reply(409,{"error":"chat_busy"})
                if target == "/api/chat" or target in TASK_RESPONSE_PATHS:
                    runtime.active_requests+=1
        connection=http.client.HTTPConnection("127.0.0.1",8081,timeout=65)
        complete=False
        try:
            connection.request(self.command,target,body=body,headers={"Cookie":cookie,"Origin":"http://127.0.0.1:8081","Content-Type":"application/json","Accept":"text/event-stream" if target=="/api/chat" else "application/json"})
            response=connection.getresponse()
            if target in TASK_RESPONSE_PATHS:
                chunks, size = [], 0
                while True:
                    chunk = response.read1(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > 32768:
                        raise ValueError("task response too large")
                if response.read(1) or not response.isclosed() or response.length not in (None, 0):
                    raise ValueError("incomplete task response")
                data = json.loads(b"".join(chunks))
                if not isinstance(data, dict) or 300 <= response.status < 400:
                    raise ValueError("invalid task response")
                if not runtime.ready or runtime.expired() or runtime.cookie != cookie:
                    return self.reply(410, {"error": "demo_expired"})
                return self.reply(response.status, data)
            self.send_response(response.status)
            for name,value in response.getheaders():
                if name.lower() in ("content-type","content-security-policy","x-content-type-options","referrer-policy"):
                    self.send_header(name,value)
            self.send_header("Cache-Control","no-store")
            self.send_header("Connection","close")
            self.end_headers()
            attached=True
            total=0
            tail=b""
            while True:
                chunk=response.read1(4096)
                if not chunk:
                    break
                total+=len(chunk)
                tail=(tail+chunk)[-4096:]
                if total>262144:
                    raise ValueError("demo response too large")
                if attached:
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except OSError:
                        # Drain the accepted upstream operation so cancellation
                        # does not falsely release the shared GPU request fence.
                        attached=False
            complete=response.isclosed() and response.length in (None, 0) and bool(re.search(rb"(?:^|[\r\n])event:\s*done[\r\n]",tail))
        except (OSError,ValueError,http.client.HTTPException):
            self.close_connection=True
        finally:
            connection.close()
            with runtime.lock:
                if target == "/api/chat" or target in TASK_RESPONSE_PATHS:
                    runtime.active_requests-=1
                    if target=="/api/chat" and not complete:
                        runtime.model_unknown+=1


def main():
    os.umask(0o077)
    config=configuration(os.environ)
    runtime=Runtime(config,os.environ.get("OPAQUE_DEMO_STATE_DIR","/state"))
    try:
        runtime.start()
        server=ThreadingHTTPServer(("0.0.0.0",8080),Proxy)
        server.runtime=runtime
        server.timeout=.5
        stop=threading.Event()
        for sig in (signal.SIGINT,signal.SIGTERM):
            signal.signal(sig,lambda *_:stop.set())
        print(json.dumps({"event":"demo_ready","lease_id":config["lease_id"],"expires_at":config["expires_at"]}),flush=True)
        while not stop.is_set() and not runtime.expired() and runtime.gateway.poll() is None:
            server.handle_request()
        server.server_close()
    finally:
        runtime.stop()


if __name__=="__main__":
    main()
