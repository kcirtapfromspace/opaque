"""Runtime boundaries using stdlib loopback fixtures; never contacts the GPU."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("hosted_demo_runtime", Path(__file__).with_name("runtime.py"))
r = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = r
spec.loader.exec_module(r)


def environment():
    return {"OPAQUE_DEMO_LEASE_ID": "a" * 32, "OPAQUE_DEMO_TENANT_ID": "demo-" + "a" * 32,
            "OPAQUE_DEMO_PROXY_SECRET": "c" * 64, "OPAQUE_DEMO_GENERATION": "1",
            "OPAQUE_DEMO_EXPIRES_AT_MS": str(int(time.time() * 1000) + 600_000),
            "OPAQUE_DEMO_MODEL_URL": "http://127.0.0.1:19680/",
            "OPAQUE_DEMO_MODEL_TEST_ORIGIN": "http://127.0.0.1:19680/",
            "OPAQUE_DEMO_MODEL_ID": "gemma-4-E2B-it-Q3_K_M.gguf"}


class RunningProcess:
    def poll(self):
        return None


def runtime():
    value = r.Runtime(r.configuration(environment()), "/tmp/unused-hosted-runtime-test")
    value.gateway = RunningProcess()
    value.ready = True
    value.cookie = "opaque_metrics_8081=private-bff-cookie"
    return value


def request(port, path, body=None, headers=None):
    """Raw socket avoids monkey-patching the test client with the runtime HTTP client."""
    body = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    items = [("Host", "127.0.0.1"), ("Connection", "close")]
    items.extend(headers or [])
    if body is not None:
        items.append(("Content-Length", str(len(body))))
    head = (f"{'GET' if body is None else 'POST'} {path} HTTP/1.1\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in items) + "\r\n").encode()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        connection.sendall(head + (body or b""))
        chunks = []
        while True:
            try:
                chunk = connection.recv(65536)
            except ConnectionResetError:
                # A rejected oversized request leaves unread client bytes;
                # preserve the error response already received before reset.
                if chunks:
                    break
                raise
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
    if not data:
        return None, b"", b""
    head, body = data.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), head, body


class GatewayResponse:
    status = 200

    def __init__(self, body=b'event: done\ndata: {}\n\n', declared_extra=0):
        self.body, self.length = body, len(body) + declared_extra
        self.closed = False

    def getheaders(self):
        return [("Content-Type", "text/event-stream"), ("Set-Cookie", "must-not-escape=private"),
                ("X-Source-Key", "must-not-escape"), ("Content-Security-Policy", "default-src 'self'")]

    def read1(self, _size):
        body, self.body = self.body, b""
        self.length -= len(body)
        self.closed = True
        return body

    def read(self, size):
        return self.read1(size)

    def isclosed(self):
        return self.closed


class GatewayConnection:
    def __init__(self, response=None, fail=False):
        self.response = response or GatewayResponse()
        self.fail = fail
        self.calls = []

    def request(self, method, target, body=None, headers=None):
        self.calls.append((method, target, body, copy.deepcopy(headers)))

    def getresponse(self):
        if self.fail:
            raise OSError("disposable gateway transport failed")
        return self.response

    def close(self):
        pass


class FakeModel(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.requests.append((self.path, dict(self.headers), body))
        if self.server.entered is not None:
            self.server.entered.set()
            self.server.release.wait(3)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.server.payload) + self.server.truncate_extra))
        self.end_headers()
        self.wfile.write(self.server.payload)
        self.close_connection = True


class ContentLengthGateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.requests.append((self.path, dict(self.headers), body))
        payload = b'{"organization":{"membership":{"persona_id":"engineer"}}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload) + self.server.truncate_extra))
        self.send_header("Set-Cookie", "private-gateway-session=must-not-forward")
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        self.close_connection = True


class RuntimeTests(unittest.TestCase):
    def test_approval_routes_bound_proofs_and_keep_identity_private(self):
        value = self.organization_runtime()
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"]), ("Cookie", "forged=identity")]
        reference = {"task_id": "46e8a66c-2ad6-4a93-a668-976e1a12769c", "manifest_sha256": "d" * 64}
        finish = {**reference, "transaction_id": "transaction-123", "credential": {"id": "credential", "response": {"attestationObject": "x" * 9000}}}
        for path, body in (("/api/work-task/approval", None),
                           ("/api/work-task/approval/start", {**reference, "method": "oauth"}),
                           ("/api/work-task/approval/start", {**reference, "method": "passkey"}),
                           ("/api/work-task/approval/finish", finish),
                           ("/api/work-task/approval/finish", {**reference, "transaction_id": "transaction-123", "code": "dex-code", "state": "transaction-123"})):
            connection = GatewayConnection(GatewayResponse(b'{"transaction_id":"transaction-123"}'))
            with patch.object(r.http.client, "HTTPConnection", return_value=connection):
                status, headers, _ = request(proxy.server_port, path, body, auth)
            self.assertEqual(status, 200)
            self.assertNotIn(b"Set-Cookie", headers)
            method, forwarded_path, forwarded_body, forwarded = connection.calls[0]
            self.assertEqual(forwarded_path, path)
            self.assertEqual(forwarded["Cookie"], value.cookie)
            self.assertEqual(forwarded["Origin"], "http://127.0.0.1:8081")
            if body is not None:
                self.assertEqual(json.loads(forwarded_body), body)
            self.assertEqual(value.active_requests, 0)
            self.assertEqual(value.model_unknown, 0)
        with patch.object(r.http.client, "HTTPConnection") as outbound:
            for path, body in (("/api/work-task/approval/start", {**reference, "method": "fido"}),
                               ("/api/work-task/approval/start", {**reference, "method": "oauth", "issuer": "https://evil.example"}),
                               ("/api/work-task/approval/finish", {**finish, "credential": []}),
                               ("/api/work-task/approval/finish", {**finish, "state": "state", "code": "code"}),
                               ("/api/work-task/approval/finish", {**finish, "credential": {"padding": "x" * 16384}})):
                self.assertEqual(request(proxy.server_port, path, body, auth)[0], 400)
            self.assertEqual(request(proxy.server_port, "/api/work-task/approval?issuer=evil", headers=auth)[0], 404)
            outbound.assert_not_called()

    def test_approval_result_is_withheld_if_lease_expires_while_gateway_responds(self):
        value = self.organization_runtime()
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"])]
        connection = GatewayConnection(GatewayResponse(b'{"authorization_url":"https://dex.example/private-challenge"}'))
        def response():
            value.config["expires_at"] = 1
            return connection.response
        connection.getresponse = response
        with patch.object(r.http.client, "HTTPConnection", return_value=connection):
            status, _, body = request(proxy.server_port, "/api/work-task/approval", headers=auth)
        self.assertEqual(status, 410)
        self.assertNotIn(b"private-challenge", body)
        self.assertEqual(value.active_requests, 0)

    def test_approval_configuration_passes_only_explicit_provider_environment(self):
        env = environment()
        env.update({"OPAQUE_DEMO_APPROVAL_ORIGIN": "https://demo.example", "OPAQUE_DEMO_OAUTH_PROVIDER": "oidc", "OPAQUE_DEMO_OAUTH_ISSUER": "https://dex.example/api/dex",
                    "OPAQUE_DEMO_OAUTH_CLIENT_ID": "opaque-demo", "OPAQUE_DEMO_OAUTH_CLIENT_SECRET": "private-fixture-value",
                    "OPAQUE_DEMO_OAUTH_REDIRECT_URI": "https://demo.example/approval/callback", "UNRELATED_SECRET": "must-not-forward"})
        config = r.configuration(env)
        self.assertEqual(config["approval_env"], {name: env[name] for name in r.APPROVAL_ENV})
        github_env = {**env, "OPAQUE_DEMO_OAUTH_PROVIDER": "github"}
        del github_env["OPAQUE_DEMO_OAUTH_ISSUER"]
        github = r.configuration(github_env)["approval_env"]
        self.assertEqual(github["OPAQUE_DEMO_OAUTH_PROVIDER"], "github")
        self.assertNotIn("OPAQUE_DEMO_OAUTH_ISSUER", github)
        for origin in ("https://user@demo.example", "https://demo.example/", "https://demo.example?tenant=foreign", "http://public.example"):
            with self.assertRaises(ValueError):
                r.configuration({**env, "OPAQUE_DEMO_APPROVAL_ORIGIN": origin})

    def test_task_reference_cannot_add_authority_and_proxy_keeps_private_identity(self):
        value = self.organization_runtime()
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"]), ("Cookie", "forged=identity")]
        reference = {"task_id": "46e8a66c-2ad6-4a93-a668-976e1a12769c", "manifest_sha256": "d" * 64}
        with patch.object(r.http.client, "HTTPConnection") as outbound:
            for path in r.TASK_PATHS:
                for invalid in ({**reference, "tenant_id": "foreign"}, {**reference, "command": "shell"},
                                {**reference, "manifest_sha256": "not-a-digest"}, {"task_id": reference["task_id"]}):
                    self.assertEqual(request(proxy.server_port, path, invalid, auth)[0], 400)
            outbound.assert_not_called()
        connection = GatewayConnection(GatewayResponse(b'{"task":{"state":"completed"}}'))
        with patch.object(r.http.client, "HTTPConnection", return_value=connection):
            status, headers, _ = request(proxy.server_port, "/api/work-task/execute", reference, auth)
        self.assertEqual(status, 200)
        self.assertNotIn(b"Set-Cookie", headers)
        method, path, body, forwarded = connection.calls[0]
        self.assertEqual((method, path), ("POST", "/api/work-task/execute"))
        self.assertEqual(json.loads(body), reference)
        self.assertEqual(forwarded["Cookie"], value.cookie)
        self.assertEqual(value.active_requests, 0)
        self.assertEqual(value.model_unknown, 0, "a source task must not charge the GPU uncertainty fence")

    def test_inflight_task_read_blocks_persona_switch_until_its_receipt_drains(self):
        value = self.organization_runtime()
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"])]
        entered, release = threading.Event(), threading.Event()
        connection = GatewayConnection(GatewayResponse(b'{"task":{"state":"completed"}}'))
        def response():
            entered.set()
            release.wait(3)
            return connection.response
        connection.getresponse = response
        results = []
        with patch.object(r.http.client, "HTTPConnection", return_value=connection) as outbound:
            running = threading.Thread(target=lambda: results.append(request(proxy.server_port, "/api/work-task", headers=auth)))
            running.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assertEqual(value.active_requests, 1)
                self.assertEqual(request(proxy.server_port, "/api/demo/persona", {"persona_id": "engineer"}, auth)[0], 409)
                self.assertEqual(outbound.call_count, 1)
            finally:
                release.set()
                running.join(3)
        self.assertFalse(running.is_alive())
        self.assertEqual(results[0][0], 200)
        self.assertEqual(value.persona, "customer_analyst")
        self.assertEqual(value.active_requests, 0)

    def organization_runtime(self):
        value = runtime()
        value.persona_cookies = {persona: "opaque_metrics_8081=private-" + persona
                                 for persona in r.PERSONAS}
        value.cookie = value.persona_cookies["customer_analyst"]
        return value

    def test_organization_identities_have_distinct_clients_and_no_engineer_metric_grant(self):
        value = runtime()
        clients, organization = r.organization_clients(value.config, "http://127.0.0.1:8081")
        self.assertEqual(len({item["subject"] for item in clients}), 3)
        self.assertEqual(len({item["client_id"] for item in clients}), 3)
        self.assertEqual({item["tenant_id"] for item in clients}, {value.config["tenant_id"]})
        members = {item["persona_id"]: item for item in organization["members"]}
        by_subject = {item["subject"]: item for item in clients}
        engineer = by_subject[members["engineer"]["subject"]]
        self.assertEqual(engineer["scopes"], ["organization:activity:read"])
        support = by_subject[members["support"]["subject"]]
        self.assertIn("metrics:read", support["scopes"])
        self.assertNotIn("metrics:stream", support["scopes"])
        analyst = by_subject[members["customer_analyst"]["subject"]]
        self.assertIn("metrics:stream", analyst["scopes"])
        self.assertNotIn(organization["other_customer"]["id"], {item["tenant_id"] for item in clients})
        for member in members.values():
            self.assertEqual(member["oauth_client_id"], by_subject[member["subject"]]["client_id"])

    def test_persona_activation_uses_target_private_cookie_only_after_complete_success(self):
        value = self.organization_runtime()
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"]),
                ("Cookie", "visitor-forged-cookie"), ("X-Persona", "support")]
        response = GatewayResponse(b'{"ok":true}')
        connection = GatewayConnection(response)
        entered, release = threading.Event(), threading.Event()
        original = connection.getresponse
        def wait_for_response():
            entered.set()
            if not release.wait(2):
                raise OSError("test response deadline")
            return original()
        connection.getresponse = wait_for_response
        results = []
        with patch.object(r.http.client, "HTTPConnection", return_value=connection) as factory:
            thread = threading.Thread(target=lambda: results.append(request(proxy.server_port,
                "/api/demo/persona", {"persona_id": "engineer"}, auth)))
            thread.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assertEqual(value.persona, "customer_analyst")
                self.assertEqual(value.cookie, value.persona_cookies["customer_analyst"])
            finally:
                release.set()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0][0], 200)
        self.assertEqual((value.persona, value.cookie), ("engineer", value.persona_cookies["engineer"]))
        factory.assert_called_once_with("127.0.0.1", 8081, timeout=15)
        method, target, body, headers = connection.calls[0]
        self.assertEqual((method, target), ("POST", "/api/demo/persona"))
        self.assertEqual(json.loads(body), {"persona_id": "engineer"})
        self.assertEqual(headers["Cookie"], value.persona_cookies["engineer"])
        self.assertEqual(headers["Origin"], "http://127.0.0.1:8081")
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("X-Persona", headers)
        self.assertNotIn(b"Set-Cookie", results[0][1])
        self.assertNotIn(b"private-", results[0][2])
        self.assertEqual((value.active_requests, value.model_requests, value.model_unknown), (0, 0, 0))

    def test_real_content_length_control_response_completes_and_truncation_fails_closed(self):
        real_connection = r.http.client.HTTPConnection
        for truncate_extra in (0, 17):
            with self.subTest(truncated=bool(truncate_extra)):
                value = self.organization_runtime()
                gateway = self.serve(ContentLengthGateway)
                gateway.requests, gateway.truncate_extra = [], truncate_extra
                proxy = self.serve(r.Proxy, value)
                # Keep the runtime's fixed gateway address assertion, but route
                # this one connection through a real stdlib response on loopback.
                def connect(host, port, timeout):
                    self.assertEqual((host, port, timeout), ("127.0.0.1", 8081, 15))
                    return real_connection("127.0.0.1", gateway.server_port, timeout=2)
                with patch.object(r.http.client, "HTTPConnection", side_effect=connect) as outbound:
                    status, headers, body = request(proxy.server_port, "/api/demo/persona",
                        {"persona_id": "engineer"}, [("Authorization", "Bearer " + value.config["secret"])])
                self.assertEqual(outbound.call_count, 1)
                self.assertEqual(len(gateway.requests), 1)
                target, forwarded, sent = gateway.requests[0]
                self.assertEqual(target, "/api/demo/persona")
                self.assertEqual(json.loads(sent), {"persona_id": "engineer"})
                self.assertEqual(forwarded["Cookie"], value.persona_cookies["engineer"])
                self.assertNotIn("Authorization", forwarded)
                self.assertNotIn(b"Set-Cookie", headers)
                self.assertNotIn(b"private-gateway-session", body)
                if truncate_extra:
                    self.assertEqual(status, 503)
                    self.assertFalse(value.ready)
                    self.assertEqual(value.persona, "customer_analyst")
                    self.assertEqual(value.cookie, value.persona_cookies["customer_analyst"])
                else:
                    self.assertEqual(status, 200)
                    self.assertTrue(value.ready)
                    self.assertEqual(value.persona, "engineer")
                    self.assertEqual(value.cookie, value.persona_cookies["engineer"])
                    self.assertEqual(json.loads(body)["organization"]["membership"]["persona_id"], "engineer")
                self.assertEqual((value.active_requests, value.model_requests, value.model_unknown), (0, 0, 0))

    def test_rejected_persona_status_preserves_active_cookie_and_readiness(self):
        for status in (400, 403, 409):
            with self.subTest(status=status):
                value = self.organization_runtime()
                proxy = self.serve(r.Proxy, value)
                response = GatewayResponse(b'{"error":"persona_denied"}')
                response.status = status
                connection = GatewayConnection(response)
                with patch.object(r.http.client, "HTTPConnection", return_value=connection):
                    result = request(proxy.server_port, "/api/demo/persona", {"persona_id": "engineer"},
                        [("Authorization", "Bearer " + value.config["secret"])])
                self.assertEqual(result[0], status)
                self.assertEqual((value.persona, value.cookie),
                                 ("customer_analyst", value.persona_cookies["customer_analyst"]))
                self.assertTrue(value.ready)
                self.assertEqual((value.active_requests, value.model_requests, value.model_unknown), (0, 0, 0))

    def test_ambiguous_persona_result_disables_runtime_without_assuming_new_identity(self):
        for response, fail, status in ((GatewayResponse(b'{"ok":true}', declared_extra=5), False, 200),
                                       (GatewayResponse(b'not json'), False, 200),
                                       (GatewayResponse(b'[]'), False, 200),
                                       (GatewayResponse(b'{}'), True, 200),
                                       (GatewayResponse(b'{"error":"upstream_failed"}'), False, 500),
                                       (GatewayResponse(b'{"error":"upstream_unavailable"}'), False, 503),
                                       (GatewayResponse(b'{"redirect":"untrusted"}'), False, 302)):
            response.status = status
            with self.subTest(body=response.body, transport_failure=fail, status=status):
                value = self.organization_runtime()
                proxy = self.serve(r.Proxy, value)
                connection = GatewayConnection(response, fail=fail)
                auth = [("Authorization", "Bearer " + value.config["secret"])]
                with patch.object(r.http.client, "HTTPConnection", return_value=connection):
                    self.assertEqual(request(proxy.server_port, "/api/demo/persona",
                        {"persona_id": "engineer"}, auth)[0], 503)
                    self.assertEqual(request(proxy.server_port, "/api/organization/activity", headers=auth)[0], 410)
                    self.assertEqual(request(proxy.server_port, "/api/demo/persona",
                        {"persona_id": "customer_analyst"}, auth)[0], 410)
                self.assertEqual(len(connection.calls), 1)
                self.assertFalse(value.ready)
                self.assertEqual((value.persona, value.cookie),
                                 ("customer_analyst", value.persona_cookies["customer_analyst"]))
                self.assertEqual((value.active_requests, value.model_requests, value.model_unknown), (0, 0, 0))

    def test_persona_controls_refuse_active_or_unknown_model_work_without_mutation(self):
        value = self.organization_runtime()
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"])]
        for field in ("active_requests", "model_requests", "model_unknown"):
            with self.subTest(field=field):
                setattr(value, field, 1)
                with patch.object(r.http.client, "HTTPConnection") as outbound:
                    for path, body in (("/api/demo/persona", {"persona_id": "engineer"}),
                                       ("/api/organization/sharing", {"enabled": False})):
                        self.assertEqual(request(proxy.server_port, path, body, auth)[0], 409)
                    outbound.assert_not_called()
                self.assertEqual(getattr(value, field), 1)
                self.assertEqual(value.persona, "customer_analyst")
                setattr(value, field, 0)

    def test_organization_controls_reject_forged_authority_before_outbound_request(self):
        value = self.organization_runtime()
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"])]
        forged = [
            ("/api/demo/persona", {"persona_id": "owner"}),
            ("/api/demo/persona", {"persona_id": ["engineer"]}),
            ("/api/demo/persona", {"persona_id": "engineer", "tenant_id": "cedar"}),
            ("/api/demo/persona", {"persona_id": "engineer", "subject": "product-engineer"}),
            ("/api/demo/persona", {"persona_id": "engineer", "reason": "extra authority"}),
            ("/api/demo/persona", {"persona_id": "support"}),
            ("/api/demo/persona", {"persona_id": "support", "reason": "\nforged case"}),
            ("/api/demo/persona", {"persona_id": "support", "reason": "Inspect failed tool", "scopes": ["metrics:read"]}),
            ("/api/organization/sharing", {"enabled": 1}),
            ("/api/organization/sharing", {"enabled": True, "tenant_id": "cedar"}),
            ("/api/organization/sharing", []),
        ]
        with patch.object(r.http.client, "HTTPConnection") as outbound:
            for path, body in forged:
                with self.subTest(path=path, body=body):
                    self.assertEqual(request(proxy.server_port, path, body, auth)[0], 400)
            for path, body in (("/api/demo/persona", None), ("/api/organization/activity", {}),
                               ("/api/organization/activity?tenant=cedar", None),
                               ("/api/organization/sharing/", {"enabled": True})):
                self.assertEqual(request(proxy.server_port, path, body, auth)[0], 404)
            for headers in ([], [auth[0], auth[0]]):
                self.assertEqual(request(proxy.server_port, "/api/demo/persona",
                    {"persona_id": "engineer"}, headers)[0], 401)
            value.config["expires_at"] = int(time.time() * 1000) - 1
            self.assertEqual(request(proxy.server_port, "/api/organization/activity", headers=auth)[0], 410)
            self.assertEqual(request(proxy.server_port, "/api/organization/sharing", {"enabled": False}, auth)[0], 410)
            outbound.assert_not_called()
        self.assertEqual(value.persona, "customer_analyst")

    def test_activity_and_sharing_use_selected_cookie_without_model_fence_changes(self):
        value = self.organization_runtime()
        value.persona, value.cookie = "engineer", value.persona_cookies["engineer"]
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"]),
                ("Cookie", value.persona_cookies["support"])]
        for path, body in (("/api/organization/activity", None),
                           ("/api/organization/sharing", {"enabled": False})):
            connection = GatewayConnection(GatewayResponse(b'{"records":[]}'))
            with patch.object(r.http.client, "HTTPConnection", return_value=connection):
                status, headers, response = request(proxy.server_port, path, body, auth)
            self.assertEqual(status, 200)
            self.assertEqual(connection.calls[0][3]["Cookie"], value.persona_cookies["engineer"])
            self.assertNotIn(b"Set-Cookie", headers)
            self.assertNotIn(b"opaque_execution_complete", response)
            self.assertEqual((value.active_requests, value.model_requests, value.model_unknown), (0, 0, 0))
            self.assertEqual(value.persona, "engineer")

    def test_requests_waiting_on_identity_change_recheck_ambiguous_readiness(self):
        for path, body in (("/api/organization/activity", None),
                           ("/api/demo/persona", {"persona_id": "customer_analyst"})):
            with self.subTest(path=path):
                value = self.organization_runtime()
                waiting = threading.Event()
                class ObservedLock:
                    def __init__(self):
                        self.lock, self.count_lock = threading.Lock(), threading.Lock()
                        self.entries = 0
                    def __enter__(self):
                        with self.count_lock:
                            self.entries += 1
                            if self.entries == 2:
                                waiting.set()
                        self.lock.acquire()
                    def __exit__(self, *_args):
                        self.lock.release()
                value.identity_lock = ObservedLock()
                proxy = self.serve(r.Proxy, value)
                entered, release = threading.Event(), threading.Event()
                connection = GatewayConnection(fail=True)
                def ambiguous_response():
                    entered.set()
                    release.wait(2)
                    raise OSError("ambiguous accepted activation")
                connection.getresponse = ambiguous_response
                auth = [("Authorization", "Bearer " + value.config["secret"])]
                first, second = [], []
                with patch.object(r.http.client, "HTTPConnection", return_value=connection) as outbound:
                    activation = threading.Thread(target=lambda: first.append(request(proxy.server_port,
                        "/api/demo/persona", {"persona_id": "engineer"}, auth)))
                    following = threading.Thread(target=lambda: second.append(request(proxy.server_port,
                        path, body, auth)))
                    activation.start()
                    try:
                        self.assertTrue(entered.wait(1))
                        following.start()
                        self.assertTrue(waiting.wait(1))
                    finally:
                        release.set()
                        activation.join(3)
                        if following.ident is not None:
                            following.join(3)
                    self.assertEqual(outbound.call_count, 1)
                self.assertFalse(activation.is_alive())
                self.assertFalse(following.is_alive())
                self.assertEqual((first[0][0], second[0][0]), (503, 410))
                self.assertFalse(value.ready)
                self.assertEqual(value.persona, "customer_analyst")

    def test_each_persona_access_token_is_clamped_to_lease_without_extended_base_ttl(self):
        value = runtime()
        clients, _ = r.organization_clients(value.config, "http://127.0.0.1:8081")
        issuer = object.__new__(r.LeaseIssuer)
        issuer.origin = "http://127.0.0.1:8082"
        clock = 1_800_000_000
        with patch.object(r.fixture.time, "time", return_value=clock):
            for lifetime in (60, 300, 600, 1_200):
                issuer.lease_expires_at_ms = (clock + lifetime) * 1000 + 999
                for client in clients:
                    with self.subTest(persona=client["subject"], lifetime=lifetime):
                        claims = issuer.claims(client, client["scopes"])
                        self.assertEqual(claims["exp"], clock + min(lifetime, 900))
                        self.assertEqual(claims["iat"], clock)
                        self.assertEqual(claims["sub"], client["subject"])
                        self.assertEqual(claims["client_id"], client["client_id"])
                        self.assertEqual(claims["tenant_id"], value.config["tenant_id"])

    def test_profile_requires_exact_model_and_production_destination(self):
        for selected in r.profiles.PROFILES.values():
            with self.subTest(profile=selected.profile_id):
                env = environment()
                env.pop("OPAQUE_DEMO_MODEL_TEST_ORIGIN")
                env.update(OPAQUE_DEMO_MODEL_PROFILE=selected.profile_id,
                           OPAQUE_DEMO_MODEL_URL=selected.url, OPAQUE_DEMO_MODEL_ID=selected.model)
                configured = r.configuration(env)
                self.assertEqual(configured["model_profile"], selected.profile_id)
                self.assertEqual(configured["model"].geturl(), selected.url)
                for other in r.profiles.PROFILES.values():
                    if other.profile_id != selected.profile_id:
                        with self.assertRaisesRegex(ValueError, "mismatch"):
                            r.configuration({**env, "OPAQUE_DEMO_MODEL_URL": other.url})
                        with self.assertRaisesRegex(ValueError, "mismatch"):
                            r.configuration({**env, "OPAQUE_DEMO_MODEL_ID": other.model})

    def test_legacy_runtime_is_explicitly_gemma_and_test_origins_are_bounded(self):
        env = environment()
        self.assertEqual(r.configuration(env)["model_profile"], "gemma4-e2b")
        qwen = r.profiles.profile("qwen35-4b")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            r.configuration({**env, "OPAQUE_DEMO_MODEL_ID": qwen.model})
        for profile in r.profiles.PROFILES.values():
            for url in ("http://127.0.0.1:19680/", "http://host.docker.internal:19680/"):
                configured = r.configuration({**env, "OPAQUE_DEMO_MODEL_PROFILE": profile.profile_id,
                    "OPAQUE_DEMO_MODEL_ID": profile.model, "OPAQUE_DEMO_MODEL_URL": url,
                    "OPAQUE_DEMO_MODEL_TEST_ORIGIN": url})
                self.assertEqual(configured["model"].geturl(), url)
        for url in ("http://127.0.0.1:80/", "http://127.0.0.1:19680", "http://localhost:19680/",
                    "http://host.docker.internal.evil:19680/", "http://evil.example:19680/",
                    "http://127.0.0.1:65536/", "http://127.0.0.1:19680/?a=b"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                r.configuration({**env, "OPAQUE_DEMO_MODEL_URL": url, "OPAQUE_DEMO_MODEL_TEST_ORIGIN": url})
        for override in ({"OPAQUE_DEMO_MODEL_PROFILE": "unknown"}, {"OPAQUE_DEMO_MODEL_PROFILE": None},
                         {"OPAQUE_DEMO_MODEL_TEST_ORIGIN": ""}):
            with self.assertRaises(ValueError):
                r.configuration({**env, **override})
        env.pop("OPAQUE_DEMO_MODEL_TEST_ORIGIN")
        with self.assertRaises(ValueError):
            r.configuration(env)

    def serve(self, handler, value=None):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.runtime = value
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def model_bridge(self, truncate_extra=0):
        value = runtime()
        model = self.serve(FakeModel)
        model.payload, model.truncate_extra = b'{"choices":[]}', truncate_extra
        model.requests, model.entered, model.release = [], None, None
        value.config["model"] = r.urlsplit(f"http://127.0.0.1:{model.server_port}/")
        return value, model, self.serve(r.ModelBridge, value)

    def test_configuration_rejects_changed_authority_and_bad_bounds(self):
        good = environment()
        self.assertEqual(r.configuration(good)["tenant_id"], good["OPAQUE_DEMO_TENANT_ID"])
        cases = [
            ("OPAQUE_DEMO_LEASE_ID", "../other"), ("OPAQUE_DEMO_TENANT_ID", "customer/other"),
            ("OPAQUE_DEMO_GENERATION", "0"), ("OPAQUE_DEMO_PROXY_SECRET", "short"),
            ("OPAQUE_DEMO_PROXY_SECRET", "z" * 64), ("OPAQUE_DEMO_MODEL_ID", "different-model"),
            ("OPAQUE_DEMO_EXPIRES_AT_MS", str(int(time.time() * 1000) - 1)),
            ("OPAQUE_DEMO_EXPIRES_AT_MS", str(int(time.time() * 1000) + 901_000)),
        ]
        cases += [("OPAQUE_DEMO_MODEL_URL", url) for url in (
            "https://evil.example/", "http://169.254.169.254/", "http://127.0.0.1/other",
            "http://user:password@127.0.0.1/", "http://127.0.0.1/?token=value", "http://127.0.0.1/#fragment")]
        for key, invalid in cases:
            with self.subTest(key=key, value=invalid), self.assertRaises(ValueError):
                r.configuration({**good, key: invalid})

    def test_health_and_proxy_require_exact_single_lease_credential(self):
        value = runtime()
        proxy = self.serve(r.Proxy, value)
        auth = ("Authorization", "Bearer " + value.config["secret"])
        for headers in ([], [("Authorization", "Bearer wrong-lease")], [auth, auth]):
            status, _, body = request(proxy.server_port, "/health", headers=headers)
            self.assertEqual(status, 401)
            self.assertNotIn(value.config["secret"].encode(), body)
        status, _, body = request(proxy.server_port, "/health", headers=[auth])
        self.assertEqual(status, 200)
        health = json.loads(body)
        self.assertEqual(health["lease_id"], value.config["lease_id"])
        self.assertEqual(health["generation"], 1)
        self.assertEqual(health["model_profile"], "gemma4-e2b")
        self.assertEqual(health["model_id"], value.config["model_id"])
        self.assertEqual(health["model_url"], value.config["model"].geturl())
        self.assertEqual(health["model_requests_in_flight"], 0)
        self.assertNotIn(value.cookie.encode(), body)
        self.assertNotIn(value.config["secret"].encode(), body)

    def test_proxy_blocks_extra_fields_unsupported_routes_and_expired_dispatch(self):
        value = runtime()
        proxy = self.serve(r.Proxy, value)
        auth = [("Authorization", "Bearer " + value.config["secret"])]
        with patch.object(r.http.client, "HTTPConnection") as outbound:
            for path in ("/mcp", "/auth/login", "/workspace?tenant=other", "/api/chat/../session"):
                self.assertEqual(request(proxy.server_port, path, headers=auth)[0], 404)
            for body in ({"message": "metrics", "tenant_id": "other"}, {"url": "evil"},
                         {"message": "x" * 2001}, {"message": ""}, ["message"]):
                self.assertEqual(request(proxy.server_port, "/api/chat", body, auth)[0], 400)
            value.config["expires_at"] = int(time.time() * 1000) - 1
            self.assertEqual(request(proxy.server_port, "/workspace", headers=auth)[0], 410)
            self.assertEqual(request(proxy.server_port, "/health", headers=auth)[0], 200)
            outbound.assert_not_called()

    def test_proxy_injects_only_private_cookie_and_fixed_origin(self):
        value = runtime()
        proxy = self.serve(r.Proxy, value)
        connection = GatewayConnection()
        auth = [("Authorization", "Bearer " + value.config["secret"]),
                ("Cookie", "visitor-controlled=wrong"), ("Origin", "https://evil.example"),
                ("X-Source-Key", "visitor-controlled-key")]
        with patch.object(r.http.client, "HTTPConnection", return_value=connection) as factory:
            status, headers, _ = request(proxy.server_port, "/api/chat", {"message": "metrics"}, auth)
        self.assertEqual(status, 200)
        self.assertNotIn(b"Set-Cookie", headers)
        self.assertNotIn(b"X-Source-Key", headers)
        factory.assert_called_once_with("127.0.0.1", 8081, timeout=65)
        method, path, body, forwarded = connection.calls[0]
        self.assertEqual((method, path), ("POST", "/api/chat"))
        self.assertEqual(json.loads(body), {"message": "metrics"})
        self.assertEqual(forwarded["Cookie"], value.cookie)
        self.assertEqual(forwarded["Origin"], "http://127.0.0.1:8081")
        self.assertNotIn("Authorization", forwarded)
        self.assertNotIn("X-Source-Key", forwarded)
        self.assertEqual(value.health()["model_requests_in_flight"], 0)

    def test_accepted_gateway_transport_failure_retains_uncertainty_and_blocks_retry(self):
        value = runtime()
        proxy = self.serve(r.Proxy, value)
        connection = GatewayConnection(fail=True)
        auth = [("Authorization", "Bearer " + value.config["secret"])]
        with patch.object(r.http.client, "HTTPConnection", return_value=connection):
            request(proxy.server_port, "/api/chat", {"message": "metrics"}, auth)
            self.assertEqual(request(proxy.server_port, "/api/chat", {"message": "metrics"}, auth)[0], 409)
        self.assertEqual(len(connection.calls), 1)
        health = value.health()
        self.assertEqual(health["active_requests"], 0)
        self.assertTrue(health["model_execution_uncertain"])
        self.assertEqual(health["model_requests_in_flight"], 1)
        bridge = self.serve(r.ModelBridge, value)
        with patch.object(r.http.client, "HTTPConnection") as outbound:
            self.assertEqual(request(bridge.server_port, "/v1/chat/completions", {"model": value.config["model_id"]})[0], 409)
            outbound.assert_not_called()

    def test_gateway_missing_terminal_event_or_truncated_framing_is_uncertain(self):
        for response in (GatewayResponse(b'event: text\ndata: {}\n\n'),
                         GatewayResponse(b'event: done\ndata: {}\n\n', declared_extra=10)):
            with self.subTest(body=response.body, declared=response.length):
                value = runtime()
                proxy = self.serve(r.Proxy, value)
                connection = GatewayConnection(response)
                with patch.object(r.http.client, "HTTPConnection", return_value=connection):
                    request(proxy.server_port, "/api/chat", {"message": "metrics"},
                            [("Authorization", "Bearer " + value.config["secret"])])
                self.assertTrue(value.health()["model_execution_uncertain"])

    def test_short_content_length_model_response_retains_uncertainty(self):
        value, model, bridge = self.model_bridge(truncate_extra=100)
        status, _, body = request(bridge.server_port, "/v1/chat/completions", {"model": value.config["model_id"]})
        self.assertEqual(status, 502)
        self.assertEqual(json.loads(body)["error"], "model_execution_uncertain")
        self.assertEqual(value.health()["model_requests_in_flight"], 1)
        self.assertTrue(value.health()["model_execution_uncertain"])
        self.assertEqual(request(bridge.server_port, "/v1/chat/completions", {"model": value.config["model_id"]})[0], 409)
        self.assertEqual(len(model.requests), 1)

    def test_complete_model_response_releases_counter_and_transmits_no_credentials(self):
        value, model, bridge = self.model_bridge()
        status, _, body = request(bridge.server_port, "/v1/chat/completions", {"model": value.config["model_id"]},
            [("Authorization", "Bearer incoming-must-not-forward"), ("Cookie", "private")])
        self.assertEqual(status, 200)
        self.assertEqual(body, model.payload)
        self.assertEqual(value.health()["model_requests_in_flight"], 0)
        self.assertFalse(value.health()["model_execution_uncertain"])
        self.assertEqual(len(model.requests), 1)
        path, headers, body = model.requests[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Cookie", headers)
        self.assertNotIn(value.config["secret"].encode(), body)
        self.assertNotIn(value.cookie.encode(), body)

    def test_model_bridge_refuses_model_selection_before_any_network_or_charge(self):
        value, model, bridge = self.model_bridge()
        for body in ({"model": "qwen35-4b"}, {"model": "Qwen3.5-4B-Q4_K_M.gguf"},
                     {"messages": []}, [], b'{broken json'):
            with self.subTest(body=body):
                self.assertEqual(request(bridge.server_port, "/v1/chat/completions", body)[0], 400)
        self.assertFalse(model.requests)
        self.assertEqual(value.health()["model_requests_in_flight"], 0)
        self.assertFalse(value.health()["model_execution_uncertain"])

    def test_bridge_serializes_model_requests_and_expiry_blocks_new_work(self):
        value, model, bridge = self.model_bridge()
        model.entered, model.release = threading.Event(), threading.Event()
        results = []
        thread = threading.Thread(target=lambda: results.append(request(bridge.server_port, "/v1/chat/completions", {"model": value.config["model_id"]})))
        thread.start()
        self.assertTrue(model.entered.wait(2))
        self.assertEqual(value.health()["model_requests_in_flight"], 1)
        self.assertEqual(request(bridge.server_port, "/v1/chat/completions", {"model": value.config["model_id"]})[0], 409)
        model.release.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0][0], 200)
        value.config["expires_at"] = int(time.time() * 1000) - 1
        self.assertEqual(request(bridge.server_port, "/v1/chat/completions", {"model": value.config["model_id"]})[0], 403)
        self.assertEqual(len(model.requests), 1)


if __name__ == "__main__":
    unittest.main()
