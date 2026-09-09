"""No cluster access: deterministic API and real loopback HTTP controller tests."""
import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import threading
import unittest
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("hosted_demo_controller", Path(__file__).with_name("controller.py"))
c = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = c
spec.loader.exec_module(c)

NOW = 1_800_000_000_000


def action(kind="provision", generation=1, slot=0, lease="a" * 32, model_id="gemma4-e2b"):
    return {"kind": kind, "lease_id": lease, "slot": slot, "generation": generation,
            "model_id": model_id,
            "tenant_id": "demo-" + lease, "expires_at": NOW + 720_000,
            "provision_deadline_at": NOW + 120_000}


class FakeKube:
    def __init__(self, slots=1):
        self.objects, self.calls = {}, []
        self.revision = 0
        self.ambiguous_kind = self.retain_kind = None
        self.created, self.release = None, None
        for slot in range(slots):
            self.put(f"opaque-demo-slot-{slot}", "configmaps", {
                "metadata": {"name": c.STATE_NAME},
                "data": {"state": json.dumps({"schema_version": 1, "generation": 0, "lease_id": None})}})

    def put(self, ns, kind, value):
        value = copy.deepcopy(value)
        self.revision += 1
        value["metadata"]["resourceVersion"] = str(self.revision)
        value["metadata"].setdefault("uid", f"uid-{self.revision}")
        if "stringData" in value:
            value["data"] = {key: base64.b64encode(text.encode()).decode() for key, text in value.pop("stringData").items()}
        self.objects[(ns, kind, value["metadata"]["name"])] = value
        return copy.deepcopy(value)

    def get(self, ns, kind, name):
        self.calls.append(("get", ns, kind, name))
        return copy.deepcopy(self.objects.get((ns, kind, name)))

    def create(self, ns, kind, value):
        self.calls.append(("create", ns, kind, value["metadata"]["name"]))
        if self.created is not None:
            self.created.set()
            self.release.wait(5)
        if (ns, kind, value["metadata"]["name"]) in self.objects:
            raise c.ControllerError("conflict")
        result = self.put(ns, kind, value)
        if self.ambiguous_kind == kind:
            raise c.AmbiguousMutation("uncertain")
        return result

    def replace(self, ns, kind, name, value):
        current = self.objects[(ns, kind, name)]
        if current["metadata"]["resourceVersion"] != value["metadata"]["resourceVersion"]:
            raise c.ControllerError("conflict")
        self.calls.append(("replace", ns, kind, name))
        return self.put(ns, kind, value)

    def delete(self, ns, kind, name, uid):
        if self.objects[(ns, kind, name)]["metadata"]["uid"] != uid:
            raise c.ControllerError("uid mismatch")
        self.calls.append(("delete", ns, kind, name))
        if kind != self.retain_kind:
            del self.objects[(ns, kind, name)]


class Response(io.BytesIO):
    status = 200
    headers = {"Content-Type": "text/event-stream", "Set-Cookie": "must-never-forward=secret"}


class FakeHttp:
    def __init__(self):
        self.reports, self.opens = [], []
        self.busy = 0
        self.health_available = True
        self.health_generation = 1
        self.health_profile = "gemma4-e2b"
        self.health_fields = {}
        self.actions = []
        self.next_alarm_at = None

    def json(self, url, method="GET", value=None, headers=None, timeout=10):
        if url.endswith("/internal/report"):
            self.reports.append(copy.deepcopy(value))
            return 200, {"ok": True}
        if url.endswith("/internal/work"):
            return 200, {"actions": self.actions, "next_alarm_at": self.next_alarm_at}
        if url.endswith("/health"):
            if not self.health_available:
                raise c.ControllerError("unavailable")
            lease = url.split("demo-")[1].split(".")[0]
            selected = c.profiles.profile(self.health_profile)
            return 200, {"ready": True, "lease_id": lease, "generation": self.health_generation,
                         "model_profile": selected.profile_id, "model_id": selected.model, "model_url": selected.url,
                         "expires_at": NOW + 720_000, "active_requests": self.busy,
                         "model_requests_in_flight": self.busy, **self.health_fields}
        raise AssertionError(url)

    def open(self, url, method="GET", body=None, headers=None, timeout=10):
        self.opens.append((url, method, body, headers))
        return Response(b'data: {"text":"synthetic only"}\n\n')


def make_controller(slots=1, kube=None, http=None, clock=lambda: NOW, **config_fields):
    config = c.Config("https://demo.opaque.info", "c" * 64,
                      tuple(f"opaque-demo-slot-{n}" for n in range(slots)),
                      "registry.example/opaque-demo@sha256:" + "1" * 64, **config_fields)
    return c.Controller(config, kube or FakeKube(slots), http or FakeHttp(), clock)


class PollingTests(unittest.TestCase):
    def scripted(self, responses, *, action_handler=None, **config_fields):
        clock, delays, requests = [NOW], [], []
        ctl = make_controller(clock=lambda: clock[0], **config_fields)
        count = len(responses)
        responses = iter(responses)

        class Stop:
            stopped = False

            def is_set(self):
                return self.stopped

            def wait(self, delay):
                delays.append(delay)
                clock[0] += round(delay * 1000)
                self.stopped = len(delays) == count

        ctl.stop = Stop()

        def queue_response(url, **_kwargs):
            self.assertTrue(url.endswith("/internal/work"))
            try:
                value = next(responses)
            except StopIteration:
                ctl.stop.stopped = True
                raise AssertionError("unexpected extra poll")
            requests.append(clock[0])
            if isinstance(value, Exception):
                raise value
            return 200, value

        ctl.http.json = queue_response
        if action_handler is not None:
            ctl.handle_action = lambda work: action_handler(work, clock)
        ctl.run()
        return ctl, delays, requests

    def test_idle_polling_stays_slow_and_actions_resume_fast_polling(self):
        handled = []
        _, delays, _ = self.scripted([
            {"actions": [], "next_alarm_at": None},
            {"actions": [action("cleanup")], "next_alarm_at": None},
            {"actions": [], "next_alarm_at": None},
        ], action_handler=lambda work, _clock: handled.append(work["kind"]))
        self.assertEqual(delays, [30, 2, 30])
        self.assertEqual(handled, ["cleanup"])

    def test_failed_action_keeps_fast_retries_and_does_not_skip_other_work(self):
        handled = []
        def fail_action(work, _clock):
            handled.append(work["slot"])
            raise c.ControllerError("runtime unavailable")
        _, delays, _ = self.scripted([
            {"actions": [action(), action(slot=1)], "next_alarm_at": NOW + 100_000},
        ], action_handler=fail_action)
        self.assertEqual(handled, [0, 1])
        self.assertEqual(delays, [2])

    def test_ready_lease_deadline_preempts_idle_wait_with_no_actions(self):
        _, delays, requests = self.scripted([
            {"actions": [], "next_alarm_at": NOW + 4250},
            {"actions": [action("cleanup")], "next_alarm_at": None},
        ], action_handler=lambda _work, _clock: None)
        self.assertEqual(delays, [4.25, 2])
        self.assertEqual(requests[1], NOW + 4250)

    def test_deadline_cap_accounts_for_time_spent_handling_actions(self):
        def handle(_work, clock):
            clock[0] += 9000
        _, delays, _ = self.scripted([
            {"actions": [action()], "next_alarm_at": NOW + 10_000},
        ], action_handler=handle)
        self.assertEqual(delays, [1])

    def test_cleanup_retry_hint_preempts_idle_wait_without_requiring_an_alarm(self):
        _, delays, _ = self.scripted([
            {"actions": [], "next_alarm_at": None, "next_poll_at": NOW + 5000},
            {"actions": [action("cleanup")], "next_alarm_at": None, "next_poll_at": None},
        ], action_handler=lambda _work, _clock: None)
        self.assertEqual(delays, [5, 2])

    def test_poll_hint_cannot_defer_an_earlier_lease_or_history_alarm(self):
        _, delays, _ = self.scripted([
            {"actions": [], "next_alarm_at": NOW + 3000, "next_poll_at": NOW + 10_000},
        ])
        self.assertEqual(delays, [3])

    def test_errors_back_off_to_cap_and_success_resets_backoff(self):
        failure = c.ControllerError("queue unavailable")
        _, delays, _ = self.scripted([
            *([failure] * 6), {"actions": [], "next_alarm_at": None}, failure,
        ])
        self.assertEqual(delays, [30, 60, 120, 240, 300, 300, 30, 30])

    def test_backoff_retains_future_deadline_but_continues_after_it_passes(self):
        failure = c.ControllerError("queue unavailable")
        ctl, delays, requests = self.scripted([
            {"actions": [], "next_alarm_at": NOW + 100_000}, failure, failure, failure,
        ])
        self.assertEqual(delays, [30, 30, 40, 120])
        self.assertEqual(requests[-1], NOW + 100_000)
        self.assertEqual(ctl.next_poll_at, NOW + 100_000)

    def test_healthy_overdue_deadline_retries_without_busy_loop_and_can_clear(self):
        _, delays, _ = self.scripted([
            {"actions": [], "next_alarm_at": NOW},
            {"actions": [], "next_alarm_at": NOW},
            {"actions": [], "next_alarm_at": None},
        ])
        self.assertEqual(delays, [2, 2, 30])

    def test_invalid_queue_deadline_preserves_previous_deadline(self):
        ctl = make_controller()
        ctl.next_poll_at = NOW + 100_000
        for field in ("next_alarm_at", "next_poll_at"):
            for invalid in (True, -1, 2**53, 1.5, float("inf"), float("nan"), "soon", {}):
                with self.subTest(field=field, deadline=invalid):
                    ctl.http.json = lambda *_args, **_kwargs: (200, {"actions": [], field: invalid})
                    with self.assertRaises(c.ControllerError):
                        ctl.poll_once()
                    self.assertEqual(ctl.next_poll_at, NOW + 100_000)

    def test_config_rejects_unbounded_or_inverted_polling_intervals(self):
        for field in ("poll_seconds", "idle_poll_seconds", "error_backoff_max_seconds"):
            for invalid in (0, -1, 301, float("inf"), float("nan"), True, "30", None):
                with self.subTest(field=field, value=invalid), self.assertRaises(c.ControllerError):
                    make_controller(**{field: invalid})
        for fields in ({"poll_seconds": 31}, {"poll_seconds": 3, "idle_poll_seconds": 2},
                       {"idle_poll_seconds": 60, "error_backoff_max_seconds": 30}):
            with self.subTest(fields=fields), self.assertRaises(c.ControllerError):
                make_controller(**fields)
        _, delays, _ = self.scripted([
            {"actions": [], "next_alarm_at": None}, c.ControllerError("queue unavailable"),
            c.ControllerError("queue unavailable"),
        ], poll_seconds=1.5, idle_poll_seconds=10, error_backoff_max_seconds=15)
        self.assertEqual(delays, [10, 10, 15])

    def test_stop_interrupts_long_idle_wait(self):
        ctl = make_controller(idle_poll_seconds=300)
        polled = threading.Event()
        def queue_response(*_args, **_kwargs):
            polled.set()
            return 200, {"actions": [], "next_alarm_at": None}
        ctl.http.json = queue_response
        thread = threading.Thread(target=ctl.run, daemon=True)
        thread.start()
        try:
            self.assertTrue(polled.wait(1))
        finally:
            ctl.stop.set()
            thread.join(1)
        self.assertFalse(thread.is_alive())


class ControllerTests(unittest.TestCase):
    def test_github_approval_configuration_requires_private_client_secret_and_no_issuer(self):
        fields = {"worker_url": "https://demo.example", "controller_secret": "c" * 64,
                  "namespaces": ("opaque-demo-slot-0",), "image": "registry.example/opaque-demo@sha256:" + "1" * 64,
                  "oauth_provider": "github", "oauth_client_id": "Ov23-example-fixture", "oauth_client_secret": "private-fixture-value"}
        config = c.Config(**fields)
        config.validate()
        resources = dict(c.runtime_resources(config, action(), "p" * 64, lambda: NOW))
        env = {item["name"]: item for item in resources["pods"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["OPAQUE_DEMO_OAUTH_PROVIDER"]["value"], "github")
        self.assertEqual(env["OPAQUE_DEMO_OAUTH_CLIENT_ID"]["value"], "Ov23-example-fixture")
        self.assertEqual(env["OPAQUE_DEMO_OAUTH_REDIRECT_URI"]["value"], "https://demo.example/approval/callback")
        self.assertNotIn("OPAQUE_DEMO_OAUTH_ISSUER", env)
        self.assertNotIn("private-fixture-value", json.dumps(resources["pods"]))
        self.assertEqual(resources["secrets"]["stringData"]["oauth-client-secret"], "private-fixture-value")
        for invalid in ({"oauth_client_secret": ""}, {"oauth_client_id": ""}, {"oauth_provider": "arbitrary"},
                        {"oauth_issuer": "https://foreign.example"}, {"oauth_client_id": "client with spaces"}):
            with self.assertRaises(c.ControllerError):
                c.Config(**{**fields, **invalid}).validate()

    def test_approval_runtime_configuration_uses_worker_origin_and_secret_reference(self):
        config = c.Config("https://demo.example", "c" * 64, ("opaque-demo-slot-0",),
                          "registry.example/opaque-demo@sha256:" + "1" * 64,
                          oauth_issuer="https://dex.example/api/dex", oauth_client_id="opaque-demo",
                          oauth_client_secret="private-fixture-value")
        config.validate()
        resources = dict(c.runtime_resources(config, action(), "p" * 64, lambda: NOW))
        env = {item["name"]: item for item in resources["pods"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["OPAQUE_DEMO_APPROVAL_ORIGIN"]["value"], "https://demo.example")
        self.assertEqual(env["OPAQUE_DEMO_OAUTH_REDIRECT_URI"]["value"], "https://demo.example/approval/callback")
        self.assertEqual(env["OPAQUE_DEMO_OAUTH_CLIENT_SECRET"]["valueFrom"]["secretKeyRef"]["key"], "oauth-client-secret")
        self.assertNotIn("private-fixture-value", json.dumps(resources["pods"]))
        self.assertEqual(resources["secrets"]["stringData"]["oauth-client-secret"], "private-fixture-value")

    def test_approval_controller_accepts_bounded_proofs_without_forwarding_browser_authority(self):
        ctl = make_controller()
        ctl.handle_action(action())
        server = self.serve_proxy(ctl)
        calls = []
        def open_response(url, method="GET", body=None, headers=None, timeout=10):
            calls.append((url, method, body, headers))
            return Response(b'{"transaction_id":"transaction-123"}')
        ctl.http.open = open_response
        reference = {"task_id": "46e8a66c-2ad6-4a93-a668-976e1a12769c", "manifest_sha256": "d" * 64}
        finish = {**reference, "transaction_id": "transaction-123", "credential": {"id": "x" * 9000}}
        for path, body in (("api/work-task/approval", None),
                           ("api/work-task/approval/start", {**reference, "method": "oauth"}),
                           ("api/work-task/approval/finish", finish)):
            status, headers, payload = self.organization_request(server, ctl, path, body)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(payload), {"transaction_id": "transaction-123"})
            self.assertNotIn("Set-Cookie", headers)
            self.assertNotIn("Cookie", calls[-1][3])
            self.assertEqual(calls[-1][3]["Authorization"], "Bearer " + ctl.runtime_secret(action()))
        self.assertEqual(self.organization_request(server, ctl, "api/work-task/approval/finish", {**finish, "credential": {"id": "x" * 16384}})[0], 400)
        self.assertEqual(self.organization_request(server, ctl, "api/work-task/approval/start?issuer=evil", {**reference, "method": "oauth"})[0], 404)
        self.assertEqual(len(calls), 3)

    def test_approval_controller_withholds_result_when_lease_expires_during_response(self):
        clock = [NOW]
        ctl = make_controller(clock=lambda: clock[0])
        ctl.handle_action(action())
        server = self.serve_proxy(ctl)
        def open_response(*_args, **_kwargs):
            clock[0] = NOW + 600_001
            return Response(b'{"authorization_url":"https://dex.example/private-challenge"}')
        ctl.http.open = open_response
        status, _, payload = self.organization_request(server, ctl, "api/work-task/approval")
        self.assertEqual(status, 503)
        self.assertNotIn(b"private-challenge", payload)

    def test_approval_controller_rejects_incomplete_response_without_disclosing_challenge(self):
        ctl = make_controller()
        ctl.handle_action(action())
        server = self.serve_proxy(ctl)
        def open_response(*_args, **_kwargs):
            response = Response(b'{"authorization_url":"https://dex.example/private-challenge"}')
            response.length = 1
            return response
        ctl.http.open = open_response
        status, _, payload = self.organization_request(server, ctl, "api/work-task/approval")
        self.assertEqual(status, 503)
        self.assertNotIn(b"private-challenge", payload)

    def serve_proxy(self, controller):
        server = c.ProxyServer(("127.0.0.1", 0), controller)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def organization_request(self, server, controller, path, body=None, *, generation="1",
                             expiry=NOW + 600_000, authorized=True, method=None):
        headers = {"X-Opaque-Lease-Generation": generation,
                   "X-Opaque-Lease-Expires-At": str(expiry),
                   "Cookie": "visitor-cookie-must-not-forward"}
        if authorized:
            headers["Authorization"] = "Bearer " + controller.config.controller_secret
        data = None if body is None else json.dumps(body).encode()
        url = f"http://127.0.0.1:{server.server_port}/sessions/{'a' * 32}/proxy/{path}"
        try:
            response = urllib.request.urlopen(urllib.request.Request(url, data=data,
                headers=headers, method=method), timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, dict(response.headers), response.read()

    def test_organization_routes_preserve_uncertain_execution_and_never_emit_completion(self):
        ctl = make_controller()
        ctl.handle_action(action())
        item, state = ctl.load_state(0)
        state.update(chat_inflight=True, execution_stopped=False, proxy_expires_at=NOW + 600_000)
        ctl.save_state(0, item, state)
        baseline = copy.deepcopy(ctl.load_state(0)[1])
        server = self.serve_proxy(ctl)
        ctl.model_lock.acquire()
        try:
            for path, body in (("api/organization/activity", None),
                               ("api/demo/persona", {"persona_id": "engineer"}),
                               ("api/organization/sharing", {"enabled": False})):
                with self.subTest(path=path):
                    status, headers, response = self.organization_request(server, ctl, path, body)
                    self.assertEqual(status, 200)
                    self.assertNotIn("Set-Cookie", headers)
                    self.assertNotIn(b"opaque_execution_complete", response)
                    self.assertEqual(ctl.load_state(0)[1], baseline)
                    url, method, forwarded_body, forwarded_headers = ctl.http.opens[-1]
                    self.assertTrue(url.endswith("/" + path))
                    self.assertEqual(method, "GET" if body is None else "POST")
                    if body is not None:
                        self.assertEqual(json.loads(forwarded_body), body)
                    self.assertEqual(forwarded_headers["Authorization"], "Bearer " + ctl.runtime_secret(action()))
                    self.assertNotIn("Cookie", forwarded_headers)
                    self.assertNotIn(ctl.config.controller_secret, json.dumps(forwarded_headers))
        finally:
            ctl.model_lock.release()
        self.assertTrue(ctl.load_state(0)[1]["chat_inflight"])
        self.assertFalse(ctl.load_state(0)[1]["execution_stopped"])

    def test_organization_routes_keep_exact_method_generation_path_and_expiry_authority(self):
        ctl = make_controller()
        ctl.handle_action(action())
        server = self.serve_proxy(ctl)
        cases = [
            ("api/organization/activity", None, {"authorized": False}, 401),
            ("api/organization/activity", None, {"generation": "2"}, 503),
            ("api/organization/activity", None, {"generation": "01"}, 404),
            ("api/organization/activity", None, {"expiry": NOW}, 503),
            ("api/organization/activity", None, {"expiry": NOW + 720_001}, 503),
            ("api/organization/activity?tenant=cedar", None, {}, 404),
            ("api/organization/activity/", None, {}, 404),
            ("api/organization/activity", {"tenant_id": "cedar"}, {}, 404),
            ("api/demo/persona", None, {}, 404),
            ("api/organization/sharing", None, {}, 404),
            ("api/demo/persona/../chat", {"persona_id": "engineer"}, {}, 404),
        ]
        for path, body, options, expected in cases:
            with self.subTest(path=path, options=options):
                self.assertEqual(self.organization_request(server, ctl, path, body, **options)[0], expected)
        self.assertFalse(ctl.http.opens)
        self.assertFalse(ctl.load_state(0)[1]["chat_inflight"])
        self.assertTrue(ctl.load_state(0)[1]["execution_stopped"])

    def test_successful_organization_controls_do_not_create_a_model_reservation(self):
        ctl = make_controller()
        ctl.handle_action(action())
        item, state = ctl.load_state(0)
        state["proxy_expires_at"] = NOW + 600_000
        ctl.save_state(0, item, state)
        baseline = copy.deepcopy(ctl.load_state(0)[1])
        server = self.serve_proxy(ctl)
        for path, body in (("api/demo/persona", {"persona_id": "engineer"}),
                           ("api/organization/sharing", {"enabled": False}),
                           ("api/organization/activity", None)):
            status, _, response = self.organization_request(server, ctl, path, body)
            self.assertEqual(status, 200)
            self.assertNotIn(b"opaque_execution_complete", response)
            self.assertEqual(ctl.load_state(0)[1], baseline)
        self.assertEqual(len(ctl.http.reports), 1)

    def test_each_catalog_profile_selects_exact_runtime_pair_and_health(self):
        for selected in c.profiles.PROFILES.values():
            with self.subTest(profile=selected.profile_id):
                ctl = make_controller()
                ctl.http.health_profile = selected.profile_id
                work = action(model_id=selected.profile_id)
                ctl.handle_action(work)
                self.assertEqual(ctl.http.reports[-1]["kind"], "ready")
                state = ctl.load_state(0)[1]
                self.assertEqual(state["model_id"], selected.profile_id)
                self.assertEqual(ctl.find_proxy_action(work["lease_id"], 1)["model_id"], selected.profile_id)
                pod = ctl.kube.get("opaque-demo-slot-0", "pods", c.resource_name(work))
                env = {row["name"]: row.get("value") for row in pod["spec"]["containers"][0]["env"]}
                self.assertEqual(env["OPAQUE_DEMO_MODEL_PROFILE"], selected.profile_id)
                self.assertEqual(env["OPAQUE_DEMO_MODEL_ID"], selected.model)
                self.assertEqual(env["OPAQUE_DEMO_MODEL_URL"], selected.url)
                self.assertNotIn("OPAQUE_DEMO_MODEL_TEST_ORIGIN", env)

    def test_model_is_immutable_for_provision_cleanup_and_retained_tombstone(self):
        ctl = make_controller()
        ctl.http.health_profile = "qwen35-4b"
        ctl.handle_action(action(model_id="qwen35-4b"))
        baseline = copy.deepcopy(ctl.kube.objects)
        for work in (action(model_id="gemma4-e2b"), action("cleanup", 2, model_id="gemma4-e2b")):
            with self.assertRaisesRegex(c.ControllerError, "binding mismatch"):
                ctl.handle_action(work)
            self.assertEqual(ctl.kube.objects, baseline)
        restarted = make_controller(kube=ctl.kube, http=ctl.http)
        restarted.handle_action(action("cleanup", 2, model_id="qwen35-4b"))
        self.assertEqual(restarted.load_state(0)[1]["model_id"], "qwen35-4b")
        count = len(ctl.http.reports)
        with self.assertRaisesRegex(c.ControllerError, "binding mismatch"):
            restarted.handle_action(action("cleanup", 2))
        self.assertEqual(len(ctl.http.reports), count)

    def test_legacy_missing_model_means_gemma_even_after_another_profile(self):
        ctl = make_controller()
        ctl.http.health_profile = "qwen35-4b"
        ctl.handle_action(action(model_id="qwen35-4b"))
        ctl.handle_action(action("cleanup", 2, model_id="qwen35-4b"))
        legacy = action(generation=3, lease="b" * 32)
        del legacy["model_id"]
        ctl.http.health_profile, ctl.http.health_generation = "gemma4-e2b", 3
        ctl.handle_action(legacy)
        item, state = ctl.load_state(0)
        self.assertEqual(state["model_id"], "gemma4-e2b")
        del state["model_id"]  # Historical occupied-state migration.
        state["schema_version"] = 1
        ctl.save_state(0, item, state)
        restarted = make_controller(kube=ctl.kube, http=ctl.http)
        self.assertEqual(restarted.load_state(0)[1]["model_id"], "gemma4-e2b")
        cleanup = {**legacy, "kind": "cleanup", "generation": 4}
        restarted.handle_action(cleanup)
        item, state = restarted.load_state(0)
        del state["model_id"]  # Historical cleaned-state migration.
        state["schema_version"] = 1
        restarted.save_state(0, item, state)
        restarted.handle_action(cleanup)
        self.assertEqual(ctl.http.reports[-1]["kind"], "cleaned")

    def test_health_profile_name_or_destination_mismatch_never_reports_ready(self):
        for fields in ({"model_profile": "qwen35-4b"}, {"model_profile": None},
                       {"model_id": "Qwen3.5-4B-Q4_K_M.gguf"},
                       {"model_url": "http://different.example:8080/"}):
            with self.subTest(fields=fields):
                ctl = make_controller()
                ctl.http.health_fields = fields
                ctl.handle_action(action())
                self.assertFalse(ctl.http.reports)
                self.assertEqual(ctl.load_state(0)[1]["status"], "provisioning")

    def test_health_mismatch_cannot_clear_uncertain_model_work(self):
        ctl = make_controller()
        ctl.handle_action(action())
        item, state = ctl.load_state(0)
        state["chat_inflight"], state["execution_stopped"] = True, False
        ctl.save_state(0, item, state)
        ctl.http.health_fields = {"model_profile": "qwen3-14b"}
        with self.assertRaisesRegex(c.ControllerError, "health invalid"):
            ctl.handle_action(action("cleanup", 2))
        self.assertTrue(ctl.load_state(0)[1]["chat_inflight"])
        self.assertFalse(any(call[0] == "delete" for call in ctl.kube.calls))

    def test_unrecognized_model_state_and_actions_fail_closed(self):
        ctl = make_controller()
        for model_id in (None, "", "gemma-4-E2B-it-Q3_K_M.gguf", "http://evil.example/", ["gemma4-e2b"]):
            with self.subTest(model_id=model_id), self.assertRaises(c.ControllerError):
                ctl.handle_action(action(model_id=model_id))
        self.assertFalse(any(call[0] == "create" for call in ctl.kube.calls))
        item, state = ctl.load_state(0)
        state["model_id"] = "untrusted"
        ctl.save_state(0, item, state)
        with self.assertRaisesRegex(c.ControllerError, "state invalid"):
            ctl.load_state(0)

    def test_current_state_missing_model_cannot_migrate_to_gemma(self):
        ctl = make_controller()
        ctl.http.health_profile = "qwen35-4b"
        ctl.handle_action(action(model_id="qwen35-4b"))
        item, state = ctl.load_state(0)
        self.assertEqual(state["schema_version"], 2)
        del state["model_id"]
        ctl.save_state(0, item, state)
        with self.assertRaisesRegex(c.ControllerError, "state invalid"):
            make_controller(kube=ctl.kube).handle_action(action())
        self.assertFalse(any(call[0] == "delete" for call in ctl.kube.calls))

    def test_fixed_pod_contract_no_controller_credential_or_service_token(self):
        ctl = make_controller()
        ctl.handle_action(action())
        ns, name = "opaque-demo-slot-0", c.resource_name(action())
        pod = ctl.kube.get(ns, "pods", name)["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["restartPolicy"], "Never")
        self.assertEqual(pod["activeDeadlineSeconds"], 720)
        self.assertEqual(pod["containers"][0]["image"], ctl.config.image)
        self.assertEqual(pod["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
        self.assertEqual(pod["containers"][0]["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertNotIn(ctl.config.controller_secret, json.dumps(pod))
        self.assertFalse(any("hostPath" in volume for volume in pod["volumes"]))
        self.assertEqual(ctl.http.reports[-1]["kind"], "ready")
        self.assertNotIn("secret", json.dumps(ctl.http.reports))

    def test_duplicate_provision_is_idempotent_and_cleanup_tombstone_blocks_replay(self):
        ctl = make_controller()
        ctl.handle_action(action())
        ctl.handle_action(action())
        self.assertEqual(sum(call[0] == "create" for call in ctl.kube.calls), 3)
        ctl.handle_action(action("cleanup", 2))
        self.assertEqual(ctl.http.reports[-1], {"kind": "cleaned", "lease_id": "a" * 32,
            "slot": 0, "generation": 2, "resources_deleted": True, "provisioning_stopped": True,
            "execution_stopped": True})
        ctl.handle_action(action())
        self.assertEqual(sum(call[0] == "create" for call in ctl.kube.calls), 3)
        ctl.handle_action(action("cleanup", 2))
        self.assertEqual(ctl.http.reports[-1]["kind"], "cleaned")
        self.assertEqual(len(ctl.kube.objects), 1)  # Durable high-water mark is intentionally retained.

    def test_create_transport_ambiguity_survives_restart_and_never_refunds(self):
        ctl = make_controller()
        ctl.kube.ambiguous_kind = "services"
        with self.assertRaises(c.AmbiguousMutation):
            ctl.handle_action(action())
        restarted = make_controller(kube=ctl.kube, http=ctl.http)
        with self.assertRaisesRegex(c.ControllerError, "quarantined"):
            restarted.handle_action(action("cleanup", 2))
        self.assertTrue(restarted.load_state(0)[1]["create_inflight"])
        self.assertFalse(any(report["kind"] == "cleaned" for report in ctl.http.reports))
        self.assertFalse(any(call[0] == "delete" for call in ctl.kube.calls))

    def test_cleanup_requires_observed_absence_and_preserves_finalizer_slot(self):
        ctl = make_controller()
        ctl.handle_action(action())
        ctl.kube.retain_kind = "pods"
        ctl.handle_action(action("cleanup", 2))
        self.assertFalse(any(report["kind"] == "cleaned" for report in ctl.http.reports))
        ctl.kube.retain_kind = None
        ctl.handle_action(action("cleanup", 2))
        self.assertEqual(ctl.http.reports[-1]["kind"], "cleaned")

    def test_unknown_model_work_requires_authenticated_zero_health_before_deletion(self):
        ctl = make_controller()
        ctl.handle_action(action())
        item, state = ctl.load_state(0)
        state["chat_inflight"], state["execution_stopped"] = True, False
        ctl.save_state(0, item, state)
        ctl.http.health_available = False
        with self.assertRaises(c.ControllerError):
            ctl.handle_action(action("cleanup", 2))
        self.assertFalse(any(call[0] == "delete" for call in ctl.kube.calls))
        ctl.http.health_available, ctl.http.busy = True, 1
        ctl.handle_action(action("cleanup", 2))
        self.assertFalse(any(call[0] == "delete" for call in ctl.kube.calls))
        ctl.http.busy = 0
        # The visitor TTL started at ready; runtime health reports its earlier provisioning hard cap.
        ctl.handle_action({**action("cleanup", 2), "expires_at": NOW + 600_000})
        self.assertEqual(ctl.http.reports[-1]["execution_stopped"], True)

    def test_cleanup_quiesces_creator_under_same_slot_lock(self):
        ctl = make_controller()
        ctl.kube.created, ctl.kube.release = threading.Event(), threading.Event()
        failures = []
        def run(value):
            try:
                ctl.handle_action(value)
            except Exception as error:
                failures.append(error)
        provision = threading.Thread(target=run, args=(action(),))
        cleanup = threading.Thread(target=run, args=(action("cleanup", 2),))
        provision.start()
        self.assertTrue(ctl.kube.created.wait(2))
        cleanup.start()
        self.assertFalse(any(call[0] == "delete" for call in ctl.kube.calls))
        ctl.kube.release.set()
        provision.join(3)
        cleanup.join(3)
        self.assertFalse(provision.is_alive() or cleanup.is_alive())
        self.assertEqual(failures, [])
        events = [call[0] for call in ctl.kube.calls if call[0] in {"create", "delete"}]
        self.assertEqual(events, ["create"] * 3 + ["delete"] * 3)
        self.assertEqual(ctl.http.reports[-1]["kind"], "cleaned")

    def test_action_scope_deadline_and_runtime_identity_fail_closed(self):
        ctl = make_controller()
        for override in ({"slot": 2}, {"generation": True}, {"tenant_id": "../../other"},
                         {"expires_at": NOW + 901_000}, {"image": "evil"}, {"lease_id": "invalid"}):
            with self.subTest(override=override), self.assertRaises(c.ControllerError):
                ctl.handle_action({**action(), **override})
        self.assertFalse(any(call[0] == "create" for call in ctl.kube.calls))
        ctl.http.health_generation = 3
        ctl.handle_action(action())
        self.assertFalse(ctl.http.reports)
        ctl.clock = lambda: NOW + 121_000
        ctl.handle_action(action())
        self.assertEqual(ctl.http.reports[-1]["kind"], "failed")

    def test_runtime_credentials_are_unique_between_slots(self):
        ctl = make_controller(2)
        ctl.handle_action(action())
        ctl.handle_action(action(slot=1, lease="b" * 32))
        self.assertNotEqual(ctl.runtime_secret(action()), ctl.runtime_secret(action(slot=1, lease="b" * 32)))

    def test_proxy_auth_generation_allowlist_and_no_cookie_forwarding(self):
        ctl = make_controller()
        ctl.handle_action(action())
        server = c.ProxyServer(("127.0.0.1", 0), ctl)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_port}/sessions/{'a' * 32}/proxy/"
        def request(path, auth=True, generation="1", body=None):
            headers = {"X-Opaque-Lease-Generation": generation, "Cookie": "browser-secret",
                       "X-Opaque-Lease-Expires-At": str(NOW + 600_000)}
            if auth:
                headers["Authorization"] = "Bearer " + ctl.config.controller_secret
            try:
                return urllib.request.urlopen(urllib.request.Request(base + path, data=body, headers=headers), timeout=2)
            except urllib.error.HTTPError as error:
                return error
        for path, auth, generation, status in (("workspace", False, "1", 401),
                ("mcp", True, "1", 404), ("workspace?url=evil", True, "1", 404),
                ("workspace", True, "2", 503)):
            with request(path, auth, generation) as response:
                self.assertEqual(response.status, status)
        self.assertEqual(ctl.http.opens, [])
        with request("api/chat", body=b'{"message":"What is my error rate?"}') as response:
            self.assertEqual(response.status, 200)
            self.assertNotIn("Set-Cookie", response.headers)
            body = response.read()
            self.assertIn(b"synthetic", body)
            self.assertIn(b"event: opaque_execution_complete", body)
        url, method, body, headers = ctl.http.opens[-1]
        self.assertEqual(method, "POST")
        self.assertNotIn("Cookie", headers)
        self.assertEqual(headers["Authorization"], "Bearer " + ctl.runtime_secret(action()))
        self.assertNotIn(ctl.config.controller_secret, json.dumps(headers))
        self.assertFalse(ctl.load_state(0)[1]["chat_inflight"])

    def test_unknown_work_in_other_slot_blocks_new_model_request(self):
        ctl = make_controller(2)
        ctl.handle_action(action())
        ctl.handle_action(action(slot=1, lease="b" * 32))
        item, state = ctl.load_state(1)
        state["chat_inflight"] = True
        ctl.save_state(1, item, state)
        server = c.ProxyServer(("127.0.0.1", 0), ctl)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/sessions/{'a'*32}/proxy/api/chat",
            data=b'{"message":"metrics"}', headers={"Authorization": "Bearer " + ctl.config.controller_secret,
            "X-Opaque-Lease-Generation": "1", "X-Opaque-Lease-Expires-At": str(NOW + 600_000)})
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        self.assertEqual(error.exception.code, 409)
        self.assertFalse(ctl.http.opens)

    def test_proxy_cannot_extend_previously_seen_visitor_expiry(self):
        ctl = make_controller()
        ctl.handle_action(action())
        server = c.ProxyServer(("127.0.0.1", 0), ctl)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_port}/sessions/{'a'*32}/proxy/workspace"
        def request(expiry):
            return urllib.request.Request(url, headers={"Authorization": "Bearer " + ctl.config.controller_secret,
                "X-Opaque-Lease-Generation": "1", "X-Opaque-Lease-Expires-At": str(expiry)})
        with urllib.request.urlopen(request(NOW + 600_000), timeout=2) as response:
            self.assertEqual(response.status, 200)
            response.read()
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request(NOW + 600_001), timeout=2)
        self.assertEqual(error.exception.code, 503)
        self.assertEqual(len(ctl.http.opens), 1)
        ctl.clock = lambda: NOW + 600_000
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request(NOW + 600_000), timeout=2)
        self.assertEqual(error.exception.code, 503)

    def test_drained_response_without_zero_health_has_no_completion_trailer(self):
        ctl = make_controller()
        ctl.handle_action(action())
        ctl.http.busy = 1
        server = c.ProxyServer(("127.0.0.1", 0), ctl)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/sessions/{'a'*32}/proxy/api/chat",
            data=b'{"message":"metrics"}', headers={"Authorization": "Bearer " + ctl.config.controller_secret,
                "X-Opaque-Lease-Generation": "1", "X-Opaque-Lease-Expires-At": str(NOW + 600_000)})
        with urllib.request.urlopen(request, timeout=2) as response:
            body = response.read()
        self.assertNotIn(b"opaque_execution_complete", body)
        self.assertTrue(ctl.load_state(0)[1]["chat_inflight"])

    def test_next_lease_uses_higher_slot_generation(self):
        ctl = make_controller()
        ctl.handle_action(action())
        ctl.handle_action(action("cleanup", 2))
        ctl.http.health_generation = 3
        ctl.handle_action(action(generation=3, lease="b" * 32))
        self.assertEqual(ctl.http.reports[-1]["kind"], "ready")
        self.assertEqual(ctl.load_state(0)[1]["lease_id"], "b" * 32)
        # Delayed old cleanup cannot delete or reset the new occupant.
        ctl.handle_action(action("cleanup", 2))
        self.assertEqual(ctl.load_state(0)[1]["lease_id"], "b" * 32)


if __name__ == "__main__":
    unittest.main()
