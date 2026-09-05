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

    def json(self, url, method="GET", value=None, headers=None, timeout=10):
        if url.endswith("/internal/report"):
            self.reports.append(copy.deepcopy(value))
            return 200, {"ok": True}
        if url.endswith("/internal/work"):
            return 200, {"actions": self.actions, "next_alarm_at": None}
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


def make_controller(slots=1, kube=None, http=None, clock=lambda: NOW):
    config = c.Config("https://demo.opaque.info", "c" * 64,
                      tuple(f"opaque-demo-slot-{n}" for n in range(slots)),
                      "registry.example/opaque-demo@sha256:" + "1" * 64)
    return c.Controller(config, kube or FakeKube(slots), http or FakeHttp(), clock)


class ControllerTests(unittest.TestCase):
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
