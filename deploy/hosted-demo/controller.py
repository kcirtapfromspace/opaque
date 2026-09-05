#!/usr/bin/env python3
"""Fixed-slot hosted synthetic demo controller. No caller-supplied pod specs.

The Worker owns admission/capacity. Kubernetes retains a per-slot mutation fence.
An interrupted or ambiguous CREATE is deliberately not automatically recoverable:
absence observed later does not prove an earlier request cannot still complete.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hmac
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_JSON = 131072
STATE_NAME = "opaque-demo-slot-state"
LABEL = "opaque.dev/hosted-demo"
LEASE_LABEL = "opaque.dev/lease-id"
GEN_LABEL = "opaque.dev/generation"
PATHS = {"workspace": "GET", "api/session": "GET", "api/chat": "POST",
         "api/organization/activity": "GET", "api/demo/persona": "POST",
         "api/organization/sharing": "POST", "api/work-task": "GET",
         "api/work-task/approve": "POST", "api/work-task/execute": "POST",
         "api/work-task/revoke": "POST"}
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
LEASE = re.compile(r"[0-9a-f]{32}\Z")
IMAGE = re.compile(r"[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}\Z")
PROFILE_SPEC = importlib.util.spec_from_file_location("opaque_demo_model_profiles", Path(__file__).with_name("model_profiles.py"))
profiles = importlib.util.module_from_spec(PROFILE_SPEC)
PROFILE_SPEC.loader.exec_module(profiles)


class ControllerError(Exception):
    """Static message only; never expose request headers, secrets or raw bodies."""


class AmbiguousMutation(ControllerError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def now_ms():
    return int(time.time() * 1000)


def encode_json(value):
    return json.dumps(value, separators=(",", ":")).encode()


class Http:
    def __init__(self, context=None):
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context or ssl.create_default_context()))

    def open(self, url, method="GET", body=None, headers=None, timeout=10):
        request = urllib.request.Request(url, data=body, method=method,
            headers={"User-Agent": "opaque-demo-controller/1", **(headers or {})})
        try:
            return self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            return error
        except (OSError, TimeoutError, urllib.error.URLError):
            raise ControllerError("transport unavailable") from None

    def json(self, url, method="GET", value=None, headers=None, timeout=10):
        request_headers = {"Accept": "application/json", **(headers or {})}
        if value is not None:
            request_headers["Content-Type"] = "application/json"
        with self.open(url, method, None if value is None else encode_json(value), request_headers, timeout=timeout) as response:
            body = response.read(MAX_JSON + 1)
            if len(body) > MAX_JSON:
                raise ControllerError("response too large")
            try:
                return response.status, json.loads(body or b"{}")
            except (ValueError, UnicodeDecodeError):
                raise ControllerError("invalid response") from None


class Kube:
    """Only core namespaced resources in the operator's fixed slot namespaces."""
    def __init__(self, namespaces, api=None, token_path=None, ca_path=None):
        self.namespaces = set(namespaces)
        self.api = api or "https://kubernetes.default.svc"
        self.token_path = token_path or "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ca_path = ca_path or "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self.http = Http(ssl.create_default_context(cafile=ca_path))

    def request(self, namespace, resource, name=None, method="GET", value=None):
        if namespace not in self.namespaces or resource not in {"pods", "services", "secrets", "configmaps"}:
            raise ControllerError("invalid Kubernetes scope")
        if name is not None and not NAME.fullmatch(name):
            raise ControllerError("invalid resource name")
        if resource == "configmaps" and name not in {None, STATE_NAME}:
            raise ControllerError("invalid state name")
        # Read projected token each request so rotation does not require restart.
        with open(self.token_path, encoding="ascii") as handle:
            token = handle.read(8192).strip()
        if not token or any(c.isspace() for c in token):
            raise ControllerError("Kubernetes credential unavailable")
        path = f"/api/v1/namespaces/{namespace}/{resource}" + (f"/{name}" if name else "")
        try:
            status, data = self.http.json(self.api + path, method, value, {"Authorization": "Bearer " + token})
        except ControllerError:
            if method in {"POST", "PUT"}:
                raise AmbiguousMutation("Kubernetes mutation uncertain") from None
            raise
        if status == 404 and method in {"GET", "DELETE"}:
            return None
        if status == 409:
            raise ControllerError("Kubernetes conflict")
        if status >= 500 and method in {"POST", "PUT"}:
            raise AmbiguousMutation("Kubernetes mutation uncertain")
        if not 200 <= status < 300:
            raise ControllerError("Kubernetes request rejected")
        return data

    def get(self, ns, kind, name):
        return self.request(ns, kind, name)

    def create(self, ns, kind, value):
        return self.request(ns, kind, method="POST", value=value)

    def replace(self, ns, kind, name, value):
        return self.request(ns, kind, name, "PUT", value)

    def delete(self, ns, kind, name, uid):
        return self.request(ns, kind, name, "DELETE", {
            "apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 1,
            "preconditions": {"uid": uid}, "propagationPolicy": "Foreground"})


@dataclass(frozen=True)
class Config:
    worker_url: str
    controller_secret: str
    namespaces: tuple[str, ...]
    image: str
    poll_seconds: float = 2

    def validate(self):
        url = urllib.parse.urlsplit(self.worker_url)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.path not in {"", "/"} or url.query or url.fragment):
            raise ControllerError("invalid Worker origin")
        if not 1 <= len(self.namespaces) <= 2 or len(set(self.namespaces)) != len(self.namespaces):
            raise ControllerError("invalid slot count")
        if not all(NAME.fullmatch(namespace) for namespace in self.namespaces):
            raise ControllerError("invalid slot namespace")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", self.controller_secret):
            raise ControllerError("invalid controller credential")
        if not IMAGE.fullmatch(self.image):
            raise ControllerError("runtime image must be digest pinned")


def validate_action(action, slots, clock):
    keys = {"kind", "lease_id", "slot", "generation", "tenant_id", "expires_at", "provision_deadline_at"}
    if not isinstance(action, dict) or set(action) not in (keys, keys | {"model_id"}):
        raise ControllerError("invalid work action")
    action = {**action, "model_id": action.get("model_id", profiles.LEGACY_PROFILE_ID)}
    try:
        profiles.profile(action["model_id"])
    except ValueError:
        raise ControllerError("invalid work model profile") from None
    if action["kind"] not in {"provision", "cleanup"} or not isinstance(action["lease_id"], str) or not LEASE.fullmatch(action["lease_id"]):
        raise ControllerError("invalid work identity")
    if type(action["slot"]) is not int or not 0 <= action["slot"] < slots:
        raise ControllerError("invalid slot")
    if type(action["generation"]) is not int or not 1 <= action["generation"] <= 2**53 - 1:
        raise ControllerError("invalid generation")
    if not isinstance(action["tenant_id"], str) or not NAME.fullmatch(action["tenant_id"]):
        raise ControllerError("invalid tenant")
    if any(type(action[field]) is not int for field in ("expires_at", "provision_deadline_at")):
        raise ControllerError("invalid deadline")
    if not 0 < action["provision_deadline_at"] <= action["expires_at"]:
        raise ControllerError("invalid deadline ordering")
    if action["expires_at"] > clock() + 900_000:
        raise ControllerError("lease deadline too long")
    return action


def labels(action):
    return {LABEL: "true", LEASE_LABEL: action["lease_id"], GEN_LABEL: str(action["generation"])}


def resource_name(action):
    return "demo-" + action["lease_id"]


def runtime_resources(config, action, secret, clock):
    selected = profiles.profile(action.get("model_id", profiles.LEGACY_PROFILE_ID))
    name = resource_name(action)
    meta = {"name": name, "labels": labels(action)}
    secret_body = {"apiVersion": "v1", "kind": "Secret", "metadata": meta, "type": "Opaque",
                   "stringData": {"proxy-secret": secret}}
    service = {"apiVersion": "v1", "kind": "Service", "metadata": meta,
               "spec": {"type": "ClusterIP", "selector": {LEASE_LABEL: action["lease_id"]},
                        "ports": [{"name": "proxy", "port": 8080, "targetPort": 8080}]}}
    env = [{"name": key, "value": str(value)} for key, value in {
        "OPAQUE_DEMO_LEASE_ID": action["lease_id"], "OPAQUE_DEMO_TENANT_ID": action["tenant_id"],
        "OPAQUE_DEMO_GENERATION": action["generation"], "OPAQUE_DEMO_EXPIRES_AT_MS": action["expires_at"],
        "OPAQUE_DEMO_MODEL_PROFILE": selected.profile_id,
        "OPAQUE_DEMO_MODEL_URL": selected.url, "OPAQUE_DEMO_MODEL_ID": selected.model,
        "OPAQUE_DEMO_STATE_DIR": "/tmp/opaque-demo",
        "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/tmp", "TMPDIR": "/tmp",
    }.items()]
    env.append({"name": "OPAQUE_DEMO_PROXY_SECRET", "valueFrom": {"secretKeyRef": {"name": name, "key": "proxy-secret"}}})
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "serviceAccountName": "opaque-demo-runtime", "enableServiceLinks": False,
        "activeDeadlineSeconds": max(1, min(900, math.ceil((action["expires_at"] - clock()) / 1000))),
        "terminationGracePeriodSeconds": 5, "nodeSelector": {"kubernetes.io/arch": "arm64"},
        "securityContext": {"runAsNonRoot": True, "runAsUser": 7383, "runAsGroup": 7383,
                            "fsGroup": 7383, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "runtime", "image": config.image, "imagePullPolicy": "IfNotPresent",
            "command": ["python3", "/opt/opaque/deploy/hosted-demo/runtime.py"], "env": env,
            "ports": [{"name": "proxy", "containerPort": 8080}],
            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                          "limits": {"cpu": "500m", "memory": "384Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "scratch", "mountPath": "/tmp"}]}],
        "volumes": [{"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}]}}
    return [("secrets", secret_body), ("services", service), ("pods", pod)]


class Controller:
    def __init__(self, config, kube, http=None, clock=now_ms):
        config.validate()
        self.config, self.kube, self.http, self.clock = config, kube, http or Http(), clock
        self.locks = [threading.RLock() for _ in config.namespaces]
        self.model_lock = threading.Lock()
        self.stop = threading.Event()

    def load_state(self, slot):
        item = self.kube.get(self.config.namespaces[slot], "configmaps", STATE_NAME)
        if item is None:
            # Precreated in manifests; missing state is not a fresh capacity grant.
            raise ControllerError("slot state unavailable")
        try:
            state = json.loads(item["data"]["state"])
            if (not isinstance(state, dict) or type(state.get("schema_version")) is not int
                    or state["schema_version"] not in {1, 2} or type(state.get("generation")) is not int
                    or state["generation"] < 0):
                raise ValueError()
            # Only historical schema 1 can omit the profile. New records must
            # not silently become Gemma if a profile field disappears.
            if state["schema_version"] == 1:
                state.setdefault("model_id", profiles.LEGACY_PROFILE_ID)
                state["schema_version"] = 2
            profiles.profile(state["model_id"])
        except (KeyError, TypeError, ValueError):
            raise ControllerError("slot state invalid") from None
        return item, state

    def save_state(self, slot, item, state):
        value = {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": STATE_NAME, "resourceVersion": item["metadata"]["resourceVersion"]},
                 "data": {"state": json.dumps(state, separators=(",", ":"))}}
        return self.kube.replace(self.config.namespaces[slot], "configmaps", STATE_NAME, value)

    def report(self, action, kind, **fields):
        status, _ = self.http.json(self.config.worker_url.rstrip("/") + "/internal/report", "POST",
            {"kind": kind, **{key: action[key] for key in ("lease_id", "slot", "generation")}, **fields},
            {"Authorization": "Bearer " + self.config.controller_secret})
        if status != 200:
            raise ControllerError("report unavailable")

    def owned(self, obj, lease_id):
        return (isinstance(obj, dict) and obj.get("metadata", {}).get("labels", {}).get(LABEL) == "true"
                and obj["metadata"]["labels"].get(LEASE_LABEL) == lease_id)

    def runtime_secret(self, action):
        item = self.kube.get(self.config.namespaces[action["slot"]], "secrets", resource_name(action))
        if not self.owned(item, action["lease_id"]):
            raise ControllerError("runtime credential unavailable")
        try:
            secret = base64.b64decode(item["data"]["proxy-secret"], validate=True).decode("ascii")
        except (KeyError, ValueError, UnicodeDecodeError):
            raise ControllerError("runtime credential invalid") from None
        if not re.fullmatch(r"[0-9a-f]{64}", secret):
            raise ControllerError("runtime credential invalid")
        return secret

    def runtime_url(self, action, path):
        return f"http://{resource_name(action)}.{self.config.namespaces[action['slot']]}.svc.cluster.local:8080/{path}"

    def health(self, action, secret, provision_generation):
        selected = profiles.profile(action.get("model_id", profiles.LEGACY_PROFILE_ID))
        status, value = self.http.json(self.runtime_url(action, "health"),
                                      headers={"Authorization": "Bearer " + secret}, timeout=2)
        if (status != 200 or not isinstance(value, dict) or value.get("lease_id") != action["lease_id"]
                or value.get("generation") != provision_generation or value.get("expires_at") != action["expires_at"]
                or value.get("model_profile") != selected.profile_id
                or value.get("model_id") != selected.model or value.get("model_url") != selected.url
                or type(value.get("active_requests")) is not int or value["active_requests"] < 0
                or type(value.get("model_requests_in_flight")) is not int or value["model_requests_in_flight"] < 0):
            raise ControllerError("runtime health invalid")
        return value

    def handle_action(self, action):
        action = validate_action(action, len(self.locks), self.clock)
        with self.locks[action["slot"]]:
            if action["kind"] == "provision":
                self.provision(action)
            else:
                self.cleanup(action)

    def provision(self, action):
        slot, ns = action["slot"], self.config.namespaces[action["slot"]]
        item, state = self.load_state(slot)
        if action["generation"] < state["generation"]:
            return
        if state.get("lease_id") not in {None, action["lease_id"]}:
            raise ControllerError("slot already occupied")
        if state.get("lease_id") is None:
            if action["generation"] <= state["generation"]:
                return
            state = {"schema_version": 2, "generation": action["generation"], "lease_id": action["lease_id"],
                     "model_id": action["model_id"],
                     "tenant_id": action["tenant_id"], "expires_at": action["expires_at"],
                     "provision_generation": action["generation"], "status": "provisioning", "create_inflight": False,
                     "chat_inflight": False, "execution_stopped": True}
            item = self.save_state(slot, item, state)
        if (state["generation"] != action["generation"] or state.get("tenant_id") != action["tenant_id"]
                or state["model_id"] != action["model_id"]
                or state.get("expires_at") != action["expires_at"] or state.get("status") == "cleanup"):
            raise ControllerError("work binding mismatch")
        if state.get("create_inflight"):
            raise ControllerError("ambiguous creation quarantined")
        if self.clock() >= action["provision_deadline_at"] or self.clock() >= action["expires_at"]:
            self.report(action, "failed")
            return
        name = resource_name(action)
        existing_secret = self.kube.get(ns, "secrets", name)
        secret = self.runtime_secret(action) if existing_secret else secrets.token_hex(32)
        for kind, resource in runtime_resources(self.config, action, secret, self.clock):
            existing = self.kube.get(ns, kind, name)
            if existing is not None:
                if not self.owned(existing, action["lease_id"]) or existing["metadata"]["labels"].get(GEN_LABEL) != str(action["generation"]):
                    raise ControllerError("existing resource binding mismatch")
                continue
            if self.clock() >= action["provision_deadline_at"]:
                self.report(action, "failed")
                return
            # Persist BEFORE issuing CREATE. Uncertain response/restart leaves a durable fence.
            state["create_inflight"] = True
            item = self.save_state(slot, item, state)
            try:
                self.kube.create(ns, kind, resource)
            except AmbiguousMutation:
                raise
            except ControllerError:
                state["create_inflight"] = False
                self.save_state(slot, item, state)
                raise
            state["create_inflight"] = False
            item = self.save_state(slot, item, state)
        try:
            health = self.health(action, secret, state["provision_generation"])
        except ControllerError:
            return  # Poll work again; never report ready merely because the Pod exists.
        if health.get("ready") is True and self.clock() < action["provision_deadline_at"]:
            state["status"] = "ready"
            self.save_state(slot, item, state)
            self.report(action, "ready")

    def cleanup(self, action):
        slot, ns = action["slot"], self.config.namespaces[action["slot"]]
        item, state = self.load_state(slot)
        if action["generation"] < state["generation"]:
            return
        if state.get("lease_id") is None:
            # A repeated acknowledged cleanup is safe only for the exact persisted tombstone.
            if state.get("cleaned_lease_id") == action["lease_id"] and state["generation"] == action["generation"]:
                if state["model_id"] != action["model_id"]:
                    raise ControllerError("cleanup model binding mismatch")
                self.report(action, "cleaned", resources_deleted=True, provisioning_stopped=True, execution_stopped=True)
                return
            # If provision never began, establish a tombstone after checking absence below.
            state = {"schema_version": 2, "generation": action["generation"], "lease_id": action["lease_id"],
                     "model_id": action["model_id"], "tenant_id": action["tenant_id"],
                     "provision_generation": action["generation"], "status": "cleanup", "create_inflight": False,
                     "chat_inflight": False, "execution_stopped": True}
        elif state.get("lease_id") != action["lease_id"]:
            raise ControllerError("cleanup lease mismatch")
        if state["model_id"] != action["model_id"]:
            raise ControllerError("cleanup model binding mismatch")
        state["generation"], state["status"] = action["generation"], "cleanup"
        item = self.save_state(slot, item, state)
        if state.get("create_inflight"):
            raise ControllerError("ambiguous creation quarantined")
        if state.get("chat_inflight") or not state.get("execution_stopped", False):
            # Worker starts its shorter visitor TTL at ready. Runtime retains its original
            # provisioning hard deadline; both identities must be checked against the right bound.
            runtime_action = {**action, "expires_at": state["expires_at"]}
            health = self.health(runtime_action, self.runtime_secret(action), state["provision_generation"])
            if health["active_requests"] != 0 or health["model_requests_in_flight"] != 0:
                return
            state["chat_inflight"], state["execution_stopped"] = False, True
            item = self.save_state(slot, item, state)
        for kind in ("pods", "services", "secrets"):
            obj = self.kube.get(ns, kind, resource_name(action))
            if obj is not None:
                if not self.owned(obj, action["lease_id"]):
                    raise ControllerError("cleanup resource ownership mismatch")
                self.kube.delete(ns, kind, resource_name(action), obj["metadata"]["uid"])
        # Deletion acknowledgement alone is not deletion evidence (finalizers can retain objects).
        if any(self.kube.get(ns, kind, resource_name(action)) is not None for kind in ("pods", "services", "secrets")):
            return
        self.save_state(slot, item, {"schema_version": 2, "generation": action["generation"],
                                   "lease_id": None, "cleaned_lease_id": action["lease_id"],
                                   "model_id": action["model_id"]})
        self.report(action, "cleaned", resources_deleted=True, provisioning_stopped=True, execution_stopped=True)

    def find_proxy_action(self, lease_id, generation):
        for slot in range(len(self.locks)):
            _, state = self.load_state(slot)
            if state.get("lease_id") == lease_id:
                if (state.get("status") != "ready" or state.get("generation") != generation
                        or state.get("create_inflight")
                        or self.clock() >= min(state.get("expires_at", 0), state.get("proxy_expires_at", state.get("expires_at", 0)))):
                    raise ControllerError("lease unavailable")
                return {"lease_id": lease_id, "generation": generation, "slot": slot,
                        "tenant_id": state["tenant_id"], "expires_at": state["expires_at"],
                        "model_id": state["model_id"]}
        raise ControllerError("lease unavailable")

    def poll_once(self):
        status, value = self.http.json(self.config.worker_url.rstrip("/") + "/internal/work",
                                      headers={"Authorization": "Bearer " + self.config.controller_secret})
        if status != 200 or not isinstance(value, dict) or not isinstance(value.get("actions"), list) or len(value["actions"]) > 2:
            raise ControllerError("invalid queue response")
        for action in value["actions"]:
            try:
                self.handle_action(action)
            except ControllerError:
                # Work is durable at the Worker; failure never returns capacity.
                continue

    def run(self):
        while not self.stop.is_set():
            try:
                self.poll_once()
            except ControllerError:
                pass
            self.stop.wait(self.config.poll_seconds)


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, controller):
        self.controller = controller
        self.connections = threading.BoundedSemaphore(8)
        super().__init__(address, ProxyHandler)

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


class ProxyHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_args):
        pass

    def reject(self, status):
        body = b'{"error":"demo session unavailable"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.proxy()

    def do_POST(self):
        self.proxy()

    def proxy(self):
        controller = self.server.controller
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + controller.config.controller_secret):
            self.reject(401)
            return
        match = re.fullmatch(r"/sessions/([0-9a-f]{32})/proxy/(" + "|".join(re.escape(path) for path in PATHS) + ")", self.path)
        raw_generation = self.headers.get("X-Opaque-Lease-Generation", "")
        raw_expiry = self.headers.get("X-Opaque-Lease-Expires-At", "")
        if (not match or not re.fullmatch(r"[1-9][0-9]{0,15}", raw_generation)
                or not re.fullmatch(r"[1-9][0-9]{0,15}", raw_expiry) or PATHS[match[2]] != self.command):
            self.reject(404)
            return
        body = None
        if self.command == "POST":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if not 0 < length <= 8192 or self.headers.get("Transfer-Encoding"):
                self.reject(400)
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.reject(400)
                return
        acquired, started = False, False
        try:
            action = controller.find_proxy_action(match[1], int(raw_generation))
            with controller.locks[action["slot"]]:
                action = controller.find_proxy_action(match[1], int(raw_generation))
                item, state = controller.load_state(action["slot"])
                expiry = int(raw_expiry)
                if (expiry <= controller.clock() or expiry > state["expires_at"]
                        or expiry > state.get("proxy_expires_at", state["expires_at"])):
                    raise ControllerError("lease expiry mismatch")
                if state.get("proxy_expires_at") != expiry:
                    state["proxy_expires_at"] = expiry
                    item = controller.save_state(action["slot"], item, state)
                if match[2] == "api/chat":
                    acquired = controller.model_lock.acquire(blocking=False)
                    if not acquired or any(controller.load_state(slot)[1].get("chat_inflight")
                                           for slot in range(len(controller.locks))):
                        self.reject(409)
                        return
                    state["chat_inflight"], state["execution_stopped"] = True, False
                    item = controller.save_state(action["slot"], item, state)
                secret = controller.runtime_secret(action)
                headers = {"Authorization": "Bearer " + secret, "Accept": "text/event-stream,application/json,text/html"}
                if body is not None:
                    headers["Content-Type"] = "application/json"
                with controller.http.open(controller.runtime_url(action, match[2]), self.command, body, headers, timeout=100) as response:
                    self.send_response(response.status)
                    # Pass only rendering/security metadata, never Set-Cookie or provider credentials.
                    for key in ("Content-Type", "Content-Security-Policy", "X-Content-Type-Options"):
                        if response.headers.get(key):
                            self.send_header(key, response.headers[key])
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    started = True
                    deadline, total, disconnected = time.monotonic() + 150, 0, False
                    while True:
                        chunk = response.read1(4096)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > 1_048_576 or time.monotonic() > deadline:
                            raise ControllerError("runtime response bound exceeded")
                        if not disconnected:
                            try:
                                self.wfile.write(chunk)
                                self.wfile.flush()
                            except OSError:
                                disconnected = True  # Drain remote work even after browser disconnect.
                    if match[2] == "api/chat":
                        complete = False
                        for _ in range(3):
                            health = controller.health(action, secret, state["provision_generation"])
                            if health["active_requests"] == 0 and health["model_requests_in_flight"] == 0:
                                complete = True
                                break
                            time.sleep(.1)
                        fresh_item, fresh = controller.load_state(action["slot"])
                        if (complete and fresh.get("lease_id") == action["lease_id"]
                                and fresh["model_id"] == action["model_id"]
                                and fresh.get("generation") == action["generation"] and fresh.get("status") == "ready"):
                            item, state = fresh_item, fresh
                            state["chat_inflight"], state["execution_stopped"] = False, True
                            controller.save_state(action["slot"], item, state)
                            if response.status == 200 and "text/event-stream" in response.headers.get("Content-Type", "") and not disconnected:
                                trailer = b"event: opaque_execution_complete\ndata: " + encode_json({
                                    "lease_id": action["lease_id"], "generation": action["generation"]}) + b"\n\n"
                                self.wfile.write(trailer)
                                self.wfile.flush()
        except (ControllerError, OSError, TimeoutError):
            if not started:
                self.reject(503)
        finally:
            if acquired:
                controller.model_lock.release()
            self.close_connection = True


def main():
    config = Config(os.environ["OPAQUE_DEMO_WORKER_URL"], os.environ["OPAQUE_DEMO_CONTROLLER_SECRET"],
                    tuple(os.environ.get("OPAQUE_DEMO_SLOT_NAMESPACES", "opaque-demo-slot-0").split(",")),
                    os.environ["OPAQUE_DEMO_RUNTIME_IMAGE"])
    controller = Controller(config, Kube(config.namespaces))
    threading.Thread(target=controller.run, daemon=True).start()
    ProxyServer(("0.0.0.0", 8080), controller).serve_forever()


if __name__ == "__main__":
    main()
