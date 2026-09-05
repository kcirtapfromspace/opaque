"""Credential-free HTTP and malformed-metadata regressions for OIDC preflight."""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest

from production_connection_preflight import (
    MAX_BODY_BYTES, PreflightError, PublicMetadata, inspect_identity, origin,
    rsa_thumbprints, strict_json,
)


def fixture(issuer="https://identity.example/dex"):
    def encode(number):
        return base64.urlsafe_b64encode(number.to_bytes((number.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    return {
        "issuer": issuer, "authorization_endpoint": issuer + "/auth",
        "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
        "response_types_supported": ["code"], "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["S256"], "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }, {"keys": [{"kty": "RSA", "kid": "public-test", "alg": "RS256", "use": "sig",
                  "n": encode(2**2047 + 65537), "e": encode(65537)}]}


class MetadataTests(unittest.TestCase):
    def inspect(self, edit=None, pins=()):
        discovery, jwks = fixture()
        if edit:
            edit(discovery, jwks)
        calls = []

        def fetch(url):
            calls.append(url)
            if url.endswith("/.well-known/openid-configuration"):
                return discovery
            if url == "https://identity.example/dex/keys":
                return jwks
            self.fail("unexpected endpoint fetch")

        result = inspect_identity("https://identity.example/dex", "opaque-broker", fetch,
                                  expected_thumbprints=pins)
        return result, calls

    def test_valid_metadata_never_claims_production_connection(self):
        result, calls = self.inspect()
        self.assertTrue(result["broker_metadata_compatible"])
        self.assertFalse(result["production_connection_verified"])
        self.assertEqual((result["source_data_requests"], result["token_requests"]), (0, 0))
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(result["unverified_requirements"]), 5)

    def test_wrong_issuer_or_foreign_endpoint_prevents_jwks_fetch(self):
        for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            with self.subTest(field=field):
                result, calls = self.inspect(lambda d, j: d.update({field: "https://other.example/key"}))
                self.assertFalse(result["broker_metadata_compatible"])
                self.assertEqual(len(calls), 1)

    def test_missing_scope_pkce_or_algorithm_fails(self):
        for field in ("scopes_supported", "code_challenge_methods_supported", "id_token_signing_alg_values_supported"):
            with self.subTest(field=field):
                result, _ = self.inspect(lambda d, j: d.update({field: []}))
                self.assertFalse(result["broker_metadata_compatible"])

    def test_private_key_and_duplicate_kid_are_rejected_without_leaking(self):
        for edit in (lambda d, j: j["keys"][0].update(d="DO-NOT-ECHO-THIS"),
                     lambda d, j: j["keys"].append(copy.deepcopy(j["keys"][0]))):
            result, _ = self.inspect(edit)
            self.assertFalse(result["broker_metadata_compatible"])
            self.assertNotIn("DO-NOT-ECHO-THIS", json.dumps(result))

    def test_key_rotation_requires_complete_matching_pin_set(self):
        result, _ = self.inspect()
        good, _ = self.inspect(pins=result["public_jwk_sha256_thumbprints"])
        bad, _ = self.inspect(pins=["A" * 43])
        self.assertTrue(good["broker_metadata_compatible"])
        self.assertFalse(bad["broker_metadata_compatible"])

    def test_late_malformed_list_cannot_leave_success_flag(self):
        result, _ = self.inspect(lambda d, j: d.update(token_endpoint_auth_methods_supported=[{}]))
        self.assertFalse(result["broker_metadata_compatible"])

    def test_duplicate_and_nonfinite_json_are_rejected(self):
        for raw in (b'{"issuer":"a","issuer":"b"}', b'{"a":NaN}', b'\xff'):
            with self.assertRaises(PreflightError):
                strict_json(raw)

    def test_url_credentials_redirect_fragments_and_loopback_lookalikes(self):
        for url in ("https://user:password@example.test/dex", "https://example.test/dex?token=hidden",
                    "https://example.test/dex#fragment", "http://127.0.0.1.evil.test/dex",
                    "http://localhost/dex", "https://example.test\\@other.test/dex",
                    "https://example.test\n/dex"):
            with self.subTest(url=url), self.assertRaises(PreflightError):
                origin(url, allow_loopback_http=True)
        self.assertEqual(origin("http://127.0.0.1:8721/dex", True), ("http", "127.0.0.1", 8721))

    def test_malformed_public_rsa_keys_are_rejected(self):
        for value in ("", "AQ==", "AAAA", "_", "A" * 1401):
            _, keys = fixture()
            keys["keys"][0]["n"] = value
            with self.assertRaises(PreflightError):
                rsa_thumbprints(keys)


class HttpTests(unittest.TestCase):
    def test_no_credentials_no_redirects_and_bounded_response(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                requests.append((self.path, dict(self.headers)))
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/not-allowed")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                body = b"{}" if self.path == "/ok" else b" " * (MAX_BODY_BYTES + 1)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = PublicMetadata()
            url = f"http://127.0.0.1:{server.server_port}"
            self.assertEqual(client.get(url + "/ok"), {})
            for path in ("/redirect", "/large"):
                with self.assertRaises(PreflightError):
                    client.get(url + path)
            self.assertEqual([path for path, _ in requests], ["/ok", "/redirect", "/large"])
            for _, headers in requests:
                self.assertNotIn("Authorization", headers)
                self.assertNotIn("Cookie", headers)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
