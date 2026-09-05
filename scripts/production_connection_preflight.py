#!/usr/bin/env python3
"""Read public OIDC metadata; never log in, acquire tokens, or query application data.

Exit 0 means the broker's OIDC metadata prerequisites passed. It does not mean
the client is registered, a user is enrolled, or an OAuth resource is connected.
Exit 1 means a metadata prerequisite failed; exit 2 means invalid local input.
Public metadata never establishes tenant membership or resource authorization.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_BODY_BYTES = 64 * 1024
PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


class PreflightError(ValueError):
    """Stable messages only: never include HTTP payloads or endpoint errors."""


def strict_json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PreflightError("duplicate JSON field")
            result[key] = value
        return result

    def constant(_):
        raise PreflightError("non-finite JSON number")

    try:
        return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise PreflightError("invalid metadata JSON") from None


def origin(url, allow_loopback_http=False):
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise PreflightError("invalid endpoint URL")
    if any(ord(char) < 33 or ord(char) > 126 for char in url) or "\\" in url:
        raise PreflightError("invalid endpoint URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise PreflightError("invalid endpoint URL") from None
    if (not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or not (parsed.scheme == "https" or allow_loopback_http and parsed.scheme == "http"
                    and parsed.hostname in {"127.0.0.1", "::1"})):
        raise PreflightError("endpoint requires HTTPS without credentials, query or fragment")
    return parsed.scheme, parsed.hostname, port or (443 if parsed.scheme == "https" else 80)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PublicMetadata:
    def __init__(self):
        # No ambient proxy, cookie jar, credentials, retry or redirect behavior.
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(self, url):
        try:
            request = Request(url, headers={"Accept": "application/json", "Accept-Encoding": "identity"})
            with self.opener.open(request, timeout=5) as response:
                if response.status != 200 or response.headers.get_content_type() not in {"application/json", "application/jwk-set+json"}:
                    raise PreflightError("metadata endpoint did not return JSON HTTP 200")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise PreflightError("compressed metadata is unsupported")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdecimal() or int(length) > MAX_BODY_BYTES):
                    raise PreflightError("metadata response exceeds the byte limit")
                raw = response.read(MAX_BODY_BYTES + 1)
                if len(raw) > MAX_BODY_BYTES:
                    raise PreflightError("metadata response exceeds the byte limit")
                return strict_json(raw)
        except PreflightError:
            raise
        except (HTTPError, URLError, OSError, ValueError):
            raise PreflightError("public metadata is unavailable; no redirects are followed") from None


def string_set(document, field):
    value = document.get(field, [])
    if (not isinstance(value, list) or len(value) > 128
            or any(not isinstance(item, str) or not 0 < len(item) <= 256 for item in value)
            or len(set(value)) != len(value)):
        raise PreflightError("invalid advertised metadata list")
    return set(value)


def rsa_thumbprints(document):
    """RFC 7638 public-key thumbprints; pin RS256 for the current resource profile."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise PreflightError("invalid public JWKS")
    keys = document["keys"]
    if not 1 <= len(keys) <= 32:
        raise PreflightError("public JWKS key count is out of bounds")
    seen_kids, thumbprints = set(), set()
    for key in keys:
        if not isinstance(key, dict) or PRIVATE_JWK_FIELDS.intersection(key):
            raise PreflightError("JWKS must contain only public keys")
        kid = key.get("kid")
        if kid is not None:
            if not isinstance(kid, str) or not 1 <= len(kid) <= 256 or kid in seen_kids:
                raise PreflightError("invalid or ambiguous JWKS key identifier")
            seen_kids.add(kid)
        if key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256":
            continue
        if key.get("use", "sig") != "sig" or key.get("key_ops", ["verify"]) != ["verify"]:
            continue
        components = {}
        for field in ("n", "e"):
            value = key.get(field)
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,1400}", value):
                raise PreflightError("invalid public RSA key")
            try:
                decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            except ValueError:
                raise PreflightError("invalid public RSA key") from None
            if (not decoded or decoded[0] == 0
                    or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value):
                raise PreflightError("noncanonical public RSA key")
            components[field] = int.from_bytes(decoded, "big")
        if (not 2048 <= components["n"].bit_length() <= 8192 or components["n"] % 2 != 1
                or not 3 <= components["e"] < 2**32 or components["e"] % 2 != 1):
            raise PreflightError("public RSA key is below the required profile")
        canonical = json.dumps({field: key[field] for field in ("e", "kty", "n")}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).digest()
        thumbprints.add(base64.urlsafe_b64encode(digest).decode().rstrip("="))
    if not thumbprints:
        raise PreflightError("no compatible public RS256 signing key")
    return sorted(thumbprints)


def inspect_identity(issuer, client_id, fetch, *, allow_loopback_http=False, expected_thumbprints=()):
    issuer_origin = origin(issuer, allow_loopback_http)
    if issuer.endswith("/") or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", client_id):
        raise PreflightError("use an exact issuer without trailing slash and a registered client identifier")
    if any(not re.fullmatch(r"[A-Za-z0-9_-]{43}", value) for value in expected_thumbprints):
        raise PreflightError("expected thumbprint must be an RFC 7638 SHA-256 base64url value")
    checks = []
    report = {
        "schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
        "issuer": issuer, "planned_client_id": client_id, "checks": checks,
        "broker_metadata_compatible": False, "production_connection_verified": False,
        "source_data_requests": 0, "token_requests": 0,
    }

    def record(name, passed, detail):
        checks.append({"name": name, "status": "pass" if passed else "blocked", "detail": detail})

    try:
        discovery = fetch(issuer + "/.well-known/openid-configuration")
        if not isinstance(discovery, dict) or discovery.get("issuer") != issuer:
            raise PreflightError("discovered issuer does not exactly match the configured issuer")
        # Reject all substituted origins before fetching any discovered endpoint.
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if origin(discovery.get(field), allow_loopback_http) != issuer_origin:
                raise PreflightError("discovered endpoint leaves the configured issuer origin")
        record("issuer_and_endpoint_binding", True, "Exact issuer and same-origin HTTPS endpoints observed.")
        flows = string_set(discovery, "response_types_supported")
        scopes = string_set(discovery, "scopes_supported")
        pkce = string_set(discovery, "code_challenge_methods_supported")
        algorithms = string_set(discovery, "id_token_signing_alg_values_supported")
        record("authorization_code", "code" in flows, "Broker login requires the authorization code flow.")
        record("pkce_s256", "S256" in pkce, "Broker login requires PKCE S256.")
        record("broker_login_scopes", {"openid", "email", "profile"} <= scopes,
               "The current broker requests openid, email and profile.")
        record("rs256_signatures", "RS256" in algorithms, "This preflight pins the current RS256 profile.")
        fingerprints = rsa_thumbprints(fetch(discovery["jwks_uri"]))
        report["public_jwk_sha256_thumbprints"] = fingerprints
        record("public_signing_keys", True, "Bounded JWKS contains a compatible public RSA signing key.")
        if expected_thumbprints:
            record("operator_key_pins", set(fingerprints) == set(expected_thumbprints),
                   "The complete compatible public signing-key set must match the operator's pins.")
        report["advertised_scopes"] = sorted(scopes)
        report["advertised_token_endpoint_auth_methods"] = sorted(string_set(discovery, "token_endpoint_auth_methods_supported"))
        report["broker_metadata_compatible"] = all(check["status"] == "pass" for check in checks)
    except PreflightError as error:
        record("metadata_validation", False, str(error))

    # OIDC discovery is never proof of these independent provisioning gates.
    report["unverified_requirements"] = [
        "Register the exact broker public client and fixed loopback callback; perform a real code+PKCE login.",
        "Enroll issuer/subject identities into two actual broker tenants and test cross-tenant denial.",
        "Provision an OAuth resource issuer/client/audience with at+jwt access tokens and admitted metric scopes; Dex ID tokens are not resource access tokens.",
        "Provision separately authorized source credentials and tenant mappings, bounded aggregates and genuine event watermarks.",
        "Verify source and model-disclosure revocation through the broker, including active work.",
    ]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--expected-jwk-thumbprint", action="append", default=[])
    parser.add_argument("--allow-loopback-http", action="store_true", help="explicit local fixture only; no localhost DNS alias")
    args = parser.parse_args()
    try:
        report = inspect_identity(args.issuer, args.client_id, PublicMetadata().get,
                                  allow_loopback_http=args.allow_loopback_http,
                                  expected_thumbprints=args.expected_jwk_thumbprint)
    except PreflightError as error:
        print(json.dumps({"error": str(error), "production_connection_verified": False}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["broker_metadata_compatible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
