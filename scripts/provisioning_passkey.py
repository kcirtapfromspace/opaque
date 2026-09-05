#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["fido2==2.2.1"]
# ///
"""Answer an Opaque provisioning challenge with an existing USB FIDO2 key.

Run with `uv run scripts/provisioning_passkey.py --begin BEGIN.json --output
ASSERTION.json`. This performs no enrollment, PIN setup, network request or
broker mutation. The broker verifies and consumes the resulting assertion.

API: https://developers.yubico.com/python-fido2/Migration_1-2.html
USB/PIN interaction: https://developers.yubico.com/python-fido2/API_Documentation/autoapi/fido2/client/index.html
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

MAX_INPUT_BYTES = 128 * 1024
PINNED_FIDO2 = "2.2.1"


class CeremonyError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise CeremonyError("JSON contains duplicate fields")
        result[name] = value
    return result


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode(value, *, maximum=1024) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise CeremonyError("challenge and credential IDs must use unpadded base64url")
    if len(value) > maximum * 2:
        raise CeremonyError("challenge or credential ID exceeds the size limit")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as error:
        raise CeremonyError("invalid base64url input") from error
    if len(raw) > maximum or encode(raw) != value:
        raise CeremonyError("noncanonical or oversized base64url input")
    return raw


def validate_begin(payload, *, now=None):
    if not isinstance(payload, dict):
        raise CeremonyError("begin response must be a JSON object")
    if "error" in payload and payload["error"] is not None:
        raise CeremonyError("broker returned an error instead of a challenge")
    begin = payload.get("result", payload)
    if not isinstance(begin, dict):
        raise CeremonyError("begin response is missing its challenge")
    challenge = begin.get("challenge")
    if len(decode(challenge, maximum=32)) != 32:
        raise CeremonyError("broker challenge must contain exactly 32 random bytes")
    rp_id = begin.get("rp_id")
    if not isinstance(rp_id, str) or len(rp_id) > 253 or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", rp_id
    ):
        raise CeremonyError("rp_id must be an exact lowercase hostname without a port or path")
    allowed = begin.get("allowed_credentials")
    if not isinstance(allowed, list) or not 1 <= len(allowed) <= 64:
        raise CeremonyError("begin response must allow between 1 and 64 existing credentials")
    for credential in allowed:
        decode(credential)
    if len(set(allowed)) != len(allowed):
        raise CeremonyError("begin response contains duplicate credential IDs")
    if begin.get("user_verification") != "required":
        raise CeremonyError("provisioning requires a user-verifying authenticator")
    expires = begin.get("expires_at")
    if type(expires) is not int or expires <= (time.time() if now is None else now):
        raise CeremonyError("broker challenge has expired or has no valid expiry")
    review = begin.get("review")
    if not isinstance(review, str) or not review.strip() or len(review.encode()) > 64 * 1024:
        raise CeremonyError("begin response must include the complete bounded review")
    if any((ord(c) < 32 and c not in "\n\t") or ord(c) == 127 or c in "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" for c in review):
        raise CeremonyError("review contains unsupported display controls")
    return dict(begin)


def load_begin(path: Path):
    with path.open("rb") as source:
        data = source.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise CeremonyError("begin response exceeds the input limit")
    try:
        return validate_begin(json.loads(data, object_pairs_hook=unique_object))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CeremonyError("begin response is not valid UTF-8 JSON") from error


def request_options(begin, *, now=None):
    begin = validate_begin(begin, now=now)
    remaining_ms = int((begin["expires_at"] - (time.time() if now is None else now)) * 1000)
    if remaining_ms <= 0:
        raise CeremonyError("broker challenge has expired")
    return {
        "challenge": begin["challenge"],
        "rpId": begin["rp_id"],
        "allowCredentials": [{"type": "public-key", "id": credential} for credential in begin["allowed_credentials"]],
        "userVerification": "required",
        "timeout": min(remaining_ms, 120_000),
    }


def assertion_json(response, begin):
    """Map Yubico's AuthenticationResponse, retaining the signed bytes exactly."""
    credential_id = encode(bytes(response.raw_id))
    if credential_id not in begin["allowed_credentials"]:
        raise CeremonyError("authenticator returned a credential outside the broker allowlist")
    auth_data = bytes(response.response.authenticator_data)
    client_data = bytes(response.response.client_data)
    signature = bytes(response.response.signature)
    if len(auth_data) < 37 or auth_data[32] & 0x05 != 0x05:
        raise CeremonyError("authenticator did not prove both presence and user verification")
    if auth_data[:32] != hashlib.sha256(begin["rp_id"].encode()).digest():
        raise CeremonyError("authenticator returned the wrong relying-party hash")
    try:
        client = json.loads(client_data, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CeremonyError("authenticator returned invalid client data") from error
    if not isinstance(client, dict) or client.get("type") != "webauthn.get" or client.get("challenge") != begin["challenge"] or client.get("origin") != f"https://{begin['rp_id']}" or client.get("crossOrigin", False) is not False:
        raise CeremonyError("authenticator answered a different challenge or origin")
    if not signature or len(signature) > 1024:
        raise CeremonyError("authenticator returned an invalid signature payload")
    return {"credential_id": credential_id, "authenticator_data": encode(auth_data), "client_data_json": encode(client_data), "signature": encode(signature)}


def collect_assertion(client, begin):
    """The injectable client permits protocol tests; the CLI always uses USB."""
    from fido2.webauthn import PublicKeyCredentialRequestOptions

    options = request_options(begin)
    cancellation = threading.Event()
    timer = threading.Timer(options["timeout"] / 1000, cancellation.set)
    timer.daemon = True
    timer.start()
    try:
        selection = client.get_assertion(PublicKeyCredentialRequestOptions.from_dict(options), event=cancellation)
        if cancellation.is_set() or time.time() >= begin["expires_at"]:
            raise CeremonyError("authenticator did not finish before the challenge deadline")
        if len(selection.get_assertions()) != 1:
            raise CeremonyError("authenticator returned an ambiguous credential selection")
        return assertion_json(selection.get_response(0), begin)
    finally:
        timer.cancel()


def usb_client(rp_id):
    try:
        if importlib.metadata.version("fido2") != PINNED_FIDO2:
            raise CeremonyError("use uv run to load the pinned python-fido2 version")
        from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
        from fido2.hid import CtapHidDevice
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise CeremonyError("run this helper with uv run to install its pinned FIDO2 dependency") from error

    class Interaction(UserInteraction):
        def prompt_up(self):
            print("Touch the registered security key.", file=sys.stderr)

        def request_pin(self, permissions, requested_rp_id):
            if requested_rp_id != rp_id or not sys.stdin.isatty():
                raise CeremonyError("the authenticator PIN requires this relying party and an interactive terminal")
            return getpass.getpass("Security key PIN: ")

        def request_uv(self, permissions, requested_rp_id):
            if requested_rp_id != rp_id:
                raise CeremonyError("authenticator requested verification for a different relying party")
            print("Complete user verification on the security key.", file=sys.stderr)
            return True

    devices = list(CtapHidDevice.list_devices())
    if len(devices) != 1:
        for device in devices:
            device.close()
        raise CeremonyError("connect exactly one accessible USB FIDO2 authenticator with the registered credential")
    device = devices[0]
    try:
        client = Fido2Client(device, DefaultClientDataCollector(f"https://{rp_id}"), user_interaction=Interaction())
    except Exception:
        device.close()
        raise
    return client, device


def write_assertion(path: Path, assertion):
    data = (json.dumps(assertion, separators=(",", ":")) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--begin", type=Path, required=True, help="JSON from the broker's provisioning begin command")
    parser.add_argument("--output", type=Path, required=True, help="new private assertion JSON file; never overwritten")
    args = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty():
            raise CeremonyError("run this ceremony in the human operator's interactive terminal")
        if os.path.lexists(args.output):
            raise CeremonyError("output already exists; choose a new private assertion file")
        begin = load_begin(args.begin)
        print(begin["review"], file=sys.stderr)
        print(f"\nAuthenticator origin: https://{begin['rp_id']}\nUser verification is required.", file=sys.stderr)
        client, device = usb_client(begin["rp_id"])
        try:
            assertion = collect_assertion(client, begin)
        finally:
            device.close()
        write_assertion(args.output, assertion)
        print(f"Assertion saved to {args.output.absolute()}; submit it with the matching begin challenge ID.")
        return 0
    except (CeremonyError, OSError) as error:
        print(f"provisioning-passkey: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("provisioning-passkey: ceremony cancelled", file=sys.stderr)
        return 1
    except Exception:
        # Authenticator exceptions may include opaque device details. Keep PINs
        # and response material out of diagnostics, including tracebacks.
        print("provisioning-passkey: authenticator ceremony failed; verify key enrollment, PIN and USB access, then request a fresh challenge", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
