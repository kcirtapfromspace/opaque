#!/usr/bin/env python3
"""Synthetic protocol tests; these do not demonstrate human/hardware approval.

Run: uv run --with fido2==2.2.1 python -m unittest discover -s scripts
     -p test_provisioning_passkey.py
"""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import provisioning_passkey as helper


def synthetic_begin():
    return {
        "challenge_id": "synthetic-challenge-id",
        "challenge": helper.encode(b"c" * 32),
        "rp_id": "opaque.local",
        "allowed_credentials": [helper.encode(b"synthetic-existing-key")],
        "user_verification": "required",
        "expires_at": int(time.time()) + 60,
        "review": "SYNTHETIC TEST ONLY\nGrant a bounded access profile.",
    }


def synthetic_response(begin, *, flags=0x05, client_changes=None, raw_id=None):
    client = {
        "type": "webauthn.get",
        "challenge": begin["challenge"],
        "origin": "https://opaque.local",
        "crossOrigin": False,
    }
    client.update(client_changes or {})
    return SimpleNamespace(
        raw_id=raw_id or helper.decode(begin["allowed_credentials"][0]),
        response=SimpleNamespace(
            authenticator_data=hashlib.sha256(begin["rp_id"].encode()).digest()
            + bytes([flags]) + (1).to_bytes(4, "big"),
            client_data=json.dumps(client, separators=(",", ":")).encode(),
            signature=b"synthetic-signature-not-human-proof",
        ),
    )


class BeginTests(unittest.TestCase):
    def test_direct_and_json_rpc_begin_responses_preserve_challenge(self):
        begin = synthetic_begin()
        for payload in [begin, {"jsonrpc": "2.0", "id": 1, "result": begin}]:
            with self.subTest(payload=payload):
                self.assertEqual(helper.validate_begin(payload), begin)

    def test_exact_allowlist_nonce_origin_and_uv_are_requested(self):
        begin = synthetic_begin()
        begin["allowed_credentials"].append(helper.encode(b"second-key"))
        options = helper.request_options(begin, now=begin["expires_at"] - 10)
        self.assertEqual(options, {
            "challenge": begin["challenge"], "rpId": "opaque.local",
            "allowCredentials": [{"type": "public-key", "id": value}
                                 for value in begin["allowed_credentials"]],
            "userVerification": "required", "timeout": 10_000,
        })

    def test_malformed_nonce_allowlist_rp_and_review_are_rejected(self):
        cases = {
            "challenge": [None, "", "YQ", helper.encode(b"c" * 32) + "=", "_x", "a" * 2049],
            "allowed_credentials": [[], ["bad="], ["a", "a"], [helper.encode(b"a")] * 65],
            "rp_id": [None, "https://opaque.local", "opaque.local:443", "opaque.local/", "Opaque.local", "-bad.local", "a..local"],
            "user_verification": [None, "preferred", "discouraged"],
            "expires_at": [True, "9999999999", 0],
            "review": [None, "", "\x1b[2Japprove", "look\u202ehere", "x" * (64 * 1024 + 1)],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    begin = synthetic_begin()
                    begin[field] = value
                    with self.assertRaises(helper.CeremonyError):
                        helper.validate_begin(begin)

    def test_error_reply_and_expired_challenge_are_rejected(self):
        with self.assertRaises(helper.CeremonyError):
            helper.validate_begin({"error": {"message": "denied"}})
        begin = synthetic_begin()
        with self.assertRaises(helper.CeremonyError):
            helper.request_options(begin, now=begin["expires_at"])

    def test_file_loader_rejects_duplicates_invalid_json_and_oversize(self):
        invalid = [b'{"challenge":"a","challenge":"b"}', b"not JSON", b"\xff",
                   b" " * (helper.MAX_INPUT_BYTES + 1)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "begin.json"
            for data in invalid:
                with self.subTest(size=len(data)):
                    path.write_bytes(data)
                    with self.assertRaises(helper.CeremonyError):
                        helper.load_begin(path)
            begin = synthetic_begin()
            path.write_text(json.dumps({"result": begin}))
            self.assertEqual(helper.load_begin(path), begin)


class AssertionTests(unittest.TestCase):
    def test_signed_bytes_are_preserved_and_bare_rust_field_names_match(self):
        begin = synthetic_begin()
        response = synthetic_response(begin)
        assertion = helper.assertion_json(response, begin)
        self.assertEqual(set(assertion), {"credential_id", "authenticator_data", "client_data_json", "signature"})
        self.assertEqual(helper.decode(assertion["credential_id"]), response.raw_id)
        self.assertEqual(helper.decode(assertion["authenticator_data"]), response.response.authenticator_data)
        self.assertEqual(helper.decode(assertion["client_data_json"]), response.response.client_data)
        self.assertEqual(helper.decode(assertion["signature"]), response.response.signature)

    def test_missing_presence_or_user_verification_is_rejected(self):
        begin = synthetic_begin()
        for flags in [0x00, 0x01, 0x04]:
            with self.subTest(flags=flags), self.assertRaises(helper.CeremonyError):
                helper.assertion_json(synthetic_response(begin, flags=flags), begin)

    def test_wrong_nonce_origin_ceremony_or_cross_origin_is_rejected(self):
        begin = synthetic_begin()
        for changes in [{"challenge": helper.encode(b"wrong" * 6 + b"!!")},
                        {"origin": "https://different.local"},
                        {"origin": "http://opaque.local"},
                        {"type": "webauthn.create"}, {"crossOrigin": True}]:
            with self.subTest(changes=changes), self.assertRaises(helper.CeremonyError):
                helper.assertion_json(synthetic_response(begin, client_changes=changes), begin)

    def test_wrong_credential_rp_hash_or_malformed_payload_is_rejected(self):
        begin = synthetic_begin()
        cases = [synthetic_response(begin, raw_id=b"other-key")]
        for name, value in [("authenticator_data", b"too short"),
                            ("authenticator_data", b"x" * 32 + b"\x05" + b"\0" * 4),
                            ("client_data", b'[]'), ("signature", b""),
                            ("signature", b"s" * 1025)]:
            response = synthetic_response(begin)
            setattr(response.response, name, value)
            cases.append(response)
        for response in cases:
            with self.subTest(response=response), self.assertRaises(helper.CeremonyError):
                helper.assertion_json(response, begin)

    def test_private_output_is_exclusive_and_does_not_follow_symlinks(self):
        begin = synthetic_begin()
        assertion = helper.assertion_json(synthetic_response(begin), begin)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assertion.json"
            helper.write_assertion(path, assertion)
            self.assertEqual(json.loads(path.read_text()), assertion)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                helper.write_assertion(path, {"overwrite": True})
            self.assertEqual(json.loads(path.read_text()), assertion)
            symlink = Path(directory) / "symlink.json"
            symlink.symlink_to(path)
            with self.assertRaises(FileExistsError):
                helper.write_assertion(symlink, {"overwrite": True})
            self.assertEqual(json.loads(path.read_text()), assertion)

    def test_cli_requires_operator_terminal_before_any_hardware_access(self):
        with patch.object(helper.sys, "stdin") as stdin, patch.object(helper, "usb_client") as usb, patch.object(helper.sys, "stderr", io.StringIO()):
            stdin.isatty.return_value = False
            self.assertEqual(helper.main(["--begin", "unused.json", "--output", "unused-output.json"]), 1)
            usb.assert_not_called()


@unittest.skipUnless(importlib.util.find_spec("fido2"), "run with pinned fido2==2.2.1 to check the actual library API")
class PinnedLibraryTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(helper.importlib.metadata.version("fido2"), helper.PINNED_FIDO2)

    def test_official_response_types_map_without_byte_reencoding(self):
        from fido2.webauthn import AuthenticationResponse, AuthenticatorAssertionResponse, AuthenticatorData, CollectedClientData

        begin = synthetic_begin()
        fake = synthetic_response(begin)
        official = AuthenticationResponse(raw_id=fake.raw_id, response=AuthenticatorAssertionResponse(
            authenticator_data=AuthenticatorData(fake.response.authenticator_data),
            client_data=CollectedClientData(fake.response.client_data),
            signature=fake.response.signature,
        ))
        self.assertEqual(helper.assertion_json(official, begin), helper.assertion_json(fake, begin))

    def test_synthetic_adapter_receives_pinned_request_options_and_cancellation(self):
        from fido2.webauthn import PublicKeyCredentialRequestOptions, UserVerificationRequirement

        begin = synthetic_begin()
        response = synthetic_response(begin)
        selection = Mock()
        selection.get_assertions.return_value = [response]
        selection.get_response.return_value = response
        client = Mock()
        client.get_assertion.return_value = selection
        assertion = helper.collect_assertion(client, begin)
        options = client.get_assertion.call_args.args[0]
        self.assertIsInstance(options, PublicKeyCredentialRequestOptions)
        self.assertEqual(options.challenge, helper.decode(begin["challenge"]))
        self.assertEqual(options.rp_id, begin["rp_id"])
        self.assertEqual(options.user_verification, UserVerificationRequirement.REQUIRED)
        self.assertEqual([value.id for value in options.allow_credentials], [helper.decode(value) for value in begin["allowed_credentials"]])
        self.assertFalse(client.get_assertion.call_args.kwargs["event"].is_set())
        self.assertEqual(assertion, helper.assertion_json(response, begin))

    def test_timeout_and_ambiguous_assertions_fail_closed(self):
        begin = synthetic_begin()
        client = Mock()
        client.get_assertion.return_value.get_assertions.return_value = [object(), object()]
        with self.assertRaisesRegex(helper.CeremonyError, "ambiguous"):
            helper.collect_assertion(client, begin)

        def cancelled(_options, *, event):
            event.set()
            return Mock()

        client.get_assertion.side_effect = cancelled
        with self.assertRaisesRegex(helper.CeremonyError, "deadline"):
            helper.collect_assertion(client, begin)

    def test_missing_or_multiple_usb_devices_do_not_start_a_ceremony(self):
        for devices in [[], [Mock(), Mock()]]:
            with self.subTest(count=len(devices)), patch("fido2.hid.CtapHidDevice.list_devices", return_value=devices), patch("fido2.client.Fido2Client") as client:
                with self.assertRaisesRegex(helper.CeremonyError, "exactly one"):
                    helper.usb_client("opaque.local")
                client.assert_not_called()
                for device in devices:
                    device.close.assert_called_once()

    def test_usb_client_keeps_default_rp_validation_and_interactive_pin_entry(self):
        from fido2.client import ClientError
        from fido2.webauthn import PublicKeyCredentialRequestOptions

        device = Mock()
        with patch("fido2.hid.CtapHidDevice.list_devices", return_value=[device]), patch("fido2.client.Fido2Client") as client:
            _, chosen_device = helper.usb_client("opaque.local")
        self.assertIs(chosen_device, device)
        collector = client.call_args.args[1]
        # Exercise the official RP validation instead of replacing it with an allow-all callback.
        options = helper.request_options(synthetic_begin())
        client_data, rp_id = collector.collect_client_data(PublicKeyCredentialRequestOptions.from_dict(options))
        self.assertEqual(client_data.origin, "https://opaque.local")
        self.assertEqual(rp_id, "opaque.local")
        with self.assertRaises(ClientError):
            collector.collect_client_data(PublicKeyCredentialRequestOptions.from_dict(dict(options, rpId="other.local")))
        interaction = client.call_args.kwargs["user_interaction"]
        with patch.object(helper.sys, "stdin") as stdin, patch.object(helper.getpass, "getpass", return_value="synthetic-test-PIN") as prompt:
            stdin.isatty.return_value = True
            self.assertEqual(interaction.request_pin(1, "opaque.local"), "synthetic-test-PIN")
            prompt.assert_called_once()
            with self.assertRaises(helper.CeremonyError):
                interaction.request_pin(1, "other.local")
        with self.assertRaises(helper.CeremonyError):
            interaction.request_uv(1, "other.local")


if __name__ == "__main__":
    unittest.main()
