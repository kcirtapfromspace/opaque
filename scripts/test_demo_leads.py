import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import demo_leads


class DemoLeadsTests(unittest.TestCase):
    def test_secret_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "secret"
            secret.write_text("a" * 64)
            secret.chmod(0o600)
            self.assertEqual(demo_leads.read_secret(secret), "a" * 64)
            secret.chmod(0o644)
            with self.assertRaises(demo_leads.LeadError):
                demo_leads.read_secret(secret)
            secret.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(secret)
            with self.assertRaises(demo_leads.LeadError):
                demo_leads.read_secret(link)

    def test_export_is_private_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "leads.json"
            data = {"leads": [{"email": "fixture@example.test"}], "next_cursor": None}
            demo_leads.write_export(output, data)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text()), data)
            with self.assertRaises(demo_leads.LeadError):
                demo_leads.write_export(output, {})
            self.assertEqual(json.loads(output.read_text()), data)

    @patch("demo_leads.http.client.HTTPSConnection")
    def test_redirect_never_receives_credentials(self, connection):
        connection.return_value.getresponse.return_value.status = 302
        with self.assertRaisesRegex(demo_leads.LeadError, "HTTP 302"):
            demo_leads.request("https://demo.opaque.info", "sensitive-token", "list", {"limit": 25})
        self.assertEqual(connection.call_count, 1)
        connection.return_value.getresponse.return_value.read.assert_not_called()
        connection.return_value.close.assert_called_once()

    @patch("demo_leads.http.client.HTTPSConnection")
    def test_errors_do_not_disclose_response_or_token(self, connection):
        response = connection.return_value.getresponse.return_value
        response.status = 500
        response.read.return_value = b'{"email":"private@example.test"}'
        with self.assertRaises(demo_leads.LeadError) as error:
            demo_leads.request("https://demo.opaque.info", "private-token", "list", {"limit": 25})
        self.assertNotIn("private", str(error.exception))
        response.read.assert_not_called()

    @patch("demo_leads.http.client.HTTPSConnection")
    def test_response_page_and_size_are_bounded(self, connection):
        response = connection.return_value.getresponse.return_value
        response.status = 200
        for body in [b"x" * 1_048_577, b"[]", b'{"leads":[{},{}],"next_cursor":null}', b'{"deleted":false}']:
            response.read.return_value = body
            with self.assertRaises(demo_leads.LeadError):
                demo_leads.request("https://demo.opaque.info", "token", "list", {"limit": 1})
        response.read.return_value = b'{"leads":[],"next_cursor":null}'
        self.assertEqual(demo_leads.request("https://demo.opaque.info", "token", "list", {"limit": 1}), {"leads": [], "next_cursor": None})

    @patch("demo_leads.http.client.HTTPSConnection")
    def test_rejects_insecure_or_ambiguous_origins_before_network(self, connection):
        for origin in ["http://demo.opaque.info", "https://demo.opaque.info/path", "https://user@demo.opaque.info", "https://demo.opaque.info?query=x", "https://demo.opaque.info#fragment"]:
            with self.assertRaises(demo_leads.LeadError):
                demo_leads.request(origin, "token", "list", {"limit": 1})
        connection.assert_not_called()

    def test_cli_exports_without_printing_contact_details(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "leads.json"
            page = {"leads": [{"id": "fixture-id", "email": "fixture@example.test"}], "next_cursor": "next-page"}
            console = io.StringIO()
            with patch("demo_leads.read_secret", return_value="token"), patch("demo_leads.request", return_value=page) as request, contextlib.redirect_stdout(console):
                self.assertEqual(demo_leads.main(["--secret-file", "unused", "list", "--output", str(output)]), 0)
            self.assertNotIn("fixture@example.test", console.getvalue())
            self.assertIn("Another page", console.getvalue())
            self.assertEqual(json.loads(output.read_text()), page)
            request.assert_called_once_with("https://demo.opaque.info", "token", "list", {"limit": 25})


if __name__ == "__main__":
    unittest.main()
