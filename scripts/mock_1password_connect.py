#!/usr/bin/env python3

"""
Minimal mock 1Password Connect API server.

Used only for local demos to show response-shape and plaintext leakage risks
without requiring a real 1Password account or Connect deployment.

Implements:
  GET /v1/vaults
  GET /v1/vaults/<vault_id>/items
  GET /v1/vaults/<vault_id>/items/<item_id>
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


DEMO_VAULT_ID = "vault_demo_123"
DEMO_ITEM_ID = "item_demo_123"

DEMO_VAULT_NAME = "DemoVault"
DEMO_ITEM_TITLE = "DemoItem"
DEMO_FIELD_LABEL = "password"

# Dummy value that is safe to show in a recorded demo.
DEMO_FIELD_VALUE = "demo_value_1p_123456"


class Handler(BaseHTTPRequestHandler):
    server_version = "opaque-mock-1password/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep demo recordings clean.
        return

    def _send(self, status: int, body: Any) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        segments = [s for s in path.split("/") if s]

        # Basic auth header check (not enforced beyond presence).
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._send(401, {"error": "missing bearer token"})
            return

        if segments == ["v1", "vaults"]:
            self._send(
                200,
                [
                    {
                        "id": DEMO_VAULT_ID,
                        "name": DEMO_VAULT_NAME,
                        "description": "Mock vault (demo-only)",
                    }
                ],
            )
            return

        if (
            len(segments) == 4
            and segments[0] == "v1"
            and segments[1] == "vaults"
            and segments[3] == "items"
        ):
            vault_id = segments[2]
            if vault_id != DEMO_VAULT_ID:
                self._send(404, {"error": f"vault not found: {vault_id}"})
                return
            self._send(
                200,
                [
                    {
                        "id": DEMO_ITEM_ID,
                        "title": DEMO_ITEM_TITLE,
                        "category": "login",
                    }
                ],
            )
            return

        if (
            len(segments) == 5
            and segments[0] == "v1"
            and segments[1] == "vaults"
            and segments[3] == "items"
        ):
            vault_id = segments[2]
            item_id = segments[4]
            if vault_id != DEMO_VAULT_ID:
                self._send(404, {"error": f"vault not found: {vault_id}"})
                return
            if item_id != DEMO_ITEM_ID:
                self._send(404, {"error": f"item not found: {item_id}"})
                return

            self._send(
                200,
                {
                    "id": DEMO_ITEM_ID,
                    "title": DEMO_ITEM_TITLE,
                    "fields": [
                        {
                            "id": "field_demo_123",
                            "label": DEMO_FIELD_LABEL,
                            "value": DEMO_FIELD_VALUE,
                        }
                    ],
                },
            )
            return

        self._send(404, {"error": f"unknown path: {path}"})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--port-file", required=True)
    args = ap.parse_args()

    httpd = HTTPServer((args.host, args.port), Handler)
    port = httpd.server_port

    with open(args.port_file, "w", encoding="utf-8") as f:
        f.write(str(port))
        f.flush()

    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

