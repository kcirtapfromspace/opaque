#!/usr/bin/env python3
"""Read or delete private demo pilot requests without putting credentials in argv."""

import argparse
import http.client
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import urlsplit


class LeadError(Exception):
    """An operator-safe error that never contains submitted contact details."""


def read_secret(path):
    if not path:
        raise LeadError("Set OPAQUE_LEAD_ADMIN_SECRET_FILE or pass --secret-file.")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise LeadError("The credential must be a regular file accessible only to its owner (0600).")
            secret = source.read(1025).decode("ascii").strip()
    except (OSError, UnicodeError) as error:
        raise LeadError("Could not read the protected credential file.") from error
    if not 32 <= len(secret) <= 1024 or any(ord(char) <= 32 or ord(char) >= 127 for char in secret):
        raise LeadError("The credential file has an invalid format.")
    return secret


def request(origin, secret, operation, payload):
    try:
        url = urlsplit(origin)
        local = url.scheme == "http" and url.hostname == "127.0.0.1"
        if (url.scheme != "https" and not local) or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("invalid origin")
        connection_class = http.client.HTTPConnection if local else http.client.HTTPSConnection
        connection = connection_class(url.hostname, url.port, timeout=15)
    except ValueError as error:
        raise LeadError("Use an HTTPS origin without a path, credentials, query, or fragment.") from error
    try:
        connection.request("POST", "/internal/leads/" + operation, body=json.dumps(payload), headers={
            "Authorization": "Bearer " + secret,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        response = connection.getresponse()
        if response.status != 200:
            # Do not follow redirects or include a response body in error output.
            raise LeadError(f"Lead service returned HTTP {response.status}; no export was written.")
        raw = response.read(1_048_577)
        if len(raw) > 1_048_576:
            raise LeadError("Lead response exceeded the export size limit.")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise LeadError("Lead service returned an invalid response.")
        if operation == "list" and (not isinstance(data.get("leads"), list) or len(data["leads"]) > payload["limit"] or not (data.get("next_cursor") is None or isinstance(data.get("next_cursor"), str))):
            raise LeadError("Lead service returned an invalid page.")
        if operation == "delete" and data.get("deleted") is not True:
            raise LeadError("Deletion was not confirmed.")
        return data
    except (OSError, http.client.HTTPException, ValueError) as error:
        raise LeadError("Lead service could not be reached or returned an invalid response.") from error
    finally:
        connection.close()


def write_export(path, data):
    # O_EXCL rejects existing files and symlinks instead of overwriting private work.
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise LeadError("Choose a new export file in an existing private directory.") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            json.dump(data, destination, ensure_ascii=False, indent=2)
            destination.write("\n")
    except (OSError, ValueError, TypeError) as error:
        Path(path).unlink(missing_ok=True)
        raise LeadError("The export could not be written.") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default="https://demo.opaque.info")
    parser.add_argument("--secret-file", default=os.environ.get("OPAQUE_LEAD_ADMIN_SECRET_FILE"))
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="Export one page to a new owner-only JSON file.")
    listing.add_argument("--limit", type=int, choices=range(1, 101), default=25, metavar="1..100")
    listing.add_argument("--cursor", help="Opaque next_cursor from the previous export.")
    listing.add_argument("--output", required=True, type=Path)
    deletion = commands.add_parser("delete", help="Delete one request by its exported ID.")
    deletion.add_argument("--id", required=True)
    args = parser.parse_args(argv)
    try:
        secret = read_secret(args.secret_file)
        if args.command == "list":
            payload = {"limit": args.limit}
            if args.cursor is not None:
                payload["cursor"] = args.cursor
            data = request(args.origin, secret, "list", payload)
            write_export(args.output, data)
            print(f"Saved {len(data['leads'])} request(s) to the protected export. " + ("Another page is available." if data.get("next_cursor") else "No further page."))
        else:
            request(args.origin, secret, "delete", {"id": args.id})
            print("Deletion confirmed.")
        return 0
    except LeadError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
