#!/usr/bin/python3 -I
"""sshd supplies the certificate key ID; the host supplies principal/command."""
from pathlib import Path
import sys
import uuid


def main():
    if len(sys.argv) != 2:
        return 1
    try:
        grant = str(uuid.UUID(sys.argv[1]))
    except ValueError:
        return 1
    if grant != sys.argv[1]:
        return 1
    principal = Path("/etc/opaque-ssh/principals").read_text().strip()
    if principal not in {"opaque-fixture-a-health", "opaque-fixture-b-health"}:
        return 1
    command = f"/usr/bin/python3 -I /opt/opaque-ssh/host_guard.py enter {grant}"
    print(f'restrict,command="{command}" {principal}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
