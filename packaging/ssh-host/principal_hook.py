#!/usr/bin/python3 -I
"""sshd supplies the certificate key ID; root configuration supplies principal."""
import importlib.util
from pathlib import Path
import re
import sys
import uuid

spec = importlib.util.spec_from_file_location("opaque_host_config", Path(__file__).with_name("host_config.py"))
host_config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_config)


def main():
    if len(sys.argv) != 2:
        return 1
    grant = uuid.UUID(sys.argv[1])
    if str(grant) != sys.argv[1] or grant.int == 0:
        return 1
    principal = host_config.protected_bytes("/etc/opaque-ssh/principals", 128).decode("ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", principal):
        return 1
    command = f"/usr/bin/python3 -I /opt/opaque-ssh/host_guard.py enter {grant}"
    print(f'restrict,command="{command}" {principal}')
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, UnicodeError):
        sys.exit(1)
