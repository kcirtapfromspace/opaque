#!/usr/bin/env python3
"""Render host configuration from an operator-reviewed broker task, without network."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

spec = importlib.util.spec_from_file_location("opaque_broker_control", Path(__file__).with_name("broker_control.py"))
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


def render(task, broker_public_key, receipt_path, cert_path, key_path, listen_host, listen_port):
    task = task.get("task", task)
    actions = task["manifest"]["actions"]
    if task["manifest"]["schema_version"] != 4 or len(actions) != 1:
        raise ValueError("one schema-4 SSH health action required")
    action = actions[0]
    control.validate_action(action)
    if not re.fullmatch(r"[a-f0-9]{64}", broker_public_key):
        raise ValueError("broker Ed25519 public key must be 32 bytes in hex")
    control.canonical_ip(listen_host)
    if type(listen_port) is not int or not 1 <= listen_port <= 65535:
        raise ValueError("invalid listener port")
    for path in (receipt_path, cert_path, key_path):
        if not Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("absolute root-custody paths required")
    value = {field: action[field] for field in control.PINNED_FIELDS}
    value.update(max_session_secs=action["max_session_secs"], broker_public_key_hex=broker_public_key,
                 receipt_private_key_path=receipt_path, tls_cert_path=cert_path, tls_key_path=key_path,
                 control_listen_host=listen_host, control_listen_port=listen_port)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--broker-public-key-hex", required=True)
    parser.add_argument("--receipt-private-key-path", default="/etc/opaque-ssh/receipt.key")
    parser.add_argument("--tls-cert-path", default="/etc/opaque-ssh/control.crt")
    parser.add_argument("--tls-key-path", default="/etc/opaque-ssh/control.key")
    parser.add_argument("--control-host", required=True)
    parser.add_argument("--control-port", type=int, default=8443)
    args = parser.parse_args()
    with args.task.open("rb") as source:
        raw = source.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError("task file too large")
    task = control.strict_json(raw)
    print(json.dumps(render(task, args.broker_public_key_hex, args.receipt_private_key_path,
                            args.tls_cert_path, args.tls_key_path, args.control_host, args.control_port), sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RecursionError):
        print("Invalid operator task or host configuration", file=sys.stderr)
        sys.exit(1)
