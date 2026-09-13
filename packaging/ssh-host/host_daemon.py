#!/usr/bin/python3 -I
"""Run the fixed host guard or control listener from root-owned configuration."""
import importlib.util
import os
from pathlib import Path
import pwd
import ssl
import sys

BASE = Path("/opt/opaque-ssh")
LEDGER = "/var/lib/opaque-ssh/grants.sqlite"


def load(name):
    spec = importlib.util.spec_from_file_location(name, BASE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in {"guard", "control"}:
        raise ValueError("fixed root-owned host service required")
    os.umask(0o077)
    guard_module = load("host_guard")
    control_module = load("broker_control")
    config, receipt_key = control_module.load_config()
    guard_module.validate_ledger_path(LEDGER)
    ledger = guard_module.Ledger(LEDGER)
    account = pwd.getpwnam(config["login_user"])
    control = control_module.BrokerControl(ledger, config, receipt_key, config["profile_id"], config["principal"])
    if sys.argv[1] == "guard":
        guard = guard_module.Guard(ledger, config["profile_id"], config["principal"], account.pw_uid, gid=account.pw_gid, broker=control)
        guard_module.serve(guard, guard_module.SOCKET_PATH)
    else:
        server = control_module.ControlServer((config["control_listen_host"], config["control_listen_port"]), control)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(config["tls_cert_path"], config["tls_key_path"])
        server.socket = tls.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No traceback or configuration/key material in service logs.
        print("SSH host service unavailable; check root-owned configuration", file=sys.stderr)
        sys.exit(1)
