#!/usr/bin/env python3
"""Disposable OpenSSH host with a deliberately synthetic local service."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

STATE = Path("/var/lib/opaque-ssh")
LOCK = threading.Lock()


class Health(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        with LOCK:
            path = STATE / "reads"
            path.write_text(str(int(path.read_text()) + 1 if path.exists() else 1))
        # Only the Docker operator can inject a slow source for termination tests.
        if (STATE / "hang").exists():
            time.sleep(30)
        body = json.dumps({"service": "fixture-api", "status": "ok", "version": "1"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    host = os.environ["FIXTURE_HOST"]
    if host not in {"fixture-a", "fixture-b"}:
        raise ValueError("fixture host only")
    principal = f"opaque-{host}-health"
    Path("/etc/opaque-ssh/principals").write_text(principal + "\n")
    key = Path("/etc/opaque-ssh/host_key")
    if not key.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    if Path("/etc/opaque-ssh/broker.json").exists():
        spec = importlib.util.spec_from_file_location("opaque_control_preflight", Path(__file__).with_name("broker_control.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.load_config()  # fail before starting any listener if custody/pins disagree
    Path("/etc/opaque-ssh/sshd_config").write_text("""Port 2222
ListenAddress 0.0.0.0
HostKey /etc/opaque-ssh/host_key
PidFile /run/opaque-ssh/sshd.pid
TrustedUserCAKeys /etc/opaque-ssh/ca.pub
AuthorizedPrincipalsFile none
AuthorizedPrincipalsCommand /opt/opaque-ssh/principal_hook.py %i
AuthorizedPrincipalsCommandUser nobody
AuthorizedKeysFile none
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
AllowUsers opaque
StrictModes yes
DisableForwarding yes
PermitTTY no
PermitTunnel no
PermitUserRC no
PermitUserEnvironment no
MaxSessions 1
MaxAuthTries 2
MaxStartups 20
LoginGraceTime 10
ClientAliveInterval 2
ClientAliveCountMax 2
UnusedConnectionTimeout 3s
ChannelTimeout session=35s
UseDNS no
LogLevel VERBOSE
""")
    app = ThreadingHTTPServer(("127.0.0.1", 8080), Health)
    app.daemon_threads = True
    threading.Thread(target=app.serve_forever, daemon=True).start()
    guard = subprocess.Popen([
        "/usr/bin/python3", "-I", "/opt/opaque-ssh/host_guard.py", "serve",
        "--db", str(STATE / "grants.sqlite"), "--socket", "/run/opaque-ssh/guard.sock",
        "--host", host, "--principal", principal, "--uid", "7382",
    ])
    sshd, control = None, None
    try:
        for _ in range(100):
            if guard.poll() is not None:
                raise RuntimeError("guard exited")
            if Path("/run/opaque-ssh/guard.sock").exists():
                break
            time.sleep(.05)
        else:
            raise RuntimeError("guard did not start")
        subprocess.run(["/usr/sbin/sshd", "-t", "-f", "/etc/opaque-ssh/sshd_config"], check=True)
        sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/opaque-ssh/sshd_config"])
        if Path("/etc/opaque-ssh/broker.json").exists():
            control = subprocess.Popen([
                "/usr/bin/python3", "-I", "/opt/opaque-ssh/broker_control.py",
                "--db", str(STATE / "grants.sqlite"), "--host", host, "--principal", principal,
            ])
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit(0)))
        while guard.poll() is None and sshd.poll() is None and (control is None or control.poll() is None):
            time.sleep(.1)
        raise RuntimeError("host service exited")
    finally:
        for child in [sshd, guard, control]:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


if __name__ == "__main__":
    main()
