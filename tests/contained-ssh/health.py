#!/usr/bin/env python3
"""Count fixed synthetic health reads, including a controlled stalled response."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import threading
import time

STATE = Path("/var/lib/opaque-contained")
LOCK = threading.Lock()
SPEC = importlib.util.spec_from_file_location("contained_processes", "/opt/opaque-contained-processes.py")
PROCESSES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROCESSES)


class Health(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path != "/ready/health":
            self.send_error(404)
            return
        with LOCK:
            # Observe the real caller while its production probe is blocked on
            # this HTTP response, before either the success or crash path exits.
            try:
                observation = PROCESSES.observe_probe()
                with (STATE / "probe-observations.jsonl").open("a") as stream:
                    stream.write(json.dumps(observation, sort_keys=True) + "\n")
            except Exception:
                (STATE / "observation-error").write_text("actual process evidence unavailable")
                self.send_error(500)
                return
            counter = STATE / "reads"
            count = int(counter.read_text()) if counter.exists() else 0
            counter.write_text(str(count + 1))
        # Long enough to interrupt the actual host guard after observing one
        # read, before the fixed production probe's two-second HTTP timeout.
        if (STATE / "stall").exists():
            time.sleep(15)
        raw = json.dumps({"service": "contained-api", "status": "ok", "version": "1"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8080), Health)
    server.daemon_threads = True
    server.serve_forever()
