#!/usr/bin/env python3
"""One fixed local health read. No caller-controlled URL, command or arguments."""
import ctypes
import http.client
import json
import os
import signal


def arm_parent_death_signal():
    """Linux fixture: never leave a probe running after its guard disappears.

    Set this inside the fixed executable after the guard has dropped privileges;
    using a preexec_fn would be unsafe in the guard's threaded socket server.
    The second parent check closes the prctl setup race. The fixture has no
    subreaper between the guard and its container init, so an already orphaned
    probe has parent 1 and is rejected before opening a network connection.
    """
    parent = os.getppid()
    if parent <= 1:
        os._exit(125)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        os._exit(125)
    if os.getppid() != parent:
        os._exit(125)


def main():
    arm_parent_death_signal()
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=40)
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        body = response.read(4097)
        if response.status != 200 or len(body) > 4096:
            raise ValueError("invalid health response")
        value = json.loads(body)
        if value != {"service": "fixture-api", "status": "ok", "version": "1"}:
            raise ValueError("unexpected health result")
        print(json.dumps(value, sort_keys=True))
    finally:
        connection.close()


if __name__ == "__main__":
    main()
