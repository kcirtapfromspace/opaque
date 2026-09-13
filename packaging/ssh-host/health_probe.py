#!/usr/bin/env python3
"""One fixed local health read. No caller-controlled URL, command or arguments."""
import ctypes
import http.client
import importlib.util
from pathlib import Path
import sys
import json
import os
import signal


def arm_parent_death_signal():
    """Linux host: never leave a probe running after its guard disappears.

    Set this inside the fixed executable after the guard has dropped privileges;
    using a preexec_fn would be unsafe in the guard's threaded socket server.
    The second parent check closes the prctl setup race. The host must have no
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


def read_health(contract):
    connection = http.client.HTTPConnection(contract["host"], contract["port"], timeout=2)
    try:
        connection.request("GET", contract["path"])
        response = connection.getresponse()
        body = response.read(4097)
        if response.status != 200 or len(body) > 4096:
            raise ValueError("invalid health response")
        value = host_config.strict_json(body)
        if value != {"service": contract["service"], "status": "ok", "version": contract["version"]}:
            raise ValueError("unexpected health result")
        return value
    finally:
        connection.close()


def execute(expected):
    expected = host_config.validate_contract(expected)
    # Compare root-owned configuration immediately before connecting. No URL,
    # request headers or shell fragments are accepted through the SSH channel.
    if expected != host_config.load_health():
        raise ValueError("host health configuration drift")
    return read_health(expected)


def main():
    arm_parent_death_signal()
    raw = sys.stdin.buffer.read(2049)
    if len(raw) > 2048:
        raise ValueError("invalid probe input")
    print(json.dumps(execute(host_config.strict_json(raw)), sort_keys=True))


spec = importlib.util.spec_from_file_location("opaque_host_config", Path(__file__).with_name("host_config.py"))
host_config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_config)

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, http.client.HTTPException, RecursionError):
        sys.exit(1)
