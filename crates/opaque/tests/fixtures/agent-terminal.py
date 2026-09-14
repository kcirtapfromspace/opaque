"""Owned controlling-terminal CLI tests; the broker is a synthetic wire peer."""
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time

ROOT = Path(sys.argv[2])
os.chmod(ROOT, 0o700)
SUPERVISOR = int(sys.argv[3]) if sys.argv[1] == "cleanup" else os.getpid()


def save(name, value):
    temporary = ROOT / (name + ".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(ROOT / name)


def owned_group(pid):
    try:
        return pid > 1 and os.getsid(pid) == SUPERVISOR and os.getpgid(pid) == pid
    except ProcessLookupError:
        return False


def groups():
    result = set()
    for name in ("wrapper.json", "child.json"):
        try:
            result.add(int(json.loads((ROOT / name).read_text())["pid"]))
        except (FileNotFoundError, ValueError, KeyError):
            pass
    return result


def kill_owned_groups():
    # The Rust parent retains the supervisor's unreaped PID until this returns;
    # another login session cannot acquire the same identity during cleanup.
    for pid in groups():
        if owned_group(pid):
            os.killpg(pid, signal.SIGKILL)


if sys.argv[1] == "cleanup":
    kill_owned_groups()
    sys.exit(0)

CASE, BINARY = sys.argv[1], sys.argv[3]
assert os.getsid(0) == os.getpgrp() == SUPERVISOR


def interrupted(_signum, _frame):
    raise RuntimeError("owned terminal supervisor interrupted")


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGTTOU, signal.SIG_IGN)

CHILD = r'''
import json, os, pathlib, signal, sys, termios
root = pathlib.Path(sys.argv[1]); case = sys.argv[2]; received = []
def save(name, value):
    temp = root / (name + ".tmp")
    temp.write_text(json.dumps(value)); temp.replace(root / name)
def interrupted(signum, _frame):
    received.append(signum)
def identity():
    return {"pid": os.getpid(), "pgid": os.getpgrp(), "sid": os.getsid(0), "foreground": os.tcgetpgrp(0), "echo": bool(termios.tcgetattr(0)[3] & termios.ECHO)}
signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGTERM, interrupted)
save("child.json", identity())
line = sys.stdin.readline()
attributes = termios.tcgetattr(0); attributes[3] &= ~termios.ECHO
termios.tcsetattr(0, termios.TCSANOW, attributes)
save("input.json", {"line": line, "identity": identity(), "echo_disabled": not bool(termios.tcgetattr(0)[3] & termios.ECHO)})
if case == "normal":
    pass
elif case == "stop_resume":
    os.kill(os.getpid(), signal.SIGTSTP)
    save("resumed.json", identity())
    assert sys.stdin.readline() == "resumed-input\n"
    save("foreground-resumed.json", identity())
else:
    while not received:
        signal.pause()
    if case == "keyboard_continue":
        save("keyboard-handler.json", {"signals": received})
        assert sys.stdin.readline() == "continue-input\n"
save("child-result.json", {"signals": received, "identity": identity()})
sys.exit(0 if case in ("ctrl_c", "keyboard_continue") else 23)
'''


def wait_for(predicate, label, seconds=10):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError(label)
        time.sleep(0.005)


def read_frame(stream):
    def exact(size):
        result = b""
        while len(result) < size:
            part = stream.recv(size - len(result))
            if not part:
                raise EOFError("incomplete controlled IPC frame")
            result += part
        return result
    size = struct.unpack(">I", exact(4))[0]
    assert size <= 4 * 1024 * 1024
    return json.loads(exact(size))


def identity(name):
    return json.loads((ROOT / name).read_text())


master = slave = None
wrapper = listener = worker = None
release_grant = threading.Event()
start_arrived = threading.Event()
requests, failures = [], []
receipt = {"case": CASE, "status": "failed", "cleanup_forced": False}
end_foreground = None
end_attributes = None
try:
    # Rust retains a duplicate master so outer failure cleanup can inspect a
    # foreground child before the child has published its identity.
    master, slave = int(sys.argv[4]), 0
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    os.tcsetpgrp(slave, SUPERVISOR)
    original_attributes = termios.tcgetattr(slave)
    end_attributes = original_attributes
    sock = ROOT / "daemon.sock"
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(sock)); listener.listen(); listener.settimeout(15)
    os.chmod(sock, 0o600)
    (ROOT / "daemon.token").write_text("synthetic-terminal-peer-token")
    def peer():
        try:
            for expected in ("agent_session_start", "agent_session_end"):
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(10)
                    handshake, request = read_frame(stream), read_frame(stream)
                    assert handshake["handshake"] == "v1"
                    assert handshake["daemon_token"] == "synthetic-terminal-peer-token"
                    assert request["method"] == expected
                    requests.append(expected)
                    if expected == "agent_session_start":
                        start_arrived.set()
                        assert release_grant.wait(10), "grant release missing"
                        result = {"session_id": "terminal-session", "session_token": "terminal-token", "mode": "delegated"}
                    else:
                        assert request["params"] == {"session_id": "terminal-session"}
                        # The actual CLI remains alive and awaits this reply.
                        # Foreground/termios restoration must precede revocation ACK.
                        assert os.tcgetpgrp(slave) == end_foreground, "foreground contract violated before cleanup acknowledgment"
                        assert termios.tcgetattr(slave) == end_attributes, "terminal attributes contract violated"
                        receipt["foreground_contract_verified_before_end_ack"] = True
                        result = {"status": "ended", "session_id": "terminal-session"}
                    wire = json.dumps({"id": request["id"], "result": result}).encode()
                    stream.sendall(struct.pack(">I", len(wire)) + wire)
        except BaseException as error:
            failures.append(type(error).__name__ + ": " + str(error))
    worker = threading.Thread(target=peer)
    worker.start()
    def wrapper_group():
        os.setpgid(0, 0)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGTTOU, signal.SIGTTIN, signal.SIGTSTP):
            signal.signal(signum, signal.SIG_DFL)
    environment = {"HOME": str(ROOT), "PATH": "/usr/bin:/bin", "NO_COLOR": "1", "TERM": "dumb"}
    profile = os.environ.get("OPAQUE_COVERAGE_PROFILE_DIR")
    if profile:
        directory = Path(profile)
        assert directory.is_absolute() and directory.is_dir()
        environment["LLVM_PROFILE_FILE"] = str(directory / "adapter-%p-%m-%c.profraw")
    command = [BINARY, "--socket", str(sock), "--json", "agent", "run", "--"]
    command += ["/definitely/missing/opaque-terminal-agent"] if CASE == "spawn_failure" else [sys.executable, "-c", CHILD, str(ROOT), CASE]
    with (ROOT / "stdout.log").open("wb") as stdout, (ROOT / "stderr.log").open("wb") as stderr:
        wrapper = subprocess.Popen(command, stdin=slave, stdout=stdout, stderr=stderr, env=environment, preexec_fn=wrapper_group)
    save("wrapper.json", {"pid": wrapper.pid})
    end_foreground = wrapper.pid
    assert owned_group(wrapper.pid)
    os.tcsetpgrp(slave, wrapper.pid)
    assert start_arrived.wait(10), "session start did not arrive"
    if CASE == "pending_cancel":
        os.kill(wrapper.pid, signal.SIGINT)
    release_grant.set()
    expected_exit = 0 if CASE in ("ctrl_c", "keyboard_continue") else 23
    if CASE == "spawn_failure":
        expected_exit = 1
    elif CASE == "pending_cancel":
        expected_exit = 130
    else:
        wait_for(lambda: (ROOT / "child.json").is_file(), "child readiness")
        child = identity("child.json")
        assert child["pid"] == child["pgid"] == child["foreground"]
        assert child["sid"] == SUPERVISOR and child["pgid"] != wrapper.pid
        os.write(master, b"terminal-input\n")
        wait_for(lambda: (ROOT / "input.json").is_file(), "foreground stdin read")
        assert identity("input.json")["line"] == "terminal-input\n"
        assert identity("input.json")["echo_disabled"] is True
        if CASE in ("ctrl_c", "keyboard_continue"):
            os.write(master, b"\x03")
            if CASE == "keyboard_continue":
                wait_for(lambda: (ROOT / "keyboard-handler.json").is_file(), "keyboard handler")
                # This interval specifically crosses the production 5s
                # external-cancellation grace period, not a readiness guess.
                deadline = time.monotonic() + 5.25
                while time.monotonic() < deadline:
                    assert wrapper.poll() is None, "keyboard signal cancelled the wrapper"
                    assert owned_group(child["pid"]), "keyboard signal killed the agent"
                    assert not (ROOT / "child-result.json").exists()
                    time.sleep(0.005)
                os.write(master, b"continue-input\n")
        elif CASE in ("direct_int", "direct_term"):
            signum = signal.SIGINT if CASE == "direct_int" else signal.SIGTERM
            os.kill(wrapper.pid, signum)
            expected_exit = 128 + signum
        elif CASE == "foreign_owner":
            # The supervisor is a distinct, known group within this owned
            # session. Simulate another foreground job taking the terminal.
            os.tcsetpgrp(slave, SUPERVISOR)
            end_foreground = SUPERVISOR
            end_attributes = termios.tcgetattr(slave)
            end_attributes[3] ^= termios.ICANON
            requested_icanon = bool(end_attributes[3] & termios.ICANON)
            termios.tcsetattr(slave, termios.TCSANOW, end_attributes)
            # Python normalizes VMIN/VTIME bytes versus ints when ICANON
            # changes. Compare the actual readback, not the pre-normalized list.
            end_attributes = termios.tcgetattr(slave)
            assert bool(end_attributes[3] & termios.ICANON) == requested_icanon
            os.kill(wrapper.pid, signal.SIGTERM)
            expected_exit = 143
            receipt["foreign_foreground_sentinel"] = True
        elif CASE == "stop_resume":
            def stopped():
                pid, status = os.waitpid(wrapper.pid, os.WUNTRACED | os.WNOHANG)
                if pid == 0:
                    return False
                assert os.WIFSTOPPED(status), "wrapper exited instead of stopping"
                return True
            wait_for(stopped, "wrapper job-control stop")
            assert os.tcgetpgrp(slave) == wrapper.pid
            assert not (ROOT / "resumed.json").exists()
            # Standard bg resumes computation, but its next terminal read
            # must stop with SIGTTIN without stealing the supervisor's tty.
            os.tcsetpgrp(slave, SUPERVISOR)
            os.kill(wrapper.pid, signal.SIGCONT)
            wait_for(stopped, "background resume must stop again")
            assert os.tcgetpgrp(slave) == SUPERVISOR
            assert identity("resumed.json")["foreground"] == SUPERVISOR
            assert termios.tcgetattr(slave) == original_attributes
            os.tcsetpgrp(slave, wrapper.pid)
            os.kill(wrapper.pid, signal.SIGCONT)
            wait_for(lambda: os.tcgetpgrp(slave) == child["pid"], "foreground child resume")
            assert not termios.tcgetattr(slave)[3] & termios.ECHO
            os.write(master, b"resumed-input\n")
        elif CASE != "normal":
            raise AssertionError("unknown terminal case")
    exit_code = wrapper.wait(timeout=12)
    worker.join(timeout=12)
    assert not worker.is_alive() and not failures, failures
    assert exit_code == expected_exit, (exit_code, expected_exit)
    assert requests == ["agent_session_start", "agent_session_end"]
    if CASE in ("spawn_failure", "pending_cancel"):
        assert not (ROOT / "child.json").exists(), "forbidden child launched"
    else:
        observed = identity("child-result.json")
        if CASE == "stop_resume":
            resumed = identity("foreground-resumed.json")
            assert resumed["foreground"] == resumed["pgid"] == child["pid"]
            assert resumed["echo"] is False
        expected_signals = [signal.SIGINT] if CASE in ("ctrl_c", "keyboard_continue", "direct_int") else [signal.SIGTERM] if CASE in ("direct_term", "foreign_owner") else []
        assert observed["signals"] == expected_signals, observed
        receipt["child_signal_count"] = len(observed["signals"])
        receipt["foreground_stdin_verified"] = True
    assert receipt.get("foreground_contract_verified_before_end_ack") is True
    receipt.update(status="passed", exit_code=exit_code, session_start_count=1, session_end_count=1)
except BaseException as error:
    receipt["error"] = type(error).__name__ + ": " + str(error)
finally:
    release_grant.set()
    def cleanup_step(operation):
        try:
            return operation()
        except BaseException as error:
            receipt["status"] = "failed"
            receipt["cleanup_error"] = type(error).__name__ + ": " + str(error)
            return None
    # If a child failed before publishing its identity, its foreground group is
    # still discoverable from the supervisor's owned controlling terminal.
    candidates = cleanup_step(groups) or set()
    if slave is not None:
        try:
            candidates.add(os.tcgetpgrp(slave))
        except OSError:
            pass
    for pid in candidates - {SUPERVISOR}:
        if cleanup_step(lambda: owned_group(pid)):
            receipt["cleanup_forced"] = True
            cleanup_step(lambda: os.killpg(pid, signal.SIGKILL))
    if wrapper is not None:
        cleanup_step(lambda: wrapper.wait(timeout=5))
    if listener is not None:
        cleanup_step(listener.close)
    if worker is not None:
        cleanup_step(lambda: worker.join(timeout=16))
        if worker.is_alive():
            receipt["status"] = "failed"
            receipt["error"] = "controlled peer failed to stop"
    # Restore supervisor ownership only after recording the CLI's independent
    # restoration evidence above. Never touch the user's terminal or group.
    if slave is not None:
        cleanup_step(lambda: os.tcsetpgrp(slave, SUPERVISOR))
        cleanup_step(lambda: os.close(slave))
    if master is not None:
        cleanup_step(lambda: os.close(master))
    if receipt["cleanup_forced"]:
        receipt["status"] = "failed"
    # All agent/terminal assertions and owned cleanup are complete. The Rust
    # parent now closes its retained master to release Darwin tty teardown;
    # Linux may deliver a final session-leader HUP during that close.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    save("result.json", receipt)

sys.exit(0 if receipt["status"] == "passed" else 1)
