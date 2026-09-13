"""Independent, non-secret Linux process evidence for the disposable fixture."""
from pathlib import Path
import subprocess

GUARD = "opaque-ssh-guard"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unit_state(name):
    result = subprocess.run(["systemctl", "show", name, "--property=ActiveState",
                             "--property=MainPID", "--property=ControlGroup"],
                            capture_output=True, timeout=5)
    require(result.returncode == 0, "systemd state query failed")
    state = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
    require(set(state) == {"ActiveState", "MainPID", "ControlGroup"}, "incomplete systemd state")
    state["MainPID"] = int(state["MainPID"])
    return state


def process(pid, proc=Path("/proc")):
    path = proc / str(pid)
    try:
        stat = (path / "stat").read_text().rsplit(") ", 1)[1].split()
        status = dict(line.split(":", 1) for line in (path / "status").read_text().splitlines())
        argv = (path / "cmdline").read_bytes().split(b"\0")
        identity = {"pid": pid, "start_time": int(stat[19]), "parent": int(stat[1]),
                "uids": [int(value) for value in status["Uid"].split()],
                "gids": [int(value) for value in status["Gid"].split()],
                "groups": [int(value) for value in status["Groups"].split()],
                "cgroups": [line.split(":", 2)[2] for line in (path / "cgroup").read_text().splitlines()],
                "fixed_probe": b"/opt/opaque-ssh/health_probe.py" in argv,
                "guard_supervisor": argv[:4] == [b"/usr/bin/python3", b"-I", b"/opt/opaque-ssh/host_daemon.py", b"guard"]}
        final_start = int((path / "stat").read_text().rsplit(") ", 1)[1].split()[19])
        require(final_start == identity["start_time"], "process identity changed during evidence read")
        return identity
    except (FileNotFoundError, ProcessLookupError):
        return None


def cgroup_members(group, root=Path("/sys/fs/cgroup")):
    require(group.startswith("/system.slice/opaque-"), "unexpected fixture cgroup")
    directory = root / group.lstrip("/")
    require(directory.is_relative_to(root) and ".." not in directory.parts, "invalid fixture cgroup")
    pids = set()
    for path in directory.rglob("cgroup.procs"):
        try:
            pids.update(int(value) for value in path.read_text().split())
        except FileNotFoundError:
            pass
    return [identity for pid in sorted(pids) if (identity := process(pid)) is not None]


def same_identity(left, right):
    return right is not None and (left["pid"], left["start_time"]) == (right["pid"], right["start_time"])


def gone(identities):
    return all(not same_identity(identity, process(identity["pid"])) for identity in identities)


def observe_probe():
    state = unit_state(GUARD)
    require(state["ActiveState"] == "active" and state["MainPID"] > 1, "guard not active during real probe")
    members = cgroup_members(state["ControlGroup"])
    guards = [item for item in members if item["pid"] == state["MainPID"]]
    probes = [item for item in members if item["fixed_probe"]]
    require(len(guards) == 1 and guards[0]["guard_supervisor"] and guards[0]["uids"] == [0] * 4,
            "unexpected guard supervisor")
    require(len(probes) == 1 and len(members) == 2, "unexpected guard cgroup process tree")
    probe = probes[0]
    require(probe["parent"] == state["MainPID"] and state["ControlGroup"] in probe["cgroups"],
            "probe lost supervisor/cgroup binding")
    require(probe["uids"] == [7382] * 4 and probe["gids"] == [7382] * 4 and probe["groups"] == [],
            "actual probe did not drop UID/GID/supplementary groups")
    return {"guard": guards[0], "probe": probe, "members": members, "cgroup": state["ControlGroup"]}


def guard_idle(observations, *, restarted=False):
    state = unit_state(GUARD)
    if state["ActiveState"] != "active" or state["MainPID"] <= 1:
        return False
    members = cgroup_members(state["ControlGroup"])
    if len(members) != 1 or members[0]["pid"] != state["MainPID"] or not members[0]["guard_supervisor"]:
        return False
    captured = [member for event in observations for member in event["members"]
                if restarted or not member["guard_supervisor"]]
    return gone(captured)
