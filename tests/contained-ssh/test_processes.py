"""Negative regressions for the independent process evidence verifier."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("contained_processes", Path(__file__).with_name("processes.py"))
PROCESSES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROCESSES)
GROUP = "/system.slice/opaque-ssh-guard.service"


def member(pid, *, probe=False):
    return {"pid": pid, "start_time": pid * 100, "parent": 10,
            "uids": [7382 if probe else 0] * 4, "gids": [7382 if probe else 0] * 4,
            "groups": [], "cgroups": [GROUP], "fixed_probe": probe,
            "guard_supervisor": not probe}


class ProcessEvidenceTests(unittest.TestCase):
    def test_observation_rejects_privilege_and_hidden_cgroup_members(self):
        guard, probe = member(10), member(11, probe=True)
        state = {"MainPID": 10, "ActiveState": "active", "ControlGroup": GROUP}
        with patch.object(PROCESSES, "unit_state", return_value=state), \
             patch.object(PROCESSES, "cgroup_members", return_value=[guard, probe]):
            self.assertEqual(PROCESSES.observe_probe()["probe"], probe)
        mutations = [{"uids": [0, 7382, 7382, 7382]}, {"gids": [0] * 4},
                     {"groups": [7382]}, {"parent": 1}, {"cgroups": ["/other"]}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), \
                 patch.object(PROCESSES, "unit_state", return_value=state), \
                 patch.object(PROCESSES, "cgroup_members", return_value=[guard, probe | mutation]):
                with self.assertRaises(RuntimeError):
                    PROCESSES.observe_probe()
        descendant = member(12) | {"guard_supervisor": False, "parent": 11}
        with patch.object(PROCESSES, "unit_state", return_value=state), \
             patch.object(PROCESSES, "cgroup_members", return_value=[guard, probe, descendant]):
            with self.assertRaises(RuntimeError):
                PROCESSES.observe_probe()

    def test_pid_reuse_is_distinct_but_permission_failure_is_not_absence(self):
        original = member(11, probe=True)
        with patch.object(PROCESSES, "process", return_value=original):
            self.assertFalse(PROCESSES.gone([original]))
        with patch.object(PROCESSES, "process", return_value=original | {"start_time": 9999}):
            self.assertTrue(PROCESSES.gone([original]))
        with patch.object(PROCESSES, "process", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                PROCESSES.gone([original])

    def test_restart_rejects_old_supervisor_or_reparented_extra_process(self):
        old_guard, probe, new_guard = member(10), member(11, probe=True), member(20)
        observation = {"members": [old_guard, probe]}
        state = {"MainPID": 20, "ActiveState": "active", "ControlGroup": GROUP}
        with patch.object(PROCESSES, "unit_state", return_value=state), \
             patch.object(PROCESSES, "cgroup_members", return_value=[new_guard]), \
             patch.object(PROCESSES, "process", return_value=None):
            self.assertTrue(PROCESSES.guard_idle([observation], restarted=True))
        for survivors in ([new_guard, member(30) | {"parent": 1}], [old_guard]):
            with patch.object(PROCESSES, "unit_state", return_value=state), \
                 patch.object(PROCESSES, "cgroup_members", return_value=survivors):
                self.assertFalse(PROCESSES.guard_idle([observation], restarted=True))

    def test_systemd_error_and_incomplete_state_do_not_qualify_cleanup(self):
        for result in (subprocess.CompletedProcess([], 1, b"", b""),
                       subprocess.CompletedProcess([], 0, b"ActiveState=inactive\n", b"")):
            with patch.object(PROCESSES.subprocess, "run", return_value=result):
                with self.assertRaises(RuntimeError):
                    PROCESSES.unit_state("opaque-ssh-guard")

    def test_kernel_record_parsing_binds_starttime_across_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "11"
            process.mkdir()
            fields = ["S", "10"] + ["0"] * 17 + ["12345"]
            (process / "stat").write_text("11 (probe name) " + " ".join(fields))
            (process / "status").write_text("Uid:\t7382\t7382\t7382\t7382\nGid:\t7382\t7382\t7382\t7382\nGroups:\t\n")
            (process / "cmdline").write_bytes(b"/usr/bin/python3\0-I\0/opt/opaque-ssh/health_probe.py\0")
            (process / "cgroup").write_text("0::" + GROUP + "\n")
            identity = PROCESSES.process(11, root)
            self.assertEqual(identity["start_time"], 12345)
            self.assertEqual(identity["groups"], [])
            self.assertTrue(identity["fixed_probe"])
            read_text = Path.read_text
            def changing_read(path, *args, **kwargs):
                value = read_text(path, *args, **kwargs)
                if path.name == "status":
                    fields[-1] = "99999"
                    (process / "stat").write_text("11 (new process) " + " ".join(fields))
                return value
            with patch.object(Path, "read_text", changing_read):
                with self.assertRaises(RuntimeError):
                    PROCESSES.process(11, root)


if __name__ == "__main__":
    unittest.main()
