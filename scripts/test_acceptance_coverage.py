"""Explicit instrumentation inputs fail closed before native acceptance runs."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import acceptance_coverage as coverage
import collect_critical_coverage as collector


class InputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.profiles = self.root / "profiles"
        self.profiles.mkdir(); self.profiles.chmod(0o1777)
        self.binary = self.root / "object"
        self.binary.write_bytes(b"synthetic object bytes for contract regression only")
        self.source = {"revision": "a" * 40, "dirty": False, "release_tree_sha256": "b" * 64}
        row = {"path": str(self.binary), "sha256": coverage.digest(self.binary), "bytes": self.binary.stat().st_size}
        self.value = {"schema": coverage.SCHEMA, "purpose": "browser", "source": self.source,
            "platform": sys.platform, "target": coverage.native_target(),
            "toolchain": coverage.TOOLCHAIN, "rustc": str(self.binary),
            "instrumentation": collector.instrumentation_flags(sys.platform, os.sysconf("SC_PAGE_SIZE")),
            "profile_dir": str(self.profiles), "objects": {name: row.copy() for name in ("opaqued", "opaque-web")},
            "qualification": "instrumented_build_candidate"}
        self.input = self.root / "input.json"

    def load(self, value=None, **kwargs):
        self.input.write_text(json.dumps(value or self.value))
        return coverage.load(self.input, root=self.root, purpose="browser", source=self.source, **kwargs)

    def test_requires_exact_source_purpose_native_platform_and_toolchain(self):
        self.assertEqual({key: value for key, value in self.load().items() if not key.startswith("_")}, self.value)
        for key, replacement in (("source", {**self.source, "revision": "c" * 40}), ("purpose", "model"),
                                 ("platform", "foreign"), ("toolchain", "stable"), ("target", "x86_64-pc-windows-msvc"),
                                 ("qualification", "release_qualified")):
            changed = {**self.value, key: replacement}
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.load(changed)

    def test_counter_flags_cannot_be_dropped_overridden_or_differ_between_peers(self):
        for flags in (self.value["instrumentation"][:-1], [*self.value["instrumentation"], "-Cinstrument-coverage=no"],
                      [f for f in self.value["instrumentation"] if f != "-Zcoverage-options=branch"]):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "instrumentation_mismatch"):
                self.load({**self.value, "instrumentation": flags})

    def test_other_architecture_on_same_os_cannot_qualify_native_counters(self):
        actual = self.value["target"]
        foreign = ("x86_64" if actual.startswith("aarch64") else "aarch64") + "-" + actual.split("-", 1)[1]
        with self.assertRaisesRegex(ValueError, "native_target_mismatch"):
            self.load({**self.value, "target": foreign})

    def test_changed_missing_and_linked_objects_do_not_qualify(self):
        changed = copy.deepcopy(self.value)
        del changed["objects"]["opaque-web"]
        with self.assertRaisesRegex(ValueError, "object_set_mismatch"):
            self.load(changed)
        self.binary.write_bytes(b"changed binary")
        with self.assertRaisesRegex(ValueError, "object_changed"):
            self.load()
        self.binary.unlink(); self.binary.symlink_to(self.input)
        with self.assertRaisesRegex(ValueError, "invalid_coverage_object"):
            self.load()

    def test_old_or_non_writable_child_profiles_are_rejected(self):
        (self.profiles / "old.profraw").write_bytes(b"old counters")
        with self.assertRaisesRegex(ValueError, "not_fresh"):
            self.load()
        (self.profiles / "old.profraw").unlink()
        self.profiles.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "uid_writable"):
            self.load()

    def test_every_observed_runtime_pid_needs_its_own_nonempty_profile(self):
        value = self.load()
        with self.assertRaisesRegex(ValueError, "child_profiles_missing"):
            coverage.profiles(value, roles={"web"})
        path = self.profiles / "web-123-456_0-.profraw"
        path.write_bytes(b"synthetic profile bytes; not an LLVM measurement")
        rows = coverage.profiles(value, roles={"web"}, process_ids={123})
        self.assertEqual(rows[0]["process_id"], 123)
        with self.assertRaisesRegex(ValueError, "process_counters_missing"):
            coverage.profiles(value, roles={"web"}, process_ids={123, 124})
        path.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "invalid_coverage_object"):
            coverage.profiles(value, roles={"web"})

    def test_no_ambient_credential_or_profile_path_is_forwarded(self):
        value = self.load()
        with patch.dict(os.environ, {"LLVM_PROFILE_FILE": "/ambient/stale.profraw", "AWS_SECRET_ACCESS_KEY": "synthetic"}):
            env = coverage.environment(value, "web")
        self.assertEqual(set(env), {"LLVM_PROFILE_FILE", "OPAQUE_COVERAGE_PROFILE_DIR", "OPAQUE_COVERAGE_RUSTC", "OPAQUE_COVERAGE_RUSTFLAGS"})
        self.assertEqual(env["LLVM_PROFILE_FILE"], str(self.profiles / "web-%p-%m-%c.profraw"))

    def test_changed_explicit_input_cannot_qualify_later_counters(self):
        value = self.load()
        self.input.write_bytes(self.input.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "input_changed_during_acceptance"):
            coverage.profiles(value, roles={"web"})

    def test_partial_probe_is_not_a_full_workspace_collection(self):
        run = collector.Collector(self.root, self.root, self.root, "collector", acceptances=("browser",), acceptance_only=True)
        run.declared_inventory_validated = True
        with patch.object(run, "collect_acceptance") as accepted, patch.object(run, "finish_collection"), patch.object(run, "execute") as execute:
            run.collect()
        accepted.assert_called_once(); execute.assert_not_called()
        self.assertEqual(run.result["status"], "acceptance_only_collected")
        self.assertNotIn("baseline", run.result)


if __name__ == "__main__":
    unittest.main()
