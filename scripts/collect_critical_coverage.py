#!/usr/bin/env python3
"""Collect critical production counters from library tests and real daemon tests.

Each invocation qualifies one native platform. Linux additionally requires root
and CAP_SYS_PTRACE for the existing split-UID composed-review tests. This runs no
native approval UI or live vendor account. Profiles must be fresh and objects explicitly inventoried;
never combine platform reports or reinterpret a passing test as measured coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import time
import tomllib

import check_llvm_coverage as gate
import synthesized_suite as suite

TOOLCHAIN = "nightly-2026-09-13"
COLLECTOR_VERSION = "0.9.1"
PACKAGES = ("opaque-core", "opaque-bounded-work", "opaque-approval")
BASE_FLAGS = ("-C", "instrument-coverage", "--cfg=coverage", "--cfg=coverage_nightly")


def instrumentation_flags(native_platform, page_size):
    require(native_platform in ("linux", "darwin"), "unsupported_native_platform")
    flags = [*BASE_FLAGS, "-Zcoverage-options=branch"]
    if native_platform == "linux":
        flags.append("-Cllvm-args=-runtime-counter-relocation")
    else:
        require(type(page_size) is int and page_size > 0 and page_size & (page_size - 1) == 0,
                "invalid_native_page_size")
        for section in ("cnts", "data", "bits"):
            flags.append(f"-Clink-arg=-Wl,-sectalign,__DATA,__llvm_prf_{section},{page_size:x}")
    return flags
REQUIRED_FILES = (
    "crates/opaque-bounded-work/src/task_store.rs",
    "crates/opaque-bounded-work/src/task_api.rs",
    "crates/opaque-bounded-work/src/resource_authority.rs",
    "crates/opaque-core/src/task.rs",
    "crates/opaque-core/src/identity_lifecycle.rs",
    "crates/opaque-approval/src/approval_server/workstation.rs",
)
CASES = {
    "task_api_e2e": ("task_plan_run_get_list_revoke_end_to_end",),
    "resource_authority_e2e": ("broker_identity_is_live_for_gateway_queries_disclosures_and_logout",),
    "mcp_gateway_e2e": (
        "adapter_signed_tool_daemon_effect_receipt_and_replay_survive_restart",
        "policy_denial_malformed_input_and_generic_bypass_make_no_http_calls",
        "revoke_during_handshake_stops_final_tool_dispatch_and_does_not_refund",
        "daemon_death_after_effect_recovers_unknown_and_never_replays",
        "expiry_during_handshake_prevents_tool_effect_and_preserves_charge",
        "projected_result_is_useful_bounded_ephemeral_and_never_replays",
        "revoked_after_provider_effect_withholds_projected_result_without_refund",
    ),
    "opaqued": (
        "resource_authority_provisioning_tests::signed_resource_tokens_need_exact_live_provisioning_scopes_despite_operator_role",
        "resource_authority_provisioning_tests::access_and_token_self_revocation_remain_denied_across_restart_and_new_grants",
        "enclave::task::remote_tests::signed_remote_receipt_drives_real_bounded_effects_once_and_survives_restart",
        "enclave::task::remote_tests::requester_reviewer_and_device_revocation_at_real_dispatch_fence_block_all_effects",
        "provisioning_api_tests::native_denial_never_produces_a_binding_or_mandate_challenge",
        "provisioning_api_tests::reviewed_challenges_are_random_peer_bound_signed_and_single_use",
        "provisioning_api_tests::only_the_authenticated_mandate_service_can_issue_for_a_verified_recipient",
        "provisioning_api_tests::request_reuse_and_issuer_role_removal_cannot_extend_a_mandate",
        "identity::lifecycle::tests::removal_regrant_revokes_old_sessions_and_reviewer_epoch",
        "identity::lifecycle::tests::dispatch_writer_fence_serializes_removal",
        "identity::lifecycle::tests::restart_retains_source_revision_and_current_authority",
        "identity::lifecycle::tests::mock_oidc_lifecycle_change_cancels_pending_login_and_fresh_login_succeeds",
    ),
    "synthesized_review_e2e": (
        "synthesized_oidc_review_receipt_and_restart_preserve_authority",
        "synthesized_signed_rejection_leaves_task_uncharged",
        "synthesized_review_timeout_rejects_late_signature_without_effects",
        "synthesized_lifecycle_regrant_during_preparation_keeps_signed_task_charged_and_denied",
    ),
}
CONTAINED_TARGET = "contained_ssh_e2e"
CONTAINED_CASES = (
    "contained_signed_ssh_runs_one_probe_and_rejects_replay_after_restart",
    "contained_guard_crash_preserves_unknown_and_kills_probe_without_replay",
    "contained_inference_rpc_rechecks_authority_after_metadata_without_refunding",
)
# These exclusions match existing explicitly ignored tests, not missing jobs.
ROOT_CASE = "trust_domain::tests::root_multi_uid_custody_matrix"
ALLOWED_IGNORED = {"ssh::tests::live_vault_host_execution", "task_store::tests::task_pagination_scales", ROOT_CASE}
SCHEMA = "opaque.critical-coverage-collection.v1"


def require(condition, reason):
    if not condition:
        raise suite.Invalid(reason)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def fresh_directory(path, mode=0o711):
    path.mkdir(mode=mode, parents=False, exist_ok=False)
    path.chmod(mode)
    return path.resolve()


def parse_environment(raw, flags):
    """Read pinned show-env output as assignments, never evaluate shell code."""
    values = {}
    for line in raw.decode().splitlines():
        match = re.fullmatch(r"([A-Z_][A-Z0-9_]*)=(.*)", line)
        require(match is not None, "invalid_collector_environment")
        key, value = match.groups()
        require(key not in values, "duplicate_collector_environment")
        parsed = shlex.split(value)
        require(len(parsed) == 1, "invalid_collector_environment_value")
        values[key] = parsed[0]
    require(values.get("__CARGO_LLVM_COV_RUSTC_WRAPPER") == "1"
            and values.get("CARGO_LLVM_COV") == "1"
            and bool(values.get("RUSTC_WRAPPER")), "missing_instrumentation_wrapper")
    encoded = values.get("__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS", "")
    require(encoded.split("\x1f") == list(BASE_FLAGS), "unexpected_instrumentation_flags")
    values["__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS"] = "\x1f".join(flags)
    return values


def selected_cases(native_platform, contained=False):
    require(native_platform in ("linux", "darwin"), "unsupported_native_platform")
    selected = {target: names for target, names in CASES.items()
                if native_platform == "linux" or target != "synthesized_review_e2e"}
    if contained:
        require(native_platform == "linux", "contained_profile_requires_linux")
        selected[CONTAINED_TARGET] = CONTAINED_CASES
    return selected


def contained_prerequisites(native_platform, *, marker=Path("/etc/opaque-contained-fixture"),
                            pid1=Path("/proc/1/comm")):
    require(native_platform == "linux" and os.geteuid() == 0 and suite.has_sys_ptrace(),
            "contained_profile_requires_linux_root_and_sys_ptrace")
    require(marker.read_bytes() == b"opaque-contained-ssh-v1\n" and pid1.read_text().strip() == "systemd",
            "contained_profile_requires_marked_systemd_host")
    require(pwd.getpwnam("opaque").pw_uid == 7382, "contained_profile_requires_host_account")
    for tool in ("vault", "systemctl", "ssh-keygen", "python3", "getent", "setpriv", "useradd", "userdel", "groupadd", "groupdel"):
        require(shutil.which(tool) is not None, "contained_profile_missing_tool_" + tool)
    return {"systemd_pid1": True, "host_uid": 7382, "marker": "opaque-contained-ssh-v1",
            "scope": "disposable actual Vault/OpenSSH/systemd host with synthetic signed review; no native human claim"}


def artifacts(raw, target_dir):
    result = {}
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(event, dict) or event.get("reason") != "compiler-artifact" or not event.get("executable"):
            continue
        path = Path(event["executable"])
        require(path.is_absolute() and path.is_file() and not path.is_symlink()
                and path.resolve().is_relative_to(target_dir), "invalid_compiler_artifact")
        target = event.get("target", {})
        kind = target.get("kind")
        require(isinstance(kind, list) and len(kind) == 1, "ambiguous_compiler_target")
        key = (target.get("name"), kind[0], event.get("profile", {}).get("test"))
        require(key not in result or result[key] == path, "duplicate_compiler_target")
        result[key] = path
    require(bool(result), "empty_compiler_artifacts")
    return result


def artifact_packages(raw, selected, root):
    """Restore Cargo's runtime package name from each exact compiled manifest."""
    contexts = {}
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(event, dict) or event.get("reason") != "compiler-artifact" or not event.get("executable"):
            continue
        binary = Path(event["executable"])
        if binary not in selected:
            continue
        manifest = Path(event.get("manifest_path", ""))
        require(manifest.is_absolute() and manifest.is_file() and not manifest.is_symlink()
                and manifest.resolve().is_relative_to(root), "invalid_artifact_package_manifest")
        package = tomllib.loads(manifest.read_text())["package"]["name"]
        require(package in (*PACKAGES, "opaqued", "opaque-mcp"), "unexpected_artifact_package")
        require(binary not in contexts or contexts[binary] == package, "ambiguous_artifact_package")
        contexts[binary] = package
    require(set(contexts) == set(selected), "missing_artifact_package_identity")
    return contexts


def suite_pass(raw, names):
    text = raw.decode()
    found = re.findall(r"^test (.+?) \.\.\. (ok|FAILED|ignored(?:, .*)?)$", text, re.MULTILINE)
    require(len(found) == len(names) and {name for name, _ in found} == names,
            "missing_or_duplicate_suite_results")
    ignored = {name for name, status in found if status.startswith("ignored")}
    require(ignored <= ALLOWED_IGNORED and all(status == "ok" or name in ignored for name, status in found),
            "failed_or_unexpected_ignored_test")
    summary = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text, re.MULTILINE)
    require(summary == [("ok", str(len(names) - len(ignored)), "0", str(len(ignored)), "0", "0")]
            and len(names) > len(ignored), "vacuous_or_incomplete_suite_result")
    return {"passed": len(names) - len(ignored), "ignored": sorted(ignored)}


def validate_case_inventory(expected, inventories):
    require(bool(expected), "empty_declared_case_selection")
    for target, names in expected.items():
        require(names and len(names) == len(set(names)), "empty_or_duplicate_declared_cases")
        require(target in inventories and bool(inventories[target]), "missing_declared_target_inventory")
        missing = set(names) - inventories[target]
        require(not missing, "required_named_test_not_found:" + target + ":" + ",".join(sorted(missing)))
    return {target: {"compiled_tests": len(inventories[target]), "selected_tests": list(names)}
            for target, names in expected.items()}


def role_requirements(target, name):
    if target in ("synthesized_review_e2e", CONTAINED_TARGET):
        return {"test", "daemon", "peer"}
    if target == "mcp_gateway_e2e":
        roles = {"test", "daemon"}
        if name in (CASES[target][0], CASES[target][5]):
            roles.add("adapter")
        return roles
    if target in ("task_api_e2e", "resource_authority_e2e"):
        return {"test", "daemon"}
    return {"test"}


def profile_inventory(directory, target, name=None):
    profiles = sorted(directory.glob("*.profraw"))
    require(bool(profiles), "no_execution_profiles")
    entries = []
    roles = set()
    for path in profiles:
        require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                "empty_or_invalid_execution_profile")
        role = path.name.split("-", 1)[0]
        require(role in {"test", "daemon", "adapter", "peer"}, "unknown_execution_profile_role")
        roles.add(role)
        entries.append({"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size, "role": role})
    require(role_requirements(target, name) <= roles, "missing_required_child_profiles")
    peers = sorted(directory.glob("peer-binary-*"))
    require(target not in ("synthesized_review_e2e", CONTAINED_TARGET) or bool(peers), "missing_instrumented_peer_object")
    require(all(p.is_file() and not p.is_symlink() and p.stat().st_size for p in peers),
            "invalid_instrumented_peer_object")
    return entries, peers


def source_inventory(root):
    inventory = []
    for package in PACKAGES:
        directory = root / "crates" / package / "src"
        files = sorted(directory.rglob("*.rs"))
        require(bool(files), "empty_declared_source_package")
        for path in files:
            require(not path.is_symlink(), "symlink_in_declared_source_scope")
            inventory.append({"package": package, "path": str(path.relative_to(root)), "sha256": sha(path)})
    require(set(REQUIRED_FILES) <= {item["path"] for item in inventory}, "required_source_not_in_inventory")
    return inventory


def validate_report_scope(report, sources, root):
    files = report.get("data", [{}])[0].get("files", [])
    declared = {item["path"] for item in sources}
    measured = set()
    for item in files:
        path = Path(item["filename"]).resolve().relative_to(root).as_posix()
        require(path in declared and path not in measured, "undeclared_or_duplicate_report_source")
        measured.add(path)
    require(set(REQUIRED_FILES) <= measured, "required_source_missing_from_collection")
    return sorted(declared - measured)


def stop_process(process):
    try:
        return suite.stop_group(process)
    except PermissionError:
        # Retain the failure instead of declaring uncertain descendant cleanup
        # successful. Always reap our direct child even if the OS denies the
        # process-group probe during exit.
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        raise suite.Invalid("process_group_cleanup_denied") from None


class Collector:
    def __init__(self, root, output, target, collector, jobs=4, contained=False):
        self.root, self.output, self.target = root, output, target
        self.collector = collector
        self.contained = contained
        self.cases = selected_cases(sys.platform, contained)
        self.flags = instrumentation_flags(sys.platform, os.sysconf("SC_PAGE_SIZE"))
        self.env = suite.environment()
        self.env.update({"RUSTUP_TOOLCHAIN": TOOLCHAIN, "CARGO_TARGET_DIR": str(target),
                         "CARGO_BUILD_JOBS": str(jobs)})
        self.commands = 0
        self.package_by_binary = {}
        self.declared_inventory_validated = False
        self.result = {"schema": SCHEMA, "status": "collecting", "platform": sys.platform,
                       "machine": platform.machine(), "coverage_packages": list(PACKAGES),
                       "test_collection_packages": [*PACKAGES, "opaqued", "opaque-mcp"],
                       "instrumentation": self.flags, "toolchain": TOOLCHAIN,
                       "collector_version": COLLECTOR_VERSION, "executions": [], "profiles": [],
                       "binaries": [], "failures": [],
                       "not_qualified": ["live vendor accounts", "real model completions", "native human approval",
                                         "contained Vault/OpenSSH/systemd service", "other native platforms"]}

    def command(self, label, argv, env=None, timeout=1800, export=None):
        print(f"coverage: {label}", flush=True)
        self.commands += 1
        log = self.output / f"command-{self.commands:03d}.log"
        # Raw fixture output is private local data; only sanitized reports are CI artifacts.
        with log.open("wb") as stream:
            log.chmod(0o600)
            process = subprocess.Popen(argv, cwd=self.root, env=env or self.env,
                                       stdin=subprocess.DEVNULL, stdout=stream,
                                       stderr=subprocess.STDOUT if export is None else subprocess.PIPE,
                                       start_new_session=True)
            try:
                _, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_process(process)
                raise suite.Invalid("command_timeout") from None
            finally:
                leaked = stop_process(process)
        require(not leaked, "command_leaked_process_group")
        require(process.returncode == 0, f"command_failed_{label}")
        require(log.stat().st_size <= 256 * 1024 * 1024, "command_output_limit")
        if export is not None:
            require(not stderr or b"error:" not in stderr.lower(), "llvm_export_error")
            log.replace(export)
            export.chmod(0o600)
            return export.read_bytes()
        return log.read_bytes()

    def setup(self):
        require(sys.platform in ("linux", "darwin"), "unsupported_native_platform")
        if sys.platform == "linux":
            require(os.geteuid() == 0 and suite.has_sys_ptrace(), "linux_root_and_sys_ptrace_required")
        if self.contained:
            self.result["contained_service_profile"] = contained_prerequisites(sys.platform)
        self.result["source_before"] = suite.source_snapshot(self.root)
        self.result["source_inventory"] = source_inventory(self.root)
        version = self.command("collector-version", [self.collector, "llvm-cov", "--version"]).decode().strip()
        require(version == f"cargo-llvm-cov {COLLECTOR_VERSION}", "unexpected_collector_version")
        verbose = self.command("compiler-identity", ["rustc", "-vV"]).decode()
        require("-nightly" in verbose, "nightly_compiler_required")
        host = re.findall(r"^host: (\S+)$", verbose, re.MULTILINE)
        require(len(host) == 1, "missing_native_target")
        self.result["compiler"] = verbose.strip().splitlines()
        self.result["target"] = host[0]
        sysroot = Path(self.command("compiler-sysroot", ["rustc", "--print", "sysroot"]).decode().strip())
        self.llvm_cov = str(sysroot / "lib/rustlib" / host[0] / "bin/llvm-cov")
        self.llvm_profdata = str(sysroot / "lib/rustlib" / host[0] / "bin/llvm-profdata")
        raw = self.command("instrumentation-environment", [self.collector, "llvm-cov", "show-env"])
        # show-env emits diagnostic information on stderr, which command logs merge.
        assignments = b"\n".join(line for line in raw.splitlines() if re.match(rb"[A-Z_][A-Z0-9_]*=", line))
        self.env.update(parse_environment(assignments, self.flags))
        self.env["OPAQUE_COVERAGE_RUSTC"] = str(sysroot / "bin/rustc")
        self.env["OPAQUE_COVERAGE_RUSTFLAGS"] = json.dumps(self.flags)
        require(Path(self.env["CARGO_LLVM_COV_TARGET_DIR"]).resolve() == self.target,
                "collector_changed_target_directory")
        self.result["preflight"] = self.preflight()

    def preflight(self):
        directory = fresh_directory(self.output / "continuous-preflight")
        source = directory / "probe.rs"
        source.write_text("#[inline(never)]\nfn observed(value: bool) -> u32 { if value { 31 } else { 17 } }\n"
                          "fn main() { println!(\"READY:{}\", observed(true)); loop { std::thread::park(); } }\n")
        binary = directory / "probe"
        self.command("continuous-probe-build", ["rustc", str(source), "--edition=2024", *self.flags,
                                                "-o", str(binary)])
        env = dict(self.env, LLVM_PROFILE_FILE=str(directory / "probe-%p-%m-%c.profraw"))
        with (directory / "stderr.log").open("wb") as stderr:
            process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.PIPE, stderr=stderr,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    require(bool(selector.select(10)), "continuous_probe_not_ready")
                    require(process.stdout.readline() == b"READY:31\n", "continuous_probe_bad_result")
                process.kill()  # SIGKILL deliberately prevents atexit profile writes.
                process.wait(timeout=10)
            finally:
                stop_process(process)
                process.stdout.close()
        profiles = list(directory.glob("*.profraw"))
        require(bool(profiles) and all(p.stat().st_size > 0 for p in profiles), "killed_child_lost_profile")
        merged = directory / "probe.profdata"
        self.command("continuous-probe-merge", [self.llvm_profdata, "merge", "--sparse", "--failure-mode=any",
                                                *map(str, profiles), "-o", str(merged)])
        raw = self.command("continuous-probe-export", [self.llvm_cov, "export", str(binary),
                          "-instr-profile=" + str(merged), "--sources", str(source)], export=directory / "probe.json")
        report = json.loads(raw)
        branches = [branch for file in report["data"][0]["files"] for branch in file["branches"]]
        require(len(branches) == 1 and branches[0][4:6] == [1, 0], "killed_child_branch_counters_not_retained")
        return {"status": "passed", "termination": "SIGKILL", "observed_branch_counts": [1, 0],
                "source_sha256": sha(source), "binary_sha256": sha(binary),
                "profile_sha256": [sha(p) for p in profiles]}

    def read_artifacts(self, raw):
        selected = artifacts(raw, self.target)
        self.package_by_binary.update(artifact_packages(raw, set(selected.values()), self.root))
        return selected

    def build(self):
        baseline = ["cargo", "test", "--locked", "--all-features", "--tests", "--no-run", "--message-format=json"]
        for package in PACKAGES:
            baseline += ["-p", package]
        self.baseline = self.read_artifacts(self.command("build-library-tests", baseline))
        require({("opaque_core", "lib", True), ("opaque_bounded_work", "lib", True),
                 ("opaque_approval", "lib", True)} <= self.baseline.keys(), "missing_critical_library_test_artifacts")
        normal = self.read_artifacts(self.command("build-daemon-and-adapter", ["cargo", "build", "--locked", "--all-features",
                           "-p", "opaqued", "-p", "opaque-mcp", "--bins", "--message-format=json"]))
        require({("opaqued", "bin", False), ("opaque-mcp", "bin", False)} <= normal.keys(), "missing_instrumented_daemon_or_adapter")
        selected = self.cases
        argv = ["cargo", "test", "--locked", "--all-features", "-p", "opaqued", "--bin", "opaqued"]
        for target in selected:
            if target != "opaqued":
                argv += ["--test", target]
        self.composition = self.read_artifacts(self.command("build-existing-composition-tests", argv + ["--no-run", "--message-format=json"]))
        self.objects = set(self.baseline.values()) | set(normal.values()) | set(self.composition.values())

    def validate_cases(self):
        expected = dict(self.cases)
        binaries = {}
        for target in expected:
            key = (target, "bin" if target == "opaqued" else "test", True)
            require(key in self.composition, "missing_composition_test_artifact")
            binaries[target] = self.composition[key]
        if sys.platform == "linux":
            expected["opaque_core"] = (ROOT_CASE,)
            binaries["opaque_core"] = self.baseline[("opaque_core", "lib", True)]
        directory = fresh_directory(self.output / "inventory-preflight")
        env = dict(self.env, LLVM_PROFILE_FILE=str(directory / "inventory-%p-%m-%c.profraw"))
        inventories = {}
        for target, binary in binaries.items():
            env["CARGO_PKG_NAME"] = self.package_by_binary[binary]
            inventories[target] = suite.inventory(self.command("preflight-inventory-" + target,
                                                               [str(binary), "--list"], env=env, timeout=60))
        self.result["declared_test_inventory"] = validate_case_inventory(expected, inventories)
        self.declared_inventory_validated = True

    def execute(self, target, binary, name=None):
        index = len(self.result["executions"])
        directory = fresh_directory(self.output / "profiles" / f"{index:03d}-{target}", 0o1777)
        env = dict(self.env, LLVM_PROFILE_FILE=str(directory / "test-%p-%m-%c.profraw"),
                   OPAQUE_COVERAGE_PROFILE_DIR=str(directory))
        with_home = fresh_directory(self.output / f"home-{index:03d}", 0o700)
        env["HOME"] = str(with_home)
        # Cargo supplies this at runtime. The existing resource gateway fixture
        # uses its package name as a harmless synthetic source credential.
        env["CARGO_PKG_NAME"] = self.package_by_binary[binary]
        names = suite.inventory(self.command("inventory-" + target, [str(binary), "--list"], env=env, timeout=60))
        # Inventory itself can produce empty-count test profiles; remove them so
        # their existence cannot satisfy execution/child-profile requirements.
        for path in directory.glob("*.profraw"):
            path.unlink()
        if name is None:
            argv = [str(binary), "--test-threads=1"]
        else:
            require(name in names, "required_named_test_not_found")
            argv = [str(binary), "--exact", name, "--nocapture", "--test-threads=1"]
            if target in ("synthesized_review_e2e", CONTAINED_TARGET) or name == ROOT_CASE:
                argv += ["--include-ignored"]
        raw = self.command("execute-" + target, argv, env=env, timeout=1200)
        if name is None:
            counts = suite_pass(raw, names)
        else:
            suite.named_pass(raw, name)
            counts = {"passed": 1, "ignored": []}
        profiles, peers = profile_inventory(directory, target, name)
        self.objects.update(peers)
        self.result["profiles"].extend(profiles)
        self.result["executions"].append({"target": target, "test": name, "package": self.package_by_binary[binary], "binary_sha256": sha(binary),
                                          "inventory_count": len(names), **counts,
                                          "profiles": [p["path"] for p in profiles]})

    def export(self, label, objects, profiles):
        merged = self.output / f"{label}.profdata"
        self.command("merge-" + label, [self.llvm_profdata, "merge", "--sparse", "--failure-mode=any",
                     *[p["path"] for p in profiles], "-o", str(merged)])
        objects = sorted(objects)
        argv = [self.llvm_cov, "export", str(objects[0]), "-instr-profile=" + str(merged)]
        for binary in objects[1:]:
            argv += ["--object", str(binary)]
        argv += ["--sources", *[str(self.root / item["path"]) for item in self.result["source_inventory"]]]
        report_path = self.output / ("llvm-coverage.json" if label == "critical" else f"{label}-llvm-coverage.json")
        raw = self.command("export-" + label, argv, export=report_path)
        report = json.loads(raw)
        missing = validate_report_scope(report, self.result["source_inventory"], self.root)
        summary = gate.evaluate(report, source_root=self.root, required_files=REQUIRED_FILES, require_branches=True)
        summary.update({"platform": sys.platform, "target": self.result["target"], "toolchain": TOOLCHAIN,
                        "coverage_packages": list(PACKAGES), "input_sha256": hashlib.sha256(raw).hexdigest()})
        save(self.output / ("coverage-summary.json" if label == "critical" else f"{label}-summary.json"), summary)
        return {"coverage_gate": summary["status"], "coverage_report_sha256": summary["input_sha256"],
                "merged_profile_sha256": sha(merged), "sources_without_mapping": missing,
                "measured": summary["measured"], "binary_count": len(objects), "profile_count": len(profiles)}

    def collect(self):
        require(self.declared_inventory_validated, "declared_inventory_not_validated")
        for (name, kind, is_test), binary in sorted(self.baseline.items()):
            if is_test:
                self.execute(name, binary)
        require(bool(self.result["executions"]), "no_library_tests_executed")
        baseline_profiles = list(self.result["profiles"])
        baseline_objects = set(self.baseline.values())
        self.result["baseline"] = self.export("baseline", baseline_objects, baseline_profiles)
        self.result["baseline"]["execution_count"] = len(self.result["executions"])
        self.result["baseline"]["binary_paths"] = [str(p) for p in sorted(baseline_objects)]
        self.result["baseline"]["profile_paths"] = [p["path"] for p in baseline_profiles]
        if sys.platform == "linux":
            self.execute("opaque_core", self.baseline[("opaque_core", "lib", True)], ROOT_CASE)
            self.result["ignored_reconciled_by_explicit_execution"] = [ROOT_CASE]
        for target, names in self.cases.items():
            key = (target, "bin" if target == "opaqued" else "test", True)
            require(key in self.composition, "missing_composition_test_artifact")
            for name in names:
                self.execute(target, self.composition[key], name)
        self.result["binaries"] = [{"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size,
                                    "package": self.package_by_binary.get(path),
                                    "kind": "cargo_artifact" if path in self.package_by_binary else "standalone_fixture_peer"}
                                   for path in sorted(self.objects)]
        self.result.update(self.export("critical", self.objects, self.result["profiles"]))
        self.result["source_after"] = suite.source_snapshot(self.root)
        require(self.result["source_after"] == self.result["source_before"], "source_changed_during_collection")
        self.result["status"] = "collected"
        if self.contained:
            self.result["not_qualified"].remove("contained Vault/OpenSSH/systemd service")
            self.result["contained_service_profile"]["executed_tests"] = list(CONTAINED_CASES)
        self.result["comparison_scope"] = (
            "Baseline and expanded reports use this native platform and the same declared production source inventory. "
            "Expanded daemon/caller mappings may add production instantiations; compare both denominators, not percentages alone.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--collector", default="cargo-llvm-cov")
    parser.add_argument("--reuse-target-dir", action="store_true",
                        help="Reuse the compiler cache; profiles still require a fresh output directory")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--contained", action="store_true",
                        help="Also require real SSH and controlled inference RPC scenarios inside the marked disposable host")
    args = parser.parse_args(argv)
    output = None
    collector = None
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    previous_sigterm = signal.signal(signal.SIGTERM, interrupted)
    try:
        root = args.source_root.resolve(strict=True)
        require(1 <= args.jobs <= 64, "invalid_build_job_count")
        require(not args.output.resolve().is_relative_to(root), "coverage_output_must_be_outside_source_checkout")
        output = fresh_directory(args.output.absolute())
        if args.reuse_target_dir and args.target_dir.is_dir():
            require(not args.target_dir.is_symlink(), "symlink_target_cache")
            target = args.target_dir.resolve()
        else:
            target = fresh_directory(args.target_dir.absolute())
        fresh_directory(output / "profiles")
        collector = Collector(root, output, target, args.collector, args.jobs, args.contained)
        collector.setup()
        if args.preflight_only:
            collector.result["status"] = "preflight_only"
        else:
            collector.build()
            collector.validate_cases()
            collector.collect()
        status = 0
    except KeyboardInterrupt:
        result = collector.result if collector else {"schema": SCHEMA, "platform": sys.platform, "failures": []}
        result["status"] = "failed"
        result["failures"].append("interrupted")
        status = 130
    except (suite.Invalid, gate.CoverageError, OSError, ValueError, KeyError, TypeError) as error:
        result = collector.result if collector else {"schema": SCHEMA, "platform": sys.platform, "failures": []}
        result["status"] = "failed"
        result["failures"].append(str(error) if isinstance(error, suite.Invalid) else type(error).__name__)
        print("coverage collection failed; inspect the private command logs and collection.json", file=sys.stderr)
        status = 2
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        if output is not None:
            save(output / "collection.json", collector.result if collector else result)
    return status


if __name__ == "__main__":
    sys.exit(main())
