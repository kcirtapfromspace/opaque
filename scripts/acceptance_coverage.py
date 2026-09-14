"""Explicit inputs for acceptance using the collector's already instrumented objects.

This contract is not a coverage report. The collector still validates and merges
fresh LLVM counters with every workspace mapping object after acceptance passes.
No ambient instrumentation or credential environment is forwarded.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

SCHEMA = "opaque.acceptance-coverage-input.v1"
TOOLCHAIN = "nightly-2026-09-13"
PURPOSES = {"packaged", "browser", "model", "service"}
BINARIES = {"opaqued", "opaque", "opaque-mcp", "opaque-mcp-contract", "opaque-approve-helper",
            "opaque-approver", "opaque-evidence", "opaque-web"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def native_target():
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(platform.machine())
    suffix = {"linux": "unknown-linux-gnu", "darwin": "apple-darwin"}.get(sys.platform)
    require(arch is not None and suffix is not None, "unsupported_coverage_native_target")
    return arch + "-" + suffix


def regular(path):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink()
            and path.resolve() == path and path.stat().st_size > 0, "invalid_coverage_object")
    return path


def validate_objects(value):
    require(isinstance(value, dict) and bool(value), "missing_coverage_objects")
    for name, row in value.items():
        require(re.fullmatch(r"[a-z][a-z0-9_-]*", name) and isinstance(row, dict)
                and set(row) == {"path", "sha256", "bytes"}, "invalid_coverage_object_record")
        path = regular(row["path"])
        require(type(row["bytes"]) is int and path.stat().st_size == row["bytes"]
                and digest(path) == row["sha256"], "coverage_object_changed")


def load(path, *, root, purpose, source=None, fresh=True):
    path = regular(path)
    require(path.stat().st_size <= 1024 * 1024, "oversized_coverage_input")
    raw = path.read_bytes()
    def unique(items):
        result = {}
        for key, item in items:
            require(key not in result, "duplicate_coverage_input_key")
            result[key] = item
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) == {"schema", "purpose", "source", "platform", "target",
            "toolchain", "rustc", "instrumentation", "profile_dir", "objects", "qualification"}, "invalid_coverage_input_fields")
    require(value["schema"] == SCHEMA and purpose in PURPOSES and value["purpose"] == purpose,
            "coverage_input_purpose_mismatch")
    require(value["platform"] == sys.platform and value["toolchain"] == TOOLCHAIN,
            "coverage_input_native_toolchain_mismatch")
    require(value["target"] == native_target(),
            "coverage_input_native_target_mismatch")
    if source is None:
        import synthesized_suite
        source = synthesized_suite.source_snapshot(root)
    require(value["source"] == source, "coverage_input_source_changed")
    require(value["qualification"] == ("instrumented_local_candidate" if source["dirty"] else "instrumented_build_candidate"),
            "coverage_input_qualification_mismatch")
    flags = value["instrumentation"]
    expected = ["-C", "instrument-coverage", "--cfg=coverage", "--cfg=coverage_nightly",
                "-Zcoverage-options=branch", "-Cdebuginfo=0"]
    if sys.platform == "linux":
        expected += ["-Cllvm-args=-runtime-counter-relocation"]
    else:
        alignment = os.sysconf("SC_PAGE_SIZE")
        expected += [f"-Clink-arg=-Wl,-sectalign,__DATA,__llvm_prf_{section},{alignment:x}" for section in ("cnts", "data", "bits")]
    require(flags == expected, "coverage_input_instrumentation_mismatch")
    regular(value["rustc"])
    directory = Path(value["profile_dir"])
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
            and directory.resolve() == directory and stat.S_IMODE(directory.stat().st_mode) == 0o1777,
            "coverage_profiles_require_explicit_uid_writable_directory")
    require(not fresh or not any(directory.iterdir()), "coverage_profiles_not_fresh")
    validate_objects(value["objects"])
    required = (BINARIES if purpose == "packaged" else {"opaqued", "opaque-web"} if purpose == "browser"
                else {"opaque", "opaqued"} if purpose == "service" else {"opaqued", "model-test"})
    require(set(value["objects"]) == required, "coverage_input_object_set_mismatch")
    return {**value, "_input_path": str(path), "_input_sha256": hashlib.sha256(raw).hexdigest()}


def environment(value, role="test"):
    require(re.fullmatch(r"[a-z]+", role), "invalid_coverage_profile_role")
    directory = Path(value["profile_dir"])
    return {"LLVM_PROFILE_FILE": str(directory / (role + "-%p-%m-%c.profraw")),
            "OPAQUE_COVERAGE_PROFILE_DIR": str(directory), "OPAQUE_COVERAGE_RUSTC": value["rustc"],
            "OPAQUE_COVERAGE_RUSTFLAGS": json.dumps(value["instrumentation"])}


def profiles(value, *, roles, process_ids=()):
    require(digest(value["_input_path"]) == value["_input_sha256"], "coverage_input_changed_during_acceptance")
    directory = Path(value["profile_dir"])
    entries = []
    for path in sorted(directory.glob("*.profraw")):
        regular(path)
        matched = re.fullmatch(r"([a-z]+)-([1-9][0-9]*)-[0-9]+_?[0-9]*-\.profraw", path.name)
        require(matched is not None, "coverage_profile_identity_missing")
        entries.append({"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size,
                        "role": matched[1], "process_id": int(matched[2])})
    require(set(roles) <= {p["role"] for p in entries}, "acceptance_child_profiles_missing")
    require(set(process_ids) <= {p["process_id"] for p in entries}, "acceptance_process_counters_missing")
    validate_objects(value["objects"])
    return entries
