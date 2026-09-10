#!/usr/bin/env python3
"""Create/recompute a bounded local evidence package. No credentials or network."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

import approval_metrics
import audit_anomalies
from verify_audit_evidence import (EvidenceError, HEX_SHA256, MAX_EXPORT_BYTES, _open_regular,
                                   checkpoint_document, inspect_export, strict_json, verify_export)

SCHEMA = "opaque.evidence-package.v1"
TOOLS = ("verify_audit_evidence.py", "approval_metrics.py", "audit_anomalies.py", "evidence_package.py")
ARTIFACTS = ("audit.jsonl", "checkpoint.json", "verification.json", "metrics.json", "anomalies.json",
             "coverage.json", "controls.json")
REPORT_LIMIT = 32 * 1024 * 1024  # up to 100,000 bounded findings
LIMITS = {name: REPORT_LIMIT for name in ARTIFACTS}
LIMITS.update({"audit.jsonl": MAX_EXPORT_BYTES, "checkpoint.json": 16 * 1024,
               "coverage.json": 64 * 1024, "controls.json": 64 * 1024, "manifest.json": 64 * 1024})


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bounded(path, limit):
    with _open_regular(path) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise EvidenceError("package_resource_limit")
    return raw


def tool_identity():
    # Release/check-out identity is independently checkable against installed
    # source. This is not a code-signing attestation or automatic trust store.
    return {name: digest(read_bounded(Path(__file__).parent / name, 1024 * 1024)) for name in TOOLS}


def documents(directory, source_id):
    snapshot = inspect_export(directory / "audit.jsonl")
    checkpoint = checkpoint_document(snapshot, source_id)
    verification = verify_export(directory / "audit.jsonl", directory / "checkpoint.json")
    metrics = approval_metrics.build_report(list(snapshot.records))
    metrics["input_evidence"] = snapshot.summary()
    anomalies = audit_anomalies.build_report(snapshot)
    common = {"export_sha256": snapshot.sha256, "source_id": source_id}
    coverage = {"schema": "opaque.evidence.coverage.v1", **common,
                "observed_range": snapshot.summary(),
                "population": "unique records from one operator-selected export",
                "producer_identity": "operator_label_only_not_authenticated",
                "hmac_verification": "not_performed_no_secret_key_in_package",
                "global_completeness": "unknown", "missing_prefix_or_tail": "unknown",
                "external_checkpoint": "unsigned_local_artifact_only",
                "policy_execution_coverage": "unknown_missing_effective_policy_and_grant_effect_lineage",
                "sensitive_operation_coverage": "unknown_missing_authoritative_sensitivity",
                "deployment_validation": "not_included",
                "certification_or_contract": "not_established",
                "privacy": "Audit metadata remains sensitive; package contains no additional config, keys or session artifacts. Input must be a custody-approved audit export; arbitrary secrets already embedded in audit fields cannot be ruled out by schema validation."}
    controls = {"schema": "opaque.evidence.controls.v1", **common,
                "mapping_status": "engineering_index_requires_security_owner_and_assessor_review",
                "controls": [
                    {"id": "evidence-format", "status": "observed", "artifacts": ["verification.json"],
                     "claim": "Bounded structural inspection of the selected v1 export."},
                    {"id": "approval-observations", "status": "observed", "artifacts": ["metrics.json", "anomalies.json"],
                     "claim": "Descriptive recorded attribution and deterministic lifecycle observations, with missingness."},
                    *[{"id": name, "status": "unavailable", "artifacts": [], "claim": reason} for name, reason in [
                        ("producer-authenticity", "Requires separately trusted producer public-key checkpoints and key custody evidence."),
                        ("independent-retention", "Requires independently retained collector receipts and retention/recovery evidence."),
                        ("policy-effect-lineage", "Requires effective policy version and authoritative decision/grant/effect lineage."),
                        ("identity-lifecycle", "Requires deployed enrollment, access review and removal/revocation evidence."),
                        ("operational-controls", "Requires actual incident response, backup/recovery, vulnerability management and control-owner evidence."),
                        ("external-assurance", "No SOC examination report, ISO certification or executed BAA is supplied or inferred."),
                    ]],
                ]}
    return {"checkpoint.json": encoded(checkpoint), "verification.json": encoded(verification),
            "metrics.json": encoded(metrics), "anomalies.json": encoded(anomalies),
            "coverage.json": encoded(coverage), "controls.json": encoded(controls)}


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def create_package(export, output, source_id):
    # Snapshot once before deriving anything; never repeatedly read a growing
    # live spool into different reports. Failures remove only our new directory.
    raw = read_bounded(export, MAX_EXPORT_BYTES)
    checkpoint_document(inspect_empty(), source_id)  # validate label before writing
    os.mkdir(output, 0o700)
    try:
        write_new(output / "audit.jsonl", raw)
        snapshot = inspect_export(output / "audit.jsonl")
        write_new(output / "checkpoint.json", encoded(checkpoint_document(snapshot, source_id)))
        for name, value in documents(output, source_id).items():
            if name != "checkpoint.json":
                write_new(output / name, value)
        entries = {}
        for name in ARTIFACTS:
            value = read_bounded(output / name, LIMITS[name])
            entries[name] = {"sha256": digest(value), "bytes": len(value)}
        manifest = {"schema": SCHEMA, "version": 1, "source_id": source_id,
                    "export_sha256": snapshot.sha256, "artifacts": entries,
                    "tools_sha256": tool_identity(), "trust": "unsigned_local_artifact_manifest"}
        manifest_raw = encoded(manifest)
        write_new(output / "manifest.json", manifest_raw)
        directory_fd = os.open(output, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return {"schema": SCHEMA, "ok": True, "manifest_sha256": digest(manifest_raw),
                "export_sha256": snapshot.sha256, "external_trust": "not_established"}
    except BaseException:
        shutil.rmtree(output)
        raise


def inspect_empty():
    from verify_audit_evidence import Snapshot
    return Snapshot((), "0" * 64, 0)


def verify_package(directory, trusted_manifest_sha256=None):
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise EvidenceError("not_package_directory")
    names = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names) > len(ARTIFACTS) + 1:
                raise EvidenceError("package_allowlist_mismatch")
    if names != set(ARTIFACTS) | {"manifest.json"}:
        raise EvidenceError("package_allowlist_mismatch")
    raw = read_bounded(directory / "manifest.json", LIMITS["manifest.json"])
    manifest_hash = digest(raw)
    if trusted_manifest_sha256 is not None and (not HEX_SHA256.fullmatch(trusted_manifest_sha256)
                                              or manifest_hash != trusted_manifest_sha256):
        raise EvidenceError("package_pin_mismatch")
    manifest = strict_json(raw)
    expected_fields = {"schema", "version", "source_id", "export_sha256", "artifacts", "tools_sha256", "trust"}
    if not isinstance(manifest, dict) or set(manifest) != expected_fields or manifest["schema"] != SCHEMA or type(manifest["version"]) is not int or manifest["version"] != 1:
        raise EvidenceError("invalid_package_manifest")
    if manifest["trust"] != "unsigned_local_artifact_manifest" or manifest["tools_sha256"] != tool_identity():
        raise EvidenceError("package_tool_or_trust_mismatch")
    if not isinstance(manifest["artifacts"], dict) or set(manifest["artifacts"]) != set(ARTIFACTS):
        raise EvidenceError("package_allowlist_mismatch")
    checkpoint_document(inspect_empty(), manifest["source_id"])
    actual = {name: read_bounded(directory / name, LIMITS[name]) for name in ARTIFACTS}
    for name, value in actual.items():
        entry = manifest["artifacts"][name]
        if not isinstance(entry, dict) or set(entry) != {"bytes", "sha256"} or type(entry["bytes"]) is not int or entry != {"bytes": len(value), "sha256": digest(value)}:
            raise EvidenceError("package_artifact_mismatch")
    if manifest["export_sha256"] != digest(actual["audit.jsonl"]):
        raise EvidenceError("package_export_mismatch")
    # Recompute semantics, so updating artifact hashes cannot launder a mixed
    # report, false coverage claim or different population into a valid package.
    # Recompute from the bytes we hashed, inside a private snapshot. The input
    # directory may be mutable; reading it twice would permit mixed snapshots.
    with tempfile.TemporaryDirectory(prefix="opaque-evidence-verify-") as temporary:
        snapshot_dir = Path(temporary)
        for name in ("audit.jsonl", "checkpoint.json"):
            write_new(snapshot_dir / name, actual[name])
        for name, expected in documents(snapshot_dir, manifest["source_id"]).items():
            if actual[name] != expected:
                raise EvidenceError("package_report_reproduction_mismatch")
    return {"schema": SCHEMA, "ok": True, "manifest_sha256": manifest_hash,
            "export_sha256": manifest["export_sha256"], "reports": "reproduced_exactly",
            "external_trust": "matches_independently_pinned_manifest" if trusted_manifest_sha256 else "not_established",
            "producer_authenticity": "unverified", "global_completeness": "unknown"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("export", type=Path)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--source-id", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--trusted-manifest-sha256")
    args = parser.parse_args(argv)
    try:
        result = create_package(args.export, args.output, args.source_id) if args.command == "create" else verify_package(args.directory, args.trusted_manifest_sha256)
    except (EvidenceError, OSError, ValueError, TypeError, RecursionError):
        result = {"schema": SCHEMA, "ok": False, "error": "invalid_evidence_package"}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
