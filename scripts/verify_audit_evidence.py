#!/usr/bin/env python3
"""Offline structural and externally pinned verification of opaque.audit.v1 exports.

No daemon, network, audit database, HMAC key, or third-party package is used.
An externally trusted checkpoint digest binds an export, not its producer identity.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Iterator

EXPORT_SCHEMA = "opaque.audit.v1"
CHECKPOINT_SCHEMA = "opaque.audit.checkpoint.v1"
REPORT_SCHEMA = "opaque.audit.verification.v1"
MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_LINES = 100_000
MAX_CHECKPOINT_BYTES = 16 * 1024
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
OPTIONAL_STRINGS = (
    "request_id", "approval_id", "client_json", "operation", "safety", "target_json",
    "outcome", "secret_names", "policy_decision", "detail", "workspace_json",
    "request_hash", "approver_json",
)
REQUIRED_STRINGS = ("schema", "event_id", "level", "kind", "record_hash")
REQUIRED_INTS = ("rowid", "sequence_number", "ts_utc_ms")
FIELDS = set(OPTIONAL_STRINGS + REQUIRED_STRINGS + REQUIRED_INTS + ("latency_ms",))


class EvidenceError(ValueError):
    """A bounded, metadata-free validation failure suitable for CLI output."""


def strict_json(raw: bytes) -> object:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise EvidenceError("duplicate_json_key")
            value[key] = item
        return value

    def invalid_constant(_):
        raise EvidenceError("nonfinite_json_number")

    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise EvidenceError("nonfinite_json_number")
        return value

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=invalid_constant, parse_float=finite_float)
    except EvidenceError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise EvidenceError("invalid_json") from error


def valid_int(value: object, minimum: int = -(2**63)) -> bool:
    return type(value) is int and minimum <= value <= 2**63 - 1


def validate_record(value: object) -> dict:
    """Validate v1 fields; normalize absent optional columns to JSON null."""
    if not isinstance(value, dict) or set(value) - FIELDS:
        raise EvidenceError("unexpected_record_fields")
    if any(name not in value for name in REQUIRED_STRINGS + REQUIRED_INTS):
        raise EvidenceError("missing_record_fields")
    for name in REQUIRED_STRINGS:
        if not isinstance(value[name], str) or not value[name]:
            raise EvidenceError("invalid_record_string")
    if value["schema"] != EXPORT_SCHEMA:
        raise EvidenceError("unsupported_export_schema")
    if not HEX_SHA256.fullmatch(value["record_hash"]):
        raise EvidenceError("invalid_record_hash")
    if not valid_int(value["rowid"], 1) or not valid_int(value["sequence_number"], 0):
        raise EvidenceError("invalid_record_position")
    if not valid_int(value["ts_utc_ms"]):
        raise EvidenceError("invalid_record_timestamp")
    normalized = dict(value)
    for name in OPTIONAL_STRINGS:
        item = value.get(name)
        if item is not None and not isinstance(item, str):
            raise EvidenceError("invalid_optional_string")
        normalized[name] = item
    latency = value.get("latency_ms")
    if latency is not None and not valid_int(latency):
        raise EvidenceError("invalid_record_latency")
    normalized["latency_ms"] = latency
    # JSON accepts escaped unpaired surrogates; the UTF-8 Rust producer does not.
    try:
        for item in normalized.values():
            if isinstance(item, str):
                item.encode("utf-8")
    except UnicodeError as error:
        raise EvidenceError("invalid_record_unicode") from error
    return normalized


@contextmanager
def _open_regular(path: Path):
    # Nonblocking open rejects FIFOs/devices before a read can wait indefinitely.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise EvidenceError("not_regular_evidence_file")
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        with stream:
            yield stream
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_records(path: Path, digest=None) -> Iterator[dict]:
    size = 0
    with _open_regular(path) as stream:
        for line_number in range(1, MAX_LINES + 2):
            raw = stream.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            size += len(raw)
            if len(raw) > MAX_LINE_BYTES or size > MAX_EXPORT_BYTES or line_number > MAX_LINES:
                raise EvidenceError("export_resource_limit")
            if digest is not None:
                digest.update(raw)
            # A final newline is the spool's complete-record framing contract.
            if not raw.endswith(b"\n"):
                raise EvidenceError("incomplete_jsonl_record")
            if not raw.strip():
                raise EvidenceError("empty_jsonl_record")
            yield validate_record(strict_json(raw))


def iter_export_records(path: Path) -> Iterator[dict]:
    """Yield bounded, validated rows, including retries; use inspect_export to dedupe."""
    yield from _read_records(path)


@dataclass(repr=False)
class Snapshot:
    records: tuple[dict, ...] = field(repr=False)
    sha256: str
    delivery_count: int

    def summary(self) -> dict:
        first = self.records[0] if self.records else None
        last = self.records[-1] if self.records else None
        return {
            "export_sha256": self.sha256,
            "record_count": len(self.records),
            "delivery_count": self.delivery_count,
            "duplicate_count": self.delivery_count - len(self.records),
            "first_sequence": first["sequence_number"] if first else None,
            "last_sequence": last["sequence_number"] if last else None,
            "first_rowid": first["rowid"] if first else None,
            "last_rowid": last["rowid"] if last else None,
            "first_record_hash": first["record_hash"] if first else None,
            "last_record_hash": last["record_hash"] if last else None,
        }


def inspect_export(path: Path) -> Snapshot:
    """Require a contiguous range of unique events; accept exact replay deliveries."""
    digest = hashlib.sha256()
    records = {}
    event_ids = set()
    previous = None
    deliveries = 0
    for record in _read_records(path, digest):
        deliveries += 1
        sequence = record["sequence_number"]
        if sequence in records:
            if records[sequence] != record:
                raise EvidenceError("conflicting_duplicate_sequence")
            continue
        if record["event_id"] in event_ids:
            raise EvidenceError("conflicting_duplicate_event_id")
        if previous is not None:
            if sequence <= previous["sequence_number"] or record["rowid"] <= previous["rowid"]:
                raise EvidenceError("record_order_regression")
            if sequence != previous["sequence_number"] + 1 or record["rowid"] != previous["rowid"] + 1:
                raise EvidenceError("interior_record_gap")
        records[sequence] = record
        event_ids.add(record["event_id"])
        previous = record
    return Snapshot(tuple(records.values()), digest.hexdigest(), deliveries)


def checkpoint_document(snapshot: Snapshot, source_id: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", source_id):
        raise EvidenceError("invalid_source_label")
    return {"schema": CHECKPOINT_SCHEMA, "source_id": source_id, **snapshot.summary()}


def _read_checkpoint(path: Path) -> tuple[dict, str]:
    with _open_regular(path) as stream:
        raw = stream.read(MAX_CHECKPOINT_BYTES + 1)
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise EvidenceError("checkpoint_resource_limit")
    value = strict_json(raw)
    if not isinstance(value, dict) or value.get("schema") != CHECKPOINT_SCHEMA:
        raise EvidenceError("unsupported_checkpoint_schema")
    # Generate its shape from the implementation's fixed summary contract.
    expected_fields = set(checkpoint_document(Snapshot((), "0" * 64, 0), "shape"))
    if set(value) != expected_fields:
        raise EvidenceError("invalid_checkpoint_fields")
    source = value.get("source_id")
    if not isinstance(source, str):
        raise EvidenceError("invalid_source_label")
    checkpoint_document(Snapshot((), "0" * 64, 0), source)
    for name in ("export_sha256",):
        if not isinstance(value[name], str) or not HEX_SHA256.fullmatch(value[name]):
            raise EvidenceError("invalid_checkpoint_hash")
    for name in ("record_count", "delivery_count", "duplicate_count"):
        if not valid_int(value[name], 0):
            raise EvidenceError("invalid_checkpoint_count")
    for name in ("first_sequence", "last_sequence", "first_rowid", "last_rowid"):
        if value[name] is not None and not valid_int(value[name], 0):
            raise EvidenceError("invalid_checkpoint_position")
    for name in ("first_record_hash", "last_record_hash"):
        if value[name] is not None and (not isinstance(value[name], str) or not HEX_SHA256.fullmatch(value[name])):
            raise EvidenceError("invalid_checkpoint_hash")
    return value, hashlib.sha256(raw).hexdigest()


def cross_check(snapshot: Snapshot, reference: Snapshot) -> dict:
    actual = {record["sequence_number"]: record for record in snapshot.records}
    expected = {record["sequence_number"]: record for record in reference.records}
    if actual.keys() != expected.keys():
        raise EvidenceError("reference_range_mismatch")
    if actual != expected:
        raise EvidenceError("reference_record_mismatch")
    return {"status": "matched", "record_count": len(actual),
            "scope": "same_range_normalized_records_including_hmac_values"}


def verify_export(path: Path, checkpoint: Path | None = None,
                  trusted_checkpoint_sha256: str | None = None,
                  reference: Path | None = None) -> dict:
    if trusted_checkpoint_sha256 is not None:
        if checkpoint is None or not HEX_SHA256.fullmatch(trusted_checkpoint_sha256):
            raise EvidenceError("invalid_checkpoint_pin")
    snapshot = inspect_export(path)
    result = {
        "schema": REPORT_SCHEMA, "ok": True, "structure": "verified",
        **snapshot.summary(), "checkpoint": "not_supplied", "external_checkpoint_pin": "not_supplied",
        "export_integrity": "unverified", "producer_identity": "unverified",
        "audit_hmac": "not_verified", "cryptographic_chain_linkage": "not_verified",
        "completeness": "unanchored_observed_range_only", "global_completeness": "not_proven",
        "cross_check": {"status": "not_supplied"},
    }
    if checkpoint is not None:
        document, checkpoint_hash = _read_checkpoint(checkpoint)
        if trusted_checkpoint_sha256 is not None and checkpoint_hash != trusted_checkpoint_sha256:
            raise EvidenceError("checkpoint_pin_mismatch")
        if any(document[name] != value for name, value in snapshot.summary().items()):
            raise EvidenceError("checkpoint_export_mismatch")
        result["checkpoint"] = "matched"
        result["checkpoint_sha256"] = checkpoint_hash
        if trusted_checkpoint_sha256 is not None:
            result["external_checkpoint_pin"] = "matched"
            result["export_integrity"] = "matches_externally_pinned_checkpoint"
            result["completeness"] = "externally_pinned_export_range_verified"
    if reference is not None:
        result["cross_check"] = cross_check(snapshot, inspect_export(reference))
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="check JSONL structure and optional external checkpoint")
    verify.add_argument("export", type=Path)
    verify.add_argument("--checkpoint", type=Path)
    verify.add_argument("--trusted-checkpoint-sha256")
    verify.add_argument("--reference", type=Path, help="independently obtained same-range SIEM JSONL")
    create = commands.add_parser("checkpoint", help="create an unsigned local checkpoint for later anchoring")
    create.add_argument("export", type=Path)
    create.add_argument("--source-id", required=True, help="operator label; not a verified producer identity")
    create.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            result = verify_export(args.export, args.checkpoint, args.trusted_checkpoint_sha256, args.reference)
        else:
            snapshot = inspect_export(args.export)
            document = checkpoint_document(snapshot, args.source_id)
            raw = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
            # Exclusive creation prevents overwriting evidence or the input export.
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
            result = {"schema": REPORT_SCHEMA, "ok": True, "checkpoint": "created_unsigned",
                      "checkpoint_sha256": hashlib.sha256(raw).hexdigest(),
                      "external_checkpoint_pin": "not_established", "global_completeness": "not_proven"}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (EvidenceError, OSError) as error:
        # Never include raw rows, filesystem paths, IDs, or arbitrary parser text.
        reason = str(error) if isinstance(error, EvidenceError) else "evidence_io_error"
        print(json.dumps({"schema": REPORT_SCHEMA, "ok": False, "error": reason}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
