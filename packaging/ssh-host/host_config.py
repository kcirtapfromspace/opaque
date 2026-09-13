"""Shared bounded health contract and root-custody checks for the Linux host."""
import json
import os
from pathlib import Path
import re
import stat

HEALTH_CONFIG = "/etc/opaque-ssh/health.json"
HEALTH_FIELDS = {"service", "version", "host", "port", "path"}


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def validate_contract(value):
    if not isinstance(value, dict) or set(value) != HEALTH_FIELDS:
        raise ValueError("invalid health contract fields")
    for field in ("service", "version"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value[field]):
            raise ValueError("invalid health identity")
    path = value["path"]
    if (not isinstance(value["host"], str) or value["host"] not in {"127.0.0.1", "::1"}
            or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
            or not isinstance(path, str) or not 1 <= len(path) <= 256
            or not path.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9/_.-]+", path)
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])):
        raise ValueError("invalid health endpoint")
    return value


def protected_bytes(path, limit, *, private=False):
    """Require a canonical absolute path and root-owned, nonwritable ancestors."""
    original = os.fspath(path)
    path = Path(original)
    if not path.is_absolute() or ".." in path.parts or str(path) != original:
        raise ValueError("canonical absolute host path required")
    for parent in reversed(path.parents):
        metadata = parent.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022):
            raise ValueError("host path requires root custody")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & (0o077 if private else 0o022) or metadata.st_size > limit):
            raise ValueError("host file requires root custody")
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError("host file too large")
        return data


def load_health(path=HEALTH_CONFIG):
    return validate_contract(strict_json(protected_bytes(path, 2048)))
