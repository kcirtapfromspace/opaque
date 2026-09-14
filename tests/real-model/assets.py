"""Immutable public model asset; no account, token or mutable model aliases."""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import time
import urllib.request

MODEL_COMMIT = "9e6855bc4be717fca1ef21360a1db4b29d5c559a"
MODEL_NAME = "SmolLM2-135M-Instruct-Q4_K_M.gguf"
MODEL_SIZE = 105454144
MODEL_SHA256 = "ed5fa30c487b282ec156c29062f1222e5c20875a944ac98289dbd242e947f747"
MODEL_URL = ("https://huggingface.co/unsloth/SmolLM2-135M-Instruct-GGUF/resolve/"
             + MODEL_COMMIT + "/" + MODEL_NAME)
LLAMA_COMMIT = "c1d0e7a004015f23bc0233470b747b596f29b264"
TEMPLATE_SHA256 = "872be49dbb638044ad01b60388f48d469ff2980e5f0dccdc22ec907db54d0788"


def digest(path):
    path = Path(path)
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("artifact must be a regular nonsymlink file")
    before = path.stat()
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    after = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after):
        raise ValueError("artifact changed during hashing")
    return {"sha256": checksum.hexdigest(), "size": after.st_size}


def verify_model(path):
    observed = digest(path)
    if observed != {"sha256": MODEL_SHA256, "size": MODEL_SIZE}:
        raise ValueError("model bytes do not match the immutable asset")
    return observed


def obtain_model(existing, output):
    if existing is not None:
        path = Path(existing).expanduser().absolute()
        verify_model(path)
        return path.resolve()
    path = Path(output) / MODEL_NAME
    temporary = path.with_suffix(".download")
    try:
        # This public immutable revision needs no ambient credentials. HTTPS
        # redirects are needed for Hugging Face's content-addressed CDN.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 300
        with opener.open(MODEL_URL, timeout=60) as response, temporary.open("xb") as stream:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if time.monotonic() > deadline:
                    raise ValueError("model download exceeded its deadline")
                if total > MODEL_SIZE:
                    raise ValueError("model download exceeds the pinned length")
                stream.write(chunk)
        verify_model(temporary)
        temporary.rename(path)
        return path
    finally:
        temporary.unlink(missing_ok=True)
