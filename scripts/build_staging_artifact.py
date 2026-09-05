#!/usr/bin/env python3
"""Prepare, build and smoke-test a LOCAL private staging image; never publish.

Only committed Git source enters the build context. Default HEAD requires a clean
worktree; --revision selects an exact existing commit independently of local edits.
No credentials are read or copied. Docker may download public build dependencies.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
RECIPE = ROOT / "examples/staging-release/Dockerfile.artifact"
SOURCE_URL = "https://github.com/kcirtapfromspace/opaque-dogfood"
PLATFORM = "linux/amd64"
SHA = re.compile(r"[0-9a-f]{40}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ArtifactError(Exception):
    """An intentionally sanitized preparation or verification failure."""


def clean_environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1")
    return env


def command(args, *, timeout=60, log=None):
    try:
        result = subprocess.run(
            list(map(str, args)), stdout=log or subprocess.PIPE,
            stderr=subprocess.STDOUT if log else subprocess.PIPE,
            env=clean_environment(), timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ArtifactError("Command unavailable or timed out; no success recorded.") from None
    if result.returncode:
        raise ArtifactError("Command failed; no success recorded. Build logs, if any, remain in the output directory.")
    return result.stdout or b""


def git(root, *args):
    return command(["git", "-C", root, *args])


def select_revision(root, requested):
    origin = git(root, "remote", "get-url", "origin").decode().strip()
    if origin not in {SOURCE_URL, SOURCE_URL + ".git",
                      "git@github.com:kcirtapfromspace/opaque-dogfood.git",
                      "ssh://git@github.com/kcirtapfromspace/opaque-dogfood.git"}:
        raise ArtifactError("Configured origin does not match the private dogfood source contract.")
    if requested is not None and not SHA.fullmatch(requested):
        raise ArtifactError("--revision must name an exact lowercase 40-character commit SHA.")
    if requested is None and git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise ArtifactError("Default HEAD build requires a clean worktree; commit source or select an explicit immutable --revision.")
    revision = git(root, "rev-parse", "--verify", (requested or "HEAD") + "^{commit}").decode().strip()
    if not SHA.fullmatch(revision) or (requested and requested != revision):
        raise ArtifactError("Selected source is not the requested immutable commit.")
    if any(line.startswith(b"160000 ") for line in git(root, "ls-tree", "-r", revision).splitlines()):
        raise ArtifactError("Submodules need an explicit source contract; this builder refuses incomplete archives.")
    return revision


def extract_source(archive, destination):
    with tarfile.open(archive, "r:") as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "source":
                raise ArtifactError("Archive contains an invalid source path.")
            if not (member.isfile() or member.isdir()):
                raise ArtifactError("Archive links and special files are not admitted to the build context.")
        source.extractall(destination, filter="data")


def prepare(root, revision, output, recipe=RECIPE):
    context = output / "context"
    context.mkdir(mode=0o700)
    archive = output / "source.tar"
    git(root, "archive", "--format=tar", "--prefix=source/", "--output=" + str(archive), revision)
    extract_source(archive, context)
    recipe_bytes = recipe.read_bytes()
    (context / "Dockerfile").write_bytes(recipe_bytes)
    # The context is a committed archive and one reviewed recipe, never a checkout.
    return context, hashlib.sha256(recipe_bytes).hexdigest()


def build_command(context, revision, local_tag, output):
    return ["docker", "buildx", "build", "--load", "--platform", PLATFORM,
            "--progress", "plain", "--file", str(context / "Dockerfile"),
            "--build-arg", "OPAQUE_BUILD_REVISION=" + revision,
            "--tag", local_tag, "--iidfile", str(output / "image-id.txt"), str(context)]


def inspect_image(image_id, revision):
    raw = command(["docker", "image", "inspect", image_id])
    if len(raw) > 1024 * 1024:
        raise ArtifactError("Image metadata exceeds the verification limit.")
    try:
        records = json.loads(raw)
        if not isinstance(records, list) or len(records) != 1:
            raise ValueError
        item = records[0]
        config = item["Config"]
        labels = config.get("Labels") or {}
        if not isinstance(labels, dict):
            raise ValueError
        matches = (item["Id"] == image_id and item["Os"] == "linux"
                   and item["Architecture"] == "amd64"
                   and config.get("User") == "65532:65532"
                   and config.get("Entrypoint") == ["/usr/local/bin/opaque"]
                   and labels.get("org.opencontainers.image.revision") == revision
                   and labels.get("org.opencontainers.image.source") == SOURCE_URL)
        if not matches:
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ArtifactError("Image identity, platform, entrypoint, user or source labels failed verification.") from None


def smoke_command(image_id, container_name):
    return ["docker", "run", "--rm", "--name", container_name,
            "--platform", PLATFORM, "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "256m",
            "--cpus", "1", "--user", "65532:65532", "--entrypoint", "/usr/local/bin/opaque",
            image_id, "--version"]


def smoke_image(image_id, revision):
    container_name = "opaque-artifact-smoke-" + uuid.uuid4().hex[:12]
    try:
        output = command(smoke_command(image_id, container_name), timeout=30)
        # Store only an exact known version shape, never arbitrary program output.
        match = re.fullmatch(rb"opaque ([0-9]+\.[0-9]+\.[0-9]+)\+([0-9a-f]{7})\r?\n?", output)
        if not match or match[2].decode() != revision[:7]:
            raise ArtifactError("Isolated smoke output did not match the expected Opaque version and source revision.")
        return "opaque " + match[1].decode() + "+" + match[2].decode()
    finally:
        # A client timeout can leave its container alive. Remove only our unique
        # smoke container; never prune caches, images, volumes or other workloads.
        try:
            command(["docker", "rm", "--force", container_name], timeout=15)
        except ArtifactError:
            pass


def output_directory(requested):
    if requested is None:
        return Path(tempfile.mkdtemp(prefix="opaque-staging-artifact-"))
    output = requested.expanduser().resolve()
    if output.exists():
        raise ArtifactError("Output directory already exists; select a new directory to preserve existing evidence.")
    output.mkdir(mode=0o700, parents=True)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", help="Exact existing commit; working-tree edits are excluded")
    parser.add_argument("--output-dir", type=Path, help="New private local directory; defaults to a temporary directory")
    parser.add_argument("--prepare-only", action="store_true", help="Export committed source and build recipe without running Docker")
    args = parser.parse_args(argv)
    output = None
    report = {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
              "status": "failed", "source_repository": SOURCE_URL, "platform": PLATFORM,
              "registry_digest": None, "published": False, "ready_for_live_dispatch": False,
              "scope": "Local build consistency and fixed smoke check only; no publication, provider effect or build attestation."}
    try:
        revision = select_revision(ROOT, args.revision)
        output = output_directory(args.output_dir)
        report.update(source_revision=revision, evidence_directory=str(output))
        context, recipe_hash = prepare(ROOT, revision, output)
        tag = "opaque-staging-artifact:" + revision[:12] + "-" + uuid.uuid4().hex[:8]
        build = build_command(context, revision, tag, output)
        report.update(recipe_sha256=recipe_hash, local_tag=tag, build_command=build)
        if args.prepare_only:
            report["status"] = "prepared"
        else:
            with (output / "build.log").open("wb") as log:
                command(build, timeout=3600, log=log)
            image_id = (output / "image-id.txt").read_text().strip()
            if not IMAGE_ID.fullmatch(image_id):
                raise ArtifactError("Build did not return a valid local immutable image ID.")
            inspect_image(image_id, revision)
            version = smoke_image(image_id, revision)
            report.update(status="validated_local", local_image_id=image_id, smoke_version=version,
                          smoke_network="none", smoke_user="65532:65532")
            # Large committed build contexts are disposable. Evidence and build
            # logs remain; Docker retains the image and its existing build cache.
            try:
                shutil.rmtree(context)
                (output / "source.tar").unlink()
                report["source_cleanup"] = "complete"
            except OSError:
                # Cleanup is distinct from the already verified artifact result.
                # Retained source is committed data in the private output folder.
                report["source_cleanup"] = "incomplete"
                report["cleanup_error"] = "Some disposable source files remain in the private evidence directory."
    except (ArtifactError, OSError, tarfile.TarError, UnicodeError) as error:
        report["error"] = str(error) if isinstance(error, ArtifactError) else "Local preparation failed; no success recorded."
    if output:
        (output / "evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] in {"prepared", "validated_local"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
