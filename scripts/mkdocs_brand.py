"""Publish the explicit shared brand asset manifest, never its source directory."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from mkdocs.structure.files import File

ROOT = Path(__file__).resolve().parent.parent


def asset_paths(source: Path) -> list[str]:
    """Fail the build on missing, changed, unsafe, or symlinked brand assets."""
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or not manifest.get("assets"):
        raise ValueError("unsupported or empty brand asset manifest")
    paths: list[str] = []
    for asset in manifest["assets"]:
        name = asset["path"]
        path = PurePosixPath(name)
        if (
            not name
            or path.is_absolute()
            or name != path.as_posix()
            or ".." in path.parts
            or "\\" in name
            or path.suffix not in {".css", ".svg", ".ttf", ".txt"}
            or name in paths
        ):
            raise ValueError("invalid brand asset path")
        file = source / name
        asset_chain = [source.parent, source]
        asset_chain.extend(source.joinpath(*path.parts[:n]) for n in range(1, len(path.parts) + 1))
        if any(parent.is_symlink() for parent in asset_chain):
            raise ValueError("brand assets must not use symlinks")
        if not file.is_file() or file.stat().st_size > 4_000_000:
            raise ValueError("missing or oversized brand asset")
        if hashlib.sha256(file.read_bytes()).hexdigest() != asset["sha256"]:
            raise ValueError("brand asset differs from its manifest")
        paths.append(name)
    return paths


def on_files(files, config):
    for name in asset_paths(ROOT / "assets/brand"):
        target = f"brand/{name}"
        if files.get_file_from_path(target) is not None:
            raise ValueError("docs shadow a shared brand asset")
        files.append(File(target, str(ROOT / "assets"), config["site_dir"], False))
    return files
