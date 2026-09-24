"""Persist bounded PoC evidence from an isolated workspace before it is removed."""

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

MAX_FILES = 12
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024


class PocArtifactError(ValueError):
    pass


def persist_poc_artifacts(
    data_dir: str,
    repo_dir: str,
    *,
    scan_id: int,
    finding_id: int,
    metadata_id: int,
    result: dict[str, Any],
) -> str:
    raw_paths = result.get("poc_artifact_paths")
    if not isinstance(raw_paths, list) or not 4 <= len(raw_paths) <= MAX_FILES:
        raise PocArtifactError(
            "PoC requires 4-12 artifact paths: harness, attack, negative control, and repeat evidence"
        )
    source_root = Path(repo_dir).resolve(strict=True)
    relative_dir = Path("poc-artifacts") / f"scan-{scan_id}" / f"finding-{finding_id}" / f"metadata-{metadata_id}"
    destination = Path(data_dir) / relative_dir
    temp_dir = destination.with_name(destination.name + ".tmp")
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True, mode=0o700)
    total_bytes = 0
    manifest = []
    seen = set()
    try:
        for raw in raw_paths:
            if not isinstance(raw, str) or not raw.strip():
                raise PocArtifactError("artifact paths must be non-empty relative strings")
            path = Path(raw)
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.name in seen
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", path.name)
            ):
                raise PocArtifactError("artifact path is absolute, traverses the workspace, or duplicates a filename")
            seen.add(path.name)
            source = source_root / path
            if source.is_symlink() or not source.is_file():
                raise PocArtifactError(f"artifact is missing or not a regular file: {raw}")
            resolved = source.resolve(strict=True)
            if not resolved.is_relative_to(source_root):
                raise PocArtifactError("artifact escapes the isolated workspace")
            size = resolved.stat().st_size
            total_bytes += size
            if size > MAX_FILE_BYTES or total_bytes > MAX_TOTAL_BYTES:
                raise PocArtifactError("PoC artifacts exceed the per-file or total size limit")
            target = temp_dir / path.name
            shutil.copyfile(resolved, target)
            target.chmod(0o600)
            manifest.append(
                {
                    "source": raw,
                    "file": path.name,
                    "size": size,
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                }
            )
        (temp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        if destination.exists():
            shutil.rmtree(destination)
        temp_dir.rename(destination)
        return relative_dir.as_posix()
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def finalize_poc_result(
    data_dir: str,
    repo_dir: str,
    *,
    scan_id: int,
    finding_id: int,
    metadata_id: int,
    result: dict[str, Any],
) -> dict[str, Any]:
    result["poc_artifact_dir"] = ""
    if result.get("poc_status") != "reproduced":
        return result
    if int(result.get("repeat_count") or 0) < 2 or not str(result.get("negative_control_observed") or "").strip():
        reason = "Reproduction lacks repeated attack and negative-control evidence"
    else:
        try:
            result["poc_artifact_dir"] = persist_poc_artifacts(
                data_dir,
                repo_dir,
                scan_id=scan_id,
                finding_id=finding_id,
                metadata_id=metadata_id,
                result=result,
            )
            return result
        except (OSError, PocArtifactError, ValueError) as exc:
            reason = str(exc)
    result["poc_status"] = "insufficient_evidence"
    result["remaining_limits"] = (str(result.get("remaining_limits") or "") + "\n" + reason).strip()
    result["_reserved_poc"] = "PoC claimed by the model but local evidence could not be retained: " + reason
    return result
