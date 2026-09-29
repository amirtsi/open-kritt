"""Persist bounded PoC and impact evidence from an isolated workspace before it is removed."""

import hashlib
import json
import posixpath
import re
import shutil
from pathlib import Path
from typing import Any

from .impact_gate import declared_evidence_paths, normalize_evidence_path
from .poc_cheatcodes import cheatcode_sites, is_poc_source, relative_imports

MAX_FILES = 20
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,120}")
_SOURCE_SUFFIXES = (".sol", ".js", ".ts", ".mjs", ".cjs")
_JS_RESOLVE_SUFFIXES = ("", ".js", ".ts", ".mjs", ".cjs", "/index.js", "/index.ts")


class PocArtifactError(ValueError):
    pass


def _capture_result(
    *,
    artifact_dir: str = "",
    captured: list[str] | None = None,
    unresolved: list[str] | None = None,
    capture_complete: bool,
    reason: str = "",
    cheatcode_sites: list | None = None,
    poc_source_paths: list | None = None,
    uncaptured_poc_imports: list | None = None,
) -> dict[str, Any]:
    return {
        "artifact_dir": artifact_dir,
        "captured_paths": list(captured or []),
        "unresolved_paths": list(unresolved or []),
        "capture_complete": capture_complete,
        "reason": reason,
        "cheatcode_sites": list(cheatcode_sites or []),
        "poc_source_paths": list(poc_source_paths or []),
        "uncaptured_poc_imports": list(uncaptured_poc_imports or []),
    }


def _artifact_name(normalized: str, used: set[str]) -> str:
    parts = normalized.split("/")
    name = parts[-1]
    if not _NAME_RE.fullmatch(name):
        raise PocArtifactError("artifact file name contains unsupported characters")
    if name in used:
        name = "__".join(parts)
        if not _NAME_RE.fullmatch(name) or name in used:
            raise PocArtifactError("artifact file name collides with another artifact")
    used.add(name)
    return name


def _resolve_source(source_root: Path, normalized: str) -> Path:
    source = source_root / normalized
    if not source.is_file():
        raise PocArtifactError("artifact is missing or not a regular file")
    resolved = source.resolve(strict=True)
    if not resolved.is_relative_to(source_root):
        raise PocArtifactError("artifact escapes the isolated workspace")
    return resolved


def _workspace_file(source_root: Path, normalized: str) -> bool:
    try:
        resolved = (source_root / normalized).resolve(strict=True)
    except OSError:
        return False
    return resolved.is_file() and resolved.is_relative_to(source_root)


def _resolve_import(source_root: Path, importer: str, specifier: str) -> str | None:
    """Workspace-relative path of a relative import, or None when it escapes the workspace or is absent."""
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(importer), specifier))
    if joined.startswith("../") or joined in ("..", ".") or posixpath.isabs(joined):
        return None
    suffixes = ("",) if importer.lower().endswith(".sol") else _JS_RESOLVE_SUFFIXES
    for suffix in suffixes:
        candidate = normalize_evidence_path(joined + suffix)
        if candidate and _workspace_file(source_root, candidate):
            return candidate
    return None


def _is_poc_import(importer: str, imported: str) -> bool:
    """A PoC helper: a test/PoC source itself, or a source file in the importer's own (non-root) directory tree."""
    if is_poc_source(imported):
        return True
    tree = posixpath.dirname(importer)
    return bool(tree) and imported.lower().endswith(_SOURCE_SUFFIXES) and imported.startswith(tree + "/")


def _collect_poc_sources(
    source_root: Path, temp_dir: Path, manifest: list[dict[str, Any]]
) -> tuple[dict[str, str], list[str]]:
    """Read captured PoC sources, follow their relative imports, and name imported PoC helpers not captured."""
    captured_files = {row["source"]: row["file"] for row in manifest}
    poc_files: dict[str, str] = {}
    uncaptured: set[str] = set()
    queue = [source for source in captured_files if is_poc_source(source)]
    while queue:
        source = queue.pop(0)
        if source in poc_files:
            continue
        try:
            poc_files[source] = (temp_dir / captured_files[source]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for specifier in relative_imports(source, poc_files[source]):
            imported = _resolve_import(source_root, source, specifier)
            if imported is None or not _is_poc_import(source, imported):
                continue
            if imported in captured_files:
                queue.append(imported)
            else:
                uncaptured.add(imported)
    return poc_files, sorted(uncaptured)


def capture_evidence(
    data_dir: str,
    repo_dir: str,
    *,
    scan_id: int,
    finding_id: int,
    metadata_id: int,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Copy the declared evidence union out of the workspace; never raises, never truncates."""
    declared = declared_evidence_paths(result if isinstance(result, dict) else {})
    if not declared:
        return _capture_result(capture_complete=True)
    if len(declared) > MAX_FILES:
        return _capture_result(
            unresolved=declared,
            capture_complete=False,
            reason=f"{len(declared)} evidence paths declared; the cap is {MAX_FILES} files after deduplication",
        )
    try:
        source_root = Path(repo_dir).resolve(strict=True)
    except OSError as exc:
        return _capture_result(unresolved=declared, capture_complete=False, reason=f"workspace unavailable: {exc}")
    relative_dir = Path("poc-artifacts") / f"scan-{scan_id}" / f"finding-{finding_id}" / f"metadata-{metadata_id}"
    destination = Path(data_dir) / relative_dir
    temp_dir = destination.with_name(destination.name + ".tmp")
    captured: list[str] = []
    unresolved: list[str] = []
    reasons: list[str] = []
    manifest: list[dict[str, Any]] = []
    used_names: set[str] = set()
    total_bytes = 0
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        temp_dir.mkdir(parents=True, mode=0o700)
        for raw in declared:
            normalized = normalize_evidence_path(raw)
            try:
                if normalized is None:
                    raise PocArtifactError("artifact path is absolute or traverses the workspace")
                resolved = _resolve_source(source_root, normalized)
                size = resolved.stat().st_size
                if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
                    raise PocArtifactError("artifact exceeds the per-file or total size limit")
                name = _artifact_name(normalized, used_names)
                target = temp_dir / name
                shutil.copyfile(resolved, target)
                target.chmod(0o600)
            except (OSError, PocArtifactError) as exc:
                unresolved.append(raw)
                reasons.append(f"{raw}: {exc}")
                continue
            total_bytes += size
            captured.append(normalized)
            manifest.append(
                {
                    "source": normalized,
                    "file": name,
                    "size": size,
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                }
            )
        poc_files, uncaptured_imports = _collect_poc_sources(source_root, temp_dir, manifest)
        (temp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        if destination.exists():
            shutil.rmtree(destination)
        temp_dir.rename(destination)
    except OSError as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return _capture_result(unresolved=declared, capture_complete=False, reason=f"artifact capture failed: {exc}")
    return _capture_result(
        artifact_dir=relative_dir.as_posix(),
        captured=captured,
        unresolved=unresolved,
        capture_complete=not unresolved,
        reason="; ".join(reasons),
        cheatcode_sites=cheatcode_sites(poc_files, helpers=set(poc_files)),
        poc_source_paths=sorted(poc_files),
        uncaptured_poc_imports=uncaptured_imports,
    )
