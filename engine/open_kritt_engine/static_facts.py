"""Deterministic facts about a target, computed without a model.

For Solidity repositories this indexes every external or public state-changing
function with its modifiers and any caller check at the top of its body, so
investigators can start from the permissionless surface instead of rediscovering
access control file by file. The index is a hint: agents still verify guards.
"""

import json
import os
import re
from pathlib import Path
from typing import Any

from .known_issues import ENGINE_WORKSPACE_DIR

STATIC_DIR = f"{ENGINE_WORKSPACE_DIR}/static-analysis"
SKIP_DIRS = frozenset(
    {
        ".git",
        ENGINE_WORKSPACE_DIR,
        "lib",
        "node_modules",
        "out",
        "cache",
        "build",
        "artifacts",
        "test",
        "tests",
        "script",
        "scripts",
        "mocks",
        "mock",
    }
)
MAX_FILES = 2000
MAX_FILE_BYTES = 2 * 1024 * 1024

HEADER_KEYWORDS = frozenset(
    {
        "external",
        "public",
        "internal",
        "private",
        "payable",
        "view",
        "pure",
        "virtual",
        "override",
        "returns",
        "memory",
        "calldata",
        "storage",
    }
)
GUARD_MODIFIER = re.compile(
    r"^(only|auth|restricted|requires?Role|whenAuthorized)|admin|owner|role|governance|keeper|operator", re.IGNORECASE
)
BODY_GUARD = re.compile(
    r"(msg\.sender|_msgSender\(\))\s*[!=]=|[!=]=\s*(msg\.sender|_msgSender\(\))"
    r"|\b(require|if)\s*\([^;]*\b(msg\.sender|_msgSender\(\))"
    r"|\bhasRole\s*\(|\b_checkRole\s*\(|\b_checkOwner\s*\("
    r"|\b_{1,2}(validate|check|assert|only|is|require)\w*(Sender|Caller|Admin|Owner|Role|Authorized)\w*\s*\("
)
CONTRACT = re.compile(r"\b(abstract\s+contract|contract|library|interface)\s+(\w+)")
FUNCTION = re.compile(r"\bfunction\s+(\w+)\s*\(|\b(receive|fallback)\s*\(")
BODY_GUARD_LINES = 15


def _strip_comments(source: str) -> str:
    def blank(match: re.Match) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return re.sub(r"/\*.*?\*/|//[^\n]*", blank, source, flags=re.DOTALL)


def _matching(text: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == opening:
            depth += 1
        elif text[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _header_modifiers(header: str) -> list[str]:
    cleaned = re.sub(r"\b(returns|override)\s*\(", lambda m: m.group(0)[:-1] + "\x00(", header)
    names: list[str] = []
    index = 0
    while index < len(cleaned):
        match = re.compile(r"\x00?\(|\b[A-Za-z_]\w*").search(cleaned, index)
        if not match:
            break
        token = match.group(0)
        if token.endswith("("):
            end = _matching(cleaned, match.end() - 1, "(", ")")
            index = end + 1 if end >= 0 else len(cleaned)
            continue
        if token not in HEADER_KEYWORDS:
            names.append(token)
        index = match.end()
    return names


def _functions(relative: str, source: str) -> list[dict[str, Any]]:
    text = _strip_comments(source)
    contracts = [(match.start(), match.group(1).split()[-1], match.group(2)) for match in CONTRACT.finditer(text)]
    entries: list[dict[str, Any]] = []
    for match in FUNCTION.finditer(text):
        name = match.group(1) or match.group(2)
        owner = next((item for item in reversed(contracts) if item[0] < match.start()), None)
        if owner is None or owner[1] == "interface":
            continue
        params_end = _matching(text, match.end() - 1, "(", ")")
        if params_end < 0:
            continue
        body_start = min(
            (pos for pos in (text.find("{", params_end), text.find(";", params_end)) if pos >= 0), default=-1
        )
        if body_start < 0 or text[body_start] == ";":
            continue
        header = text[params_end + 1 : body_start]
        words = set(re.findall(r"\b\w+\b", re.sub(r"\((?:[^()]|\([^()]*\))*\)", " ", header)))
        visibility = "external" if "external" in words else "public" if "public" in words else None
        if visibility is None or words & {"view", "pure"}:
            continue
        modifiers = _header_modifiers(header)
        body_end = _matching(text, body_start, "{", "}")
        body_head = "\n".join(
            text[body_start : body_end if body_end > 0 else len(text)].splitlines()[:BODY_GUARD_LINES]
        )
        if any(GUARD_MODIFIER.search(modifier) for modifier in modifiers):
            guard = "modifier"
        elif BODY_GUARD.search(body_head):
            guard = "body_sender_check"
        else:
            guard = "none"
        entries.append(
            {
                "file": relative,
                "line": text.count("\n", 0, match.start()) + 1,
                "contract": owner[2],
                "function": name,
                "visibility": visibility,
                "payable": "payable" in words,
                "modifiers": modifiers,
                "guard": guard,
            }
        )
    return entries


def solidity_access_index(source_root: Path) -> list[dict[str, Any]]:
    root = Path(source_root)
    entries: list[dict[str, Any]] = []
    seen = 0
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = sorted(name for name in subdirs if name not in SKIP_DIRS)
        for name in sorted(names):
            if not name.endswith(".sol") or name.endswith((".t.sol", ".s.sol")):
                continue
            path = Path(directory) / name
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            seen += 1
            if seen > MAX_FILES:
                return entries
            entries.extend(
                _functions(path.relative_to(root).as_posix(), path.read_text(encoding="utf-8", errors="replace"))
            )
    return entries


def _line(entry: dict[str, Any]) -> str:
    modifiers = ", ".join(entry["modifiers"]) or "none"
    payable = "; payable" if entry["payable"] else ""
    return (
        f"- {entry['file']}:{entry['line']} {entry['contract']}.{entry['function']} "
        f"({entry['visibility']}{payable}; modifiers: {modifiers}; guard: {entry['guard']})"
    )


def build_static_facts(source_root: Path, target_root: Path) -> dict[str, Any] | None:
    entries = solidity_access_index(source_root)
    if not entries:
        return None
    unguarded = [entry for entry in entries if entry["guard"] == "none"]
    guarded = [entry for entry in entries if entry["guard"] != "none"]
    directory = Path(target_root) / STATIC_DIR
    directory.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Deterministic access index",
        "",
        f"{len(entries)} external/public state-changing Solidity functions; {len(unguarded)} have no caller guard.",
        "Computed from source text without a compiler: treat guards as hints and verify them in code.",
        "",
        "## Unguarded state-changing entrypoints",
        *[_line(entry) for entry in unguarded],
        "",
        "## Guarded by a modifier or a caller check",
        *[_line(entry) for entry in guarded],
    ]
    (directory / "ACCESS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (directory / "access-index.json").write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return {"path": f"{STATIC_DIR}/ACCESS.md", "entrypoints": len(entries), "unguarded": len(unguarded)}
