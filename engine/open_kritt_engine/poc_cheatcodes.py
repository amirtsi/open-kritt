"""Deterministic scan of captured PoC sources for state-injection cheatcodes.

Pure functions only. Feeds rule E2 of the economic reality gate: every site found here
must be declared by D4 in ``setup_mutations``, so a model cannot hide that its PoC placed
the exploited balance or state itself.
"""

import re
from pathlib import PurePosixPath
from typing import Any

from .impact_gate import normalize_evidence_path

_SOURCE_SUFFIXES = (".sol", ".js", ".ts", ".mjs", ".cjs")
_TEST_DIRS = frozenset({"test", "tests", "poc", "pocs", "script", "exploit", "exploits"})
_SOL_PATTERNS = (
    ("deal", re.compile(r"\bvm\.deal\s*\(|(?<![\w.])deal\s*\(|(?<![\w.])(?:hoax|startHoax)\s*\(")),
    ("store", re.compile(r"\bvm\.store\s*\(")),
    ("etch", re.compile(r"\bvm\.etch\s*\(")),
    ("prank", re.compile(r"\bvm\.(?:prank|startPrank)\s*\(")),
    ("selfdestruct_fund", re.compile(r"(?<![\w.])selfdestruct\s*\(")),
    ("time", re.compile(r"\bvm\.(?:warp|roll)\s*\(")),
)
_JS_PATTERNS = (
    ("deal", re.compile(r"hardhat_setBalance|(?<![\w.])setBalance\s*\(")),
    ("store", re.compile(r"hardhat_setStorageAt|(?<![\w.])setStorageAt\s*\(")),
    ("prank", re.compile(r"hardhat_impersonateAccount|(?<![\w.])impersonateAccount\s*\(")),
    ("time", re.compile(r"evm_increaseTime|evm_mine|(?<![\w.])time\.increase\s*\(")),
)


def is_poc_source(path: str) -> bool:
    posix = PurePosixPath(path)
    if not posix.name.lower().endswith(_SOURCE_SUFFIXES):
        return False
    if posix.name.endswith(".t.sol") or ".test." in posix.name or ".spec." in posix.name:
        return True
    return any(part.lower() in _TEST_DIRS for part in posix.parts[:-1])


def _patterns(path: str):
    return _SOL_PATTERNS if path.lower().endswith(".sol") else _JS_PATTERNS


def _strip_comments(source: str) -> str:
    """Blank // and /* */ comments, keep newlines, and never treat quoted text as a comment."""
    out: list[str] = []
    i, n = 0, len(source)
    quote = ""
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if quote:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
        elif ch in "\"'`":
            quote = ch
            out.append(ch)
            i += 1
        elif ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                i += 1
        elif ch == "/" and nxt == "*":
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append("".join("\n" if c == "\n" else " " for c in source[i:end]))
            i = end
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def cheatcode_sites(files: dict[str, str]) -> list[dict[str, Any]]:
    found: set[tuple[str, str]] = set()
    for path in sorted(files):
        if not is_poc_source(path):
            continue
        for number, line in enumerate(_strip_comments(files[path]).splitlines(), start=1):
            for kind, pattern in _patterns(path):
                for match in pattern.finditer(line):
                    if line[: match.start()].rstrip().endswith("function"):
                        continue
                    found.add((f"{path}:{number}", kind))
    return [{"site": site, "kind": kind} for site, kind in sorted(found)]


def normalize_site(raw: Any) -> str | None:
    text = str(raw or "").strip()
    path, sep, line = text.rpartition(":")
    if not sep or not line.isdigit():
        return None
    normalized = normalize_evidence_path(path)
    return f"{normalized}:{int(line)}" if normalized else None
