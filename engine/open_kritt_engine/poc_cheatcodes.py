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
# Cheatcode methods reachable through any handle name (vm, hevm, cheats, ...).
_HANDLE_METHOD_KINDS = {
    "deal": "deal",
    "store": "store",
    "mockCall": "store",
    "mockCallRevert": "store",
    "etch": "etch",
    "prank": "prank",
    "startPrank": "prank",
    "warp": "time",
    "roll": "time",
}
_HANDLE_CALL = re.compile(r"\b\w+\.(" + "|".join(sorted(_HANDLE_METHOD_KINDS, key=len, reverse=True)) + r")\s*\(")
# RPC method names that a Foundry test (vm.rpc) or a JS test can send to a local node.
_RPC_PATTERNS = (
    ("deal", re.compile(r"\b(?:hardhat|anvil)_setBalance\b")),
    ("store", re.compile(r"\b(?:hardhat|anvil)_setStorageAt\b")),
    ("prank", re.compile(r"\b(?:hardhat|anvil)_impersonateAccount\b")),
    ("etch", re.compile(r"\b(?:hardhat|anvil)_setCode\b")),
    ("time", re.compile(r"\bevm_increaseTime\b|\bevm_mine\b")),
)
_SOL_PATTERNS = (
    ("deal", re.compile(r"(?<![\w.])(?:deal|hoax|startHoax)\s*\(")),
    ("store", re.compile(r"\bchecked_write\w*\s*\(")),
    ("prank", re.compile(r"(?<![\w])changePrank\s*\(")),
    ("selfdestruct_fund", re.compile(r"(?<![\w.])selfdestruct\s*\(")),
    *_RPC_PATTERNS,
)
_JS_PATTERNS = (
    ("deal", re.compile(r"(?<![\w.])setBalance\s*\(")),
    ("store", re.compile(r"(?<![\w.])setStorageAt\s*\(")),
    ("prank", re.compile(r"(?<![\w.])impersonateAccount\s*\(")),
    ("etch", re.compile(r"(?<![\w])setCode\s*\(")),
    ("time", re.compile(r"(?<![\w.])time\.increase\s*\(")),
    *_RPC_PATTERNS,
)
_REGEX_PRECEDERS = frozenset("(,=:[!&|?{};+-*%<>~^")
_SOL_IMPORT = re.compile(
    r"\bimport\b\s*(?:[^;'\"]{0,500}?\bfrom\s*)?[\"']([^\"'\n]{1,500})[\"']",
)
_JS_IMPORT = re.compile(
    r"\bimport\b\s*(?:[^;'\"`()]{0,500}?\bfrom\s*)?[\"']([^\"'\n]{1,500})[\"']"
    r"|\b(?:import|require)\s*\(\s*[\"']([^\"'\n]{1,500})[\"']\s*\)",
)


def is_poc_source(path: str) -> bool:
    posix = PurePosixPath(path)
    if not posix.name.lower().endswith(_SOURCE_SUFFIXES):
        return False
    if posix.name.endswith(".t.sol") or ".test." in posix.name or ".spec." in posix.name:
        return True
    return any(part.lower() in _TEST_DIRS for part in posix.parts[:-1])


def _is_solidity(path: str) -> bool:
    return path.lower().endswith(".sol")


def _patterns(path: str):
    return _SOL_PATTERNS if _is_solidity(path) else _JS_PATTERNS


def _regex_literal_end(source: str, start: int) -> int:
    """Index just past a JS regex literal opening at ``start``, or -1 when it does not close on this line."""
    i, n = start + 1, len(source)
    in_class = False
    while i < n and source[i] != "\n":
        ch = source[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            return i + 1
        i += 1
    return -1


def _strip_comments(source: str, *, js: bool = False) -> str:
    """Blank // and /* */ comments, keep newlines, and never treat quoted text as a comment.

    With ``js`` a ``/`` that follows an operator or opening bracket starts a regex literal, which is
    copied verbatim so a quote inside it does not open a string.
    """
    out: list[str] = []
    i, n = 0, len(source)
    quote = ""
    previous = ""  # last non-space character emitted outside strings and comments
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
                previous = ch
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
        elif js and ch == "/" and (not previous or previous in _REGEX_PRECEDERS):
            end = _regex_literal_end(source, i)
            if end == -1:
                out.append(ch)
                i += 1
            else:
                out.append(source[i:end])
                i = end
            previous = "/"
        else:
            out.append(ch)
            if not ch.isspace():
                previous = ch
            i += 1
    return "".join(out)


def _code_lines(path: str, source: str) -> list[str]:
    # split("\n"), not splitlines(): editors and compilers number lines by \n only, while
    # splitlines() also breaks on \f, \v, \x1c-\x1e, \x85 and U+2028/2029.
    return _strip_comments(source, js=not _is_solidity(path)).split("\n")


def cheatcode_sites(files: dict[str, str], *, helpers: frozenset[str] | set[str] = frozenset()) -> list[dict[str, Any]]:
    """Cheatcode sites of the PoC sources in ``files``; ``helpers`` names PoC-imported files to scan as well."""
    found: set[tuple[str, str]] = set()
    for path in sorted(files):
        if not is_poc_source(path) and path not in helpers:
            continue
        solidity = _is_solidity(path)
        for number, line in enumerate(_code_lines(path, files[path]), start=1):
            matches = [(kind, match) for kind, pattern in _patterns(path) for match in pattern.finditer(line)]
            if solidity:
                matches.extend((_HANDLE_METHOD_KINDS[m.group(1)], m) for m in _HANDLE_CALL.finditer(line))
            for kind, match in matches:
                if line[: match.start()].rstrip().endswith("function"):
                    continue
                found.add((f"{path}:{number}", kind))
    return [{"site": site, "kind": kind} for site, kind in sorted(found)]


def relative_imports(path: str, source: str) -> list[str]:
    """Relative (./ or ../) import specifiers of a Solidity or JS/TS source; package imports are ignored."""
    pattern = _SOL_IMPORT if _is_solidity(path) else _JS_IMPORT
    code = _strip_comments(source, js=not _is_solidity(path))
    specifiers: list[str] = []
    for match in pattern.finditer(code):
        spec = next((group for group in match.groups() if group), "")
        if spec.startswith(("./", "../")) and spec not in specifiers:
            specifiers.append(spec)
    return specifiers


def normalize_site(raw: Any) -> str | None:
    """Canonical ``path:line``; a trailing ``:col`` (``path:line:col``) is accepted and dropped."""
    text = str(raw or "").strip()
    head, sep, last = text.rpartition(":")
    if sep and last.isdigit():
        path, sep2, line = head.rpartition(":")
        if sep2 and line.isdigit() and path:
            text = f"{path}:{line}"
    path, sep, line = text.rpartition(":")
    if not sep or not line.isdigit():
        return None
    normalized = normalize_evidence_path(path)
    return f"{normalized}:{int(line)}" if normalized else None
