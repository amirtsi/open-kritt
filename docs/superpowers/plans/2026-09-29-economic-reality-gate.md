# Economic Reality Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Block `submission_ready` for findings whose PoC injects the exploited state, whose attacker does not profit, whose trigger is privileged, whose root cause is already fixed/known upstream, whose precondition is absent on-chain, or whose impact is below a configured USD threshold.

**Architecture:** A new frozen readiness policy `v2.7-impact-gate-2` adds two check groups (`economic_reality`, `reality_context`) to the pure gate `evaluate_readiness`. D4 reports PoC economics, D5 reports context checks, and the engine deterministically scans captured PoC sources for cheatcode sites at capture time (I/O stays in `poc_artifacts.py`; the gate stays pure). Backend snapshots the new version and the preflight requires `materiality_min_usd` for bounty scans.

**Tech Stack:** Python 3.11 engine (pytest, Ruff), Node/Express backend (node:test), workflow-pack JSON post-scripts.

**Spec:** `docs/superpowers/specs/2026-09-29-economic-reality-gate-design.md`

## Global Constraints

- New policy identifier, exactly: `v2.7-impact-gate-2`. `v2.7-impact-gate-1` stays frozen and must evaluate exactly as before (its two new check groups always pass).
- New check group names, exactly: `economic_reality`, `reality_context` (appended to `READINESS_CHECKS`).
- New scan configuration key, exactly: `materiality_min_usd` (number > 0), required by preflight for `public_bounty` and `audit_competition` on gated workflows.
- Output-format descriptors: max depth 4, max 64 fields per format (`backend/src/lib/fieldDefinitions.js`). New D4/D5 fields are top-level (flattened) to respect this; the spec's `economic_evidence` / `reality_checks` groupings become these top-level keys: D4 `setup_mutations`, `attacker_pnl`, `victim_loss`, `privileged_calls`; D5 `upstream_fix`, `precondition_live`, `materiality`.
- Never declare engine-owned keys (`_engine_*`, `_chip_lifecycle`) in output formats.
- Conventional Commits; lint/format clean (Ruff, ESLint/Prettier).
- Redeploy single services with `docker compose up -d --build --no-deps <service>`.

## Review Focus

1. A PoC whose captured files include no test source (only production copies and logs) — expect E2 to block with "PoC source was not captured", never pass vacuously.
2. A cheatcode hidden after a string containing `//` (e.g. `"https://x"; vm.deal(a, 1);`) — expect the scanner to still report it (string-aware comment stripping).
3. Production contract copies in the capture (e.g. `src/Payments.sol` containing `selfdestruct(`) — expect them ignored; only test/PoC sources are scanned.
4. A D4 `site` written with a leading `./` or as an absolute workspace path — expect normalization to match the scanner's workspace-relative key.
5. `materiality_min_usd` missing on a gate-2 `public_bounty` scan created outside the preflight (e.g. direct API) — expect C4 to block with a reason naming the missing threshold, not to pass.

---

### Task 1: Deterministic PoC cheatcode scanner

**Files:**
- Create: `engine/open_kritt_engine/poc_cheatcodes.py`
- Create: `engine/tests/test_poc_cheatcodes.py`
- Create: `engine/tests/fixtures/poc_cheatcodes/VeloPositionManagerSweepFork.t.sol` (copy of `.data/engine/poc-artifacts/scan-28/finding-2428/metadata-*/VeloPositionManagerSweepFork.t.sol`)
- Create: `engine/tests/fixtures/poc_cheatcodes/RefundETHSweep.t.sol` (copy from `finding-2142`)
- Create: `engine/tests/fixtures/poc_cheatcodes/StakingRewardsFutureStartFork.t.sol` (copy from `finding-2166`)

**Interfaces:**
- Produces: `is_poc_source(path: str) -> bool`; `cheatcode_sites(files: dict[str, str]) -> list[dict[str, str]]` returning sorted unique `{"site": "<path>:<line>", "kind": "deal|store|etch|prank|selfdestruct_fund|time"}`; `normalize_site(raw: str) -> str | None`.

- [ ] **Step 1: Copy the real-data fixtures**

```bash
mkdir -p engine/tests/fixtures/poc_cheatcodes
cp .data/engine/poc-artifacts/scan-28/finding-2428/metadata-*/VeloPositionManagerSweepFork.t.sol engine/tests/fixtures/poc_cheatcodes/
cp .data/engine/poc-artifacts/scan-28/finding-2142/metadata-*/RefundETHSweep.t.sol engine/tests/fixtures/poc_cheatcodes/
cp .data/engine/poc-artifacts/scan-28/finding-2166/metadata-*/StakingRewardsFutureStartFork.t.sol engine/tests/fixtures/poc_cheatcodes/
```

- [ ] **Step 2: Write the failing tests**

```python
from pathlib import Path

from open_kritt_engine.poc_cheatcodes import cheatcode_sites, is_poc_source, normalize_site

FIXTURES = Path(__file__).parent / "fixtures" / "poc_cheatcodes"


def load(name, as_path):
    return {as_path: (FIXTURES / name).read_text(encoding="utf-8")}


def sites(files):
    return {(row["site"], row["kind"]) for row in cheatcode_sites(files)}


def test_is_poc_source_accepts_tests_and_rejects_production_copies():
    assert is_poc_source("test/Sweep.t.sol")
    assert is_poc_source("poc/attack/Exploit.sol")
    assert is_poc_source("tests/exploit.test.ts")
    assert not is_poc_source("src/Payments.sol")
    assert not is_poc_source("poc/attack/output.txt")


def test_real_2428_victim_prank_is_found():
    found = sites(load("VeloPositionManagerSweepFork.t.sol", "test/VeloPositionManagerSweepFork.t.sol"))
    assert ("test/VeloPositionManagerSweepFork.t.sol:107", "prank") in found
    assert ("test/VeloPositionManagerSweepFork.t.sol:131", "prank") in found


def test_real_2142_selfdestruct_and_deals_are_found_and_interface_declarations_ignored():
    found = sites(load("RefundETHSweep.t.sol", "test/RefundETHSweep.t.sol"))
    assert ("test/RefundETHSweep.t.sol:22", "selfdestruct_fund") in found
    assert ("test/RefundETHSweep.t.sol:48", "deal") in found
    assert ("test/RefundETHSweep.t.sol:52", "prank") in found
    assert not any(site.endswith(":6") for site, _ in found)  # `function deal(address, uint256) external;`


def test_real_2166_store_prank_and_warp_are_found():
    found = sites(load("StakingRewardsFutureStartFork.t.sol", "test/StakingRewardsFutureStartFork.t.sol"))
    assert ("test/StakingRewardsFutureStartFork.t.sol:96", "store") in found
    assert ("test/StakingRewardsFutureStartFork.t.sol:102", "store") in found
    assert ("test/StakingRewardsFutureStartFork.t.sol:134", "prank") in found
    assert ("test/StakingRewardsFutureStartFork.t.sol:149", "time") in found
    assert not any(site.endswith(":7") for site, _ in found)


def test_comments_are_ignored_but_code_after_a_url_string_is_not():
    source = (
        "// vm.deal(a, 1);\n"
        "/* vm.store(a, b, c);\n vm.etch(a, b); */\n"
        'string memory u = "https://x"; vm.deal(a, 1);\n'
    )
    assert sites({"test/A.t.sol": source}) == {("test/A.t.sol:4", "deal")}


def test_production_copies_are_not_scanned():
    assert cheatcode_sites({"src/Payments.sol": "function f() { selfdestruct(payable(a)); }"}) == []


def test_hardhat_helpers_are_found_in_js_tests():
    source = 'await network.provider.request({ method: "hardhat_setBalance", params: [a, "0x1"] });\n'
    source += "await impersonateAccount(owner);\n"
    assert sites({"test/exploit.test.js": source}) == {
        ("test/exploit.test.js:1", "deal"),
        ("test/exploit.test.js:2", "prank"),
    }


def test_normalize_site():
    assert normalize_site("./test/A.t.sol:12") == "test/A.t.sol:12"
    assert normalize_site("test/A.t.sol:12") == "test/A.t.sol:12"
    assert normalize_site("/abs/test/A.t.sol:12") is None
    assert normalize_site("test/A.t.sol") is None
    assert normalize_site("") is None
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd engine && python3 -m pytest tests/test_poc_cheatcodes.py -q -p no:warnings`
Expected: FAIL with `ModuleNotFoundError: No module named 'open_kritt_engine.poc_cheatcodes'`

- [ ] **Step 4: Write the implementation**

```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd engine && python3 -m pytest tests/test_poc_cheatcodes.py -q -p no:warnings && ruff check open_kritt_engine/poc_cheatcodes.py tests/test_poc_cheatcodes.py && ruff format --check open_kritt_engine/poc_cheatcodes.py tests/test_poc_cheatcodes.py`
Expected: all pass. If `normalize_evidence_path("./test/A.t.sol")` does not strip `./`, strip a leading `./` in `normalize_site` before calling it.

- [ ] **Step 6: Commit**

```bash
git add engine/open_kritt_engine/poc_cheatcodes.py engine/tests/test_poc_cheatcodes.py engine/tests/fixtures/poc_cheatcodes
git commit -m "feat(engine): scan captured PoC sources for state-injection cheatcodes"
```

### Task 2: Record cheatcode sites at evidence capture

**Files:**
- Modify: `engine/open_kritt_engine/poc_artifacts.py` (`_capture_result`, `capture_evidence`)
- Modify: `engine/open_kritt_engine/impact_gate.py` (`evidence_block`)
- Modify: `engine/open_kritt_engine/post_processing.py:1114-1121` (pass new capture fields)
- Test: `engine/tests/test_poc_artifacts.py`, `engine/tests/test_impact_gate.py`

**Interfaces:**
- Consumes: `cheatcode_sites`, `is_poc_source` (Task 1).
- Produces: capture dict keys `cheatcode_sites: list[dict]`, `poc_source_paths: list[str]`; `evidence_block(..., cheatcode_sites=None, poc_source_paths=None)` storing both keys in `_engine_evidence` (always present, lists).

- [ ] **Step 1: Write the failing tests**

Add to `engine/tests/test_poc_artifacts.py` (reuse its existing `capture` helper and workspace fixture style at lines 1-37):

```python
def test_capture_records_cheatcode_sites_of_poc_sources_only(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "test").mkdir(parents=True)
    (workspace / "src").mkdir()
    (workspace / "test" / "Attack.t.sol").write_text("contract T {\n  function t() public { vm.deal(a, 1); }\n}\n")
    (workspace / "src" / "Payments.sol").write_text("contract P { function k() public { selfdestruct(payable(a)); } }\n")
    (workspace / "out.txt").write_text("ok\n")
    result = capture_evidence(
        str(tmp_path / "data"),
        str(workspace),
        scan_id=1,
        finding_id=2,
        metadata_id=3,
        result={"poc_artifact_paths": ["test/Attack.t.sol", "src/Payments.sol", "out.txt"]},
    )
    assert result["poc_source_paths"] == ["test/Attack.t.sol"]
    assert result["cheatcode_sites"] == [{"site": "test/Attack.t.sol:2", "kind": "deal"}]


def test_capture_without_paths_has_empty_cheatcode_fields(tmp_path):
    result = capture_evidence(str(tmp_path / "d"), str(tmp_path), scan_id=1, finding_id=2, metadata_id=3, result={})
    assert result["cheatcode_sites"] == [] and result["poc_source_paths"] == []
```

Add to `engine/tests/test_impact_gate.py`:

```python
def test_evidence_block_carries_cheatcode_fields():
    block = evidence_block(
        make_d4(),
        make_manifest(),
        capture_complete=True,
        artifact_dir=ARTIFACT_DIR,
        policy_version=POLICY_VERSION,
        legacy=False,
        cheatcode_sites=[{"site": "test/A.t.sol:3", "kind": "deal"}],
        poc_source_paths=["test/A.t.sol"],
    )
    assert block["cheatcode_sites"] == [{"site": "test/A.t.sol:3", "kind": "deal"}]
    assert block["poc_source_paths"] == ["test/A.t.sol"]
    assert make_evidence()["cheatcode_sites"] == []
```

- [ ] **Step 2: Run to verify failure**

Run: `cd engine && python3 -m pytest tests/test_poc_artifacts.py tests/test_impact_gate.py -q -p no:warnings`
Expected: FAIL (`KeyError: 'poc_source_paths'`, unexpected keyword `cheatcode_sites`).

- [ ] **Step 3: Implement**

In `poc_artifacts.py`: import `from .poc_cheatcodes import cheatcode_sites, is_poc_source`; add `cheatcode_sites: list | None = None, poc_source_paths: list | None = None` params to `_capture_result` and return them as `list(... or [])`. In `capture_evidence`, after the copy loop and before the manifest write, collect sources:

```python
        poc_files: dict[str, str] = {}
        for row in manifest:
            if is_poc_source(row["source"]):
                try:
                    poc_files[row["source"]] = (temp_dir / row["file"]).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
```

and pass `cheatcode_sites=cheatcode_sites(poc_files), poc_source_paths=sorted(poc_files)` in the final successful `_capture_result(...)`.

In `impact_gate.py` `evidence_block`: add keyword params `cheatcode_sites: list | None = None, poc_source_paths: list | None = None` and set in `block`:

```python
        "cheatcode_sites": [dict(row) for row in _rows(cheatcode_sites)],
        "poc_source_paths": [path for path in _strings(poc_source_paths) if path],
```

In `post_processing.py` `evidence_block(...)` call (d4 branch), add:

```python
                cheatcode_sites=capture.get("cheatcode_sites") or [],
                poc_source_paths=capture.get("poc_source_paths") or [],
```

- [ ] **Step 4: Run tests**

Run: `cd engine && python3 -m pytest tests/ -q -p no:warnings -k "poc_artifacts or impact_gate or cheatcodes" && ruff check . && ruff format --check .`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add engine/open_kritt_engine/poc_artifacts.py engine/open_kritt_engine/impact_gate.py engine/open_kritt_engine/post_processing.py engine/tests/test_poc_artifacts.py engine/tests/test_impact_gate.py
git commit -m "feat(engine): record PoC cheatcode sites in captured evidence"
```

### Task 3: Policy `v2.7-impact-gate-2` with economic and context rules

**Files:**
- Modify: `engine/open_kritt_engine/readiness_policies.py`
- Modify: `engine/open_kritt_engine/impact_gate.py` (`READINESS_CHECKS`, new `economic_reasons`, `context_reasons`, `evaluate_readiness`)
- Test: `engine/tests/test_readiness_policies.py`, `engine/tests/test_impact_gate.py`, create `engine/tests/test_economic_gate.py`

**Interfaces:**
- Consumes: `normalize_site` (Task 1); `_engine_evidence.cheatcode_sites` / `poc_source_paths` (Task 2).
- Produces: `POLICY_VERSION = "v2.7-impact-gate-2"`, `POLICY_VERSION_GATE_1 = "v2.7-impact-gate-1"`, `ECONOMIC_POLICY_VERSIONS = frozenset({POLICY_VERSION})`, `HIGH_VALUE_KINDS = frozenset({"public_bounty", "audit_competition"})` in `readiness_policies.py`; `economic_reasons(*, d3, d4, evidence, kind) -> list[str]`; `context_reasons(*, d5, kind, threshold) -> list[str]` in `impact_gate.py`.

- [ ] **Step 1: Write the failing tests** — `engine/tests/test_economic_gate.py`

```python
import copy

from open_kritt_engine.impact_gate import evaluate_readiness, evidence_block
from open_kritt_engine.readiness_policies import POLICY_VERSION, POLICY_VERSION_GATE_1

from test_impact_gate import ARTIFACT_DIR, EVALUATED_AT, make_d3, make_d4, make_d5, make_manifest, make_scan

SITE = "test/Attack.t.sol:10"


def good_d4():
    d4 = make_d4()
    d4["setup_mutations"] = [
        {"site": SITE, "kind": "deal", "beneficiary_role": "attacker", "justification": "attacker gas and capital"}
    ]
    d4["attacker_pnl"] = {"asset": "WETH", "attacker_in": "1", "attacker_out": "101", "net_positive": True}
    d4["victim_loss"] = [
        {"party": "vault depositors", "asset": "WETH", "amount": "100", "preexisting_on_fork": True, "evidence_paths": ["balances.json"]}
    ]
    d4["privileged_calls"] = []
    return d4


def good_d5():
    d5 = make_d5()
    d5["upstream_fix"] = {"status": "none_found", "evidence": "searched all branches and team notes"}
    d5["precondition_live"] = {"status": "present_now", "evidence": "vault holds 100 WETH at block 1"}
    d5["materiality"] = {"usd_affected": 250000, "price_source": "DefiLlama", "threshold_usd": 15000, "basis": "vault WETH"}
    return d5


def scan(threshold=15000, kind="public_bounty", version=POLICY_VERSION):
    s = make_scan(kind=kind, version=version)
    if threshold is not None:
        s["configuration"]["materiality_min_usd"] = threshold
    return s


def evidence(d4, sites=({"site": SITE, "kind": "deal"},), sources=("test/Attack.t.sol",)):
    return evidence_block(
        d4, make_manifest(), capture_complete=True, artifact_dir=ARTIFACT_DIR, policy_version=POLICY_VERSION,
        legacy=False, cheatcode_sites=list(sites), poc_source_paths=list(sources),
    )


def run(d4=None, d5=None, sites=({"site": SITE, "kind": "deal"},), sources=("test/Attack.t.sol",), **scan_kw):
    d4 = d4 if d4 is not None else good_d4()
    return evaluate_readiness(
        scan=scan(**scan_kw), d3=make_d3(), d4=d4, evidence=evidence(d4, sites, sources),
        d5=d5 if d5 is not None else good_d5(), evaluated_at=EVALUATED_AT,
    )


def reasons(readiness):
    return " | ".join(readiness["blocking_reasons"])


def test_positive_control_is_submission_ready():
    r = run()
    assert r["ready"] is True, r["blocking_reasons"]
    assert r["checks"]["economic_reality"] == "pass" and r["checks"]["reality_context"] == "pass"


def test_gate_1_ignores_the_new_fields():
    r = evaluate_readiness(
        scan=make_scan(version=POLICY_VERSION_GATE_1), d3=make_d3(), d4=make_d4(),
        evidence=evidence_block(make_d4(), make_manifest(), capture_complete=True, artifact_dir=ARTIFACT_DIR,
                                policy_version=POLICY_VERSION_GATE_1, legacy=False),
        d5=make_d5(), evaluated_at=EVALUATED_AT,
    )
    assert r["ready"] is True
    assert r["checks"]["economic_reality"] == "pass" and r["checks"]["reality_context"] == "pass"


def test_missing_blocks_fail_e1_and_c1():
    r = run(d4=make_d4(), d5=make_d5())
    assert r["checks"]["economic_reality"] == "fail" and r["checks"]["reality_context"] == "fail"


def test_e2_undeclared_cheatcode_site_blocks():
    r = run(sites=({"site": SITE, "kind": "deal"}, {"site": "test/Attack.t.sol:20", "kind": "prank"}))
    assert "test/Attack.t.sol:20" in reasons(r) and r["ready"] is False


def test_e2_no_captured_poc_source_blocks():
    r = run(sites=(), sources=())
    assert "PoC source was not captured" in reasons(r)


def test_e2_accepts_dot_slash_site_spelling():
    d4 = good_d4()
    d4["setup_mutations"][0]["site"] = "./" + SITE
    assert run(d4=d4)["ready"] is True


def test_2428_victim_funds_injected_into_protocol_blocks_e3_e5_c3():
    d4 = good_d4()
    d4["setup_mutations"].append(
        {"site": "test/Attack.t.sol:107", "kind": "prank", "beneficiary_role": "protocol_contract",
         "justification": "live EOA transfers 1 WETH into VeloPositionManager"}
    )
    d4["victim_loss"] = [{"party": "EOA", "asset": "WETH", "amount": "1", "preexisting_on_fork": False, "evidence_paths": []}]
    d5 = good_d5()
    d5["precondition_live"] = {"status": "absent_now", "evidence": "manager WETH balance 0 at block 157500563"}
    r = run(d4=d4, d5=d5, sites=({"site": SITE, "kind": "deal"}, {"site": "test/Attack.t.sol:107", "kind": "prank"}))
    text = reasons(r)
    assert "protocol_contract" in text and "preexisting" in text and "absent_now" in text


def test_2142_attacker_pays_itself_blocks_e4():
    d4 = good_d4()
    d4["attacker_pnl"] = {"asset": "ETH", "attacker_in": "2", "attacker_out": "2", "net_positive": False}
    assert "net profit" in reasons(run(d4=d4))


def test_2145_dust_blocks_c4():
    d5 = good_d5()
    d5["materiality"] = {"usd_affected": 0.0000001, "price_source": "DefiLlama", "threshold_usd": 15000, "basis": "46 wei"}
    assert "materiality" in reasons(run(d5=d5)).lower()


def test_2166_owner_trigger_and_upstream_fix_block_e6_c2():
    d4 = good_d4()
    d4["privileged_calls"] = [{"site": "test/Attack.t.sol:134", "role": "owner", "function": "setReward"}]
    d5 = good_d5()
    d5["upstream_fix"] = {"status": "fixed_upstream", "evidence": "ExtraFi/extra-contracts sets lastUpdateTime = startTime"}
    text = reasons(run(d4=d4, d5=d5))
    assert "privileged" in text and "fixed_upstream" in text


def test_missing_threshold_on_bounty_scan_blocks_c4():
    assert "materiality_min_usd" in reasons(run(threshold=None))


def test_private_audit_skips_threshold_and_privilege_rules():
    d4 = good_d4()
    d4["privileged_calls"] = [{"site": SITE, "role": "owner", "function": "setFee"}]
    r = run(d4=d4, threshold=None, kind="private_audit")
    assert r["checks"]["economic_reality"] == "pass" and r["checks"]["reality_context"] == "pass"
```

In `engine/tests/test_impact_gate.py`: extend `CHECKS` with `"economic_reality", "reality_context"`; make `make_scan` default `version=POLICY_VERSION_GATE_1` (import it) so the existing gate-1 suite keeps asserting gate-1 behavior unchanged. In `engine/tests/test_readiness_policies.py:62` change to `assert POLICY_VERSION == "v2.7-impact-gate-2"` and add `assert POLICY_VERSION_GATE_1 == "v2.7-impact-gate-1"`.

- [ ] **Step 2: Run to verify failure**

Run: `cd engine && python3 -m pytest tests/test_economic_gate.py tests/test_impact_gate.py tests/test_readiness_policies.py -q -p no:warnings`
Expected: FAIL (`ImportError: cannot import name 'POLICY_VERSION_GATE_1'`).

- [ ] **Step 3: Implement policies**

In `readiness_policies.py`:

```python
POLICY_VERSION = "v2.7-impact-gate-2"
POLICY_VERSION_GATE_1 = "v2.7-impact-gate-1"
ECONOMIC_POLICY_VERSIONS = frozenset({POLICY_VERSION})
HIGH_VALUE_KINDS = frozenset({"public_bounty", "audit_competition"})
```

Rename the literal dict keys `POLICY_VERSION:` in `_POLICIES` and `_FAMILY_DIMENSIONS` to `POLICY_VERSION_GATE_1:`, then after each dict add the frozen copy for gate-2:

```python
_POLICIES[POLICY_VERSION] = dict(_POLICIES[POLICY_VERSION_GATE_1])
```

```python
_FAMILY_DIMENSIONS[POLICY_VERSION] = dict(_FAMILY_DIMENSIONS[POLICY_VERSION_GATE_1])
```

Update the 10 fixture files under `engine/tests/fixtures/impact/` only if their tests fail; they pin gate-1 explicitly and should keep passing unchanged.

- [ ] **Step 4: Implement the rules in `impact_gate.py`**

Import `ECONOMIC_POLICY_VERSIONS, HIGH_VALUE_KINDS` from `.readiness_policies` and `from .poc_cheatcodes import normalize_site` (import inside the functions if a circular import appears, since `poc_cheatcodes` imports `normalize_evidence_path` from this module). Append `"economic_reality", "reality_context"` to `READINESS_CHECKS`. Add:

```python
FUNDS_FAMILIES = frozenset({"funds_loss"})
VALUE_FAMILIES = frozenset({"funds_loss", "permanent_freezing", "temporary_freezing"})
MUTATION_ROLES = ("attacker", "victim_user", "protocol_contract", "privileged_role", "third_party", "time")
UPSTREAM_OK = "none_found"
PRECONDITION_OK = "present_now"


def economic_reasons(*, d3: dict[str, Any], d4: dict[str, Any], evidence: dict[str, Any], kind: str) -> list[str]:
    reasons: list[str] = []
    mutations = _rows(d4.get("setup_mutations"))
    pnl = _dict(d4.get("attacker_pnl"))
    losses = _rows(d4.get("victim_loss"))
    privileged = _rows(d4.get("privileged_calls"))
    if not isinstance(d4.get("setup_mutations"), list) or not pnl or not isinstance(d4.get("victim_loss"), list) \
            or not isinstance(d4.get("privileged_calls"), list):
        reasons.append("D4 did not report setup_mutations, attacker_pnl, victim_loss and privileged_calls.")
    for row in mutations:
        if row.get("beneficiary_role") not in MUTATION_ROLES:
            reasons.append(f"Setup mutation at '{_text(row.get('site'))}' has an unknown beneficiary_role.")
    # E2
    if not _strings(evidence.get("poc_source_paths")):
        reasons.append("PoC source was not captured, so its setup mutations cannot be verified.")
    declared = {normalize_site(row.get("site")) for row in mutations} - {None}
    undeclared = sorted(
        {_text(row.get("site")) for row in _rows(evidence.get("cheatcode_sites"))} - declared
    )
    if undeclared:
        reasons.append("PoC cheatcode sites are not declared in setup_mutations: " + ", ".join(undeclared) + ".")
    # E3
    injected = [_text(row.get("site")) for row in mutations if row.get("beneficiary_role") == "protocol_contract"]
    if injected:
        reasons.append(
            "The PoC placed funds or state into a protocol_contract (" + ", ".join(injected)
            + "); the exploited balance must already exist on the fork."
        )
    family = _text(d3.get("impact_family"))
    # E4
    if family in FUNDS_FAMILIES and pnl.get("net_positive") is not True:
        reasons.append("The attacker has no positive net profit (outflows do not exceed inflows, including self-funding).")
    # E5
    if family in VALUE_FAMILIES and not any(row.get("preexisting_on_fork") is True for row in losses):
        reasons.append("No victim loss is of funds preexisting on the fork; injected funds do not count.")
    # E6
    if kind in HIGH_VALUE_KINDS:
        roles = [row for row in mutations if row.get("beneficiary_role") == "privileged_role"]
        if privileged or roles:
            sites = [_text(row.get("site")) for row in [*privileged, *roles]]
            reasons.append("The attack path needs a privileged actor (" + ", ".join(sites) + ").")
    return reasons


def context_reasons(*, d5: dict[str, Any], kind: str, threshold: Any) -> list[str]:
    reasons: list[str] = []
    upstream = _dict(d5.get("upstream_fix"))
    live = _dict(d5.get("precondition_live"))
    materiality = _dict(d5.get("materiality"))
    if not upstream or not live or not materiality:
        reasons.append("D5 did not report upstream_fix, precondition_live and materiality.")
    if upstream and upstream.get("status") != UPSTREAM_OK:
        reasons.append(f"Upstream fix status is '{upstream.get('status')}': the root cause is already fixed or documented.")
    if live and live.get("status") != PRECONDITION_OK:
        reasons.append(f"Precondition status is '{live.get('status')}', not present on the live chain now.")
    if kind in HIGH_VALUE_KINDS:
        try:
            minimum = float(threshold)
        except (TypeError, ValueError):
            minimum = 0.0
        if minimum <= 0:
            reasons.append("Scan configuration has no materiality_min_usd, so materiality cannot be verified.")
        else:
            try:
                affected = float(materiality.get("usd_affected"))
            except (TypeError, ValueError):
                affected = -1.0
            if affected < minimum:
                reasons.append(f"Materiality ${affected:,.2f} is below the scan threshold ${minimum:,.2f}.")
    return reasons
```

In `evaluate_readiness`, before `ready = ...`:

```python
    # rules 10-11 (economic reality gate)
    if version in ECONOMIC_POLICY_VERSIONS:
        checks["economic_reality"].extend(economic_reasons(d3=d3, d4=d4, evidence=evidence, kind=kind))
        threshold = _dict(_dict(scan).get("configuration")).get("materiality_min_usd")
        checks["reality_context"].extend(context_reasons(d5=d5, kind=kind, threshold=threshold))
```

- [ ] **Step 5: Run the engine suite**

Run: `cd engine && python3 -m pytest tests/ -q -p no:warnings && ruff check . && ruff format --check .`
Expected: PASS. Any failure in other engine tests that pinned the old check tuple or policy string: update the expected tuple/string, never the gate-1 behavior.

- [ ] **Step 6: Commit**

```bash
git add engine/open_kritt_engine/readiness_policies.py engine/open_kritt_engine/impact_gate.py engine/tests
git commit -m "feat(engine): add v2.7-impact-gate-2 economic reality and context rules"
```

### Task 4: Backend version snapshot and preflight materiality check

**Files:**
- Modify: `backend/src/lib/v27Pipeline.js:13`
- Modify: `backend/src/lib/scanPreflight.js` (gated block, after `repeat_runs`)
- Test: `backend/test/v27Pipeline.test.js:19`, `backend/test/scanPreflight.test.js`

**Interfaces:**
- Produces: `READINESS_POLICY_VERSION === 'v2.7-impact-gate-2'`; preflight check id `materiality`.

- [ ] **Step 1: Write the failing tests**

In `backend/test/v27Pipeline.test.js:19`: `assert.equal(READINESS_POLICY_VERSION, 'v2.7-impact-gate-2');`

Add to `backend/test/scanPreflight.test.js` (the file's `input()` helper already builds a gated `public_bounty` payload):

```js
test('preflight blocks a bounty scan without materiality_min_usd', () => {
  const checks = scanPreflight(input());
  const materiality = checks.find((c) => c.id === 'materiality');
  assert.equal(materiality.level, 'block');
  assert.match(materiality.message, /materiality_min_usd/);
});

test('preflight accepts a positive materiality_min_usd', () => {
  const base = input();
  base.payload.configuration.materiality_min_usd = 15000;
  const materiality = scanPreflight(base).find((c) => c.id === 'materiality');
  assert.equal(materiality.level, 'ok');
});

test('preflight does not require materiality for private audits', () => {
  const base = input();
  base.payload.configuration.investigation_kind = 'private_audit';
  assert.equal(scanPreflight(base).find((c) => c.id === 'materiality'), undefined);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd backend && node --test test/v27Pipeline.test.js test/scanPreflight.test.js`
Expected: FAIL (version string, missing `materiality` check).

- [ ] **Step 3: Implement**

`v27Pipeline.js:13`: `export const READINESS_POLICY_VERSION = 'v2.7-impact-gate-2';`

In `scanPreflight.js`, inside `if (gated) {`, after the `repeat_runs` block:

```js
    if (HIGH_VALUE_KINDS.has(configuration.investigation_kind)) {
      const minimum = Number(configuration.materiality_min_usd);
      checks.push(
        Number.isFinite(minimum) && minimum > 0
          ? check('materiality', 'ok', `Findings below $${minimum.toLocaleString('en-US')} cannot become submission-ready.`)
          : check(
              'materiality',
              'block',
              'Set configuration.materiality_min_usd to the smallest payout worth reporting (for example the program minimum for Critical). The readiness gate blocks dust and injected-fund findings against it.'
            )
      );
    }
```

If any existing preflight test asserts that no check is `block` for the default `input()`, add `materiality_min_usd: 15000` to `input()`'s configuration and keep the new "blocks without" test by deleting the key in that test.

- [ ] **Step 4: Run backend checks**

Run: `cd backend && npm test && npm run lint && npm run format:check`
Expected: PASS. Update other backend tests that assert the literal `'v2.7-impact-gate-1'` only where they read `READINESS_POLICY_VERSION` for new scans; fixtures describing stored gate-1 results stay as they are.

- [ ] **Step 5: Commit**

```bash
git add backend/src/lib/v27Pipeline.js backend/src/lib/scanPreflight.js backend/test
git commit -m "feat(backend): snapshot v2.7-impact-gate-2 and require materiality for bounty scans"
```

### Task 5: D3/D4/D5 post-script prompts and output formats

**Files:**
- Modify: `workflow-packs/web3-v2.7/post-scripts/d3-hostile-verification.post-script.json` (`content`)
- Modify: `workflow-packs/web3-v2.7/post-scripts/d4-local-poc.post-script.json` (`content`, `outputFormat`)
- Modify: `workflow-packs/web3-v2.7/post-scripts/d5-report-readiness.post-script.json` (`content`, `outputFormat`)
- Test: `scripts/web3-v2.7-workflow.test.mjs`

**Interfaces:**
- Produces: D4 output keys `setup_mutations`, `attacker_pnl`, `victim_loss`, `privileged_calls`; D5 output keys `upstream_fix`, `precondition_live`, `materiality` — exactly the shapes Task 3 reads.

- [ ] **Step 1: Write the failing tests** — append to `scripts/web3-v2.7-workflow.test.mjs`

```js
test('v2.7 D4 reports PoC economics for the economic reality gate', async () => {
  const { 'd4-local-poc.post-script.json': d4 } = await loadPostScripts();
  const f = d4.outputFormat;
  assert.deepEqual(Object.keys(f.setup_mutations.items.fields).sort(), ['beneficiary_role', 'justification', 'kind', 'site']);
  assert.deepEqual(f.setup_mutations.items.fields.beneficiary_role.enum, [
    'attacker', 'victim_user', 'protocol_contract', 'privileged_role', 'third_party', 'time',
  ]);
  assert.deepEqual(Object.keys(f.attacker_pnl.fields).sort(), ['asset', 'attacker_in', 'attacker_out', 'net_positive']);
  assert.equal(f.victim_loss.items.fields.preexisting_on_fork, 'boolean');
  assert.deepEqual(Object.keys(f.privileged_calls.items.fields).sort(), ['function', 'role', 'site']);
  for (const rule of [/every cheatcode/i, /preexisting_on_fork/, /protocol_contract/, /live deployment/i]) {
    assert.match(d4.content, rule);
  }
});

test('v2.7 D5 reports reality checks for the economic reality gate', async () => {
  const { 'd5-report-readiness.post-script.json': d5 } = await loadPostScripts();
  const f = d5.outputFormat;
  assert.deepEqual(f.upstream_fix.fields.status.enum, ['none_found', 'fixed_upstream', 'documented_known']);
  assert.deepEqual(f.precondition_live.fields.status.enum, ['present_now', 'absent_now', 'unknown']);
  assert.equal(f.materiality.fields.usd_affected, 'number');
  for (const rule of [/all branches/i, /usd_affected/, /preexisting_on_fork: true/]) assert.match(d5.content, rule);
});

test('v2.7 D3 asks the live-state and privileged-trigger questions', async () => {
  const { 'd3-hostile-verification.post-script.json': d3 } = await loadPostScripts();
  assert.match(d3.content, /present on the live chain now/i);
  assert.match(d3.content, /privileged role/i);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test scripts/web3-v2.7-workflow.test.mjs`
Expected: FAIL (`Cannot read properties of undefined (reading 'items')`).

- [ ] **Step 3: Edit the JSON files with a script** (keeps formatting and avoids hand-escaping)

```bash
node --input-type=module - <<'EOF'
import { readFileSync, writeFileSync } from 'node:fs';
const dir = 'workflow-packs/web3-v2.7/post-scripts/';
const edit = (name, fn) => {
  const path = dir + name;
  const data = JSON.parse(readFileSync(path, 'utf8'));
  fn(data);
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
};
const roles = ['attacker', 'victim_user', 'protocol_contract', 'privileged_role', 'third_party', 'time'];
edit('d4-local-poc.post-script.json', (d) => {
  Object.assign(d.outputFormat, {
    setup_mutations: { type: 'array', items: { type: 'object', fields: {
      site: 'string',
      kind: { type: 'string', enum: ['deal', 'store', 'etch', 'prank', 'selfdestruct_fund', 'time', 'other'] },
      beneficiary_role: { type: 'string', enum: roles },
      justification: 'string',
    }, required: ['site', 'kind', 'beneficiary_role', 'justification'] } },
    attacker_pnl: { type: 'object', fields: {
      asset: 'string', attacker_in: 'string', attacker_out: 'string', net_positive: 'boolean',
    }, required: ['asset', 'attacker_in', 'attacker_out', 'net_positive'] },
    victim_loss: { type: 'array', items: { type: 'object', fields: {
      party: 'string', asset: 'string', amount: 'string', preexisting_on_fork: 'boolean',
      evidence_paths: { type: 'array', items: 'string' },
    }, required: ['party', 'asset', 'amount', 'preexisting_on_fork', 'evidence_paths'] } },
    privileged_calls: { type: 'array', items: { type: 'object', fields: {
      site: 'string', role: 'string', function: 'string',
    }, required: ['site', 'role', 'function'] } },
  });
  d.content += '\nEconomic evidence (the readiness gate enforces it). When the scan configuration names a deployed address, build the PoC against that live deployment on a local fork; never self-deploy a copy of a contract that is already deployed. List every cheatcode or state-injection call site in the PoC source (deal, hoax, vm.store, vm.etch, vm.prank/startPrank, selfdestruct funding, vm.warp/roll, hardhat_setBalance/setStorageAt/impersonateAccount) in setup_mutations as relative/path:line with its kind and beneficiary_role; the engine scans the captured PoC source and blocks any undeclared site. Pranking any identity other than the attacker is a mutation: a real user acting normally is victim_user, an owner/admin/keeper is privileged_role. Funds or state the PoC places into an in-scope contract are protocol_contract. In attacker_pnl compare everything the attacker put in (including self-funded forced transfers) with everything it took out; net_positive is true only when it took out more. In victim_loss set preexisting_on_fork true only when that party held the lost funds at the fork block before any setup mutation; funds the PoC gave a victim may demonstrate the mechanism but are never preexisting. List every call in the attack path that requires a privileged role in privileged_calls.\n';
});
edit('d5-report-readiness.post-script.json', (d) => {
  Object.assign(d.outputFormat, {
    upstream_fix: { type: 'object', fields: {
      status: { type: 'string', enum: ['none_found', 'fixed_upstream', 'documented_known'] }, evidence: 'string',
    }, required: ['status', 'evidence'] },
    precondition_live: { type: 'object', fields: {
      status: { type: 'string', enum: ['present_now', 'absent_now', 'unknown'] }, evidence: 'string',
    }, required: ['status', 'evidence'] },
    materiality: { type: 'object', fields: {
      usd_affected: 'number', price_source: 'string', threshold_usd: 'number', basis: 'string',
    }, required: ['usd_affected', 'price_source', 'threshold_usd', 'basis'] },
  });
  d.content += '\nReality checks (the readiness gate enforces them). upstream_fix: search the target\'s public repository on all branches, its commit history, team notes about known or fixed bugs, and the program\'s published known-issues list for a fix or description of the same root cause; report fixed_upstream or documented_known with the exact location, else none_found with what you searched. precondition_live: read the live chain (or the pinned fork state before any setup mutation) and report whether the balance or state the attack exploits is present now, citing address, call, block and value. materiality: price only the D4 victim_loss entries with preexisting_on_fork: true at live prices, name the price source, and copy the scan configuration materiality_min_usd into threshold_usd. submission_ready must be false whenever upstream_fix is not none_found, precondition_live is not present_now, usd_affected is below threshold_usd, or D4 shows injected, self-funded or privileged preconditions.\n';
});
edit('d3-hostile-verification.post-script.json', (d) => {
  d.content += '\nBefore keeping a candidate, also try to disprove it with two live-reality questions: is the balance or state it exploits present on the live chain now (not only if someone later sends funds or configures it)? Does its trigger require a privileged role (owner, admin, keeper, multisig)? Record the answers as unverified_assumptions with material true when they are open, and use privileged_only when the trigger needs a privileged role.\n';
});
EOF
```

- [ ] **Step 4: Run workflow and descriptor checks**

Run: `node --test scripts/web3-v2.7-workflow.test.mjs scripts/web3-v2.8-workflow.test.mjs scripts/web3-v2.8-staking-workflow.test.mjs && npx prettier --check workflow-packs/web3-v2.7/post-scripts/*.json`
Expected: PASS. The existing test "v2.7 post-scripts keep their names and validate" runs the backend descriptor validator: if D4 exceeds 64 fields, drop `justification` from `setup_mutations` (and from the test's expected key list and the `required` list).

- [ ] **Step 5: Commit**

```bash
git add workflow-packs/web3-v2.7/post-scripts scripts/web3-v2.7-workflow.test.mjs
git commit -m "feat(workflows): report PoC economics and live reality checks in v2.7 D3-D5"
```

### Task 6: Deploy and import

**Files:** none changed (operations). `local/integration` is the branch the running stack is built from.

- [ ] **Step 1: Full local checks**

Run: `cd engine && python3 -m pytest tests/ -q -p no:warnings && ruff check . && ruff format --check . && cd ../backend && npm test && npm run lint && npm run format:check && cd .. && node --test scripts/web3-v2.7-workflow.test.mjs`
Expected: PASS.

- [ ] **Step 2: Merge into the running integration branch**

```bash
git switch local/integration && git merge --no-ff feat/economic-reality-gate -m "Merge branch 'feat/economic-reality-gate' into local/integration"
```

- [ ] **Step 3: Rebuild engine and backend without touching the database**

```bash
docker compose up -d --build --no-deps engine backend
```

- [ ] **Step 4: Import the three rewritten post-scripts** (new IDs; `resolveV27Pipeline` picks the newest per name)

```bash
./kritt-headless import post-script ./workflow-packs/web3-v2.7/post-scripts/d3-hostile-verification.post-script.json
./kritt-headless import post-script ./workflow-packs/web3-v2.7/post-scripts/d4-local-poc.post-script.json
./kritt-headless import post-script ./workflow-packs/web3-v2.7/post-scripts/d5-report-readiness.post-script.json
```

If `kritt-headless` has no `post-script` import command, use the same HTTP call the UI uses: `POST /api/post-scripts` with `{name, description, content, outputFormat}` from each file.

- [ ] **Step 5: Smoke check**

Run a preflight for the Extra Finance payload without and with `materiality_min_usd` (`python3 scratch/extra-finance/launch.py` after adding `"materiality_min_usd": 15000` to `scratch/extra-finance/configuration.json`) and confirm: without it the `materiality` check is `BLOCK`; with it `OK`. Confirm `GET /api/post-scripts` lists the three new IDs.
