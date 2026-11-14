# Economic Reality Gate (`v2.7-impact-gate-2`) — Design

Status: design for review, 2026-09-29. Implementation plan follows in a separate document.

## 1. Problem

Two bounty campaigns failed at triage even though the pipeline marked findings ready:

- SSV Network (scan 27): both reports closed. 1854 was already hot-fixed on-chain; 1855 was on
  the program's own known-issues list. Both PoCs self-deployed contracts instead of exercising
  the live proxy.
- Extra Finance (scan 28): 9 findings survived D3, D5 marked three `submission_ready`
  (2428 Critical, 2166 High, 2145 High), and a manual hostile review rejected all seven
  High/Critical findings.

The v2.7 gate (`v2.7-impact-gate-1`) answers "did the bug happen?" and "did the
claimed impact happen?". It never asks whether the impact happens **now, on the real
chain, without the PoC's help, for an amount worth reporting**. Every scan-28 rejection
lives in that gap:

| Finding | What the PoC did | Why it is not a bounty |
| --- | --- | --- |
| 2428 | `vm.prank(VICTIM)` moved 1 WETH from a live EOA into VeloPositionManager, then swept it | Live manager WETH balance is 0; the "victim" funds were placed by the PoC |
| 2106 | A vm-funded account transferred 1 WETH into LendingPool, then swept it | Live LendingPool WETH balance is 0 |
| 2142 | `selfdestruct` forced 1 ETH into LendingPool, then a deposit refund swept it | Live balance is 0 and the forced ETH is the attacker's own money: net profit 0 |
| 2145 | Two dealt accounts, 30-day warp, double rounding | Loss is 46 wei (dust) |
| 2105, 2615, 2115 | Treasury-fee rounding | Dust, and protocol fee, not user funds |
| 2166 | Owner impersonated via `vm.store` + `startPrank`, funded reward program | Owner-triggered, fixed in the public repo (`lastUpdateTime = startTime`, documented in `BUG_FIXES_AND_MODIFICATIONS.md`), no reward program active since 2026-01 |

The saved scan-28 PoCs (`.data/engine/poc-artifacts/scan-28/`) confirm the pattern: every
rejected finding uses `deal`, `vm.store`, `selfdestruct`, or `vm.prank` of a non-attacker
identity to create the state it then exploits.

## 2. Decisions already made

| Decision | Choice |
| --- | --- |
| Enforcement | Blocking, in the engine gate (option A). Advisory-only reporting is what failed. |
| Profile | Evolve v2.7 in place with a new frozen policy version `v2.7-impact-gate-2`. Scans created before the change keep `v2.7-impact-gate-1`. |
| Data source | D4 reports what the PoC did; D5 reports context checks; the engine cross-checks D4 against the saved PoC source deterministically. |
| Scope | This spec is sub-project 1. Deterministic static analysis (Slither auto-run, CodeQL for supported languages) and target-preparation tooling (target scorecard, live-source fetch + drift check, program known-issues capture) are separate follow-up specs. |

## 3. New structured fields

### 3.1 D4 `economic_evidence` (object, required for gated scans)

```json
{
  "setup_mutations": [
    {
      "site": "test/Sweep.t.sol:107",
      "kind": "prank | deal | store | etch | selfdestruct_fund | warp | roll | other",
      "target": "0x... or label",
      "beneficiary_role": "attacker | victim_user | protocol_contract | privileged_role | third_party | time",
      "justification": "string"
    }
  ],
  "attacker_pnl": {
    "asset": "symbol/address",
    "attacker_in": "decimal string, token units",
    "attacker_out": "decimal string, token units",
    "net_positive": true
  },
  "victim_loss": [
    {
      "party": "address or role",
      "asset": "symbol/address",
      "amount": "decimal string, token units",
      "preexisting_on_fork": true,
      "evidence_paths": ["artifacts/..."]
    }
  ],
  "privileged_calls": [
    { "site": "file:line", "role": "owner | admin | keeper | multisig | other", "function": "setReward" }
  ]
}
```

Rules D4 is instructed to follow:

- Every cheatcode call site in the PoC appears in `setup_mutations` with its role.
- `vm.prank`/`startPrank` as any identity other than the attacker is a mutation: a
  real user acting normally is `victim_user`; the owner/admin is `privileged_role`.
- `preexisting_on_fork` is true only when the lost funds were held by that party at the
  fork block **before any setup mutation**. Funds a PoC gives a victim may demonstrate
  the mechanism but never count as preexisting.
- `net_positive` compares attacker outflows to inflows **including** the attacker's own
  forced transfers (selfdestruct, donations).

### 3.2 D5 `reality_checks` (object, required for gated scans)

```json
{
  "upstream_fix": {
    "status": "none_found | fixed_upstream | documented_known",
    "evidence": "repo/branch/commit/doc checked and what was found"
  },
  "precondition_live": {
    "status": "present_now | absent_now | unknown",
    "evidence": "live chain reads (address, call, block, value)"
  },
  "materiality": {
    "usd_affected": 0,
    "price_source": "string",
    "threshold_usd": 0,
    "basis": "which preexisting victim_loss entries were priced"
  }
}
```

D5 must search the target's public repository **all branches**, team notes (e.g.
`BUG_FIXES_AND_MODIFICATIONS.md`), and the program known-issues list for a fix or
description of the same root cause. `usd_affected` prices only `victim_loss` entries with
`preexisting_on_fork: true`.

### 3.3 Scan configuration

- `materiality_min_usd` (number). Required when `investigation_kind` is `public_bounty` or
  `audit_competition`; the preflight check blocks without it. Guidance: the program's
  minimum payout for the lowest severity you would submit (Extra Finance: $15,000 Critical
  minimum).

## 4. Gate rules (`v2.7-impact-gate-2`)

Two new check groups in `evaluate_readiness`. Every failed rule adds a blocking reason.

### 4.1 `economic_reality`

| # | Rule | Blocks |
| --- | --- | --- |
| E1 | `economic_evidence` present and schema-valid | Missing/malformed block |
| E2 | Deterministic site coverage: every cheatcode site the engine finds in the captured PoC source (§5) is listed in `setup_mutations` | Undeclared mutation (model hid an injection) |
| E3 | No `setup_mutations` entry with `beneficiary_role` `protocol_contract` (state or funds placed into an in-scope contract) | 2428, 2106, 2142 |
| E4 | For `funds_loss`: `attacker_pnl.net_positive` is true | 2142 (attacker paid itself) |
| E5 | For `funds_loss`, `permanent_freezing`, `temporary_freezing`: at least one `victim_loss` with `preexisting_on_fork: true` | 2428, 2106, 2166 |
| E6 | `privileged_calls` is empty for `public_bounty` / `audit_competition` (and no `setup_mutations` with `privileged_role`) | 2166 |

### 4.2 `reality_context`

| # | Rule | Blocks |
| --- | --- | --- |
| C1 | `reality_checks` present and schema-valid | Missing/malformed block |
| C2 | `upstream_fix.status` is `none_found` | 2166 (`fixed_upstream`), SSV 1855 (`documented_known`) |
| C3 | `precondition_live.status` is `present_now` | 2428, 2106, 2142, 2166 |
| C4 | `materiality.usd_affected >= materiality_min_usd` from the scan configuration | 2145, 2105, 2615, 2115 |

Accepted trade-off: C3 and E5 also block real bugs whose preconditions only appear in the
future (e.g. a new reward program, a new empty reserve). Those stay visible as
`impact_proven` findings with their blocking reasons, for manual judgement; they are never
labelled `submission_ready`.

### 4.3 Expected outcome on scan 28

Every one of the seven High/Critical findings fails at least two independent rules
(E-group and C-group), so a single wrong model field cannot make it ready.

## 5. Deterministic cheatcode scanner

New pure function `poc_cheatcode_sites(files) -> list[{site, kind}]` in
`engine/open_kritt_engine/impact_gate.py` (or a small sibling module), run over the files
`capture_evidence` already copied to `poc-artifacts/scan-*/finding-*/metadata-*`:

- Solidity/Foundry: `vm.(deal|store|etch|prank|startPrank|warp|roll)(`, forge-std `deal(`,
  `hoax(`, `startHoax(`, `selfdestruct(`; comments and interface declarations
  (`function prank(`) are ignored.
- Hardhat/JS: `hardhat_setBalance`, `hardhat_setStorageAt`, `hardhat_impersonateAccount`,
  `setBalance(`, `impersonateAccount(`.
- A site is `relative/path:line`. E2 matches on that key.

If the capture is incomplete, E2 blocks (the engine cannot prove coverage).

## 6. Prompt changes

- **D4** (`d4-local-poc.post-script.json`): add `economic_evidence` to the output format and
  the rules in §3.1; require forking the live deployment named in `deployment_context`, never
  self-deployed copies when a live address exists (SSV lesson).
- **D5** (`d5-report-readiness.post-script.json`): add `reality_checks` and the search duty in
  §3.2; restate that `submission_ready` must be false when any §4 rule would fail.
- **D3** (`d3-hostile-verification.post-script.json`): add two falsification prompts — "is the
  exploited balance/state present on the live chain now?" and "does the trigger require a
  privileged role?" — so obvious cases die before D4 spends tokens.

Post-scripts are resolved by name, newest ID first (`backend/src/lib/v27Pipeline.js`), so
re-importing the three files makes new scans use them; existing scans keep their snapshot.

## 7. Versioning

- `READINESS_POLICY_VERSION` becomes `v2.7-impact-gate-2` in `backend/src/lib/v27Pipeline.js`
  and `engine/open_kritt_engine/readiness_policies.py`.
- `_POLICIES` keeps the frozen `v2.7-impact-gate-1` table; gate-2 copies it and enables the
  two new groups. `evaluate_readiness` runs the new groups only for gate-2.
- Frontend: the readiness panel already lists `blocking_reasons`; no UI change is required.
  The new check-group names appear in the existing checks list.

## 8. Testing

- **Unit (engine, pytest):** one fixture per scan-28 finding (2428, 2106, 2142, 2145, 2105,
  2166) with realistic D4/D5 blocks, each asserting the exact rules it fails; one
  positive-control fixture (preexisting victim funds, attacker profit, no privileged calls,
  `none_found`, `present_now`, above threshold) asserting `ready: true`; gate-1 fixtures
  unchanged.
- **Real data:** run `poc_cheatcode_sites` over the saved `.data/engine/poc-artifacts/scan-28`
  files in a test (copied into `engine/tests/fixtures/`) and assert it finds the `prank` at
  `VeloPositionManagerSweepFork.t.sol:107`, the `selfdestruct` sites in 2142 and the
  `vm.store` sites in 2166.
- **Backend (node:test):** preflight blocks a `public_bounty` payload without
  `materiality_min_usd`; `resolveV27Pipeline` returns `v2.7-impact-gate-2`.
- **Workflow structure:** extend `scripts/web3-v2.7-workflow.test.mjs` to assert the new
  output-format fields and prompt duties exist.
- **Acceptance:** re-evaluating scan-28 D4/D5 results under gate-2 is not meaningful (old
  results lack the new fields); acceptance is the fixture suite above plus the next live scan.

## 9. Out of scope (follow-up specs)

1. Deterministic static analysis: Slither JSON at workspace preparation fed to D0; CodeQL in the
   runner for supported languages (not Solidity).
2. Target preparation: scorecard (TVL at risk, verified-source coverage, audit count, known-issue
   list), automatic live-source fetch + implementation drift check, program known-issues capture
   into the known-issues corpus.
