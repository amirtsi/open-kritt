# Live scan tracking design

Date: 2026-09-26. Status: approved design, pending implementation plan.

## Problem

While a scan runs, the researcher cannot see what matters:

- The only headline quality metric is **Exploitable**, which counts D2's own `exploitable` flag. D2 cannot verify deployment facts, so the flag is almost always false and the number reads 0 even when candidates exist. Nothing downstream is gated on it.
- The live job list exists (`statusSummary.activeJobs`) but shows no durations or slowness signal.
- Why lanes and candidates drop out is invisible: `stub_explanation` is stored per job but never exposed, and D3 verdict reasons are not aggregated.

## Goal

One live panel on the scan page that answers, without opening individual findings:

1. How many candidates survived each verified stage, and what dropped out where (funnel).
2. What is running now, and whether anything is unusually slow (activity).
3. Why lanes and findings were closed or blocked (dropout reasons).

The Overview KPIs switch from D2's claim to engine-verified counts.

## Non-goals

- Changing what D2's `exploitable` means (handled separately in the v2.7 D2 wording).
- Acting on jobs (restart, cancel) from this panel.
- Server push; polling is enough.
- Semantic clustering of free-text reasons.

## Section 1: funnel

Every stage counts **canonical** findings only (`dedupeIsCanonical = true`), except Raw. Each count is a subset of the previous one.

| Stage | Definition (engine-owned fields) |
| --- | --- |
| Raw | every D2 candidate row for the scan |
| Canonical | `dedupeIsCanonical = true` |
| D3 kept | D3 `verdict` in {`confirmed`, `plausible_needs_poc`} |
| Bug reproduced | `_engine_evidence.bug_status = reproduced` |
| Impact proven | `_engine_evidence.impact_status = proven` and `_engine_evidence.capture_complete = true` |
| Ready | `_engine_readiness.ready = true` |

For each stage the funnel also reports:

- `pending`: findings that reached the previous stage but have no result for this one yet.
- `dropped`: counts of the stage's own status values for findings that did not pass. For D3 this is the verdict breakdown; for D4 it is `bug_status` and `impact_status`; for Ready it is the grouped `_engine_readiness.blocking_reasons`.

The D3/D4/D5 stages are identified through `configuration.v27_pipeline` (`d3`, `d4`, `d5` post-script ids). A scan without a v2.7 pipeline gets Raw and Canonical only, with the post-script stages omitted.

Before deduplication has run, Canonical reports `status: "waiting"` instead of 0, and later stages are `waiting` as well. A stage is `waiting` until at least one attempt for it has been recorded.

## Section 2: activity

- **Active jobs**: one row per job from `statusSummary.activeJobs`, with the stage label (step name or post-script stage), phase label, elapsed time since `startedAt`, and the model.
- **Slower than usual**: a running job is flagged when its elapsed time exceeds twice the median `run_time_ms` of completed jobs of the same step or post-processing stage. Fewer than three completed jobs means no flag.
- **Stage progress**: per workflow depth, completed and expected lineages plus stub and record counts; per post-processing stage (dedupe, ranker, each post-script), completed, running and failed attempts.
- **Recent errors**: the five most recent failed or interrupted attempts, each with its stage, a short error text, and whether a later attempt for the same lineage or finding completed.

Display only; no actions.

## Section 3: dropout reasons

1. **Stub reasons (workflow steps)**: `stub_explanation` of completed stub jobs, grouped per step. Grouping key: lowercase, collapsed whitespace, file paths (`something/like/this.ext`), `path:line` references and bare numbers removed. Each group shows the count, one full example, and links to up to five jobs.
2. **D3 dropouts**: canonical findings whose D3 verdict is not kept, grouped by verdict. Each entry lists the finding id and summary, the first 300 characters of D3 `reason`, and a link to the finding.
3. **Readiness blockers**: findings with a D5 result and `_engine_readiness.ready = false`, grouped by blocking reason. Each group links to its findings.

Limits: at most 20 groups per section and 50 entries per group, with explicit `more` counts. All text is model output about untrusted code and is rendered as plain text.

## Architecture

### Backend

- `backend/src/lib/scanLive.js`: pure `buildScanLive({ scan, steps, stepMetadata, postMetadata, vulnerabilities, enrichments, postScripts, now })` returning `{ funnel, activity, dropouts }`. No database access.
- `loadScanLive(db, scan)` in the same module: loads only the needed columns. From enrichment results it reads `verdict`, `reason`, `bug_status`, `impact_status` and the `_engine_*` blocks; from step and post-processing metadata `status`, `stub`, `stub_explanation`, `run_time_ms`, timestamps, `error` and lineage or finding ids. Reports and PoC bodies are never loaded.
- `GET /api/scans/:id/live` returns `buildScanLive` output, or 404 for an unknown scan. Existing `/graph` and `/scans/:id` responses are unchanged.
- `GET /api/overview` adds `keptCount` and `impactProvenCount` for the selected research, computed with the funnel helpers. `exploitableCount` stays for compatibility.

### Frontend

- `frontend/src/components/ScanLive.jsx`: `ScanLivePanel` with `LiveFunnel`, `LiveActivity` and `LiveDropouts` subcomponents; presentational pieces take plain props so they render statically in tests.
- `ScanDetail.jsx`: renders `ScanLivePanel` above the existing graph panel. It polls `/live` every 5 seconds while the scan status is in `GRAPH_LIVE_STATUSES`, otherwise loads once.
- `Overview.jsx`: the Findings and Exploitable KPIs become **D3 kept** and **Impact proven**.
- `Scans.jsx` scan card: the exploitable stat becomes **D3 kept**. This needs `keptCount` in the scan list counts (`repo.js` per-scan counts).

## Error handling

- Missing or malformed `_engine_*` blocks count as "no result" for that stage, never as a pass.
- Legacy results synthesized at read time (`legacy: true`) are counted by their normalized statuses; they can never reach Ready, per the existing readiness policy.
- A `/live` failure shows an inline error in the panel with retry; the rest of the scan page keeps working.

## Testing

Backend (`node:test`), with fixtures:

- funnel stages are nested subsets; `pending` and `dropped` counts
- `waiting` before dedupe and before each post-script stage
- a scan without `v27_pipeline` has no post-script stages
- failed and stub enrichments are handled
- slowness flag at more than 2x the median, and no flag with fewer than three samples
- stub grouping ignores paths, `path:line` and numbers
- group and entry caps with `more` counts
- readiness blocker grouping
- route: response shape and 404
- overview: `keptCount` and `impactProvenCount`

Frontend (Vitest, static render):

- panel before post-processing, during D3, and completed
- funnel `waiting` state
- slow-job marker
- dropout groups with caps
- new Overview KPI labels and scan card stat

Manual, in the running stack:

- a completed v2.7 scan with a full funnel shows canonical, kept, reproduced, impact proven and zero ready, with its readiness blockers
- a running scan updates live
