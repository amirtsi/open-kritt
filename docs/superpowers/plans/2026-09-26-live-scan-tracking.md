# Live Scan Tracking Implementation Plan (backend)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A live panel on the scan page showing a verified-findings funnel, current activity, and grouped dropout reasons; Overview and scan cards show engine-verified counts instead of D2's `exploitable` claim.

**Architecture:** A pure backend module `backend/src/lib/scanLive.js` turns plain rows into `{ funnel, activity, dropouts }`; `loadScanLive` loads only the needed columns and `GET /api/scans/:id/live` serves it. A separate React component `ScanLivePanel` polls that endpoint while the scan is live. Overview and scan-list counts reuse the same funnel helpers.

**Tech Stack:** Node + Express + Prisma (backend, `node:test`), React 19 + Vite (frontend, Vitest with `renderToStaticMarkup`, no DOM environment).

**Spec:** `docs/superpowers/specs/2026-09-26-live-scan-tracking-design.md`

**Scope:** backend only (Tasks 1–5). The frontend panel, the ScanDetail wiring, and the Overview and scan-card changes get a separate plan.

## Global Constraints

- Funnel stages count canonical findings (`dedupeIsCanonical === true`) except Raw; each stage is a subset of the previous one.
- Stage definitions: D3 kept = `verdict` in {`confirmed`, `plausible_needs_poc`}; Bug reproduced = `_engine_evidence.bug_status === 'reproduced'`; Impact proven = `_engine_evidence.impact_status === 'proven'` and `_engine_evidence.capture_complete === true`; Ready = `_engine_readiness.ready === true`.
- D3/D4/D5 post-script ids come from `configuration.v27_pipeline` (`d3`, `d4`, `d5`); without it only Raw and Canonical are reported.
- A stage is `waiting` until at least one attempt for it is recorded.
- Slower than usual: elapsed > 2 × median `runTimeMs` of completed jobs of the same step or post-processing stage; fewer than 3 completed samples means no flag.
- Recent errors: the 5 most recent failed or interrupted attempts.
- Dropout limits: at most 20 groups per section, 50 entries per group, explicit `more` counts; D3 reasons truncated to 300 characters.
- Missing or malformed `_engine_*` blocks never count as a pass. Supplemental enrichments (`supplementalRunId != null`) are ignored.
- All model text is rendered as plain text (React text nodes only, never `dangerouslySetInnerHTML`).
- Poll `/live` every 5 seconds while the scan status is in `GRAPH_LIVE_STATUSES`; otherwise load once.
- `exploitableCount` and `exploitable` stay in API responses for compatibility.
- Conventional Commits; end commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- A scan with findings but no dedupe yet (live scan early in discovery): funnel must say `waiting`, not 0. Covered in Task 1.
- A finding whose D4 result lacks `_engine_evidence` (legacy or failed parse): it must not count as reproduced and must show as `unknown`. Covered in Task 1.
- Readiness reasons carrying ids ("Material assumption 'A2' is still open."): different ids must land in one group. Covered in Task 3.
- An active job with no completed peers in its step (first jobs of a lane): no slowness flag. Covered in Task 2.
- A `/live` request for a scan id that does not exist or is not numeric: 404/400, not 500. Covered in Task 4.

## File Structure

- Create `backend/src/lib/scanLive.js`: funnel, activity, dropouts builders, `buildScanLive`, `loadScanLive`.
- Create `backend/test/scanLive.test.js`: unit tests for the module.
- Modify `backend/src/routes/scans.js`: `GET /:id/live`.
- Modify `backend/src/lib/repo.js`: `findingCountsByScan` adds `keptFindings`; `assembleScans` serializes it.
- Modify `backend/src/lib/serialize.js`: pass `keptFindings` through `serializeScan`.
- Modify `backend/src/routes/overview.js`: `keptCount`, `impactProvenCount`.
- Create `frontend/src/components/ScanLive.jsx`: `ScanLivePanel`, `LiveFunnel`, `LiveActivity`, `LiveDropouts`.
- Create `frontend/src/components/ScanLive.test.jsx`.
- Modify `frontend/src/api/client.js`: `scanLive(id)`.
- Modify `frontend/src/pages/ScanDetail.jsx`, `frontend/src/pages/Overview.jsx`, `frontend/src/pages/Scans.jsx`.

---

### Task 1: Funnel builder

**Files:**
- Create: `backend/src/lib/scanLive.js`
- Test: `backend/test/scanLive.test.js`

**Interfaces:**
- Produces: `latestStageResults(enrichments) -> Map<postScriptId string, Map<vulnerabilityId string, { stub: boolean, result: object }>>`, `buildFunnel({ scan, vulnerabilities, enrichments, postMetadata }) -> Array<Stage>` where `Stage = { id, label, status: 'counted'|'waiting', count, pending, dropped: Record<string, number> }` and ids are `raw`, `canonical`, `d3_kept`, `bug_reproduced`, `impact_proven`, `ready`. Also `pipelineIds(scan) -> { d3, d4, d5 } | null`.

- [ ] **Step 1: Write the failing tests**

```js
// backend/test/scanLive.test.js
import assert from 'node:assert/strict';
import test from 'node:test';

import { buildFunnel } from '../src/lib/scanLive.js';

const PIPELINE = { d3: '15', d4: '13', d5: '16' };
const scan = (configuration = { v27_pipeline: PIPELINE }) => ({ id: 26n, status: 'post_processing', configuration });
const vuln = (id, dedupeIsCanonical) => ({ id: BigInt(id), dedupeIsCanonical });
const enrich = (vulnerabilityId, postScriptId, result, stub = false) => ({
  vulnerabilityId: BigInt(vulnerabilityId),
  postScriptId: BigInt(postScriptId),
  stub,
  supplementalRunId: null,
  result,
});
const attempt = (kind, postScriptId = null) => ({ kind, postScriptId: postScriptId && BigInt(postScriptId), status: 'completed' });
const byId = (stages) => Object.fromEntries(stages.map((stage) => [stage.id, stage]));

test('funnel waits for dedupe before counting canonical findings', () => {
  const stages = byId(buildFunnel({ scan: scan(), vulnerabilities: [vuln(1, null), vuln(2, null)], enrichments: [], postMetadata: [] }));
  assert.equal(stages.raw.count, 2);
  assert.equal(stages.canonical.status, 'waiting');
  assert.equal(stages.canonical.pending, 2);
  assert.equal(stages.d3_kept.status, 'waiting');
  assert.equal(stages.ready.status, 'waiting');
});

test('funnel stages are nested subsets with dropped reasons', () => {
  const vulnerabilities = [vuln(1, true), vuln(2, true), vuln(3, true), vuln(4, false), vuln(5, true)];
  const enrichments = [
    enrich(1, 15, { verdict: 'confirmed' }),
    enrich(2, 15, { verdict: 'plausible_needs_poc' }),
    enrich(3, 15, { verdict: 'false_positive' }),
    enrich(1, 13, { _engine_evidence: { bug_status: 'reproduced', impact_status: 'proven', capture_complete: true } }),
    enrich(2, 13, { _engine_evidence: { bug_status: 'reproduced', impact_status: 'partial', capture_complete: true } }),
    enrich(1, 16, { _engine_readiness: { ready: false, blocking_reasons: ["Material assumption 'A2' is still open."] } }),
  ];
  const postMetadata = [attempt('dedupe'), attempt('post_script', 15), attempt('v27_poc', 13), attempt('post_script', 16)];
  const stages = byId(buildFunnel({ scan: scan(), vulnerabilities, enrichments, postMetadata }));

  assert.deepEqual(
    ['raw', 'canonical', 'd3_kept', 'bug_reproduced', 'impact_proven', 'ready'].map((id) => stages[id].count),
    [5, 4, 2, 2, 1, 0]
  );
  assert.deepEqual(stages.canonical.dropped, { duplicate: 1 });
  assert.equal(stages.d3_kept.pending, 1);
  assert.deepEqual(stages.d3_kept.dropped, { false_positive: 1 });
  assert.deepEqual(stages.impact_proven.dropped, { partial: 1 });
  assert.deepEqual(stages.ready.dropped, { "material assumption '…' is still open.": 1 });
});

test('missing engine evidence never counts as reproduced', () => {
  const stages = byId(
    buildFunnel({
      scan: scan(),
      vulnerabilities: [vuln(1, true)],
      enrichments: [enrich(1, 15, { verdict: 'confirmed' }), enrich(1, 13, { poc_status: 'reproduced' })],
      postMetadata: [attempt('dedupe'), attempt('post_script', 15), attempt('v27_poc', 13)],
    })
  );
  assert.equal(stages.bug_reproduced.count, 0);
  assert.deepEqual(stages.bug_reproduced.dropped, { unknown: 1 });
});

test('stub and supplemental enrichments do not pass a stage', () => {
  const stages = byId(
    buildFunnel({
      scan: scan(),
      vulnerabilities: [vuln(1, true), vuln(2, true)],
      enrichments: [
        enrich(1, 15, {}, true),
        { ...enrich(2, 15, { verdict: 'confirmed' }), supplementalRunId: 7n },
      ],
      postMetadata: [attempt('dedupe'), attempt('post_script', 15)],
    })
  );
  assert.equal(stages.d3_kept.count, 0);
  assert.deepEqual(stages.d3_kept.dropped, { stub: 1 });
  assert.equal(stages.d3_kept.pending, 1);
});

test('a scan without a v2.7 pipeline reports raw and canonical only', () => {
  const stages = buildFunnel({ scan: scan({}), vulnerabilities: [vuln(1, true)], enrichments: [], postMetadata: [attempt('dedupe')] });
  assert.deepEqual(
    stages.map((stage) => stage.id),
    ['raw', 'canonical']
  );
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && node --test test/scanLive.test.js`
Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/lib/scanLive.js`.

- [ ] **Step 3: Implement the funnel**

```js
// backend/src/lib/scanLive.js
// Live view of one scan: a funnel of engine-verified findings, current
// activity, and grouped reasons for dropouts. The builders are pure; the
// loader fetches only the columns they read.

const KEPT_VERDICTS = new Set(['confirmed', 'plausible_needs_poc']);
const POST_SCRIPT_KINDS = new Set(['post_script', 'v27_poc']);

const text = (value) => (value === null || value === undefined ? null : value.toString());
const plainObject = (value) => (value && typeof value === 'object' && !Array.isArray(value) ? value : {});

export function pipelineIds(scan) {
  const raw = plainObject(plainObject(scan?.configuration).v27_pipeline);
  const ids = { d3: text(raw.d3), d4: text(raw.d4), d5: text(raw.d5) };
  return ids.d3 && ids.d4 && ids.d5 ? ids : null;
}

// Latest non-supplemental enrichment per post-script and finding.
export function latestStageResults(enrichments) {
  const stages = new Map();
  for (const row of enrichments) {
    if (row.supplementalRunId !== null && row.supplementalRunId !== undefined) continue;
    const script = text(row.postScriptId);
    if (!stages.has(script)) stages.set(script, new Map());
    stages.get(script).set(text(row.vulnerabilityId), { stub: Boolean(row.stub), result: plainObject(row.result) });
  }
  return stages;
}

export function normalizeBlocker(reason) {
  const head = `${reason ?? ''}`.split(':')[0];
  return head.toLowerCase().replace(/'[^']*'/g, "'…'").replace(/\s+/g, ' ').trim() || 'unspecified';
}

function stageAttempted(postMetadata, predicate) {
  return postMetadata.some(predicate);
}

function tally(target, label) {
  target[label] = (target[label] || 0) + 1;
}

function evidence(entry) {
  return plainObject(entry?.result?._engine_evidence);
}

function stage(id, label, status, count, pending, dropped) {
  return { id, label, status, count, pending, dropped };
}

export function buildFunnel({ scan, vulnerabilities, enrichments, postMetadata }) {
  const raw = vulnerabilities.length;
  const canonical = vulnerabilities.filter((row) => row.dedupeIsCanonical === true).map((row) => text(row.id));
  const dedupeSeen = stageAttempted(postMetadata, (row) => row.kind === 'dedupe');
  const stages = [
    stage('raw', 'Raw', 'counted', raw, 0, {}),
    stage(
      'canonical',
      'Canonical',
      dedupeSeen ? 'counted' : 'waiting',
      canonical.length,
      vulnerabilities.filter((row) => row.dedupeIsCanonical === null || row.dedupeIsCanonical === undefined).length,
      vulnerabilities.some((row) => row.dedupeIsCanonical === false)
        ? { duplicate: vulnerabilities.filter((row) => row.dedupeIsCanonical === false).length }
        : {}
    ),
  ];
  const ids = pipelineIds(scan);
  if (!ids) return stages;

  const results = latestStageResults(enrichments);
  const seen = (scriptId) =>
    stageAttempted(postMetadata, (row) => POST_SCRIPT_KINDS.has(row.kind) && text(row.postScriptId) === scriptId);

  const step = (id, label, scriptId, previous, passes, dropLabel) => {
    const byFinding = results.get(scriptId) || new Map();
    const passed = [];
    const dropped = {};
    let pending = 0;
    for (const findingId of previous) {
      const entry = byFinding.get(findingId);
      if (!entry) pending += 1;
      else if (entry.stub) tally(dropped, 'stub');
      else if (passes(entry)) passed.push(findingId);
      else for (const reason of [dropLabel(entry)].flat()) tally(dropped, reason);
    }
    stages.push(stage(id, label, seen(scriptId) ? 'counted' : 'waiting', passed.length, pending, dropped));
    return passed;
  };

  const kept = step(
    'd3_kept',
    'D3 kept',
    ids.d3,
    canonical,
    (entry) => KEPT_VERDICTS.has(entry.result.verdict),
    (entry) => `${entry.result.verdict ?? 'unknown'}`
  );
  const reproduced = step(
    'bug_reproduced',
    'Bug reproduced',
    ids.d4,
    kept,
    (entry) => evidence(entry).bug_status === 'reproduced',
    (entry) => `${evidence(entry).bug_status ?? 'unknown'}`
  );
  const proven = step(
    'impact_proven',
    'Impact proven',
    ids.d4,
    reproduced,
    (entry) => evidence(entry).impact_status === 'proven' && evidence(entry).capture_complete === true,
    (entry) =>
      evidence(entry).impact_status === 'proven' ? 'capture_incomplete' : `${evidence(entry).impact_status ?? 'unknown'}`
  );
  step(
    'ready',
    'Ready',
    ids.d5,
    proven,
    (entry) => plainObject(entry.result._engine_readiness).ready === true,
    (entry) => {
      const reasons = plainObject(entry.result._engine_readiness).blocking_reasons;
      return Array.isArray(reasons) && reasons.length ? [...new Set(reasons.map(normalizeBlocker))] : ['unknown'];
    }
  );
  return stages;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && node --test test/scanLive.test.js`
Expected: PASS (5 tests).

- [ ] **Step 5: Lint, format, commit**

```bash
cd backend && npx eslint src/lib/scanLive.js test/scanLive.test.js && npx prettier --write src/lib/scanLive.js test/scanLive.test.js && node --test test/scanLive.test.js
cd .. && git add backend/src/lib/scanLive.js backend/test/scanLive.test.js
git commit -m "feat(backend): build a verified-findings funnel for a scan

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Activity builder

**Files:**
- Modify: `backend/src/lib/scanLive.js`
- Test: `backend/test/scanLive.test.js`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `buildActivity({ activeJobs, stepMetadata, postMetadata, now }) -> { jobs: Array<Job>, recentErrors: Array<ErrorRow> }`.
  - `activeJobs` is `statusSummary.activeJobs` from `assembleScan` (fields used: `metadataId`, `kind`, `title`, `phaseLabel`, `startedAt`, `model`).
  - `stepMetadata` rows: `{ id, stepId, kind, status, runTimeMs, runStartedAt, insertedAt, updatedAt, error }`.
  - `postMetadata` rows: `{ id, kind, postScriptId, status, runTimeMs, updatedAt, error }`.
  - `Job = { metadataId, title, phaseLabel, model, elapsedMs, medianMs: number|null, slow: boolean }`.
  - `ErrorRow = { metadataId, stage, status, message, at, recovered: boolean }`.

- [ ] **Step 1: Write the failing tests**

Append to `backend/test/scanLive.test.js`, and add `buildActivity` to the import from `../src/lib/scanLive.js`:

```js
const NOW = new Date('2026-09-26T12:00:00Z');
const minutesAgo = (minutes) => new Date(NOW.getTime() - minutes * 60_000);
const stepRow = (id, stepId, status, runTimeMs, extra = {}) => ({
  id: BigInt(id),
  stepId: BigInt(stepId),
  kind: 'step',
  status,
  runTimeMs,
  runStartedAt: null,
  insertedAt: minutesAgo(60),
  updatedAt: minutesAgo(30),
  error: null,
  ...extra,
});

test('a running job slower than twice its step median is flagged', () => {
  const stepMetadata = [
    stepRow(1, 281, 'completed', 60_000),
    stepRow(2, 281, 'completed', 120_000),
    stepRow(3, 281, 'completed', 180_000),
    stepRow(4, 281, 'running', null),
    stepRow(5, 282, 'running', null),
  ];
  const activeJobs = [
    { metadataId: '4', kind: 'step', title: '2 · Investigate authority', phaseLabel: 'Running harness', startedAt: minutesAgo(5), model: 'gpt-6-sol' },
    { metadataId: '5', kind: 'step', title: '2 · Investigate protocol', phaseLabel: 'Running harness', startedAt: minutesAgo(50), model: 'gpt-6-sol' },
  ];
  const { jobs } = buildActivity({ activeJobs, stepMetadata, postMetadata: [], now: NOW });

  assert.deepEqual(
    jobs.map((job) => [job.metadataId, job.medianMs, job.slow]),
    [
      ['4', 120_000, true],
      ['5', null, false],
    ]
  );
  assert.equal(jobs[0].elapsedMs, 300_000);
});

test('recent errors list the five newest failures and whether they recovered', () => {
  const stepMetadata = [
    ...[1, 2, 3, 4, 5, 6].map((n) =>
      stepRow(10 + n, 281, n === 6 ? 'interrupted' : 'failed', null, { updatedAt: minutesAgo(10 - n), error: `boom ${n}` })
    ),
    stepRow(30, 281, 'completed', 1000, { prevId: null }),
  ];
  const { recentErrors } = buildActivity({ activeJobs: [], stepMetadata, postMetadata: [], now: NOW });

  assert.deepEqual(
    recentErrors.map((row) => row.metadataId),
    ['16', '15', '14', '13', '12']
  );
  assert.equal(recentErrors[0].status, 'interrupted');
  assert.equal(recentErrors[0].message, 'boom 6');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && node --test test/scanLive.test.js`
Expected: FAIL with `SyntaxError: The requested module ... does not provide an export named 'buildActivity'`.

- [ ] **Step 3: Implement the activity builder**

Append to `backend/src/lib/scanLive.js`:

```js
const MIN_SAMPLES = 3;
const RECENT_ERRORS = 5;
const ERROR_STATUSES = new Set(['failed', 'interrupted']);

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function stageKey(row, fromPost) {
  if (fromPost) return `post:${row.kind}:${text(row.postScriptId) ?? ''}`;
  return `step:${text(row.stepId)}`;
}

export function buildActivity({ activeJobs, stepMetadata, postMetadata, now }) {
  const rows = [
    ...stepMetadata.map((row) => ({ row, key: stageKey(row, false) })),
    ...postMetadata.map((row) => ({ row, key: stageKey(row, true) })),
  ];
  const samples = new Map();
  const keyById = new Map();
  for (const { row, key } of rows) {
    keyById.set(text(row.id), key);
    if (row.status !== 'completed' || row.runTimeMs === null || row.runTimeMs === undefined) continue;
    if (!samples.has(key)) samples.set(key, []);
    samples.get(key).push(Number(row.runTimeMs));
  }
  const jobs = activeJobs.map((job) => {
    const values = samples.get(keyById.get(`${job.metadataId}`)) || [];
    const medianMs = values.length >= MIN_SAMPLES ? median(values) : null;
    const elapsedMs = Math.max(0, now.getTime() - new Date(job.startedAt).getTime());
    return {
      metadataId: `${job.metadataId}`,
      title: job.title,
      phaseLabel: job.phaseLabel,
      model: job.model || null,
      elapsedMs,
      medianMs,
      slow: medianMs !== null && elapsedMs > 2 * medianMs,
    };
  });
  const recentErrors = rows
    .filter(({ row }) => ERROR_STATUSES.has(row.status))
    .sort((a, b) => new Date(b.row.updatedAt) - new Date(a.row.updatedAt))
    .slice(0, RECENT_ERRORS)
    .map(({ row, key }) => ({
      metadataId: text(row.id),
      stage: key,
      status: row.status,
      message: `${row.error ?? ''}`.slice(0, 300),
      at: row.updatedAt,
      recovered: rows.some(
        (other) =>
          other.key === key &&
          other.row.status === 'completed' &&
          new Date(other.row.updatedAt) > new Date(row.updatedAt) &&
          text(other.row.prevId) === text(row.prevId)
      ),
    }));
  return { jobs, recentErrors };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && node --test test/scanLive.test.js`
Expected: PASS (7 tests).

- [ ] **Step 5: Lint, format, commit**

```bash
cd backend && npx eslint src/lib/scanLive.js test/scanLive.test.js && npx prettier --write src/lib/scanLive.js test/scanLive.test.js && node --test test/scanLive.test.js
cd .. && git add backend/src/lib/scanLive.js backend/test/scanLive.test.js
git commit -m "feat(backend): report active jobs, slowness, and recent errors for a scan

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Dropout reasons builder

**Files:**
- Modify: `backend/src/lib/scanLive.js`
- Test: `backend/test/scanLive.test.js`

**Interfaces:**
- Consumes: `latestStageResults`, `pipelineIds`, `normalizeBlocker` (Task 1).
- Produces: `normalizeStubReason(text) -> string`, `buildDropouts({ scan, steps, stepMetadata, vulnerabilities, enrichments }) -> { stubs: Section, d3: Section, blockers: Section }`.
  - `Section = { groups: Array<Group>, more: number }`.
  - `Group = { key, label, count, example, entries: Array<{ id, summary, detail }>, more }`.
  - `steps` rows are `{ id, name }`; `vulnerabilities` rows are `{ id, dedupeIsCanonical, jsonAnswer }`.

- [ ] **Step 1: Write the failing tests**

Append to `backend/test/scanLive.test.js`, and add `buildDropouts` and `normalizeStubReason` to the import:

```js
test('stub reasons group across file paths, line references and numbers', () => {
  assert.equal(
    normalizeStubReason('No  entrypoint in src/ccip/Wallet.sol:12 after 3 checks'),
    normalizeStubReason('no entrypoint in src/shares/Shares.sol:88 after 7 checks')
  );
});

test('dropouts group stubs per step, D3 rejections by verdict, and readiness blockers', () => {
  const steps = [{ id: 281n, name: 'Investigate authority and value boundaries' }];
  const stepMetadata = [
    stepRow(1, 281, 'completed', 1000, { stub: true, stubExplanation: 'No concrete failure in src/A.sol:1.' }),
    stepRow(2, 281, 'completed', 1000, { stub: true, stubExplanation: 'No concrete failure in src/B.sol:9.' }),
    stepRow(3, 281, 'completed', 1000, { stub: false, stubExplanation: null }),
  ];
  const vulnerabilities = [
    { id: 1n, dedupeIsCanonical: true, jsonAnswer: { summary: 'Oracle leaf not bound' } },
    { id: 2n, dedupeIsCanonical: true, jsonAnswer: { summary: 'Fee rounding' } },
  ];
  const enrichments = [
    enrich(1, 15, { verdict: 'confirmed' }),
    enrich(2, 15, { verdict: 'false_positive', reason: 'x'.repeat(400) }),
    enrich(1, 16, { _engine_readiness: { ready: false, blocking_reasons: ["Material assumption 'A2' is still open.", "Material assumption 'A3' is still open."] } }),
  ];
  const dropouts = buildDropouts({ scan: scan(), steps, stepMetadata, vulnerabilities, enrichments });

  assert.equal(dropouts.stubs.groups.length, 1);
  assert.equal(dropouts.stubs.groups[0].count, 2);
  assert.match(dropouts.stubs.groups[0].label, /Investigate authority/);
  assert.deepEqual(
    dropouts.d3.groups.map((group) => [group.key, group.count]),
    [['false_positive', 1]]
  );
  assert.equal(dropouts.d3.groups[0].entries[0].detail.length, 300);
  assert.deepEqual(
    dropouts.blockers.groups.map((group) => [group.key, group.count]),
    [["material assumption '…' is still open.", 1]]
  );
});

test('dropout sections cap groups at 20 and entries at 50', () => {
  const steps = Array.from({ length: 25 }, (_, n) => ({ id: BigInt(n + 1), name: `Step ${n + 1}` }));
  const stepMetadata = [
    ...steps.map((step, n) => stepRow(100 + n, Number(step.id), 'completed', 1, { stub: true, stubExplanation: `reason ${String.fromCharCode(97 + n)}` })),
    ...Array.from({ length: 60 }, (_, n) => stepRow(500 + n, 1, 'completed', 1, { stub: true, stubExplanation: 'same reason' })),
  ];
  const { stubs } = buildDropouts({ scan: scan(), steps, stepMetadata, vulnerabilities: [], enrichments: [] });

  assert.equal(stubs.groups.length, 20);
  assert.equal(stubs.more, 6);
  const biggest = stubs.groups[0];
  assert.equal(biggest.count, 60);
  assert.equal(biggest.entries.length, 50);
  assert.equal(biggest.more, 10);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && node --test test/scanLive.test.js`
Expected: FAIL with a missing export for `buildDropouts`.

- [ ] **Step 3: Implement the dropouts builder**

Append to `backend/src/lib/scanLive.js`:

```js
const MAX_GROUPS = 20;
const MAX_ENTRIES = 50;
const REASON_CHARS = 300;

export function normalizeStubReason(reason) {
  return `${reason ?? ''}`
    .toLowerCase()
    .replace(/[\w.-]+(\/[\w.-]+)+(:\d+)?/g, '<path>')
    .replace(/\d+/g, '#')
    .replace(/\s+/g, ' ')
    .trim();
}

function section(groupsByKey) {
  const groups = [...groupsByKey.values()].sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
  return {
    groups: groups.slice(0, MAX_GROUPS).map((group) => ({
      ...group,
      entries: group.entries.slice(0, MAX_ENTRIES),
      more: Math.max(0, group.entries.length - MAX_ENTRIES),
    })),
    more: Math.max(0, groups.length - MAX_GROUPS),
  };
}

function addEntry(groups, key, label, example, entry) {
  if (!groups.has(key)) groups.set(key, { key, label, count: 0, example, entries: [] });
  const group = groups.get(key);
  group.count += 1;
  group.entries.push(entry);
}

export function buildDropouts({ scan, steps, stepMetadata, vulnerabilities, enrichments }) {
  const stepNames = new Map(steps.map((step) => [text(step.id), step.name]));
  const stubs = new Map();
  for (const row of stepMetadata) {
    if (row.status !== 'completed' || !row.stub) continue;
    const explanation = `${row.stubExplanation ?? ''}`.trim() || 'No explanation recorded.';
    const stepName = stepNames.get(text(row.stepId)) || `Step ${text(row.stepId)}`;
    addEntry(stubs, `${text(row.stepId)}:${normalizeStubReason(explanation)}`, stepName, explanation, {
      id: text(row.id),
      summary: stepName,
      detail: explanation.slice(0, REASON_CHARS),
    });
  }

  const d3 = new Map();
  const blockers = new Map();
  const ids = pipelineIds(scan);
  if (ids) {
    const results = latestStageResults(enrichments);
    const summaries = new Map(
      vulnerabilities.map((row) => [text(row.id), `${plainObject(row.jsonAnswer).summary ?? `Finding ${text(row.id)}`}`])
    );
    const canonical = new Set(vulnerabilities.filter((row) => row.dedupeIsCanonical === true).map((row) => text(row.id)));
    for (const [findingId, entry] of results.get(ids.d3) || []) {
      if (!canonical.has(findingId) || entry.stub || KEPT_VERDICTS.has(entry.result.verdict)) continue;
      const verdict = `${entry.result.verdict ?? 'unknown'}`;
      const reason = `${entry.result.reason ?? ''}`;
      addEntry(d3, verdict, verdict, reason.slice(0, REASON_CHARS), {
        id: findingId,
        summary: summaries.get(findingId),
        detail: reason.slice(0, REASON_CHARS),
      });
    }
    for (const [findingId, entry] of results.get(ids.d5) || []) {
      const readiness = plainObject(entry.result._engine_readiness);
      if (entry.stub || readiness.ready !== false) continue;
      const reasons = Array.isArray(readiness.blocking_reasons) ? readiness.blocking_reasons : [];
      const seen = new Set();
      for (const reason of reasons.length ? reasons : ['unknown']) {
        const key = normalizeBlocker(reason);
        if (seen.has(key)) continue;
        seen.add(key);
        addEntry(blockers, key, key, `${reason}`.slice(0, REASON_CHARS), {
          id: findingId,
          summary: summaries.get(findingId),
          detail: `${reason}`.slice(0, REASON_CHARS),
        });
      }
    }
  }
  return { stubs: section(stubs), d3: section(d3), blockers: section(blockers) };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && node --test test/scanLive.test.js`
Expected: PASS (10 tests).

- [ ] **Step 5: Lint, format, commit**

```bash
cd backend && npx eslint src/lib/scanLive.js test/scanLive.test.js && npx prettier --write src/lib/scanLive.js test/scanLive.test.js && node --test test/scanLive.test.js
cd .. && git add backend/src/lib/scanLive.js backend/test/scanLive.test.js
git commit -m "feat(backend): group stub, D3 and readiness dropout reasons for a scan

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Loader and `GET /api/scans/:id/live`

**Files:**
- Modify: `backend/src/lib/scanLive.js`
- Modify: `backend/src/routes/scans.js` (next to the `/:id/graph` route)
- Test: `backend/test/scanLive.test.js`

**Interfaces:**
- Consumes: `buildFunnel`, `buildActivity`, `buildDropouts`.
- Produces: `buildScanLive({ scan, steps, stepMetadata, postMetadata, vulnerabilities, enrichments, activeJobs, now }) -> { scanId, status, funnel, activity, dropouts }` and `loadScanLive(db, scan, { activeJobs, now }) -> Promise<same>`. Response of `GET /api/scans/:id/live` is that object; 404 `{ error: 'Scan not found.' }`; 400 for a non-numeric id.

- [ ] **Step 1: Write the failing tests**

Append to `backend/test/scanLive.test.js`, and add `loadScanLive` to the import:

```js
test('loadScanLive reads only the needed columns and assembles every section', async () => {
  const calls = [];
  const table = (name, rows) => ({
    findMany: async (args) => {
      calls.push([name, args]);
      return rows;
    },
    findUnique: async () => ({ stepIds: [281n] }),
  });
  const db = {
    workflow: table('workflow', []),
    step: table('step', [{ id: 281n, name: 'Investigate authority' }]),
    stepMetadata: table('stepMetadata', [stepRow(1, 281, 'completed', 1000)]),
    postProcessMetadata: table('postProcessMetadata', []),
    vulnerability: table('vulnerability', [vuln(1, null)]),
    vulnerabilityEnrichment: table('vulnerabilityEnrichment', []),
  };
  const live = await loadScanLive(db, { id: 26n, workflowId: 28n, status: 'running', configuration: { v27_pipeline: PIPELINE } }, { activeJobs: [], now: NOW });

  assert.equal(live.scanId, '26');
  assert.equal(live.funnel[0].count, 1);
  assert.deepEqual(Object.keys(live.dropouts), ['stubs', 'd3', 'blockers']);
  const enrichmentCall = calls.find(([name]) => name === 'vulnerabilityEnrichment')[1];
  assert.equal(enrichmentCall.select.result, true);
  const metadataCall = calls.find(([name]) => name === 'stepMetadata')[1];
  assert.equal(metadataCall.select.promptFilled, undefined);
  assert.equal(metadataCall.select.stubExplanation, true);
});
```

Add a route-level test to `backend/test/scanPagination.test.js`, where route helpers are already tested, by exporting a small handler factory from `routes/scans.js`:

```js
import { scanLiveHandler } from '../src/routes/scans.js';

function fakeResponse() {
  return {
    statusCode: 200,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

test('scan live route returns 404 for an unknown scan and 400 for a malformed id', async () => {
  const handler = scanLiveHandler({ findScan: async () => null, load: async () => ({}) });
  const missing = fakeResponse();
  await handler({ params: { id: '999' } }, missing, (error) => {
    throw error;
  });
  assert.equal(missing.statusCode, 404);

  const malformed = fakeResponse();
  await handler({ params: { id: 'abc' } }, malformed, (error) => {
    throw error;
  });
  assert.equal(malformed.statusCode, 400);
});

test('scan live route returns the loaded live view', async () => {
  const handler = scanLiveHandler({
    findScan: async (id) => ({ id }),
    load: async (scan) => ({ scanId: `${scan.id}`, funnel: [] }),
  });
  const res = fakeResponse();
  await handler({ params: { id: '26' } }, res, (error) => {
    throw error;
  });
  assert.deepEqual(res.body, { scanId: '26', funnel: [] });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && node --test test/scanLive.test.js test/scanPagination.test.js`
Expected: FAIL with missing exports `loadScanLive` and `scanLiveHandler`.

- [ ] **Step 3: Implement the loader**

Append to `backend/src/lib/scanLive.js`:

```js
export function buildScanLive({ scan, steps, stepMetadata, postMetadata, vulnerabilities, enrichments, activeJobs, now }) {
  return {
    scanId: text(scan.id),
    status: scan.status,
    funnel: buildFunnel({ scan, vulnerabilities, enrichments, postMetadata }),
    activity: buildActivity({ activeJobs, stepMetadata, postMetadata, now }),
    dropouts: buildDropouts({ scan, steps, stepMetadata, vulnerabilities, enrichments }),
  };
}

const METADATA_SELECT = {
  id: true,
  stepId: true,
  prevId: true,
  kind: true,
  status: true,
  stub: true,
  stubExplanation: true,
  runTimeMs: true,
  runStartedAt: true,
  insertedAt: true,
  updatedAt: true,
  error: true,
};

export async function loadScanLive(db, scan, { activeJobs = [], now = new Date() } = {}) {
  const scanId = BigInt(scan.id);
  const workflow = await db.workflow.findUnique({ where: { id: BigInt(scan.workflowId) }, select: { stepIds: true } });
  const stepIds = workflow?.stepIds || [];
  const [steps, stepMetadata, postMetadata, vulnerabilities, enrichments] = await Promise.all([
    stepIds.length ? db.step.findMany({ where: { id: { in: stepIds } }, select: { id: true, name: true } }) : [],
    db.stepMetadata.findMany({ where: { scanId, kind: 'step' }, select: METADATA_SELECT }),
    db.postProcessMetadata.findMany({
      where: { scanId },
      select: { id: true, kind: true, postScriptId: true, status: true, runTimeMs: true, updatedAt: true, error: true },
    }),
    db.vulnerability.findMany({ where: { scanId }, select: { id: true, dedupeIsCanonical: true, jsonAnswer: true } }),
    db.vulnerabilityEnrichment.findMany({
      where: { scanId },
      select: { vulnerabilityId: true, postScriptId: true, stub: true, supplementalRunId: true, result: true },
      orderBy: { id: 'asc' },
    }),
  ]);
  return buildScanLive({ scan, steps, stepMetadata, postMetadata, vulnerabilities, enrichments, activeJobs, now });
}
```

Note: `result` is selected whole because Prisma cannot project JSON sub-keys; the builders read only `verdict`, `reason` and the `_engine_*` blocks from it. `jsonAnswer` is selected for the finding summary only.

- [ ] **Step 4: Implement the route**

In `backend/src/routes/scans.js`, add to the imports:

```js
import { loadScanLive } from '../lib/scanLive.js';
```

Add next to the `/:id/graph` route:

```js
export function scanLiveHandler({ findScan, load }) {
  return async (req, res, next) => {
    try {
      if (!/^\d+$/.test(`${req.params.id}`)) return res.status(400).json({ error: 'Scan id must be a number.' });
      const scan = await findScan(BigInt(req.params.id));
      if (!scan) return res.status(404).json({ error: 'Scan not found.' });
      res.json(await load(scan));
    } catch (e) {
      next(e);
    }
  };
}

// GET /api/scans/:id/live: verified-findings funnel, activity, and dropout reasons.
router.get(
  '/:id/live',
  scanLiveHandler({
    findScan: (id) => prisma.scan.findUnique({ where: { id } }),
    load: async (scan) => {
      const assembled = await assembleScan(scan);
      return loadScanLive(prisma, scan, { activeJobs: assembled.statusSummary?.activeJobs || [], now: new Date() });
    },
  })
);
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd backend && node --test test/scanLive.test.js test/scanPagination.test.js && npm test`
Expected: PASS; full suite `# fail 0`.

- [ ] **Step 6: Lint, format, commit**

```bash
cd backend && npx eslint src && npx prettier --write src/lib/scanLive.js src/routes/scans.js test/scanLive.test.js test/scanPagination.test.js && npm test
cd .. && git add backend/src/lib/scanLive.js backend/src/routes/scans.js backend/test/scanLive.test.js backend/test/scanPagination.test.js
git commit -m "feat(backend): serve the live scan view at GET /api/scans/:id/live

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Verified counts for Overview and scan cards

**Files:**
- Modify: `backend/src/lib/scanLive.js` (add `verifiedCounts`)
- Modify: `backend/src/routes/overview.js`
- Modify: `backend/src/lib/repo.js` (`findingCountsByScan`, `assembleScans`)
- Modify: `backend/src/lib/serialize.js` (`serializeScan` counts)
- Test: `backend/test/scanLive.test.js`, `backend/test/dataIntegrity.test.js`

**Interfaces:**
- Consumes: `buildFunnel` (Task 1).
- Produces: `verifiedCounts({ scan, vulnerabilities, enrichments }) -> { kept: number, impactProven: number }`. `/api/overview` adds `keptCount` and `impactProvenCount`. Scan objects gain `keptFindings`.

- [ ] **Step 1: Write the failing tests**

Append to `backend/test/scanLive.test.js`, and add `verifiedCounts` to the import:

```js
test('verified counts sum kept and impact-proven findings per scan', () => {
  const counts = verifiedCounts({
    scan: scan(),
    vulnerabilities: [vuln(1, true), vuln(2, true)],
    enrichments: [
      enrich(1, 15, { verdict: 'confirmed' }),
      enrich(2, 15, { verdict: 'plausible_needs_poc' }),
      enrich(1, 13, { _engine_evidence: { bug_status: 'reproduced', impact_status: 'proven', capture_complete: true } }),
    ],
  });
  assert.deepEqual(counts, { kept: 2, impactProven: 1 });
});
```

In `backend/test/dataIntegrity.test.js`, next to the existing `summarizeCanonicalFindings` test, import `summarizeVerifiedFindings` from `../src/routes/overview.js` and add:

```js
test('overview verified counts add up across the scans of a research', () => {
  const scans = [
    { id: 21n, configuration: { v27_pipeline: { d3: '12', d4: '13', d5: '14' } } },
    { id: 26n, configuration: { v27_pipeline: { d3: '15', d4: '13', d5: '16' } } },
  ];
  const vulnerabilities = [
    { id: 1n, scanId: 21n, dedupeIsCanonical: true },
    { id: 2n, scanId: 26n, dedupeIsCanonical: true },
  ];
  const enrichments = [
    { vulnerabilityId: 1n, scanId: 21n, postScriptId: 12n, stub: false, supplementalRunId: null, result: { verdict: 'confirmed' } },
    { vulnerabilityId: 2n, scanId: 26n, postScriptId: 15n, stub: false, supplementalRunId: null, result: { verdict: 'false_positive' } },
  ];
  assert.deepEqual(summarizeVerifiedFindings(scans, vulnerabilities, enrichments), { keptCount: 1, impactProvenCount: 0 });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && node --test test/scanLive.test.js test/dataIntegrity.test.js`
Expected: FAIL with missing exports `verifiedCounts` and `summarizeVerifiedFindings`.

- [ ] **Step 3: Implement**

Append to `backend/src/lib/scanLive.js`:

```js
export function verifiedCounts({ scan, vulnerabilities, enrichments }) {
  const stages = Object.fromEntries(
    buildFunnel({ scan, vulnerabilities, enrichments, postMetadata: [] }).map((stage) => [stage.id, stage.count])
  );
  return { kept: stages.d3_kept ?? 0, impactProven: stages.impact_proven ?? 0 };
}
```

In `backend/src/routes/overview.js`, add the import and helper:

```js
import { verifiedCounts } from '../lib/scanLive.js';

export function summarizeVerifiedFindings(scans, vulnerabilities, enrichments) {
  let keptCount = 0;
  let impactProvenCount = 0;
  for (const scan of scans) {
    const id = `${scan.id}`;
    const counts = verifiedCounts({
      scan,
      vulnerabilities: vulnerabilities.filter((row) => `${row.scanId}` === id),
      enrichments: enrichments.filter((row) => `${row.scanId}` === id),
    });
    keptCount += counts.kept;
    impactProvenCount += counts.impactProven;
  }
  return { keptCount, impactProvenCount };
}
```

In the `GET /` handler, change the `focusVulns` query to select `id`, `scanId`, `jsonAnswer` and `dedupeIsCanonical`. Load the enrichments for the research scans, then add the verified counts to the response:

```js
    const focusVulns = researchIds.length
      ? await prisma.vulnerability.findMany({
          where: { scanId: { in: researchIds } },
          select: { id: true, scanId: true, jsonAnswer: true, dedupeIsCanonical: true },
        })
      : [];
    const focusEnrichments = researchIds.length
      ? await prisma.vulnerabilityEnrichment.findMany({
          where: { scanId: { in: researchIds } },
          select: { vulnerabilityId: true, scanId: true, postScriptId: true, stub: true, supplementalRunId: true, result: true },
          orderBy: { id: 'asc' },
        })
      : [];
    const { findingsCount, exploitableCount } = summarizeCanonicalFindings(focusVulns);
    const { keptCount, impactProvenCount } = summarizeVerifiedFindings(researchRaw, focusVulns, focusEnrichments);
```

and include `keptCount, impactProvenCount,` in the `res.json({...})` object next to `exploitableCount`.

In `backend/src/lib/repo.js` `findingCountsByScan(scanIds)`:
- add `keptFindings: 0` to `empty()`;
- change the signature to `findingCountsByScan(scans)` taking scan rows;
- compute `keptFindings` with `verifiedCounts` per scan from vulnerabilities (select `id`, `scanId`, `jsonAnswer`, `dedupeIsCanonical`) and a `vulnerabilityEnrichment.findMany` over the same scan ids (select as above).

Update both callers (`assembleScans` and the one near line 887) to pass scan rows and to copy `keptFindings: c.keptFindings` into the `serializeScan` counts. In `backend/src/lib/serialize.js`, accept `keptFindings = 0` next to `exploitable = 0` and emit `keptFindings` next to `exploitable`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && node --test test/scanLive.test.js test/dataIntegrity.test.js && npm test`
Expected: PASS; full suite `# fail 0`.

- [ ] **Step 5: Lint, format, commit**

```bash
cd backend && npx eslint src && npx prettier --write src/lib/scanLive.js src/routes/overview.js src/lib/repo.js src/lib/serialize.js test/scanLive.test.js test/dataIntegrity.test.js && npm test
cd .. && git add backend/src backend/test
git commit -m "feat(backend): expose D3-kept and impact-proven counts on overview and scans

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

