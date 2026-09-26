// backend/test/scanLive.test.js
import assert from 'node:assert/strict';
import test from 'node:test';

import { buildActivity, buildFunnel } from '../src/lib/scanLive.js';

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
const attempt = (kind, postScriptId = null) => ({
  kind,
  postScriptId: postScriptId && BigInt(postScriptId),
  status: 'completed',
});
const byId = (stages) => Object.fromEntries(stages.map((stage) => [stage.id, stage]));

test('funnel waits for dedupe before counting canonical findings', () => {
  const stages = byId(
    buildFunnel({ scan: scan(), vulnerabilities: [vuln(1, null), vuln(2, null)], enrichments: [], postMetadata: [] })
  );
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
    enrich(1, 16, {
      _engine_readiness: { ready: false, blocking_reasons: ["Material assumption 'A2' is still open."] },
    }),
  ];
  const postMetadata = [
    attempt('dedupe'),
    attempt('post_script', 15),
    attempt('v27_poc', 13),
    attempt('post_script', 16),
  ];
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
      enrichments: [enrich(1, 15, {}, true), { ...enrich(2, 15, { verdict: 'confirmed' }), supplementalRunId: 7n }],
      postMetadata: [attempt('dedupe'), attempt('post_script', 15)],
    })
  );
  assert.equal(stages.d3_kept.count, 0);
  assert.deepEqual(stages.d3_kept.dropped, { stub: 1 });
  assert.equal(stages.d3_kept.pending, 1);
});

test('a scan without a v2.7 pipeline reports raw and canonical only', () => {
  const stages = buildFunnel({
    scan: scan({}),
    vulnerabilities: [vuln(1, true)],
    enrichments: [],
    postMetadata: [attempt('dedupe')],
  });
  assert.deepEqual(
    stages.map((stage) => stage.id),
    ['raw', 'canonical']
  );
});

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
    {
      metadataId: '4',
      kind: 'step',
      title: '2 · Investigate authority',
      phaseLabel: 'Running harness',
      startedAt: minutesAgo(5),
      model: 'gpt-6-sol',
    },
    {
      metadataId: '5',
      kind: 'step',
      title: '2 · Investigate protocol',
      phaseLabel: 'Running harness',
      startedAt: minutesAgo(50),
      model: 'gpt-6-sol',
    },
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
      stepRow(10 + n, 281, n === 6 ? 'interrupted' : 'failed', null, {
        updatedAt: minutesAgo(10 - n),
        error: `boom ${n}`,
      })
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
