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
