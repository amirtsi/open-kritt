// backend/test/scanLive.test.js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildActivity,
  buildDropouts,
  buildFunnel,
  loadScanLive,
  normalizeStubReason,
  verifiedCounts,
  verifiedCountsByScan,
} from '../src/lib/scanLive.js';

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
    enrich(1, 16, {
      _engine_readiness: {
        ready: false,
        blocking_reasons: ["Material assumption 'A2' is still open.", "Material assumption 'A3' is still open."],
      },
    }),
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
    ...steps.map((step, n) =>
      stepRow(100 + n, Number(step.id), 'completed', 1, {
        stub: true,
        stubExplanation: `reason ${String.fromCharCode(97 + n)}`,
      })
    ),
    ...Array.from({ length: 60 }, (_, n) =>
      stepRow(500 + n, 1, 'completed', 1, { stub: true, stubExplanation: 'same reason' })
    ),
  ];
  const { stubs } = buildDropouts({ scan: scan(), steps, stepMetadata, vulnerabilities: [], enrichments: [] });

  assert.equal(stubs.groups.length, 20);
  assert.equal(stubs.more, 6);
  const biggest = stubs.groups[0];
  assert.equal(biggest.count, 60);
  assert.equal(biggest.entries.length, 50);
  assert.equal(biggest.more, 10);
});

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
  const live = await loadScanLive(
    db,
    { id: 26n, workflowId: 28n, status: 'running', configuration: { v27_pipeline: PIPELINE } },
    { activeJobs: [], now: NOW }
  );

  assert.equal(live.scanId, '26');
  assert.equal(live.funnel[0].count, 1);
  assert.deepEqual(Object.keys(live.dropouts), ['stubs', 'd3', 'blockers']);
  const enrichmentCall = calls.find(([name]) => name === 'vulnerabilityEnrichment')[1];
  assert.equal(enrichmentCall.select.result, true);
  const metadataCall = calls.find(([name]) => name === 'stepMetadata')[1];
  assert.equal(metadataCall.select.promptFilled, undefined);
  assert.equal(metadataCall.select.stubExplanation, true);
});

test('verified counts sum kept and impact-proven findings per scan', () => {
  const counts = verifiedCounts({
    scan: scan(),
    vulnerabilities: [vuln(1, true), vuln(2, true)],
    enrichments: [
      enrich(1, 15, { verdict: 'confirmed' }),
      enrich(2, 15, { verdict: 'plausible_needs_poc' }),
      enrich(1, 13, {
        _engine_evidence: { bug_status: 'reproduced', impact_status: 'proven', capture_complete: true },
      }),
    ],
  });
  assert.deepEqual(counts, { kept: 2, impactProven: 1 });
});

test('running post-script jobs are measured against completed runs of the same script', async () => {
  const mirror = (id, status, runTimeMs) => ({
    id: BigInt(id),
    kind: 'post_script',
    postScriptId: 13n,
    vulnerabilityId: BigInt(id),
    batchIndex: null,
    status,
    runTimeMs,
    updatedAt: minutesAgo(40),
    error: null,
  });
  const stepMetadataRows = (args) =>
    args.where.kind === 'step'
      ? []
      : [
          mirror(901, 'completed', 60_000),
          mirror(902, 'completed', 60_000),
          mirror(903, 'completed', 60_000),
          mirror(900, 'running', null),
        ];
  const db = {
    workflow: { findUnique: async () => ({ stepIds: [] }) },
    step: { findMany: async () => [] },
    stepMetadata: { findMany: async (args) => stepMetadataRows(args) },
    postProcessMetadata: {
      findMany: async () => [
        {
          id: 900n,
          kind: 'post_script',
          postScriptId: 15n,
          status: 'completed',
          runTimeMs: 1,
          updatedAt: minutesAgo(50),
          error: null,
        },
      ],
    },
    vulnerability: { findMany: async () => [] },
    vulnerabilityEnrichment: { findMany: async () => [] },
  };
  const activeJobs = [
    {
      metadataId: '900',
      kind: 'post_script',
      title: 'D4 · Local PoC',
      phaseLabel: 'Running harness',
      startedAt: minutesAgo(30),
      model: 'claude-opus-5',
    },
  ];

  const live = await loadScanLive(
    db,
    { id: 26n, workflowId: 28n, status: 'post_processing', configuration: { v27_pipeline: PIPELINE } },
    { activeJobs, now: NOW }
  );

  assert.equal(live.activity.jobs[0].medianMs, 60_000);
  assert.equal(live.activity.jobs[0].slow, true);
});

test('an error is recovered only by a later success of the same lineage or finding', () => {
  const post = (id, vulnerabilityId, status, minutes) => ({
    id: BigInt(id),
    kind: 'post_script',
    postScriptId: 13n,
    vulnerabilityId: BigInt(vulnerabilityId),
    batchIndex: null,
    status,
    runTimeMs: 1000,
    updatedAt: minutesAgo(minutes),
    error: status === 'failed' ? 'poc failed' : null,
  });
  const { recentErrors } = buildActivity({
    activeJobs: [],
    stepMetadata: [
      stepRow(1, 281, 'failed', null, {
        prevTable: 'step_results',
        prevId: 5n,
        repeatRun: 0,
        updatedAt: minutesAgo(20),
        error: 'x',
      }),
      stepRow(2, 281, 'completed', 1000, {
        prevTable: 'step_results',
        prevId: 6n,
        repeatRun: 0,
        updatedAt: minutesAgo(10),
      }),
      stepRow(3, 281, 'failed', null, {
        prevTable: 'step_results',
        prevId: 7n,
        repeatRun: 0,
        updatedAt: minutesAgo(20),
        error: 'y',
      }),
      stepRow(4, 281, 'completed', 1000, {
        prevTable: 'step_results',
        prevId: 7n,
        repeatRun: 0,
        updatedAt: minutesAgo(10),
      }),
    ],
    postMetadata: [post(10, 17, 'failed', 20), post(11, 42, 'completed', 10)],
    now: NOW,
  });
  const recovered = Object.fromEntries(recentErrors.map((row) => [row.metadataId, row.recovered]));
  assert.deepEqual(recovered, { 1: false, 3: true, 10: false });
});

test('verified counts per scan query only pipeline scans, D3 and D4 rows, and attribute rows to their scan', async () => {
  const calls = [];
  const db = {
    vulnerability: {
      findMany: async (args) => {
        calls.push(['vulnerability', args]);
        return [
          { id: 1n, scanId: 21n, dedupeIsCanonical: true },
          { id: 2n, scanId: 26n, dedupeIsCanonical: true },
        ];
      },
    },
    vulnerabilityEnrichment: {
      findMany: async (args) => {
        calls.push(['enrichment', args]);
        return [
          {
            vulnerabilityId: 1n,
            scanId: 21n,
            postScriptId: 12n,
            stub: false,
            supplementalRunId: null,
            result: { verdict: 'confirmed' },
          },
          {
            vulnerabilityId: 1n,
            scanId: 21n,
            postScriptId: 13n,
            stub: false,
            supplementalRunId: null,
            result: { _engine_evidence: { bug_status: 'reproduced', impact_status: 'proven', capture_complete: true } },
          },
          {
            vulnerabilityId: 2n,
            scanId: 26n,
            postScriptId: 15n,
            stub: false,
            supplementalRunId: null,
            result: { verdict: 'false_positive' },
          },
        ];
      },
    },
  };
  const scans = [
    { id: 21n, configuration: { v27_pipeline: { d3: '12', d4: '13', d5: '14' } } },
    { id: 26n, configuration: { v27_pipeline: { d3: '15', d4: '13', d5: '16' } } },
    { id: 5n, configuration: {} },
  ];

  const counts = await verifiedCountsByScan(db, scans);

  assert.deepEqual(Object.fromEntries(counts), {
    21: { kept: 1, impactProven: 1 },
    26: { kept: 0, impactProven: 0 },
    5: { kept: 0, impactProven: 0 },
  });
  const where = calls.find(([name]) => name === 'enrichment')[1].where;
  assert.equal(where.supplementalRunId, null);
  assert.deepEqual(
    where.OR.map((clause) => [clause.scanId, clause.postScriptId.in]),
    [
      [21n, [12n, 13n]],
      [26n, [15n, 13n]],
    ]
  );
  assert.equal(calls.find(([name]) => name === 'vulnerability')[1].select.jsonAnswer, undefined);
});

test('verified counts per scan skip the database when no scan has a pipeline', async () => {
  const db = {
    vulnerability: { findMany: async () => assert.fail('no query expected') },
    vulnerabilityEnrichment: { findMany: async () => assert.fail('no query expected') },
  };
  assert.deepEqual(Object.fromEntries(await verifiedCountsByScan(db, [{ id: 5n, configuration: {} }])), {
    5: { kept: 0, impactProven: 0 },
  });
});
