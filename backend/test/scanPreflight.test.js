import assert from 'node:assert/strict';
import { test } from 'node:test';

import { scanPreflight } from '../src/lib/scanPreflight.js';

const GATED = 'Solidity Vault Bug-Class Review v2.8';

function input(overrides = {}) {
  return {
    payload: {
      model_provider: 'codex',
      harness: 'codex',
      configuration: {
        investigation_kind: 'public_bounty',
        repeat_runs: 2,
        known_issue_sources: ['audits/'],
        deployment_context: 'Vault 0xabc on Ethereum with fee 50 bps',
        v27_after_d3: ['2', '6'],
      },
      jobLimit: null,
    },
    workflow: { name: GATED, steps: { 0: 1, 1: 3, 2: 3 }, unboundDepths: [2] },
    workerCount: 6,
    estimatedEntrypoints: null,
    activeResearchScanIds: [],
    optionalPostScripts: [
      { id: '2', name: 'Patched since' },
      { id: '6', name: 'Is Malicious Actor in scope' },
    ],
    ...overrides,
  };
}

const byId = (checks) => Object.fromEntries(checks.map((check) => [check.id, check]));
const withConfig = (configuration) => input({ payload: { ...input().payload, configuration } });

test('a well-prepared gated scan raises no warnings', () => {
  const checks = scanPreflight(input());
  assert.deepEqual(
    checks.filter((check) => check.level === 'warn' || check.level === 'block'),
    []
  );
});

test('a local model for discovery and a non-native harness are flagged', () => {
  const local = byId(
    scanPreflight(input({ payload: { ...input().payload, model_provider: 'ollama', harness: 'ollama' } }))
  );
  assert.equal(local.discovery_model.level, 'warn');
  const routed = byId(
    scanPreflight(input({ payload: { ...input().payload, model_provider: 'openrouter', harness: 'codex' } }))
  );
  assert.equal(routed.native_harness.level, 'info');
});

test('high-value investigations are nudged to repeat runs, workers, and optional post-scripts', () => {
  const configuration = { ...input().payload.configuration, repeat_runs: 1, v27_after_d3: [] };
  const checks = byId(scanPreflight({ ...withConfig(configuration), workerCount: 3 }));
  assert.equal(checks.repeat_runs.level, 'info');
  assert.equal(checks.workers.level, 'info');
  assert.equal(checks.after_d3.level, 'info');
  assert.match(checks.after_d3.message, /"2", "6"/);
});

test('missing production configuration and known-issue sources are warnings', () => {
  const checks = byId(scanPreflight(withConfig({ investigation_kind: 'public_bounty', repeat_runs: 2 })));
  assert.equal(checks.deployment_context.level, 'warn');
  assert.equal(checks.known_issues.level, 'warn');
});

test('budget estimates jobs from the workflow shape and flags a job limit below it', () => {
  const estimated = byId(scanPreflight(input({ estimatedEntrypoints: 70 })));
  // 70 entrypoints x 3 lanes at D1, x 3 unbound investigators at D2, twice for repeat_runs=2, plus D0.
  assert.equal(estimated.budget.estimatedJobs, 2 * (1 + 70 * 3 + 70 * 3 * 3));
  assert.equal(estimated.budget.level, 'info');

  const limited = byId(
    scanPreflight(input({ estimatedEntrypoints: 70, payload: { ...input().payload, jobLimit: 500 } }))
  );
  assert.equal(limited.budget.level, 'warn');

  const unknown = byId(scanPreflight(input()));
  assert.equal(unknown.budget.estimatedJobs, null);
});

test('another active scan on the same research is reported', () => {
  const checks = byId(scanPreflight(input({ activeResearchScanIds: ['26'] })));
  assert.equal(checks.active_research.level, 'info');
  assert.match(checks.active_research.message, /#26/);
});

test('ungated workflows skip v2.7-only checks', () => {
  const checks = byId(
    scanPreflight(input({ workflow: { name: 'external-flow-analysis', steps: { 0: 1 }, unboundDepths: [] } }))
  );
  assert.equal(checks.after_d3, undefined);
  assert.equal(checks.repeat_runs, undefined);
});

test('preflight inputs come from the workflow shape, settings, and the research history', async () => {
  const { loadPreflightInputs } = await import('../src/lib/scanPreflight.js');
  const scans = [
    {
      id: 26n,
      status: 'completed',
      workflowId: 28n,
      repoFull: 'enzyme-onyx',
      configuration: { program: 'Immunefi Enzyme Onyx' },
      insertedAt: new Date(2),
    },
    {
      id: 22n,
      status: 'running',
      workflowId: 28n,
      repoFull: 'ssv-network',
      configuration: { program: 'Immunefi SSV Network' },
      insertedAt: new Date(1),
    },
  ];
  const db = {
    workflow: { findUnique: async () => ({ id: 30n, name: GATED, stepIds: [1n, 2n, 3n, 4n, 5n, 6n, 7n] }) },
    step: {
      findMany: async ({ where }) =>
        where.id.in.length === 7
          ? [
              { id: 1n, depth: 0, boundSourceStepId: null },
              ...[2n, 3n, 4n].map((id) => ({ id, depth: 1, boundSourceStepId: null })),
              ...[5n, 6n, 7n].map((id) => ({ id, depth: 2, boundSourceStepId: null })),
            ]
          : [{ id: 277n, depth: 0, boundSourceStepId: null }],
    },
    scan: { findMany: async () => scans },
    stepResult: { count: async ({ where }) => (where.scanId === 26n && where.stepId.in[0] === 277n ? 74 : 0) },
    postScript: {
      findMany: async () => [
        { id: 2n, name: 'Patched since' },
        { id: 6n, name: 'Is Malicious Actor in scope' },
      ],
    },
  };
  db.workflow.findUnique = async ({ where }) =>
    where.id === 30n
      ? { id: 30n, name: GATED, stepIds: [1n, 2n, 3n, 4n, 5n, 6n, 7n] }
      : { id: 28n, name: 'v2.7', stepIds: [277n] };

  const inputs = await loadPreflightInputs(
    db,
    { workflowId: '30', configuration: { program: 'Immunefi Enzyme Onyx' } },
    { readSettings: async () => ({ settings: { workerCount: { value: 3 } } }) }
  );

  assert.deepEqual(inputs.workflow, { name: GATED, steps: { 0: 1, 1: 3, 2: 3 }, unboundDepths: [1, 2] });
  assert.equal(inputs.workerCount, 3);
  assert.equal(inputs.estimatedEntrypoints, 74);
  assert.deepEqual(inputs.activeResearchScanIds, []);
  assert.deepEqual(inputs.optionalPostScripts, [
    { id: '2', name: 'Patched since' },
    { id: '6', name: 'Is Malicious Actor in scope' },
  ]);
});

test('the preflight route validates the workflow and returns the checks', async () => {
  const { scanPreflightHandler } = await import('../src/routes/scans.js');
  const respond = () => ({
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
  });
  const handler = scanPreflightHandler({ loadInputs: async () => input() });

  const missing = respond();
  await handler({ body: {} }, missing, (error) => {
    throw error;
  });
  assert.equal(missing.statusCode, 400);

  const ok = respond();
  await handler({ body: { workflowId: '30', model_provider: 'codex', harness: 'codex' } }, ok, (error) => {
    throw error;
  });
  assert.ok(Array.isArray(ok.body.checks));
  assert.ok(ok.body.checks.some((row) => row.id === 'budget'));
});
