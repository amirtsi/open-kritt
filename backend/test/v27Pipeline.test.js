import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  READINESS_POLICY_VERSION,
  resolveV27Pipeline,
  V27_GATED_WORKFLOW_NAMES,
  v27PostScriptOrder,
  V27_POST_SCRIPT_NAMES,
  V27_WORKFLOW_NAME,
} from '../src/lib/v27Pipeline.js';

const scripts = Object.entries(V27_POST_SCRIPT_NAMES).map(([stage, name], index) => ({
  id: BigInt(index + 11),
  name,
  stage,
}));

test('the readiness policy identifier is the v2.7 impact gate', () => {
  assert.equal(READINESS_POLICY_VERSION, 'v2.7-impact-gate-1');
});

test('v2.7 resolves its three ordered post-processing stages and the readiness policy', async () => {
  const db = {
    workflow: { findUnique: async () => ({ name: V27_WORKFLOW_NAME }) },
    postScript: { findMany: async () => [...scripts].reverse() },
  };
  assert.deepEqual(await resolveV27Pipeline(db, 28), {
    d3: '11',
    d4: '12',
    d5: '13',
    afterD3: [],
    readinessPolicyVersion: READINESS_POLICY_VERSION,
  });
});

test('other workflows are unaffected and missing v2.7 stages fail closed', async () => {
  const other = { workflow: { findUnique: async () => ({ name: 'v2.6' }) } };
  assert.equal(await resolveV27Pipeline(other, 1), null);
  const missing = {
    workflow: { findUnique: async () => ({ name: V27_WORKFLOW_NAME }) },
    postScript: { findMany: async () => scripts.slice(0, 2) },
  };
  await assert.rejects(resolveV27Pipeline(missing, 28), { status: 422 });
});

const extraScripts = [
  { id: 2n, name: 'Patched since' },
  { id: 6n, name: 'Is Malicious Actor in scope' },
];

function gatedDb(workflowName = V27_WORKFLOW_NAME) {
  return {
    workflow: { findUnique: async () => ({ name: workflowName }) },
    postScript: {
      findMany: async ({ where }) =>
        where.name ? [...scripts].reverse() : extraScripts.filter((row) => where.id.in.includes(row.id)),
    },
  };
}

test('v2.7 snapshots validated after-D3 post-scripts in the order given', async () => {
  const resolved = await resolveV27Pipeline(gatedDb(), 28, { afterD3: ['6', '2', '6'] });
  assert.deepEqual(resolved.afterD3, ['6', '2']);
  assert.deepEqual(v27PostScriptOrder(resolved), ['11', '6', '2', '12', '13']);
});

const afterD3Error = (error) => error.errors?.[0]?.field === 'configuration.v27_after_d3';

test('after-D3 post-scripts must exist and must not repeat a pipeline stage', async () => {
  await assert.rejects(resolveV27Pipeline(gatedDb(), 28, { afterD3: ['999'] }), afterD3Error);
  await assert.rejects(resolveV27Pipeline(gatedDb(), 28, { afterD3: ['11'] }), afterD3Error);
  await assert.rejects(resolveV27Pipeline(gatedDb(), 28, { afterD3: ['abc'] }), afterD3Error);
});

test('without extras the pipeline order is unchanged', async () => {
  const resolved = await resolveV27Pipeline(gatedDb(), 28);
  assert.deepEqual(resolved.afterD3, []);
  assert.deepEqual(v27PostScriptOrder(resolved), ['11', '12', '13']);
});

test('the Solidity vault bug-class workflow uses the same gated pipeline', async () => {
  assert.ok(V27_GATED_WORKFLOW_NAMES.includes('Solidity Vault Bug-Class Review v2.8'));
  const resolved = await resolveV27Pipeline(gatedDb('Solidity Vault Bug-Class Review v2.8'), 30);
  assert.equal(resolved.d3, '11');
});
