import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveV27Pipeline, V27_POST_SCRIPT_NAMES, V27_WORKFLOW_NAME } from '../src/lib/v27Pipeline.js';

const scripts = Object.entries(V27_POST_SCRIPT_NAMES).map(([stage, name], index) => ({
  id: BigInt(index + 11),
  name,
  stage,
}));

test('v2.7 resolves its three ordered post-processing stages', async () => {
  const db = {
    workflow: { findUnique: async () => ({ name: V27_WORKFLOW_NAME }) },
    postScript: { findMany: async () => [...scripts].reverse() },
  };
  assert.deepEqual(await resolveV27Pipeline(db, 28), { d3: '11', d4: '12', d5: '13' });
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
