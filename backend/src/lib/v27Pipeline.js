import { ValidationError } from './validation.js';

export const V27_WORKFLOW_NAME = 'Recall-First External Flow Review v2.7';
// Workflows whose scans use the gated D3 -> D4 -> D5 pipeline and readiness policy.
export const V27_GATED_WORKFLOW_NAMES = Object.freeze([
  V27_WORKFLOW_NAME,
  'Solidity Vault Bug-Class Review v2.8',
  'Solidity Staking Registry Bug-Class Review v2.8',
]);
// Identifier of the deterministic readiness policy the engine applies to
// findings of the v2.7 workflow. Snapshotted into each gated scan's
// configuration; the engine dispatches on the exact string.
export const READINESS_POLICY_VERSION = 'v2.7-impact-gate-1';
export const V27_POST_SCRIPT_NAMES = Object.freeze({
  d3: 'v2.7 D3 Hostile Canonical Verification',
  d4: 'v2.7 D4 Local PoC and Negative Control',
  d5: 'v2.7 D5 Scope Severity and Report Readiness',
});

// A scan snapshots the three immutable post-script IDs. Other workflows keep
// their ordinary post-script configuration and existing scans never change.
export async function resolveV27Pipeline(db, workflowId, { afterD3 = [] } = {}) {
  const workflow = await db.workflow.findUnique({
    where: { id: BigInt(workflowId) },
    select: { name: true },
  });
  if (!V27_GATED_WORKFLOW_NAMES.includes(workflow?.name)) return null;

  const scripts = await db.postScript.findMany({
    where: { name: { in: Object.values(V27_POST_SCRIPT_NAMES) } },
    orderBy: { id: 'desc' },
    select: { id: true, name: true },
  });
  const ids = {};
  for (const [stage, name] of Object.entries(V27_POST_SCRIPT_NAMES)) {
    const script = scripts.find((candidate) => candidate.name === name);
    if (!script) {
      throw new ValidationError([
        { field: 'workflowId', message: `v2.7 requires post-script "${name}" before a scan can start.` },
      ]);
    }
    ids[stage] = script.id.toString();
  }
  return {
    ...ids,
    afterD3: await resolveAfterD3(db, afterD3, Object.values(ids)),
    readinessPolicyVersion: READINESS_POLICY_VERSION,
  };
}

// Optional post-scripts that run only on findings D3 kept, before D4.
async function resolveAfterD3(db, requested, pipelineIds) {
  const values = Array.isArray(requested) ? requested : [];
  const ids = [...new Set(values.map((value) => `${value}`.trim()))];
  const invalid = ids.filter((id) => !/^\d+$/.test(id) || pipelineIds.includes(id));
  const found = ids.length
    ? await db.postScript.findMany({
        where: { id: { in: ids.filter((id) => /^\d+$/.test(id)).map(BigInt) } },
        select: { id: true },
      })
    : [];
  const existing = new Set(found.map((row) => row.id.toString()));
  const missing = ids.filter((id) => /^\d+$/.test(id) && !existing.has(id));
  if (invalid.length || missing.length) {
    throw new ValidationError([
      {
        field: 'configuration.v27_after_d3',
        message: `after_d3 post-scripts must be existing post-scripts other than D3, D4 and D5: ${[...invalid, ...missing].join(', ')}.`,
      },
    ]);
  }
  return ids;
}

export function v27PostScriptOrder(pipeline) {
  return [pipeline.d3, ...(pipeline.afterD3 || []), pipeline.d4, pipeline.d5];
}
