import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validatePostScript, validateWorkflow } from '../backend/src/lib/validation.js';
import { parseWorkflowImport } from '../frontend/src/lib/workflowTransfer.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../workflow-packs/web3-v2.7');
const workflowPath = path.join(root, '01-recall-first-verified-external-flow-review-v2.7.workflow.json');

async function loadWorkflow() {
  return parseWorkflowImport(await readFile(workflowPath, 'utf8'));
}

test('v2.7 bounds fan-out and routes each D1 lane only to its matching D2 investigator', async () => {
  const workflow = await loadWorkflow();
  const valid = validateWorkflow(workflow);

  assert.equal(valid.maxDepth, 2);
  assert.deepEqual(valid.levels.map((level) => level.steps.length), [1, 3, 3]);
  assert.equal(valid.levels[0].multiOutput, true);
  assert.equal(valid.levels[1].multiOutput, false);
  assert.equal(valid.levels[2].multiOutput, true);
  assert.ok(valid.levels.every((level) => !level.consumesAll));
  assert.equal(valid.levels[1].bindPrevious, false);
  assert.equal(valid.levels[2].bindPrevious, true);
  assert.deepEqual(
    valid.levels[2].steps.map((step) => step.boundSourceStepId),
    valid.levels[1].steps.map((step) => step.clientId)
  );
  assert.match(valid.levels[1].steps[0].content, /AT MOST ONE output record/);
  assert.match(valid.levels[2].steps[0].content, /ONE record per root cause/);
});

test('v2.7 persists D2 candidates before post-processing and defines separate D3, D4, D5 scripts', async () => {
  const workflow = await loadWorkflow();
  const terminal = workflow.levels[2].outputFormat;
  for (const key of [
    'summary', 'explanation', 'file_path', 'line', 'trigger_flow', 'malicious_actor',
    'malicious_input_example', 'vulnerability_type', 'root_cause_fingerprint', 'fix_locus',
  ]) {
    assert.ok(key in terminal, key);
  }

  const names = [
    'd3-hostile-verification.post-script.json',
    'd4-local-poc.post-script.json',
    'd5-report-readiness.post-script.json',
  ];
  const scripts = await Promise.all(names.map(async (name) =>
    JSON.parse(await readFile(path.join(root, 'post-scripts', name), 'utf8'))
  ));
  scripts.forEach((script) => validatePostScript(script));
  assert.equal(scripts[0].outputFormat.verdict, 'string');
  assert.equal(scripts[1].outputFormat.poc_artifact_paths, 'array');
  assert.equal(scripts[2].outputFormat.submission_ready, 'boolean');
});
