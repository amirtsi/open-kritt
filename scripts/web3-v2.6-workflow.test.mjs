import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validateWorkflow } from '../backend/src/lib/validation.js';
import { parseWorkflowImport } from '../frontend/src/lib/workflowTransfer.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../workflow-packs/web3-v2.6');
const workflowPath = path.join(root, '01-recall-first-external-flow-review-v2.6.workflow.json');

async function loadWorkflow() {
  return parseWorkflowImport(await readFile(workflowPath, 'utf8'));
}

test('v2.6 recall-first workflow is importable and preserves branch-local discovery', async () => {
  const imported = await loadWorkflow();
  const valid = validateWorkflow(imported);

  assert.match(imported.name, /Recall-First .* v2\.6$/);
  assert.equal(valid.maxDepth, 2);
  assert.deepEqual(
    imported.levels.map((level) => level.multiOutput),
    [true, true, true]
  );
  assert.equal(imported.levels.some((level) => level.consumesAll), false);
  assert.equal(imported.levels[2].steps.length, 3);
  assert.equal(imported.levels[2].multiOutput, true);
});

test('v2.6 discovers technical candidates before precision and program gates', async () => {
  const imported = await loadWorkflow();
  const terminalPrompts = imported.levels[2].steps.map((step) => step.content).join('\n');
  const allPrompts = imported.levels.flatMap((level) => level.steps.map((step) => step.content)).join('\n');

  assert.match(terminalPrompts, /stage skipping/i);
  assert.match(terminalPrompts, /replay across sessions or domains/i);
  assert.match(terminalPrompts, /trailing or unused bits/i);
  assert.match(terminalPrompts, /panic\/exception\/fatal paths/i);
  assert.match(terminalPrompts, /consensus-process crash/i);
  assert.match(terminalPrompts, /cross-component invariant/i);
  assert.match(terminalPrompts, /must not be suppressed/i);
  assert.match(terminalPrompts, /set exploitable=false and (?:state|name|preserve)/i);
  assert.doesNotMatch(allPrompts, /\{\{extra\./);
});

test('v2.6 keeps the terminal finding contract small and standard', async () => {
  const imported = await loadWorkflow();
  const terminalKeys = Object.keys(imported.levels.at(-1).outputFormat).sort();

  assert.deepEqual(terminalKeys, [
    'explanation',
    'exploitable',
    'file_path',
    'line',
    'malicious_actor',
    'malicious_input_example',
    'summary',
    'trigger_flow',
    'vulnerability_type',
  ]);
});
