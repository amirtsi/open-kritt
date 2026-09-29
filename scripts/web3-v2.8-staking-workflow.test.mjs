import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validateWorkflow } from '../backend/src/lib/validation.js';
import { parseWorkflowImport } from '../frontend/src/lib/workflowTransfer.js';

const packs = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../workflow-packs');
const stakingPath = path.join(packs, 'web3-v2.8/02-solidity-staking-registry-bug-class-review-v2.8.workflow.json');
const vaultPath = path.join(packs, 'web3-v2.8/01-solidity-vault-bug-class-review-v2.8.workflow.json');

async function load(file) {
  return parseWorkflowImport(await readFile(file, 'utf8'));
}

const levelAt = (workflow, depth) => workflow.levels.find((level) => level.depth === depth);
const refs = (content) => [...content.matchAll(/\{\{\s*([A-Za-z0-9_.]+)\s*\}\}/g)].map((match) => match[1]);
const FORBIDDEN_NAMES = /\b(onyx|enzyme|immunefi|hackenproof|ssv|somnia|chainlink|ccip|lido|eigen)\b/i;

test('the staking variant is a valid gated workflow with three lanes and three unbound impact agents', async () => {
  const workflow = await load(stakingPath);
  assert.equal(workflow.name, 'Solidity Staking Registry Bug-Class Review v2.8');
  validateWorkflow(workflow);
  assert.deepEqual(
    workflow.levels.map((level) => [level.depth, level.steps.length]),
    [
      [0, 1],
      [1, 3],
      [2, 3],
    ]
  );
  assert.equal(levelAt(workflow, 2).bindPrevious, false);
});

test('the staking variant keeps the shared output formats and D0 prompt', async () => {
  const [staking, vault] = await Promise.all([load(stakingPath), load(vaultPath)]);
  for (const depth of [0, 1, 2]) {
    assert.deepEqual(levelAt(staking, depth).outputFormat, levelAt(vault, depth).outputFormat, `depth ${depth}`);
  }
  assert.equal(levelAt(staking, 0).steps[0].content, levelAt(vault, 0).steps[0].content);
});

test('staking lanes cover balance accounting, registry and oracle lifecycle, and custody', async () => {
  const focus = levelAt(await load(stakingPath), 1).steps.map((step) => step.content);
  assert.match(focus[0], /balance and fee accounting/i);
  assert.match(focus[1], /registry and oracle lifecycle/i);
  assert.match(focus[1], /merkle|proof/i);
  assert.match(focus[1], /quorum/i);
  assert.match(focus[2], /custody and value movement/i);
  for (const content of focus) {
    assert.doesNotMatch(content, /request and queue lifecycle/i);
    assert.match(content, /Return a stub ONLY when this entrypoint has no path relevant to this bug class/);
    assert.match(content, /Do NOT stub because guards look sufficient/);
  }
});

test('staking impact agents name staking victims and keep the root-cause rules', async () => {
  const impacts = levelAt(await load(stakingPath), 2).steps.map((step) => step.content);
  assert.match(impacts[0], /Hunt only for theft of funds/);
  assert.match(impacts[1], /Hunt only for freezing of funds/);
  assert.match(impacts[2], /Hunt only for protocol insolvency and broken value conservation/);
  for (const content of impacts) {
    assert.match(content, /stakers|operators/);
    assert.doesNotMatch(content, /\bthe vault\b/);
    assert.match(content, /Emit ONE record per root cause/);
    assert.match(content, /\{\{lane_summary\}\}/);
  }
});

test('the staking variant stays target-neutral and uses only known template variables', async () => {
  const workflow = await load(stakingPath);
  for (const level of workflow.levels) {
    for (const step of level.steps) {
      assert.doesNotMatch(step.content, FORBIDDEN_NAMES, `${step.name} names a specific target`);
      for (const ref of refs(step.content)) {
        assert.match(ref, /^(repo_full|commit_sha|repo_scope|dependencies|configuration|entrypoint_\w+|lane_\w+)$/);
      }
    }
  }
});
