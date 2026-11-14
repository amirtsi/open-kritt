import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validateWorkflow } from '../backend/src/lib/validation.js';
import { parseWorkflowImport } from '../frontend/src/lib/workflowTransfer.js';

const packs = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../workflow-packs');
const v28Path = path.join(packs, 'web3-v2.8/01-solidity-vault-bug-class-review-v2.8.workflow.json');
const v27Path = path.join(packs, 'web3-v2.7/01-recall-first-verified-external-flow-review-v2.7.workflow.json');

async function load(file) {
  return parseWorkflowImport(await readFile(file, 'utf8'));
}

const levelAt = (workflow, depth) => workflow.levels.find((level) => level.depth === depth);
const refs = (content) => [...content.matchAll(/\{\{\s*([A-Za-z0-9_.]+)\s*\}\}/g)].map((match) => match[1]);
const FORBIDDEN_NAMES = /\b(onyx|enzyme|immunefi|hackenproof|ssv|somnia|chainlink|ccip)\b/i;

test('v2.8 is a valid gated workflow with three bug-class lanes and three impact agents', async () => {
  const workflow = await load(v28Path);
  assert.equal(workflow.name, 'Solidity Vault Bug-Class Review v2.8');
  validateWorkflow(workflow);
  assert.deepEqual(
    workflow.levels.map((level) => [level.depth, level.steps.length]),
    [
      [0, 1],
      [1, 3],
      [2, 3],
    ]
  );
  const d2 = levelAt(workflow, 2);
  assert.equal(d2.bindPrevious, false, 'every lane record must reach every impact agent');
  assert.ok(d2.steps.every((step) => step.boundSourceStepId === undefined));
});

test('v2.8 keeps the v2.7 output formats so D3, D4 and D5 apply unchanged', async () => {
  const [v28, v27] = await Promise.all([load(v28Path), load(v27Path)]);
  for (const depth of [0, 1, 2]) {
    assert.deepEqual(levelAt(v28, depth).outputFormat, levelAt(v27, depth).outputFormat, `depth ${depth}`);
  }
});

test('v2.8 lanes are bug classes and stub only when the entrypoint is irrelevant to the class', async () => {
  const lanes = levelAt(await load(v28Path), 1).steps;
  const focus = lanes.map((step) => step.content);
  assert.match(focus[0], /share and fee accounting/i);
  assert.match(focus[1], /request and queue lifecycle/i);
  assert.match(focus[2], /custody and value movement/i);
  for (const content of focus) {
    assert.match(content, /Return a stub ONLY when this entrypoint has no path relevant to this bug class/);
    assert.match(content, /Do NOT stub because guards look sufficient/);
  }
});

test('v2.8 runs one investigator per impact type with the v2.7 root-cause and exploitable rules', async () => {
  const investigators = levelAt(await load(v28Path), 2).steps;
  const impacts = investigators.map((step) => step.content);
  assert.match(impacts[0], /Hunt only for theft of funds/);
  assert.match(impacts[1], /Hunt only for freezing of funds/);
  assert.match(impacts[2], /Hunt only for protocol insolvency and broken value conservation/);
  for (const content of impacts) {
    assert.match(content, /Emit ONE record per root cause/);
    assert.match(content, /exploitable=true when the code shows an unprivileged, actor-controlled path/);
    assert.match(content, /\{\{lane_summary\}\}/);
  }
});

test('v2.8 points discovery at the deterministic access index and stays target-neutral', async () => {
  const workflow = await load(v28Path);
  assert.match(levelAt(workflow, 0).steps[0].content, /static-analysis\/ACCESS\.md/);
  for (const level of workflow.levels) {
    for (const step of level.steps) {
      assert.doesNotMatch(step.content, FORBIDDEN_NAMES, `${step.name} names a specific target`);
      for (const ref of refs(step.content)) {
        assert.match(ref, /^(repo_full|commit_sha|repo_scope|dependencies|configuration|entrypoint_\w+|lane_\w+)$/);
      }
    }
  }
});
