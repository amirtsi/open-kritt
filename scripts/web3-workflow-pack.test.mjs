import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validateWorkflow } from '../backend/src/lib/validation.js';
import { parseWorkflowImport } from '../frontend/src/lib/workflowTransfer.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../workflow-packs/web3-v2.3');

async function workflowDocuments() {
  const filenames = (await readdir(root)).filter((name) => name.endsWith('.workflow.json')).sort();
  return Promise.all(
    filenames.map(async (filename) => ({
      filename,
      document: JSON.parse(await readFile(path.join(root, filename), 'utf8')),
    }))
  );
}

test('v2.3 workflows use progressive fan-out and pass the production validators', async () => {
  const documents = await workflowDocuments();
  assert.equal(documents.length, 7);

  for (const { filename, document } of documents) {
    const imported = parseWorkflowImport(JSON.stringify(document));
    const valid = validateWorkflow(imported);
    const finalLevel = imported.levels.at(-1);
    const references = [...JSON.stringify(imported).matchAll(/\{\{([A-Za-z0-9_.]+)\}\}/g)].map((match) => match[1]);

    assert.match(imported.name, /Progressive v2\.3$/, filename);
    assert.equal(valid.maxDepth, imported.levels.length - 1, filename);
    assert.equal(finalLevel.multiOutput, true, filename);
    assert.equal(finalLevel.steps.length, 1, filename);
    assert.equal(
      imported.levels.some((level) => level.consumesAll),
      false,
      filename
    );
    assert.equal(
      references.some((key) => key.startsWith('dedup_')),
      false,
      filename
    );
    assert.equal(
      references.some((key) => key.startsWith('program_')),
      false,
      filename
    );
  }
});

test('v2.3 bundle matches the seven portable workflow files', async () => {
  const documents = await workflowDocuments();
  const bundle = JSON.parse(await readFile(path.join(root, '_all_workflows_v2.json'), 'utf8'));

  assert.deepEqual(
    bundle.map((document) => document.workflow.name),
    documents.map(({ document }) => document.workflow.name)
  );
});
