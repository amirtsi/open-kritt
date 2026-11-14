import assert from 'node:assert/strict';
import test from 'node:test';

import { researchLabel, selectResearchScans } from '../src/lib/researchScope.js';

const ACTIVE = ['prewarming_cache', 'running', 'post_processing'];
const day = (n) => new Date(Date.UTC(2026, 8, n));

function scan(id, { program, status = 'completed', inserted = id, updated = inserted, repoFull = 'repo' } = {}) {
  return {
    id: BigInt(id),
    status,
    repoFull,
    insertedAt: day(inserted),
    updatedAt: day(updated),
    configuration: program ? { program } : {},
  };
}

const SCANS = [
  scan(21, { program: 'Immunefi SSV Network', repoFull: 'ssv-network', inserted: 1, updated: 2 }),
  scan(22, { program: 'Immunefi SSV Network', repoFull: 'ssv-network', inserted: 3, updated: 4 }),
  scan(23, { program: 'Immunefi Enzyme Onyx', repoFull: 'enzyme-onyx', inserted: 5, updated: 6 }),
  scan(24, { program: 'Immunefi Enzyme Onyx', repoFull: 'enzyme-onyx', status: 'failed', inserted: 7, updated: 8 }),
  scan(26, { program: 'Immunefi Enzyme Onyx', repoFull: 'enzyme-onyx', status: 'running', inserted: 9, updated: 10 }),
];

test('research label prefers the program, then research id, then the repository', () => {
  assert.equal(researchLabel(scan(1, { program: 'Immunefi Enzyme Onyx' })), 'Immunefi Enzyme Onyx');
  assert.equal(researchLabel({ ...scan(2), configuration: { research_id: 'somnia-2025' } }), 'somnia-2025');
  assert.equal(researchLabel(scan(3, { repoFull: 'owner/repo' })), 'owner/repo');
});

test('an explicit research anchor selects only scans from the same research, newest update first', () => {
  const result = selectResearchScans(SCANS, { research: '22', activeStatuses: ACTIVE });

  assert.deepEqual(
    result.scans.map((item) => item.id),
    [22n, 21n]
  );
  assert.deepEqual(result.research, {
    anchorScanId: '22',
    label: 'Immunefi SSV Network',
    requestedFound: true,
    scanCount: 2,
  });
  assert.equal(result.runningCount, 0);
});

test('the current research is the newest active scan, otherwise the newest scan', () => {
  assert.equal(selectResearchScans(SCANS, { research: 'current', activeStatuses: ACTIVE }).research.anchorScanId, '26');

  const idle = SCANS.map((item) => ({ ...item, status: 'completed' }));
  const latest = [...idle, scan(27, { program: 'Immunefi SSV Network', inserted: 11 })];
  assert.equal(
    selectResearchScans(latest, { research: 'current', activeStatuses: ACTIVE }).research.label,
    'Immunefi SSV Network'
  );
});

test('an unknown research anchor falls back to the current research and says so', () => {
  const result = selectResearchScans(SCANS, { research: '999', activeStatuses: ACTIVE });

  assert.equal(result.research.anchorScanId, '26');
  assert.equal(result.research.requestedFound, false);
});

test('status filters apply inside the research while counts stay research-wide', () => {
  const running = selectResearchScans(SCANS, { research: '26', status: 'running', activeStatuses: ACTIVE });
  assert.deepEqual(
    running.scans.map((item) => item.id),
    [26n]
  );
  assert.equal(running.runningCount, 1);
  assert.equal(running.research.scanCount, 3);

  const failed = selectResearchScans(SCANS, { research: '26', status: 'failed', activeStatuses: ACTIVE });
  assert.deepEqual(
    failed.scans.map((item) => item.id),
    [24n]
  );
});

test('no scans yields an empty research selection', () => {
  const result = selectResearchScans([], { research: 'current', activeStatuses: ACTIVE });
  assert.deepEqual(result.scans, []);
  assert.equal(result.research, null);
  assert.equal(result.runningCount, 0);
});
