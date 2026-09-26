import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DEFAULT_SCAN_PAGE_SIZE,
  findingExportSourceProfile,
  researchScanPage,
  scanLiveHandler,
  MAX_SCAN_PAGE_SIZE,
  SCAN_LIST_ORDER,
  scanListPagination,
  serializedScanVulnerabilities,
} from '../src/routes/scans.js';
import {
  FindingExportTooManyFindingsError,
  FindingExportTooManyRelatedRecordsError,
} from '../src/lib/findingExport.js';

test('scan lists sort newest activity first with a stable id tie-breaker', () => {
  assert.deepEqual(SCAN_LIST_ORDER, [{ updatedAt: 'desc' }, { id: 'desc' }]);
});

test('scan pagination remains opt-in for backward-compatible list consumers', () => {
  assert.equal(scanListPagination({}), null);
  assert.equal(scanListPagination({ status: 'completed' }), null);
});

test('scan pagination applies defaults and calculates the database offset', () => {
  assert.deepEqual(scanListPagination({ page: '3' }), {
    page: 3,
    pageSize: DEFAULT_SCAN_PAGE_SIZE,
    skip: DEFAULT_SCAN_PAGE_SIZE * 2,
  });
  assert.deepEqual(scanListPagination({ pageSize: '20' }), { page: 1, pageSize: 20, skip: 0 });
});

test('scan pagination rejects malformed and excessive values', () => {
  assert.throws(
    () => scanListPagination({ page: '0', pageSize: String(MAX_SCAN_PAGE_SIZE + 1) }),
    (error) => {
      assert.deepEqual(error.errors, [
        { field: 'page', message: 'Page must be a positive integer.' },
        { field: 'pageSize', message: `Page size must be between 1 and ${MAX_SCAN_PAGE_SIZE}.` },
      ]);
      return true;
    }
  );
  assert.throws(() => scanListPagination({ page: ['1', '2'] }), /Validation failed/);
});

test('bounded finding reads stop before loading related export data', async () => {
  let query;
  const db = {
    vulnerability: {
      findMany: async (options) => {
        query = options;
        return [{ id: 1n }, { id: 2n }, { id: 3n }];
      },
    },
    vulnerabilityEnrichment: {
      findMany: async () => assert.fail('enrichments must not load after the finding limit is exceeded'),
    },
  };

  await assert.rejects(
    () => serializedScanVulnerabilities(7n, { maxFindings: 2, db }),
    FindingExportTooManyFindingsError
  );
  assert.equal(query.take, 3);
  assert.deepEqual(query.where, {
    scanId: 7n,
    OR: [{ dedupeIsCanonical: true }, { dedupeIsCanonical: null }],
  });
});

test('finding export source profiles preserve database byte counts as bigints', async () => {
  const profile = await findingExportSourceProfile(7n, {
    db: {
      $queryRaw: async () => [
        {
          findingCount: 3n,
          enrichmentCount: 4n,
          duplicateCount: 2n,
          totalBytes: 1024n,
          largestRecordBytes: 512n,
        },
      ],
    },
  });

  assert.deepEqual(profile, {
    findingCount: 3n,
    enrichmentCount: 4n,
    duplicateCount: 2n,
    totalBytes: 1024n,
    largestRecordBytes: 512n,
  });
});

test('bounded finding reads cap related post-processing records', async () => {
  let enrichmentQuery;
  const db = {
    vulnerability: { findMany: async () => [{ id: 1n }] },
    vulnerabilityEnrichment: {
      findMany: async (options) => {
        enrichmentQuery = options;
        return [{ id: 1n }, { id: 2n }, { id: 3n }];
      },
    },
  };

  await assert.rejects(
    () => serializedScanVulnerabilities(7n, { maxFindings: 2, maxRelatedRecords: 2, db }),
    FindingExportTooManyRelatedRecordsError
  );
  assert.equal(enrichmentQuery.take, 3);
});

test('research scan pages slice the selection and report research-wide counts', () => {
  const selection = {
    research: { anchorScanId: '26', label: 'Immunefi Enzyme Onyx', requestedFound: true, scanCount: 3 },
    scans: [{ id: 26n }, { id: 24n }, { id: 23n }],
    runningCount: 1,
  };

  const { pageScans, body } = researchScanPage(selection, { page: 2, pageSize: 2, skip: 2 });

  assert.deepEqual(
    pageScans.map((scan) => scan.id),
    [23n]
  );
  assert.deepEqual(body, {
    page: 2,
    pageSize: 2,
    totalItems: 3,
    totalPages: 2,
    startIndex: 2,
    endIndex: 3,
    runningCount: 1,
    research: selection.research,
  });
});

function fakeResponse() {
  return {
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
  };
}

test('scan live route returns 404 for an unknown scan and 400 for a malformed id', async () => {
  const handler = scanLiveHandler({ findScan: async () => null, load: async () => ({}) });
  const missing = fakeResponse();
  await handler({ params: { id: '999' } }, missing, (error) => {
    throw error;
  });
  assert.equal(missing.statusCode, 404);

  const malformed = fakeResponse();
  await handler({ params: { id: 'abc' } }, malformed, (error) => {
    throw error;
  });
  assert.equal(malformed.statusCode, 400);
});

test('scan live route returns the loaded live view', async () => {
  const handler = scanLiveHandler({
    findScan: async (id) => ({ id }),
    load: async (scan) => ({ scanId: `${scan.id}`, funnel: [] }),
  });
  const res = fakeResponse();
  await handler({ params: { id: '26' } }, res, (error) => {
    throw error;
  });
  assert.deepEqual(res.body, { scanId: '26', funnel: [] });
});
