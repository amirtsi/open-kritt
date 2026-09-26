// A "research" groups scans that investigate the same target: the explicit
// research_id, else the bounty program, else the repository. Benchmark runs of
// the same target form a separate research.

function scanConfiguration(scan) {
  const configuration = scan?.configuration;
  return configuration && typeof configuration === 'object' && !Array.isArray(configuration) ? configuration : {};
}

export function scanResearchKey(scan) {
  const configuration = scanConfiguration(scan);
  const identity = configuration.research_id || configuration.program || scan?.repoFull || scan?.id;
  const kind = configuration.benchmark_mode === true ? 'benchmark' : 'research';
  return `${identity}::${kind}`;
}

export function researchLabel(scan) {
  const configuration = scanConfiguration(scan);
  return `${configuration.program || configuration.research_id || scan?.repoFull || `Scan ${scan?.id}`}`;
}

const newestFirst = (field) => (left, right) =>
  right[field] - left[field] || (right.id > left.id ? 1 : right.id < left.id ? -1 : 0);

function currentAnchor(scans, activeStatuses) {
  const byInsertion = [...scans].sort(newestFirst('insertedAt'));
  return byInsertion.find((scan) => activeStatuses.includes(scan.status)) || byInsertion[0] || null;
}

function matchesStatus(scan, status, activeStatuses) {
  if (!status || status === 'all') return true;
  if (status === 'running') return activeStatuses.includes(scan.status);
  return scan.status === status;
}

// Select the scans of one research. `research` is a scan id that anchors the
// research, or "current" for the research of the newest active (else newest)
// scan. An unknown anchor falls back to the current research.
export function selectResearchScans(scans, { research, status = 'all', activeStatuses }) {
  const requested = /^\d+$/.test(`${research ?? ''}`)
    ? scans.find((scan) => `${scan.id}` === `${research}`) || null
    : null;
  const anchor = requested || currentAnchor(scans, activeStatuses);
  if (!anchor) return { research: null, scans: [], runningCount: 0 };

  const key = scanResearchKey(anchor);
  const researchScans = scans.filter((scan) => scanResearchKey(scan) === key).sort(newestFirst('updatedAt'));
  return {
    research: {
      anchorScanId: `${anchor.id}`,
      label: researchLabel(anchor),
      requestedFound: Boolean(requested) || !/^\d+$/.test(`${research ?? ''}`),
      scanCount: researchScans.length,
    },
    scans: researchScans.filter((scan) => matchesStatus(scan, status, activeStatuses)),
    runningCount: researchScans.filter((scan) => activeStatuses.includes(scan.status)).length,
  };
}
