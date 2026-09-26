// backend/src/lib/scanLive.js
// Live view of one scan: a funnel of engine-verified findings, current
// activity, and grouped reasons for dropouts. The builders are pure; the
// loader fetches only the columns they read.

const KEPT_VERDICTS = new Set(['confirmed', 'plausible_needs_poc']);
const POST_SCRIPT_KINDS = new Set(['post_script', 'v27_poc']);

const text = (value) => (value === null || value === undefined ? null : value.toString());
const plainObject = (value) => (value && typeof value === 'object' && !Array.isArray(value) ? value : {});

export function pipelineIds(scan) {
  const raw = plainObject(plainObject(scan?.configuration).v27_pipeline);
  const ids = { d3: text(raw.d3), d4: text(raw.d4), d5: text(raw.d5) };
  return ids.d3 && ids.d4 && ids.d5 ? ids : null;
}

// Latest non-supplemental enrichment per post-script and finding.
export function latestStageResults(enrichments) {
  const stages = new Map();
  for (const row of enrichments) {
    if (row.supplementalRunId !== null && row.supplementalRunId !== undefined) continue;
    const script = text(row.postScriptId);
    if (!stages.has(script)) stages.set(script, new Map());
    stages.get(script).set(text(row.vulnerabilityId), { stub: Boolean(row.stub), result: plainObject(row.result) });
  }
  return stages;
}

export function normalizeBlocker(reason) {
  const head = `${reason ?? ''}`.split(':')[0];
  return (
    head
      .toLowerCase()
      .replace(/'[^']*'/g, "'…'")
      .replace(/\s+/g, ' ')
      .trim() || 'unspecified'
  );
}

function stageAttempted(postMetadata, predicate) {
  return postMetadata.some(predicate);
}

function tally(target, label) {
  target[label] = (target[label] || 0) + 1;
}

function evidence(entry) {
  return plainObject(entry?.result?._engine_evidence);
}

function stage(id, label, status, count, pending, dropped) {
  return { id, label, status, count, pending, dropped };
}

export function buildFunnel({ scan, vulnerabilities, enrichments, postMetadata }) {
  const raw = vulnerabilities.length;
  const canonical = vulnerabilities.filter((row) => row.dedupeIsCanonical === true).map((row) => text(row.id));
  const dedupeSeen = stageAttempted(postMetadata, (row) => row.kind === 'dedupe');
  const stages = [
    stage('raw', 'Raw', 'counted', raw, 0, {}),
    stage(
      'canonical',
      'Canonical',
      dedupeSeen ? 'counted' : 'waiting',
      canonical.length,
      vulnerabilities.filter((row) => row.dedupeIsCanonical === null || row.dedupeIsCanonical === undefined).length,
      vulnerabilities.some((row) => row.dedupeIsCanonical === false)
        ? { duplicate: vulnerabilities.filter((row) => row.dedupeIsCanonical === false).length }
        : {}
    ),
  ];
  const ids = pipelineIds(scan);
  if (!ids) return stages;

  const results = latestStageResults(enrichments);
  const seen = (scriptId) =>
    stageAttempted(postMetadata, (row) => POST_SCRIPT_KINDS.has(row.kind) && text(row.postScriptId) === scriptId);

  const step = (id, label, scriptId, previous, passes, dropLabel) => {
    const byFinding = results.get(scriptId) || new Map();
    const passed = [];
    const dropped = {};
    let pending = 0;
    for (const findingId of previous) {
      const entry = byFinding.get(findingId);
      if (!entry) pending += 1;
      else if (entry.stub) tally(dropped, 'stub');
      else if (passes(entry)) passed.push(findingId);
      else for (const reason of [dropLabel(entry)].flat()) tally(dropped, reason);
    }
    stages.push(stage(id, label, seen(scriptId) ? 'counted' : 'waiting', passed.length, pending, dropped));
    return passed;
  };

  const kept = step(
    'd3_kept',
    'D3 kept',
    ids.d3,
    canonical,
    (entry) => KEPT_VERDICTS.has(entry.result.verdict),
    (entry) => `${entry.result.verdict ?? 'unknown'}`
  );
  const reproduced = step(
    'bug_reproduced',
    'Bug reproduced',
    ids.d4,
    kept,
    (entry) => evidence(entry).bug_status === 'reproduced',
    (entry) => `${evidence(entry).bug_status ?? 'unknown'}`
  );
  const proven = step(
    'impact_proven',
    'Impact proven',
    ids.d4,
    reproduced,
    (entry) => evidence(entry).impact_status === 'proven' && evidence(entry).capture_complete === true,
    (entry) =>
      evidence(entry).impact_status === 'proven'
        ? 'capture_incomplete'
        : `${evidence(entry).impact_status ?? 'unknown'}`
  );
  step(
    'ready',
    'Ready',
    ids.d5,
    proven,
    (entry) => plainObject(entry.result._engine_readiness).ready === true,
    (entry) => {
      const reasons = plainObject(entry.result._engine_readiness).blocking_reasons;
      return Array.isArray(reasons) && reasons.length ? [...new Set(reasons.map(normalizeBlocker))] : ['unknown'];
    }
  );
  return stages;
}

const MIN_SAMPLES = 3;
const RECENT_ERRORS = 5;
const ERROR_STATUSES = new Set(['failed', 'interrupted']);

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function stageKey(row, fromPost) {
  if (fromPost) return `post:${row.kind}:${text(row.postScriptId) ?? ''}`;
  return `step:${text(row.stepId)}`;
}

export function buildActivity({ activeJobs, stepMetadata, postMetadata, now }) {
  const rows = [
    ...stepMetadata.map((row) => ({ row, key: stageKey(row, false) })),
    ...postMetadata.map((row) => ({ row, key: stageKey(row, true) })),
  ];
  const samples = new Map();
  const keyById = new Map();
  for (const { row, key } of rows) {
    keyById.set(text(row.id), key);
    if (row.status !== 'completed' || row.runTimeMs === null || row.runTimeMs === undefined) continue;
    if (!samples.has(key)) samples.set(key, []);
    samples.get(key).push(Number(row.runTimeMs));
  }
  const jobs = activeJobs.map((job) => {
    const values = samples.get(keyById.get(`${job.metadataId}`)) || [];
    const medianMs = values.length >= MIN_SAMPLES ? median(values) : null;
    const elapsedMs = Math.max(0, now.getTime() - new Date(job.startedAt).getTime());
    return {
      metadataId: `${job.metadataId}`,
      title: job.title,
      phaseLabel: job.phaseLabel,
      model: job.model || null,
      elapsedMs,
      medianMs,
      slow: medianMs !== null && elapsedMs > 2 * medianMs,
    };
  });
  const recentErrors = rows
    .filter(({ row }) => ERROR_STATUSES.has(row.status))
    .sort((a, b) => new Date(b.row.updatedAt) - new Date(a.row.updatedAt))
    .slice(0, RECENT_ERRORS)
    .map(({ row, key }) => ({
      metadataId: text(row.id),
      stage: key,
      status: row.status,
      message: `${row.error ?? ''}`.slice(0, 300),
      at: row.updatedAt,
      recovered: rows.some(
        (other) =>
          other.key === key &&
          other.row.status === 'completed' &&
          new Date(other.row.updatedAt) > new Date(row.updatedAt) &&
          text(other.row.prevId) === text(row.prevId)
      ),
    }));
  return { jobs, recentErrors };
}
