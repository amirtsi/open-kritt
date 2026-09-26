// Launch checklist for a scan, computed before it is created. Each check is
// { id, level: 'ok' | 'info' | 'warn' | 'block', message }. The checks encode
// the open·kritt creators' run advice and lessons from earlier research runs.

import { V27_GATED_WORKFLOW_NAMES } from './v27Pipeline.js';

const NATIVE_HARNESS = { codex: 'codex', claude: 'claude-code' };
const HIGH_VALUE_KINDS = new Set(['public_bounty', 'audit_competition']);
const RECOMMENDED_WORKERS = 6;

function check(id, level, message, extra = {}) {
  return { id, level, message, ...extra };
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function nonEmpty(value) {
  if (Array.isArray(value)) return value.length > 0;
  return `${value ?? ''}`.trim().length > 0;
}

// Discovery jobs per repeat: D0 once, then each entrypoint through every D1
// lane, then every lane record through one bound or every unbound D2 step.
export function estimateJobs({ steps, unboundDepths = [] }, entrypoints, repeatRuns) {
  if (!Number.isInteger(entrypoints) || entrypoints <= 0) return null;
  const lanes = steps[1] || 0;
  const investigators = unboundDepths.includes(2) ? steps[2] || 0 : steps[2] ? 1 : 0;
  const perRun = (steps[0] || 0) + entrypoints * lanes + entrypoints * lanes * investigators;
  return perRun * Math.max(1, repeatRuns);
}

export function scanPreflight({
  payload,
  workflow,
  workerCount,
  estimatedEntrypoints = null,
  activeResearchScanIds = [],
  optionalPostScripts = [],
}) {
  const configuration = record(payload?.configuration);
  const provider = `${payload?.model_provider ?? ''}`;
  const harness = `${payload?.harness ?? ''}`;
  const gated = V27_GATED_WORKFLOW_NAMES.includes(workflow?.name);
  const repeatRuns = Number(configuration.repeat_runs) || 1;
  const checks = [];

  checks.push(
    provider === 'ollama'
      ? check(
          'discovery_model',
          'warn',
          'A local model drives discovery. Small local models missed every entrypoint in earlier runs; use a frontier model for discovery.'
        )
      : check('discovery_model', 'ok', `Discovery runs on ${provider}/${payload?.model ?? 'default'}.`)
  );

  if (provider !== 'ollama') {
    checks.push(
      NATIVE_HARNESS[provider] === harness
        ? check('native_harness', 'ok', `${provider} runs in its native ${harness} harness.`)
        : check(
            'native_harness',
            'info',
            `${provider} runs through ${harness}. The creators recommend each model in its native harness (GPT in Codex, Claude in Claude Code).`
          )
    );
  }

  checks.push(
    nonEmpty(configuration.deployment_context)
      ? check('deployment_context', 'ok', 'Production deployment configuration is provided.')
      : check(
          'deployment_context',
          'warn',
          'No configuration.deployment_context. Give the exact production configuration (deployed addresses, parameters, enabled hooks and roles); without it agents chase impossible paths or dismiss reachable bugs.'
        )
  );

  checks.push(
    nonEmpty(configuration.known_issue_sources)
      ? check('known_issues', 'ok', 'Known-issue sources are listed.')
      : check(
          'known_issues',
          'warn',
          'No configuration.known_issue_sources. Novelty will stay unverified unless the repository ships audit reports.'
        )
  );

  if (gated) {
    if (HIGH_VALUE_KINDS.has(configuration.investigation_kind) && repeatRuns < 2) {
      checks.push(
        check(
          'repeat_runs',
          'info',
          'repeat_runs is 1. For a high-value target use 2 or 3: a second pass builds on the first and finds what it missed.'
        )
      );
    }
    const requested = Array.isArray(configuration.v27_after_d3) ? configuration.v27_after_d3.map(String) : [];
    const missing = optionalPostScripts.filter((script) => !requested.includes(`${script.id}`));
    if (missing.length) {
      checks.push(
        check(
          'after_d3',
          'info',
          `Add ${missing.map((script) => script.name).join(' and ')} as after-D3 checks: configuration.v27_after_d3: [${missing
            .map((script) => `"${script.id}"`)
            .join(', ')}]. They run only on findings D3 kept.`
        )
      );
    }
  }

  if (Number(workerCount) < RECOMMENDED_WORKERS) {
    checks.push(
      check(
        'workers',
        'info',
        `workerCount is ${workerCount}. Raise it to ${RECOMMENDED_WORKERS} if memory allows (about 1.5 GB per runner) so verification is not the bottleneck.`
      )
    );
  }

  const estimatedJobs = estimateJobs(workflow || { steps: {} }, estimatedEntrypoints, repeatRuns);
  const jobLimit = payload?.jobLimit ?? null;
  if (estimatedJobs === null) {
    checks.push(
      check('budget', 'info', 'No job estimate: this research has no earlier entrypoint count.', { estimatedJobs })
    );
  } else if (jobLimit !== null && jobLimit < estimatedJobs) {
    checks.push(
      check(
        'budget',
        'warn',
        `About ${estimatedJobs} discovery jobs are expected but the job limit is ${jobLimit}; the scan would stop before covering every entrypoint.`,
        { estimatedJobs }
      )
    );
  } else {
    checks.push(
      check(
        'budget',
        'info',
        `About ${estimatedJobs} discovery jobs are expected before post-processing. Budget for it: under-spending is a common reason bugs are missed.`,
        { estimatedJobs }
      )
    );
  }

  if (activeResearchScanIds.length) {
    checks.push(
      check(
        'active_research',
        'info',
        `Scan ${activeResearchScanIds.map((id) => `#${id}`).join(', ')} is already running on this research and will share workers.`
      )
    );
  }
  return checks;
}

const ACTIVE_STATUSES = new Set([
  'queued',
  'pending',
  'prewarming_cache',
  'running',
  'rate_limited',
  'post_processing',
]);
const OPTIONAL_AFTER_D3 = ['Patched since', 'Is Malicious Actor in scope'];

// Same grouping rule as the research views: research_id, else program, else repository.
function researchIdentity(configuration, repoFull) {
  const config = record(configuration);
  return `${config.research_id || config.program || repoFull || ''}`;
}

async function workflowShape(db, workflowId) {
  const workflow = await db.workflow.findUnique({ where: { id: BigInt(workflowId) } });
  if (!workflow) return null;
  const steps = workflow.stepIds?.length
    ? await db.step.findMany({
        where: { id: { in: workflow.stepIds } },
        select: { id: true, depth: true, boundSourceStepId: true },
      })
    : [];
  const counts = {};
  for (const step of steps) counts[step.depth] = (counts[step.depth] || 0) + 1;
  const unboundDepths = Object.keys(counts)
    .map(Number)
    .filter(
      (depth) =>
        depth > 0 && steps.filter((step) => step.depth === depth).every((step) => step.boundSourceStepId == null)
    )
    .sort((a, b) => a - b);
  return { workflow, steps, shape: { name: workflow.name, steps: counts, unboundDepths } };
}

export async function loadPreflightInputs(db, payload, { readSettings }) {
  const loaded = await workflowShape(db, payload.workflowId);
  const identity = researchIdentity(payload.configuration, payload.repo_full);
  const scans = (await db.scan.findMany({ orderBy: { insertedAt: 'desc' }, take: 200 })).filter(
    (scan) => researchIdentity(scan.configuration, scan.repoFull) === identity
  );

  let estimatedEntrypoints = null;
  const previous = scans.find((scan) => !ACTIVE_STATUSES.has(scan.status));
  if (previous) {
    const previousShape = await workflowShape(db, previous.workflowId);
    const entrySteps = (previousShape?.steps || []).filter((step) => step.depth === 0).map((step) => step.id);
    if (entrySteps.length) {
      const count = await db.stepResult.count({
        where: {
          scanId: previous.id,
          stepId: { in: entrySteps },
          OR: [{ repeatRun: null }, { repeatRun: { lte: 1 } }],
        },
      });
      estimatedEntrypoints = count || null;
    }
  }

  const optional = await db.postScript.findMany({
    where: { name: { in: OPTIONAL_AFTER_D3 } },
    orderBy: { id: 'desc' },
    select: { id: true, name: true },
  });
  const optionalPostScripts = OPTIONAL_AFTER_D3.map((name) => optional.find((row) => row.name === name))
    .filter(Boolean)
    .map((row) => ({ id: row.id.toString(), name: row.name }));

  const settings = await readSettings();
  return {
    workflow: loaded?.shape || null,
    workerCount: Number(settings?.settings?.workerCount?.value),
    estimatedEntrypoints,
    activeResearchScanIds: scans.filter((scan) => ACTIVE_STATUSES.has(scan.status)).map((scan) => scan.id.toString()),
    optionalPostScripts,
  };
}
