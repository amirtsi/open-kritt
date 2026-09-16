# OpenKritt Recall-First Workflow Pack v2.6

This pack restores the short branch-preserving shape of upstream
`external-flow-analysis`: external surfaces -> distinct flows -> findings. It is
intended for benchmark recall and the first discovery pass of an authorized review.

## Why this exists

The v2.4 workflows combine discovery, global candidate consolidation, adversarial
verification, deterministic reproduction, program eligibility, and final emission.
That improves precision only after a candidate survives every stage. It also creates
several independent ways to lose a real bug before OpenKritt records a finding.

The v2.6 workflow makes discovery responsible for one result: preserve concrete,
code-grounded technical candidates. Deduplication, reproduction, severity, deployment
confirmation, and bounty-program eligibility belong in post-processing or a later
verification run.

## Shape

1. Map every externally influenced production surface.
2. Trace each materially distinct flow, state transition, invariant, and alternate
   sequence.
3. Run three independent adversarial lenses on every flow:
   identity/protocol state; parsing/crash boundaries; and accounting/consensus.

There is no consume-all boundary and no early scope or PoC gate. All three levels use
multi-output fan-out. The terminal schema is OpenKritt's standard nine-field finding
contract.

## Run requirements

- Pin the target commit and every source dependency used by production wiring.
- Treat a scan with missing dependency source as incomplete, not clean.
- Put repeated runs in the engine's `configuration.repeat_runs`; prompt metadata such
  as `extra.repeat_runs` does not cause engine repetitions.
- Keep one working provider/model for the whole discovery pass. A provider login or
  policy failure before all branches complete invalidates coverage.
- Apply hostile verification, deduplication, scope, and eligibility post-scripts only
  after raw technical candidates have been stored.

Import with:

```bash
./kritt-headless import workflow \
  ./workflow-packs/web3-v2.6/01-recall-first-external-flow-review-v2.6.workflow.json
```

Run the structural regression tests with:

```bash
node --test scripts/web3-v2.6-workflow.test.mjs
```
