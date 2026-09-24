# Recall-First External Flow Review v2.7

v2.7 is a separate profile for new scans. It leaves v2.6 and existing scan data intact.

1. D0 emits one record per production handler, including the least-privileged actor and reachability evidence.
2. D1-A/B/C map authority, protocol/state, and input/availability respectively. Each emits at most one record per handler, keeping paths and variants in arrays.
3. Bound routing sends D1-A only to D2-A, D1-B only to D2-B, and D1-C only to D2-C. D2 emits one raw finding per concrete root cause. A missing dependency is an explicit coverage gap. There is no global consume-all step.
4. OpenKritt stores all D2 candidates and applies its built-in semantic deduplication to them. Only canonical findings go to the following post-scripts.
5. D3 checks source, reachability, guards, deployment facts, impact, novelty and scope, and returns a hostile verification verdict without spending time on a PoC.
6. D4 runs only for D3 `confirmed` or `plausible_needs_poc` results. It attempts a local PoC, negative control and repeated runs, then persists bounded evidence files before temporary workspace cleanup.
7. D5 runs only after D4 status is `reproduced` **and** artifact capture succeeded. It assesses scope, severity, novelty and report readiness. A missing program rule or deployment prerequisite prevents `submission_ready=true`.

The three post-scripts are in `post-scripts/`. New scans using this workflow automatically snapshot their IDs in the order D3, D4, D5. The engine uses these IDs for conditional stage gating. Other workflows and existing scans use their prior post-script behavior.

The PoC stage cannot prove that model-written stdout is authentic by itself; a reviewer must inspect the saved harness, logs and negative control. A successful build or a proposed test is never sufficient for report readiness.

Before claiming effectiveness, benchmark v2.6 and v2.7 on the same pinned commit, scope, model and reasoning settings. Measure ground-truth recall, canonical precision, raw-to-canonical ratio, PoC reproduction, submission-ready precision, calls/tokens, wall time, coverage completion and provider failures. Do not launch a full-cost scan merely to test importability.

Run structural checks with `node --test scripts/web3-v2.7-workflow.test.mjs`.
