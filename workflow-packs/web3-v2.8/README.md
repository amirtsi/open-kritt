# Solidity Vault Bug-Class Review v2.8

v2.8 applies the open·kritt creators' advice for focused workflows to Solidity vault protocols:

- **Narrow bug-class lanes instead of generic ones.** D1 maps each entrypoint through three bug classes: share and fee accounting, request and queue lifecycle, and custody and value movement. A lane stubs only when the entrypoint has nothing to do with its class.
- **One investigator per impact type.** D2 is unbound, so every lane record reaches three fresh-context investigators, each hunting one bounty impact: theft of funds, freezing of funds, and insolvency or broken value conservation.
- **Deterministic facts first.** D0 starts from `.open-kritt/static-analysis/ACCESS.md`, the engine's compiler-free access index. Slither is available in the runner for deeper checks.

The output formats and D2 root-cause rules are identical to v2.7. The gated D3 hostile verification, D4 local PoC and D5 report readiness post-scripts therefore apply unchanged, and v2.8 scans get the same readiness gate.

## Build

`01-solidity-vault-bug-class-review-v2.8.workflow.json` is generated from the v2.7 pack. Re-run the builder after editing v2.7:

```bash
python3 workflow-packs/web3-v2.8/build_from_v27.py
```

## Run requirements

- **Cost.** D2 costs about three times D1: every relevant lane record goes to all three impact investigators. Budget accordingly; the creators spent over $2,000 in tokens on a winning audit competition.
- **Repeat runs.** Use `configuration.repeat_runs` of 2 or 3 on high-value targets, so the second pass builds on the first.
- **Extra post-scripts.** Add the upstream-fix and actor-scope checks as after-D3 post-scripts. They then run only on findings D3 kept, before D4: `configuration.v27_after_d3: ["<Patched since id>", "<Is Malicious Actor in scope id>"]`.
- **Deployment configuration.** Give the exact production configuration in the scan configuration: deployed addresses, parameters, enabled hooks and roles.

Import with:

```bash
./kritt-headless import workflow ./workflow-packs/web3-v2.8/01-solidity-vault-bug-class-review-v2.8.workflow.json
```

Structural checks:

```bash
node --test scripts/web3-v2.8-workflow.test.mjs
```
