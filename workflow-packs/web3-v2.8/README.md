# Solidity Bug-Class Reviews v2.8

v2.8 applies the open·kritt creators' advice for focused workflows to Solidity protocol families. Two variants share everything except their lanes and impact wording:

| Pack | Protocol family | D1 bug-class lanes |
| ---- | --------------- | ------------------ |
| `01-solidity-vault-bug-class-review-v2.8` | Vaults with share accounting and request queues | share and fee accounting; request and queue lifecycle; custody and value movement |
| `02-solidity-staking-registry-bug-class-review-v2.8` | Validator and operator registries with oracle-committed state | balance and fee accounting; registry and oracle lifecycle; custody and value movement |

Pick the variant whose lanes match the target's flows: a lane with no matching flow mostly returns stubs.

Both variants follow the same rules:

- **Narrow bug-class lanes instead of generic ones.** D1 maps each entrypoint through the variant's three bug classes. A lane stubs only when the entrypoint has nothing to do with its class.
- **One investigator per impact type.** D2 is unbound, so every lane record reaches three fresh-context investigators, each hunting one bounty impact: theft of funds, freezing of funds, and insolvency or broken value conservation.
- **Deterministic facts first.** D0 starts from `.open-kritt/static-analysis/ACCESS.md`, the engine's compiler-free access index. Slither is available in the runner for deeper checks.

The output formats and D2 root-cause rules are identical to v2.7. The gated D3 hostile verification, D4 local PoC and D5 report readiness post-scripts therefore apply unchanged, and v2.8 scans get the same readiness gate.

## Build

Both workflow files are generated from the v2.7 pack. Re-run the builder after editing v2.7:

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
./kritt-headless import workflow ./workflow-packs/web3-v2.8/02-solidity-staking-registry-bug-class-review-v2.8.workflow.json
```

Structural checks:

```bash
node --test scripts/web3-v2.8-workflow.test.mjs scripts/web3-v2.8-staking-workflow.test.mjs
```
