"""Build the v2.8 Solidity vault workflow from the v2.7 pack.

v2.8 keeps v2.7's output formats and D2 root-cause rules (so the gated D3, D4
and D5 post-scripts apply unchanged) and replaces only the focus sentences:
D1 lanes become Solidity vault bug classes and D2 becomes one unbound
investigator per bounty impact type. Re-run after editing the v2.7 pack:

    python3 workflow-packs/web3-v2.8/build_from_v27.py
"""

import copy
import json
from pathlib import Path

PACKS = Path(__file__).resolve().parent.parent
SOURCE = PACKS / "web3-v2.7" / "01-recall-first-verified-external-flow-review-v2.7.workflow.json"
TARGET = PACKS / "web3-v2.8" / "01-solidity-vault-bug-class-review-v2.8.workflow.json"

NAME = "Solidity Vault Bug-Class Review v2.8"
DESCRIPTION = (
    "D0 maps production entrypoints starting from the deterministic access index. Three D1 lanes each map one "
    "Solidity vault bug class (share and fee accounting, request and queue lifecycle, custody and value movement). "
    "Every lane record reaches three D2 investigators, one per bounty impact type (theft, freezing, insolvency), "
    "which persist concrete root-cause candidates for gated D3 hostile verification, D4 local PoC and D5 report "
    "readiness."
)
D0_ADDENDUM = (
    "Start from .open-kritt/static-analysis/ACCESS.md when the workspace provides it: it lists every external or "
    "public state-changing function with its modifiers and caller checks. Treat it as an inventory to verify, not "
    "as proof; still include callbacks, hooks, and entrypoints it cannot see."
)
V27_STUB_RULE = (
    "Return a stub ONLY when this entrypoint has no state-changing, value-moving, persisted-input, or "
    "later-consumed path relevant to your lane (for example a pure view getter)."
)
V28_STUB_RULE = (
    "Return a stub ONLY when this entrypoint has no path relevant to this bug class (for example a pure view "
    "getter or an unrelated admin setter)."
)
LANES = [
    (
        "d1-accounting",
        "Map share and fee accounting lane",
        "Map share and fee accounting for this entrypoint: share mint and burn math, conversion between assets and "
        "shares, share price and valuation inputs, rounding direction at every division, fee accrual, fee share "
        "minting and settlement, first and last depositor states, donations and balance-based valuation, and every "
        "invariant that ties total supply, tracked assets, and fees together. Keep only paths relevant to this bug "
        "class.",
    ),
    (
        "d1-lifecycle",
        "Map request and queue lifecycle lane",
        "Map the request and queue lifecycle for this entrypoint: request creation, cancellation, execution, partial "
        "fills, batching, ordering and skips, minimum durations, escrowed assets and shares, controller, owner and "
        "recipient binding, hook and validator calls at each transition, replay and double execution, and state left "
        "behind after revocation or reconfiguration. Keep only paths relevant to this bug class.",
    ),
    (
        "d1-custody",
        "Map custody and value movement lane",
        "Map custody and value movement for this entrypoint: every transfer, approval, native value send, refund and "
        "sweep; who funds and who receives; forwarders, wallets and cross-chain or cross-component messages; "
        "callbacks and external calls that can re-enter or redirect value; and whether each sender, recipient and "
        "amount is bound to the authorized actor. Keep only paths relevant to this bug class.",
    ),
]
LANE_RECORD = (
    "Lane record from D1: focus {{lane_focus}}; summary {{lane_summary}}; paths {{lane_paths}}; sinks "
    "{{lane_sinks}}; invariants {{lane_invariants}}; variants {{lane_variants}}; reachability "
    "{{lane_reachability}}; focal location {{lane_file_path}}:{{lane_line}}."
)
IMPACTS = [
    (
        "d2-theft",
        "Investigate theft of funds",
        "Hunt only for theft of funds: an unprivileged actor ends with assets, shares, fees, refunds, or native value "
        "that belong to depositors, the vault, or the protocol, through this lane's bug class. Follow value to its "
        "final holder and quantify what moves.",
    ),
    (
        "d2-freezing",
        "Investigate freezing of funds",
        "Hunt only for freezing of funds: an unprivileged actor makes deposited assets, shares, escrowed requests, or "
        "claims unrecoverable, or blocks them for a period, through this lane's bug class. State whether an admin can "
        "recover them and how long the freeze lasts.",
    ),
    (
        "d2-insolvency",
        "Investigate insolvency and value conservation",
        "Hunt only for protocol insolvency and broken value conservation: an unprivileged sequence leaves liabilities "
        "(shares, claims, owed fees) above backing assets, or moves value between depositors without an equivalent "
        "exchange, through this lane's bug class. Quantify the deficit.",
    ),
]


def build() -> dict:
    document = json.loads(SOURCE.read_text(encoding="utf-8"))
    d0, d1, d2 = document["workflow"]["levels"]
    result = copy.deepcopy(document)
    workflow = result["workflow"]
    workflow["name"] = NAME
    workflow["description"] = DESCRIPTION
    workflow["levels"][0]["steps"][0]["content"] = d0["steps"][0]["content"].rstrip("\n") + "\n\n" + D0_ADDENDUM + "\n"

    lane_lines = d1["steps"][1]["content"].split("\n")
    if V27_STUB_RULE not in lane_lines[4]:
        raise SystemExit("v2.7 D1 stub rule changed; update build_from_v27.py")
    rules = lane_lines[4].replace(V27_STUB_RULE, V28_STUB_RULE)
    workflow["levels"][1]["steps"] = [
        {"name": name, "content": "\n".join([lane_lines[0], lane_lines[1], "", focus, rules, ""]), "clientId": client}
        for client, name, focus in LANES
    ]

    investigator = d2["steps"][0]["content"].split("\n")
    workflow["levels"][2]["bindPrevious"] = False
    workflow["levels"][2]["steps"] = [
        {
            "name": name,
            "content": "\n".join([investigator[0], investigator[1], LANE_RECORD, "", focus, *investigator[5:]]),
            "clientId": client,
        }
        for client, name, focus in IMPACTS
    ]
    return result


if __name__ == "__main__":
    TARGET.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {TARGET}")
