import json

from test_impact_gate import ARTIFACT_DIR, EVALUATED_AT, make_d3, make_d4, make_d5, make_manifest, make_scan

from open_kritt_engine.impact_gate import evaluate_readiness, evidence_block
from open_kritt_engine.poc_artifacts import capture_evidence
from open_kritt_engine.readiness_policies import POLICY_VERSION, POLICY_VERSION_GATE_1

SITE = "test/Attack.t.sol:10"


def good_d4():
    d4 = make_d4()
    d4["setup_mutations"] = [
        {"site": SITE, "kind": "deal", "beneficiary_role": "attacker", "justification": "attacker gas and capital"}
    ]
    d4["attacker_pnl"] = {"asset": "WETH", "attacker_in": "1", "attacker_out": "101", "net_positive": True}
    d4["victim_loss"] = [
        {
            "party": "vault depositors",
            "asset": "WETH",
            "amount": "100",
            "preexisting_on_fork": True,
            "evidence_paths": ["balances.json"],
        }
    ]
    d4["privileged_calls"] = []
    return d4


def good_d5():
    d5 = make_d5()
    d5["upstream_fix"] = {"status": "none_found", "evidence": "searched all branches and team notes"}
    d5["precondition_live"] = {"status": "present_now", "evidence": "vault holds 100 WETH at block 1"}
    d5["materiality"] = {
        "usd_affected": 250000,
        "price_source": "DefiLlama",
        "threshold_usd": 15000,
        "basis": "vault WETH",
    }
    return d5


def scan(threshold=15000, kind="public_bounty", version=POLICY_VERSION):
    s = make_scan(kind=kind, version=version)
    if threshold is not None:
        s["configuration"]["materiality_min_usd"] = threshold
    return s


def evidence(d4, sites=({"site": SITE, "kind": "deal"},), sources=("test/Attack.t.sol",)):
    return evidence_block(
        d4,
        make_manifest(),
        capture_complete=True,
        artifact_dir=ARTIFACT_DIR,
        policy_version=POLICY_VERSION,
        legacy=False,
        cheatcode_sites=list(sites),
        poc_source_paths=list(sources),
    )


def run(d4=None, d5=None, sites=({"site": SITE, "kind": "deal"},), sources=("test/Attack.t.sol",), **scan_kw):
    d4 = d4 if d4 is not None else good_d4()
    return evaluate_readiness(
        scan=scan(**scan_kw),
        d3=make_d3(),
        d4=d4,
        evidence=evidence(d4, sites, sources),
        d5=d5 if d5 is not None else good_d5(),
        evaluated_at=EVALUATED_AT,
    )


def reasons(readiness):
    return " | ".join(readiness["blocking_reasons"])


def test_positive_control_is_submission_ready():
    r = run()
    assert r["ready"] is True, r["blocking_reasons"]
    assert r["checks"]["economic_reality"] == "pass" and r["checks"]["reality_context"] == "pass"


def test_gate_1_ignores_the_new_fields():
    r = evaluate_readiness(
        scan=make_scan(version=POLICY_VERSION_GATE_1),
        d3=make_d3(),
        d4=make_d4(),
        evidence=evidence_block(
            make_d4(),
            make_manifest(),
            capture_complete=True,
            artifact_dir=ARTIFACT_DIR,
            policy_version=POLICY_VERSION_GATE_1,
            legacy=False,
        ),
        d5=make_d5(),
        evaluated_at=EVALUATED_AT,
    )
    assert r["ready"] is True
    assert r["checks"]["economic_reality"] == "pass" and r["checks"]["reality_context"] == "pass"


def test_missing_blocks_fail_e1_and_c1():
    r = run(d4=make_d4(), d5=make_d5())
    assert r["checks"]["economic_reality"] == "fail" and r["checks"]["reality_context"] == "fail"


def test_e2_undeclared_cheatcode_site_blocks():
    r = run(sites=({"site": SITE, "kind": "deal"}, {"site": "test/Attack.t.sol:20", "kind": "prank"}))
    assert "test/Attack.t.sol:20" in reasons(r) and r["ready"] is False


def test_e2_no_captured_poc_source_blocks():
    r = run(sites=(), sources=())
    assert "No Foundry/Hardhat PoC test source was captured" in reasons(r)


def test_e2_accepts_dot_slash_site_spelling():
    d4 = good_d4()
    d4["setup_mutations"][0]["site"] = "./" + SITE
    assert run(d4=d4)["ready"] is True


def test_2428_victim_funds_injected_into_protocol_blocks_e3_e5_c3():
    d4 = good_d4()
    d4["setup_mutations"].append(
        {
            "site": "test/Attack.t.sol:107",
            "kind": "prank",
            "beneficiary_role": "protocol_contract",
            "justification": "live EOA transfers 1 WETH into VeloPositionManager",
        }
    )
    d4["victim_loss"] = [
        {"party": "EOA", "asset": "WETH", "amount": "1", "preexisting_on_fork": False, "evidence_paths": []}
    ]
    d5 = good_d5()
    d5["precondition_live"] = {"status": "absent_now", "evidence": "manager WETH balance 0 at block 157500563"}
    r = run(d4=d4, d5=d5, sites=({"site": SITE, "kind": "deal"}, {"site": "test/Attack.t.sol:107", "kind": "prank"}))
    text = reasons(r)
    assert "protocol_contract" in text and "preexisting" in text and "absent_now" in text


def test_2142_attacker_pays_itself_blocks_e4_and_c3():
    d4 = good_d4()
    d4["attacker_pnl"] = {"asset": "ETH", "attacker_in": "2", "attacker_out": "2", "net_positive": False}
    d5 = good_d5()
    d5["precondition_live"] = {"status": "absent_now", "evidence": "LendingPool ETH balance 0 at the fork block"}
    r = run(d4=d4, d5=d5)
    text = reasons(r)
    assert "net profit" in text and "absent_now" in text
    assert r["checks"]["economic_reality"] == "fail" and r["checks"]["reality_context"] == "fail"


def test_2145_dust_blocks_c4():
    d5 = good_d5()
    d5["materiality"] = {
        "usd_affected": 0.0000001,
        "price_source": "DefiLlama",
        "threshold_usd": 15000,
        "basis": "46 wei",
    }
    assert "materiality" in reasons(run(d5=d5)).lower()


def test_2166_owner_trigger_and_upstream_fix_block_e6_c2():
    d4 = good_d4()
    d4["privileged_calls"] = [{"site": "test/Attack.t.sol:134", "role": "owner", "function": "setReward"}]
    d5 = good_d5()
    d5["upstream_fix"] = {
        "status": "fixed_upstream",
        "evidence": "ExtraFi/extra-contracts sets lastUpdateTime = startTime",
    }
    text = reasons(run(d4=d4, d5=d5))
    assert "privileged" in text and "fixed_upstream" in text


def test_missing_threshold_on_bounty_scan_blocks_c4():
    assert "materiality_min_usd" in reasons(run(threshold=None))


def test_private_audit_skips_threshold_and_privilege_rules():
    d4 = good_d4()
    d4["privileged_calls"] = [{"site": SITE, "role": "owner", "function": "setFee"}]
    r = run(d4=d4, threshold=None, kind="private_audit")
    assert r["checks"]["economic_reality"] == "pass" and r["checks"]["reality_context"] == "pass"


# --- fix round 1: fail-closed on malformed evidence -------------------------


def test_c4_rejects_nan_usd_affected():
    d5 = good_d5()
    d5["materiality"] = {**d5["materiality"], "usd_affected": float("nan")}
    r = run(d5=d5)
    assert r["checks"]["reality_context"] == "fail"
    assert "not a finite number" in reasons(r)


def test_c4_rejects_string_nan_usd_affected():
    d5 = good_d5()
    d5["materiality"] = {**d5["materiality"], "usd_affected": "NaN"}
    r = run(d5=d5)
    assert r["checks"]["reality_context"] == "fail"
    assert "not a finite number" in reasons(r)


def test_c4_rejects_string_threshold():
    r = run(threshold="nan")
    assert r["checks"]["reality_context"] == "fail"
    assert "materiality_min_usd" in reasons(r)


def test_c4_rejects_boolean_threshold():
    r = run(threshold=True)
    assert r["checks"]["reality_context"] == "fail"
    assert "materiality_min_usd" in reasons(r)


def test_c4_rejects_boolean_usd_affected():
    d5 = good_d5()
    d5["materiality"] = {**d5["materiality"], "usd_affected": True}
    r = run(d5=d5)
    assert r["checks"]["reality_context"] == "fail"
    assert "not a finite number" in reasons(r)


def test_e6_string_row_in_privileged_calls_still_blocks():
    d4 = good_d4()
    d4["privileged_calls"] = ["owner: setReward()"]
    r = run(d4=d4)
    assert r["checks"]["economic_reality"] == "fail"
    assert "privileged" in reasons(r)


def test_e1_rejects_non_dict_victim_loss_row():
    d4 = good_d4()
    d4["victim_loss"] = ["vault lost 100 WETH"]
    r = run(d4=d4)
    assert r["checks"]["economic_reality"] == "fail"
    assert "victim_loss" in reasons(r)


def test_e1_rejects_stringly_typed_net_positive_for_non_funds_family():
    d3 = make_d3()
    d3["impact_family"] = "confidentiality_loss"
    d4 = good_d4()
    d4["attacker_pnl"] = {"asset": "WETH", "attacker_in": "1", "attacker_out": "101", "net_positive": "true"}
    r = evaluate_readiness(
        scan=scan(),
        d3=d3,
        d4=d4,
        evidence=evidence(d4),
        d5=good_d5(),
        evaluated_at=EVALUATED_AT,
    )
    assert r["checks"]["economic_reality"] == "fail"
    assert "net_positive" in reasons(r)


def test_e1_rejects_unparseable_declared_site():
    d4 = good_d4()
    d4["setup_mutations"][0]["site"] = "not-a-site"
    r = run(d4=d4, sites=())
    assert r["checks"]["economic_reality"] == "fail"
    assert "not-a-site" in reasons(r)


def test_c1_rejects_unknown_upstream_status():
    d5 = good_d5()
    d5["upstream_fix"] = {"status": "definitely_maybe", "evidence": "asked the team"}
    r = run(d5=d5)
    assert r["checks"]["reality_context"] == "fail"
    assert "definitely_maybe" in reasons(r)


def test_e5_alone_for_permanent_freezing():
    d3 = make_d3()
    d3["impact_family"] = "permanent_freezing"
    d4 = good_d4()
    d4["victim_loss"][0]["preexisting_on_fork"] = False
    r = evaluate_readiness(
        scan=scan(),
        d3=d3,
        d4=d4,
        evidence=evidence(d4),
        d5=good_d5(),
        evaluated_at=EVALUATED_AT,
    )
    assert r["checks"]["economic_reality"] == "fail"
    assert "preexisting" in reasons(r)


def test_e6_for_audit_competition():
    d4 = good_d4()
    d4["privileged_calls"] = [{"site": SITE, "role": "owner", "function": "setFee"}]
    r = run(d4=d4, kind="audit_competition")
    assert r["checks"]["economic_reality"] == "fail"
    assert "privileged" in reasons(r)


# --- final fix round ---------------------------------------------------------


def test_uncaptured_poc_import_blocks_e2():
    d4 = good_d4()
    block = evidence(d4)
    block["uncaptured_poc_imports"] = ["test/Base.t.sol"]
    r = evaluate_readiness(scan=scan(), d3=make_d3(), d4=d4, evidence=block, d5=good_d5(), evaluated_at=EVALUATED_AT)
    assert r["checks"]["economic_reality"] == "fail"
    assert "PoC imports sources that were not captured: test/Base.t.sol." in reasons(r)


def test_evidence_block_carries_uncaptured_poc_imports():
    block = evidence_block(
        good_d4(),
        make_manifest(),
        capture_complete=True,
        artifact_dir=ARTIFACT_DIR,
        policy_version=POLICY_VERSION,
        legacy=False,
        uncaptured_poc_imports=["test/Base.t.sol", ""],
    )
    assert block["uncaptured_poc_imports"] == ["test/Base.t.sol"]
    assert evidence(good_d4())["uncaptured_poc_imports"] == []


def test_e2_accepts_path_line_col_site_spelling():
    d4 = good_d4()
    d4["setup_mutations"][0]["site"] = SITE + ":9"
    assert run(d4=d4)["ready"] is True


def test_2428_mislabelled_as_preexisting_victim_funds_still_blocks_on_c3():
    """vm.prank(VICTIM); WETH.transfer(POSITION_MANAGER, 1e18) labelled victim_user + preexisting."""
    d4 = good_d4()
    d4["setup_mutations"].append(
        {
            "site": "test/Attack.t.sol:107",
            "kind": "prank",
            "beneficiary_role": "victim_user",
            "justification": "live EOA transfers 1 WETH into VeloPositionManager",
        }
    )
    d4["victim_loss"] = [
        {
            "party": "live EOA",
            "asset": "WETH",
            "amount": "1",
            "preexisting_on_fork": True,
            "evidence_paths": ["balances.json"],
        }
    ]
    d5 = good_d5()
    d5["precondition_live"] = {"status": "absent_now", "evidence": "manager WETH balance 0 at block 157500563"}
    r = run(d4=d4, d5=d5, sites=({"site": SITE, "kind": "deal"}, {"site": "test/Attack.t.sol:107", "kind": "prank"}))
    assert r["ready"] is False
    assert r["checks"]["economic_reality"] == "pass"  # the mislabel defeats E3/E5 ...
    assert r["checks"]["reality_context"] == "fail"  # ... but C3 still blocks
    assert "absent_now" in reasons(r)


def test_2106_vm_funded_account_transfers_into_lending_pool_blocks_e3_and_c3():
    d4 = good_d4()
    d4["setup_mutations"] = [
        {"site": SITE, "kind": "deal", "beneficiary_role": "attacker", "justification": "attacker capital"},
        {
            "site": "test/Attack.t.sol:40",
            "kind": "deal",
            "beneficiary_role": "third_party",
            "justification": "vm.deal funds a helper account with WETH",
        },
        {
            "site": "test/Attack.t.sol:41",
            "kind": "prank",
            "beneficiary_role": "protocol_contract",
            "justification": "helper transfers 1 WETH directly into LendingPool",
        },
    ]
    d4["victim_loss"] = [
        {
            "party": "LendingPool",
            "asset": "WETH",
            "amount": "1",
            "preexisting_on_fork": False,
            "evidence_paths": ["balances.json"],
        }
    ]
    d5 = good_d5()
    d5["precondition_live"] = {"status": "absent_now", "evidence": "LendingPool WETH balanceOf = 0 at the fork block"}
    sites = (
        {"site": SITE, "kind": "deal"},
        {"site": "test/Attack.t.sol:40", "kind": "deal"},
        {"site": "test/Attack.t.sol:41", "kind": "prank"},
    )
    text = reasons(run(d4=d4, d5=d5, sites=sites))
    assert "protocol_contract (test/Attack.t.sol:41)" in text
    assert "absent_now" in text


def test_2105_treasury_fee_dust_blocks_c4():
    d4 = good_d4()
    d4["victim_loss"] = [
        {
            "party": "treasury",
            "asset": "USDC",
            "amount": "0.000003",
            "preexisting_on_fork": True,
            "evidence_paths": ["balances.json"],
        }
    ]
    d5 = good_d5()
    d5["materiality"] = {
        "usd_affected": 0.000003,
        "price_source": "USDC at $1",
        "threshold_usd": 15000,
        "basis": "treasury fee rounding, 3 base units",
    }
    r = run(d4=d4, d5=d5)
    assert r["checks"]["reality_context"] == "fail"
    assert "below the scan threshold $15,000.00" in reasons(r)


def test_gate_2_requires_victim_loss_evidence_to_be_captured():
    d4 = good_d4()
    d4["victim_loss"][0]["evidence_paths"] = ["victim-balances.json"]
    r = run(d4=d4)
    assert r["checks"]["provenance"] == "fail"
    assert "victim-balances.json" in reasons(r)


def test_gate_1_ignores_victim_loss_evidence_paths():
    d4 = {**make_d4(), "victim_loss": [{"party": "x", "evidence_paths": ["never-captured.json"]}]}
    r = evaluate_readiness(
        scan=make_scan(version=POLICY_VERSION_GATE_1),
        d3=make_d3(),
        d4=d4,
        evidence=evidence_block(
            d4,
            make_manifest(),
            capture_complete=True,
            artifact_dir=ARTIFACT_DIR,
            policy_version=POLICY_VERSION_GATE_1,
            legacy=False,
        ),
        d5=make_d5(),
        evaluated_at=EVALUATED_AT,
    )
    assert r["checks"]["provenance"] == "pass"


ATTACK_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ForkBase} from "./ForkBase.t.sol";

contract AttackTest is ForkBase {
    function testDrain() public {
        vm.deal(attacker, 1 ether);
        vm.startPrank(attacker);
        vault.drain();
        vm.stopPrank();
    }
}
"""
BASE_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

abstract contract ForkBase is Test {
    function setUp() public virtual {
        vm.createSelectFork("optimism", 157500563);
        vm.warp(block.timestamp + 1 days);
    }
}
"""


def e2e(tmp_path, poc_paths):
    workspace = tmp_path / "ws"
    (workspace / "test").mkdir(parents=True)
    (workspace / "test" / "Attack.t.sol").write_text(ATTACK_SOURCE)
    (workspace / "test" / "ForkBase.t.sol").write_text(BASE_SOURCE)
    (workspace / "attack.log").write_text("drained 100 WETH\n")
    (workspace / "balances.json").write_text(json.dumps({"vault_before": "100", "vault_after": "0"}))
    d4 = good_d4()
    d4["poc_artifact_paths"] = [*poc_paths, "attack.log"]
    d4["setup_mutations"] = [
        {"site": "test/Attack.t.sol:9", "kind": "deal", "beneficiary_role": "attacker", "justification": "gas"},
        {"site": "test/Attack.t.sol:10", "kind": "prank", "beneficiary_role": "attacker", "justification": "self"},
        {"site": "./test/ForkBase.t.sol:9:9", "kind": "time", "beneficiary_role": "time", "justification": "accrue"},
    ]
    capture = capture_evidence(
        str(tmp_path / "data"), str(workspace), scan_id=1, finding_id=2, metadata_id=3, result=d4
    )
    block = evidence_block(
        d4,
        set(capture["captured_paths"]),
        capture_complete=capture["capture_complete"],
        artifact_dir=capture["artifact_dir"],
        policy_version=POLICY_VERSION,
        legacy=False,
        cheatcode_sites=capture["cheatcode_sites"],
        poc_source_paths=capture["poc_source_paths"],
        uncaptured_poc_imports=capture["uncaptured_poc_imports"],
    )
    return evaluate_readiness(scan=scan(), d3=make_d3(), d4=d4, evidence=block, d5=good_d5(), evaluated_at=EVALUATED_AT)


def test_end_to_end_capture_to_readiness_is_ready_when_every_site_and_the_base_are_captured(tmp_path):
    r = e2e(tmp_path, ["test/Attack.t.sol", "test/ForkBase.t.sol"])
    assert r["ready"] is True, r["blocking_reasons"]


def test_end_to_end_capture_to_readiness_blocks_when_the_base_file_is_not_captured(tmp_path):
    r = e2e(tmp_path, ["test/Attack.t.sol"])
    assert r["ready"] is False
    assert r["checks"]["economic_reality"] == "fail"
    assert "PoC imports sources that were not captured: test/ForkBase.t.sol." in reasons(r)
