from test_impact_gate import ARTIFACT_DIR, EVALUATED_AT, make_d3, make_d4, make_d5, make_manifest, make_scan

from open_kritt_engine.impact_gate import evaluate_readiness, evidence_block
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
    assert "PoC source was not captured" in reasons(r)


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


def test_2142_attacker_pays_itself_blocks_e4():
    d4 = good_d4()
    d4["attacker_pnl"] = {"asset": "ETH", "attacker_in": "2", "attacker_out": "2", "net_positive": False}
    assert "net profit" in reasons(run(d4=d4))


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
