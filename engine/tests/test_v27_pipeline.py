from open_kritt_engine.v27_pipeline import eligible_for_stage, pipeline_ids, preceding_results


def scan():
    return {"configuration": {"v27_pipeline": {"d3": "11", "d4": "12", "d5": "13"}}}


def test_v27_gates_poc_and_report_on_prior_results():
    current = scan()
    assert pipeline_ids(current) == {"d3": 11, "d4": 12, "d5": 13}
    assert eligible_for_stage(current, 11, {})
    assert not eligible_for_stage(current, 12, {})
    assert not eligible_for_stage(current, 12, {11: {"verdict": "false_positive"}})
    assert eligible_for_stage(current, 12, {11: {"verdict": "plausible_needs_poc"}})
    assert not eligible_for_stage(current, 13, {12: {"poc_status": "reproduced"}})
    prior = {11: {"verdict": "confirmed"}, 12: {"poc_status": "reproduced", "poc_artifact_dir": "poc-artifacts/scan-1"}}
    assert eligible_for_stage(current, 13, prior)
    assert preceding_results(current, 13, prior) == {"d3": prior[11], "d4": prior[12]}


def test_unconfigured_scans_keep_existing_post_script_behavior():
    assert pipeline_ids({"configuration": {}}) == {}
    assert eligible_for_stage({"configuration": {}}, 7, {})


def test_report_readiness_requires_verified_scope_novelty_and_saved_poc():
    from open_kritt_engine.v27_pipeline import enforce_report_readiness

    d4 = {"poc_status": "reproduced", "poc_artifact_dir": "poc-artifacts/scan-4/finding-9/metadata-20"}
    ready = {
        "submission_ready": True,
        "scope_status": "in_scope_verified",
        "novelty_status": "novel_verified",
        "scope_evidence": "Program names this asset",
        "novelty_evidence": "Checked published reports",
        "missing_requirements": "",
        "artifact_reference": d4["poc_artifact_dir"],
    }
    assert enforce_report_readiness(dict(ready), d4)["submission_ready"] is True
    assert enforce_report_readiness(dict(ready, scope_evidence=""), d4)["submission_ready"] is False
    assert enforce_report_readiness(dict(ready), {})["submission_ready"] is False
