from open_kritt_engine.poc_artifacts import finalize_poc_result


def result(paths):
    return {
        "poc_status": "reproduced",
        "poc_artifact_paths": paths,
        "repeat_count": 2,
        "negative_control_observed": "rejected",
        "remaining_limits": "",
        "_reserved_poc": "observed",
    }


def test_poc_artifacts_survive_workspace_cleanup(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name in ("poc.py", "attack.log", "control.log", "repeat.log"):
        (workspace / name).write_text(name)
    record = finalize_poc_result(
        str(tmp_path / "data"),
        str(workspace),
        scan_id=4,
        finding_id=9,
        metadata_id=20,
        result=result(["poc.py", "attack.log", "control.log", "repeat.log"]),
    )
    assert record["poc_status"] == "reproduced"
    stored = tmp_path / "data" / record["poc_artifact_dir"]
    assert (stored / "manifest.json").exists()
    for child in workspace.iterdir():
        child.unlink()
    assert (stored / "attack.log").read_text() == "attack.log"


def test_missing_or_escaping_artifact_blocks_report_readiness(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    record = finalize_poc_result(
        str(tmp_path / "data"),
        str(workspace),
        scan_id=4,
        finding_id=9,
        metadata_id=21,
        result=result(["../secret", "attack.log", "control.log", "repeat.log"]),
    )
    assert record["poc_status"] == "insufficient_evidence"
    assert record["poc_artifact_dir"] == ""
