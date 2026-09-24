"""Conditional post-processing gates for the versioned v2.7 scan profile."""

from typing import Any

D3_PASS_VERDICTS = frozenset({"confirmed", "plausible_needs_poc"})


def pipeline_ids(scan: dict[str, Any]) -> dict[str, int]:
    configuration = scan.get("configuration")
    raw = configuration.get("v27_pipeline") if isinstance(configuration, dict) else None
    if not isinstance(raw, dict):
        return {}
    try:
        ids = {stage: int(raw[stage]) for stage in ("d3", "d4", "d5")}
    except (KeyError, TypeError, ValueError):
        return {}
    if any(value <= 0 for value in ids.values()) or len(set(ids.values())) != 3:
        return {}
    return ids


def stage_for_script(scan: dict[str, Any], script_id: int) -> str | None:
    return next((stage for stage, value in pipeline_ids(scan).items() if value == script_id), None)


def prior_results(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {
        int(row["post_script_id"]): row["result"]
        for row in rows
        if isinstance(row.get("result"), dict) and not row.get("stub")
    }


def eligible_for_stage(scan: dict[str, Any], script_id: int, results: dict[int, dict[str, Any]]) -> bool:
    stage = stage_for_script(scan, script_id)
    if stage in (None, "d3"):
        return True
    ids = pipeline_ids(scan)
    if stage == "d4":
        return results.get(ids["d3"], {}).get("verdict") in D3_PASS_VERDICTS
    if stage == "d5":
        d4 = results.get(ids["d4"], {})
        return d4.get("poc_status") == "reproduced" and bool(d4.get("poc_artifact_dir"))
    return False


def preceding_results(scan: dict[str, Any], script_id: int, results: dict[int, dict[str, Any]]) -> dict[str, Any]:
    stage = stage_for_script(scan, script_id)
    ids = pipeline_ids(scan)
    if stage == "d4":
        return {"d3": results.get(ids["d3"], {})}
    if stage == "d5":
        return {"d3": results.get(ids["d3"], {}), "d4": results.get(ids["d4"], {})}
    return {}


def enforce_report_readiness(result: dict[str, Any], d4: dict[str, Any]) -> dict[str, Any]:
    """Keep a model's report-ready claim behind explicit evidence gates."""
    required = (
        d4.get("poc_status") == "reproduced"
        and bool(d4.get("poc_artifact_dir"))
        and result.get("scope_status") == "in_scope_verified"
        and result.get("novelty_status") == "novel_verified"
        and bool(str(result.get("scope_evidence") or "").strip())
        and bool(str(result.get("novelty_evidence") or "").strip())
        and result.get("artifact_reference") == d4.get("poc_artifact_dir")
        and not str(result.get("missing_requirements") or "").strip()
    )
    if result.get("submission_ready") is True and not required:
        result["submission_ready"] = False
        result["missing_requirements"] = (
            str(result.get("missing_requirements") or "").strip()
            + "\nReadiness gate: verified PoC, scope, novelty, artifact reference and no missing requirements are required."
        ).strip()
    return result
