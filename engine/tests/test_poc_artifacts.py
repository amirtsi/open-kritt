import json
import os

from open_kritt_engine.poc_artifacts import MAX_FILES, capture_evidence


def result(poc_paths=(), impact_paths=(), chain_paths=()):
    return {
        "bug_status": "reproduced",
        "impact_status": "proven",
        "poc_artifact_paths": list(poc_paths),
        "impact_artifact_paths": list(impact_paths),
        "impact_chain": [{"id": "hop-1", "status": "proven", "evidence_paths": list(chain_paths)}],
    }


def workspace_with(tmp_path, names):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    for name in names:
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(name)
    return workspace


def capture(tmp_path, workspace, record, metadata_id=20):
    return capture_evidence(
        str(tmp_path / "data"),
        str(workspace),
        scan_id=4,
        finding_id=9,
        metadata_id=metadata_id,
        result=record,
    )


def test_capture_unions_and_dedupes_declared_paths_and_survives_cleanup(tmp_path):
    workspace = workspace_with(tmp_path, ["poc.py", "attack.log", "logs/balances.json"])
    capture_result = capture(
        tmp_path,
        workspace,
        result(["poc.py", "attack.log"], ["attack.log", "./logs/balances.json"], ["logs/balances.json"]),
    )
    assert capture_result["capture_complete"] is True
    assert capture_result["captured_paths"] == ["poc.py", "attack.log", "logs/balances.json"]
    assert capture_result["unresolved_paths"] == []
    assert capture_result["artifact_dir"] == "poc-artifacts/scan-4/finding-9/metadata-20"
    assert capture_result["reason"] == ""
    assert MAX_FILES == 20

    stored = tmp_path / "data" / capture_result["artifact_dir"]
    manifest = json.loads((stored / "manifest.json").read_text())
    assert [entry["source"] for entry in manifest] == ["poc.py", "attack.log", "logs/balances.json"]
    assert {entry["file"] for entry in manifest} == {"poc.py", "attack.log", "balances.json"}
    assert all(entry["sha256"] for entry in manifest)
    for child in workspace.rglob("*"):
        if child.is_file():
            child.unlink()
    assert (stored / "balances.json").read_text() == "logs/balances.json"


def test_cap_overflow_marks_capture_incomplete_without_copying(tmp_path):
    names = [f"f{i}.log" for i in range(MAX_FILES + 1)]
    workspace = workspace_with(tmp_path, names)
    capture_result = capture(tmp_path, workspace, result(names))
    assert capture_result["capture_complete"] is False
    assert capture_result["artifact_dir"] == ""
    assert capture_result["captured_paths"] == []
    assert sorted(capture_result["unresolved_paths"]) == sorted(names)
    assert str(MAX_FILES) in capture_result["reason"]
    assert not (tmp_path / "data").exists()


def test_traversal_absolute_and_missing_paths_are_unresolved(tmp_path):
    workspace = workspace_with(tmp_path, ["attack.log"])
    (tmp_path / "secret").write_text("secret")
    capture_result = capture(
        tmp_path, workspace, result(["../secret", str(tmp_path / "secret"), "missing.log", "attack.log"])
    )
    assert capture_result["capture_complete"] is False
    assert capture_result["captured_paths"] == ["attack.log"]
    assert capture_result["unresolved_paths"] == ["../secret", str(tmp_path / "secret"), "missing.log"]
    assert capture_result["artifact_dir"]
    assert not (tmp_path / "data" / capture_result["artifact_dir"] / "secret").exists()


def test_symlinks_are_resolved_inside_the_workspace_only(tmp_path):
    workspace = workspace_with(tmp_path, ["real.log"])
    (tmp_path / "outside.log").write_text("outside")
    os.symlink(workspace / "real.log", workspace / "inside-link.log")
    os.symlink(tmp_path / "outside.log", workspace / "escape-link.log")
    capture_result = capture(tmp_path, workspace, result(["inside-link.log", "escape-link.log"]))
    assert capture_result["captured_paths"] == ["inside-link.log"]
    assert capture_result["unresolved_paths"] == ["escape-link.log"]
    assert capture_result["capture_complete"] is False
    stored = tmp_path / "data" / capture_result["artifact_dir"]
    assert (stored / "inside-link.log").read_text() == "real.log"
    assert not (stored / "escape-link.log").exists()


def test_duplicate_basenames_get_distinct_artifact_names(tmp_path):
    workspace = workspace_with(tmp_path, ["a/out.log", "b/out.log"])
    capture_result = capture(tmp_path, workspace, result(["a/out.log", "b/out.log"]))
    assert capture_result["capture_complete"] is True
    manifest = json.loads((tmp_path / "data" / capture_result["artifact_dir"] / "manifest.json").read_text())
    files = [entry["file"] for entry in manifest]
    assert len(set(files)) == 2


def test_no_declared_paths_is_complete_without_an_artifact_dir(tmp_path):
    workspace = workspace_with(tmp_path, [])
    capture_result = capture(tmp_path, workspace, result())
    assert capture_result == {
        "artifact_dir": "",
        "captured_paths": [],
        "unresolved_paths": [],
        "capture_complete": True,
        "reason": "",
        "cheatcode_sites": [],
        "poc_source_paths": [],
        "uncaptured_poc_imports": [],
    }


def test_missing_workspace_is_reported_not_raised(tmp_path):
    capture_result = capture(tmp_path, tmp_path / "nope", result(["attack.log"]))
    assert capture_result["capture_complete"] is False
    assert capture_result["artifact_dir"] == ""
    assert capture_result["reason"]


def test_capture_records_cheatcode_sites_of_poc_sources_only(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "test").mkdir(parents=True)
    (workspace / "src").mkdir()
    (workspace / "test" / "Attack.t.sol").write_text("contract T {\n  function t() public { vm.deal(a, 1); }\n}\n")
    (workspace / "src" / "Payments.sol").write_text(
        "contract P { function k() public { selfdestruct(payable(a)); } }\n"
    )
    (workspace / "out.txt").write_text("ok\n")
    result = capture_evidence(
        str(tmp_path / "data"),
        str(workspace),
        scan_id=1,
        finding_id=2,
        metadata_id=3,
        result={"poc_artifact_paths": ["test/Attack.t.sol", "src/Payments.sol", "out.txt"]},
    )
    assert result["poc_source_paths"] == ["test/Attack.t.sol"]
    assert result["cheatcode_sites"] == [{"site": "test/Attack.t.sol:2", "kind": "deal"}]


def test_capture_without_paths_has_empty_cheatcode_fields(tmp_path):
    result = capture_evidence(str(tmp_path / "d"), str(tmp_path), scan_id=1, finding_id=2, metadata_id=3, result={})
    assert result["cheatcode_sites"] == [] and result["poc_source_paths"] == []
    assert result["uncaptured_poc_imports"] == []


# --- final fix round: imported PoC helpers -----------------------------------


def import_workspace(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "test" / "utils").mkdir(parents=True)
    (workspace / "src").mkdir()
    (workspace / "test" / "Attack.t.sol").write_text(
        'import "forge-std/Test.sol";\nimport {Base} from "./Base.t.sol";\nimport {Pool} from "../src/Pool.sol";\n'
        'import {H} from "./utils/Helper.sol";\n'
        "contract T is Base {\n  function t() public { vm.deal(a, 1); }\n}\n"
    )
    (workspace / "test" / "Base.t.sol").write_text("contract Base {\n  function setUp() public { vm.prank(v); }\n}\n")
    (workspace / "test" / "utils" / "Helper.sol").write_text("contract H {}\n")
    (workspace / "src" / "Pool.sol").write_text("contract Pool {}\n")
    return workspace


def capture_paths(tmp_path, workspace, paths):
    return capture_evidence(
        str(tmp_path / "data"),
        str(workspace),
        scan_id=1,
        finding_id=2,
        metadata_id=3,
        result={"poc_artifact_paths": paths},
    )


def test_uncaptured_poc_helpers_imported_by_a_poc_are_reported(tmp_path):
    workspace = import_workspace(tmp_path)
    result = capture_paths(tmp_path, workspace, ["test/Attack.t.sol"])
    assert result["uncaptured_poc_imports"] == ["test/Base.t.sol", "test/utils/Helper.sol"]
    assert result["cheatcode_sites"] == [{"site": "test/Attack.t.sol:6", "kind": "deal"}]


def test_captured_poc_helpers_are_scanned_and_not_reported(tmp_path):
    workspace = import_workspace(tmp_path)
    result = capture_paths(tmp_path, workspace, ["test/Attack.t.sol", "test/Base.t.sol", "test/utils/Helper.sol"])
    assert result["uncaptured_poc_imports"] == []
    assert {row["site"] for row in result["cheatcode_sites"]} == {"test/Attack.t.sol:6", "test/Base.t.sol:2"}


def test_non_test_helper_in_the_poc_tree_is_followed_when_captured(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "exploitkit").mkdir(parents=True)
    (workspace / "exploitkit" / "Run.t.sol").write_text('import "./Setup.sol";\ncontract R {}\n')
    (workspace / "exploitkit" / "Setup.sol").write_text(
        "contract S {\n function f() public { vm.store(a, s, v); }\n}\n"
    )
    missing = capture_paths(tmp_path, workspace, ["exploitkit/Run.t.sol"])
    assert missing["uncaptured_poc_imports"] == ["exploitkit/Setup.sol"]
    captured = capture_paths(tmp_path, workspace, ["exploitkit/Run.t.sol", "exploitkit/Setup.sol"])
    assert captured["uncaptured_poc_imports"] == []
    assert captured["cheatcode_sites"] == [{"site": "exploitkit/Setup.sol:2", "kind": "store"}]


def test_imports_escaping_the_workspace_or_missing_are_ignored(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "test").mkdir(parents=True)
    (tmp_path / "Outside.t.sol").write_text("contract O {}\n")
    (workspace / "test" / "A.t.sol").write_text('import "../../Outside.t.sol";\nimport "./Missing.t.sol";\n')
    result = capture_paths(tmp_path, workspace, ["test/A.t.sol"])
    assert result["uncaptured_poc_imports"] == []


def test_js_relative_requires_resolve_extensionless_helpers(tmp_path):
    workspace = tmp_path / "ws"
    (workspace / "test").mkdir(parents=True)
    (workspace / "test" / "exploit.test.js").write_text(
        "const { ethers } = require('hardhat');\nconst { fund } = require('./fixtures');\n"
    )
    (workspace / "test" / "fixtures.js").write_text("module.exports = {};\n")
    result = capture_paths(tmp_path, workspace, ["test/exploit.test.js"])
    assert result["uncaptured_poc_imports"] == ["test/fixtures.js"]
