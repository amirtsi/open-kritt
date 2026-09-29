from pathlib import Path

from open_kritt_engine.static_facts import STATIC_DIR, build_static_facts, solidity_access_index

VAULT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

contract Vault {
    // function commented(uint256 a) external {}
    /* function blockCommented() public {} */
    constructor(address owner_) {}

    function deposit(uint256 assets, address receiver)
        external
        nonReentrant
        returns (uint256 shares)
    {
        shares = assets;
    }

    function setFee(uint256 bps) external onlyAdminOrOwner {}

    function sweep(address token) external {
        require(msg.sender == owner, "not owner");
    }

    function pause() public {
        if (msg.sender != admin) revert Unauthorized();
    }

    function settle(uint256 amount) external {
        require(registry.isDepositHandler(msg.sender), Unauthorized());
    }

    function forward() external {
        __validateSender();
    }

    function totalAssets() external view returns (uint256) {
        return 0;
    }

    function helper() internal {}

    receive() external payable {}
}

interface IVault {
    function deposit(uint256 assets, address receiver) external returns (uint256);
}
"""


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "Vault.sol").write_text(VAULT, encoding="utf-8")
    for vendored in ("lib/oz/Token.sol", "test/Vault.t.sol", "script/Deploy.s.sol"):
        path = root / vendored
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("contract X { function f() external {} }\n", encoding="utf-8")
    return root


def test_index_lists_state_changing_entrypoints_with_their_guards(tmp_path):
    entries = {entry["function"]: entry for entry in solidity_access_index(_repo(tmp_path))}

    assert set(entries) == {"deposit", "setFee", "sweep", "pause", "settle", "forward", "receive"}
    assert entries["deposit"] == {
        "file": "src/Vault.sol",
        "line": 9,
        "contract": "Vault",
        "function": "deposit",
        "visibility": "external",
        "payable": False,
        "modifiers": ["nonReentrant"],
        "guard": "none",
    }
    assert entries["setFee"]["guard"] == "modifier"
    assert entries["sweep"]["guard"] == "body_sender_check"
    assert entries["pause"]["guard"] == "body_sender_check"
    assert entries["settle"]["guard"] == "body_sender_check"
    assert entries["forward"]["guard"] == "body_sender_check"
    assert entries["receive"]["payable"] is True


def test_build_writes_summary_and_json_outside_the_source_tree(tmp_path):
    repo = _repo(tmp_path)
    target = tmp_path / "workspace"
    target.mkdir()

    summary = build_static_facts(repo, target)

    assert summary == {"path": f"{STATIC_DIR}/ACCESS.md", "entrypoints": 7, "unguarded": 2}
    access = (target / STATIC_DIR / "ACCESS.md").read_text(encoding="utf-8")
    assert "src/Vault.sol:9 Vault.deposit" in access
    assert access.index("Unguarded") < access.index("setFee")
    assert (target / STATIC_DIR / "access-index.json").is_file()
    assert not (repo / STATIC_DIR).exists()


def test_repository_without_solidity_builds_nothing(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "main.go").write_text("package main\n", encoding="utf-8")
    target = tmp_path / "workspace"
    target.mkdir()

    assert build_static_facts(repo, target) is None
    assert not (target / STATIC_DIR).exists()
