from pathlib import Path

from open_kritt_engine.poc_cheatcodes import cheatcode_sites, is_poc_source, normalize_site

FIXTURES = Path(__file__).parent / "fixtures" / "poc_cheatcodes"


def load(name, as_path):
    return {as_path: (FIXTURES / name).read_text(encoding="utf-8")}


def sites(files):
    return {(row["site"], row["kind"]) for row in cheatcode_sites(files)}


def test_is_poc_source_accepts_tests_and_rejects_production_copies():
    assert is_poc_source("test/Sweep.t.sol")
    assert is_poc_source("poc/attack/Exploit.sol")
    assert is_poc_source("tests/exploit.test.ts")
    assert not is_poc_source("src/Payments.sol")
    assert not is_poc_source("poc/attack/output.txt")


def test_real_2428_victim_prank_is_found():
    found = sites(load("VeloPositionManagerSweepFork.t.sol", "test/VeloPositionManagerSweepFork.t.sol"))
    assert ("test/VeloPositionManagerSweepFork.t.sol:107", "prank") in found
    assert ("test/VeloPositionManagerSweepFork.t.sol:131", "prank") in found


def test_real_2142_selfdestruct_and_deals_are_found_and_interface_declarations_ignored():
    found = sites(load("RefundETHSweep.t.sol", "test/RefundETHSweep.t.sol"))
    assert ("test/RefundETHSweep.t.sol:22", "selfdestruct_fund") in found
    assert ("test/RefundETHSweep.t.sol:48", "deal") in found
    assert ("test/RefundETHSweep.t.sol:52", "prank") in found
    assert not any(site.endswith(":6") for site, _ in found)  # `function deal(address, uint256) external;`


def test_real_2166_store_prank_and_warp_are_found():
    found = sites(load("StakingRewardsFutureStartFork.t.sol", "test/StakingRewardsFutureStartFork.t.sol"))
    assert ("test/StakingRewardsFutureStartFork.t.sol:96", "store") in found
    assert ("test/StakingRewardsFutureStartFork.t.sol:102", "store") in found
    assert ("test/StakingRewardsFutureStartFork.t.sol:134", "prank") in found
    assert ("test/StakingRewardsFutureStartFork.t.sol:149", "time") in found
    assert not any(site.endswith(":7") for site, _ in found)


def test_comments_are_ignored_but_code_after_a_url_string_is_not():
    source = (
        '// vm.deal(a, 1);\n/* vm.store(a, b, c);\n vm.etch(a, b); */\nstring memory u = "https://x"; vm.deal(a, 1);\n'
    )
    assert sites({"test/A.t.sol": source}) == {("test/A.t.sol:4", "deal")}


def test_production_copies_are_not_scanned():
    assert cheatcode_sites({"src/Payments.sol": "function f() { selfdestruct(payable(a)); }"}) == []


def test_hardhat_helpers_are_found_in_js_tests():
    source = 'await network.provider.request({ method: "hardhat_setBalance", params: [a, "0x1"] });\n'
    source += "await impersonateAccount(owner);\n"
    assert sites({"test/exploit.test.js": source}) == {
        ("test/exploit.test.js:1", "deal"),
        ("test/exploit.test.js:2", "prank"),
    }


def test_normalize_site():
    assert normalize_site("./test/A.t.sol:12") == "test/A.t.sol:12"
    assert normalize_site("test/A.t.sol:12") == "test/A.t.sol:12"
    assert normalize_site("/abs/test/A.t.sol:12") is None
    assert normalize_site("test/A.t.sol") is None
    assert normalize_site("") is None
