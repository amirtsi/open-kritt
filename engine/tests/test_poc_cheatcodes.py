from pathlib import Path

import pytest

from open_kritt_engine.poc_cheatcodes import cheatcode_sites, is_poc_source, normalize_site, relative_imports

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
    assert normalize_site("test/A.t.sol:12:5") == "test/A.t.sol:12"
    assert normalize_site("./test/A.t.sol:12:5") == "test/A.t.sol:12"
    assert normalize_site("test/A.t.sol:12:") is None


# --- final fix round: pattern coverage ---------------------------------------


def one_site(path, line):
    return sites({path: line + "\n"})


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        ("vm.etch(target, code);", "etch"),
        ("hoax(attacker, 1 ether);", "deal"),
        ("startHoax(attacker);", "deal"),
        ("vm.roll(block.number + 1);", "time"),
        ("vm.mockCall(oracle, data, ret);", "store"),
        ("vm.mockCallRevert(oracle, data, err);", "store"),
        ("stdstore.target(t).sig(t.balanceOf.selector).with_key(a).checked_write(1e18);", "store"),
        ("changePrank(owner);", "prank"),
        ("vm.changePrank(owner);", "prank"),
        ("hevm.store(target, slot, value);", "store"),
        ("cheats.deal(attacker, 1 ether);", "deal"),
        ("cheats.startPrank(owner);", "prank"),
        ("hevm.warp(block.timestamp + 1 days);", "time"),
        ('vm.rpc("anvil_setBalance", params);', "deal"),
        ('vm.rpc("anvil_setStorageAt", params);', "store"),
        ('vm.rpc("anvil_impersonateAccount", params);', "prank"),
        ('vm.rpc("anvil_setCode", params);', "etch"),
    ],
)
def test_solidity_cheatcode_forms_are_found(line, kind):
    assert one_site("test/A.t.sol", line) == {("test/A.t.sol:1", kind)}


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        ('await network.provider.send("hardhat_setStorageAt", [a, s, v]);', "store"),
        ('await network.provider.send("hardhat_impersonateAccount", [a]);', "prank"),
        ('await network.provider.send("hardhat_setCode", [a, code]);', "etch"),
        ('await provider.send("anvil_setBalance", [a, "0x1"]);', "deal"),
        ('await provider.send("anvil_setStorageAt", [a, s, v]);', "store"),
        ('await provider.send("anvil_impersonateAccount", [a]);', "prank"),
        ('await provider.send("anvil_setCode", [a, code]);', "etch"),
        ("await setBalance(a, 10n ** 18n);", "deal"),
        ("await setStorageAt(a, 0, v);", "store"),
        ("await setCode(a, code);", "etch"),
        ('await network.provider.send("evm_increaseTime", [3600]);', "time"),
        ('await network.provider.send("evm_mine");', "time"),
        ("await time.increase(3600);", "time"),
    ],
)
def test_js_cheatcode_forms_are_found(line, kind):
    assert one_site("test/exploit.test.ts", line) == {("test/exploit.test.ts:1", kind)}


def test_interface_declarations_of_new_forms_are_ignored():
    source = "interface Vm {\n  function mockCall(address, bytes calldata, bytes calldata) external;\n"
    source += "  function changePrank(address) external;\n}\n"
    assert sites({"test/A.t.sol": source}) == set()


def test_line_numbers_count_newlines_only():
    source = "string memory s = 'a b';\nvm.deal(a, 1);\n"
    assert sites({"test/A.t.sol": source}) == {("test/A.t.sol:2", "deal")}


def test_quote_inside_a_js_regex_literal_does_not_hide_code():
    source = 'const re = /"/g; await setBalance(a, 1);\n'
    assert sites({"test/exploit.test.js": source}) == {("test/exploit.test.js:1", "deal")}


def test_js_division_is_not_a_regex_literal():
    source = 'const x = a / b; const s = "/"; await setBalance(a, 1);\n'
    assert sites({"test/exploit.test.js": source}) == {("test/exploit.test.js:1", "deal")}


def test_relative_imports_keep_only_relative_specifiers():
    sol = 'import "forge-std/Test.sol";\nimport {Base} from "./Base.t.sol";\nimport "../lib/Helper.sol";\n'
    sol += 'import "@openzeppelin/token/ERC20.sol";\n// import "./Commented.sol";\n'
    assert relative_imports("test/A.t.sol", sol) == ["./Base.t.sol", "../lib/Helper.sol"]
    js = "import { ethers } from 'hardhat';\nimport helpers from './helpers';\nconst b = require('../base.js');\n"
    js += "const c = require('chai');\n"
    assert relative_imports("test/a.test.js", js) == ["./helpers", "../base.js"]
