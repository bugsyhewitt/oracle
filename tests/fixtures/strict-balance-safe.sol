// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart to strict-balance-vuln.sol (SWC-132).
//
// The safe design never branches on `address(this).balance`. It tracks the
// total deposited in a dedicated storage accumulator (`tracked`) and gates the
// payout on that internally-controlled value, which force-feeding cannot
// influence (a `selfdestruct`-push or CREATE2 pre-fund changes the raw balance
// but not `tracked`). Authorisation is by `msg.sender`, not by balance.
//
// solc emits no balance comparison feeding a JUMPI here, so the
// strict-balance-equality detector must NOT flag it.
contract StrictBalanceSafe {
    uint256 public constant target = 10 ether;
    uint256 public tracked;

    function deposit() external payable {
        tracked += msg.value;
    }

    function claim() external {
        // gate on the internally-tracked accumulator, never the raw balance.
        require(tracked >= target, "not enough deposited");
        tracked = 0;
        payable(msg.sender).transfer(target);
    }
}
