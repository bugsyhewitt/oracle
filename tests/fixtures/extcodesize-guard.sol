// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's post-call path coverage (POST_V01 Tier 1 Item 1).
//
// A common (and flawed) access-control idiom: "only allow externally-owned
// accounts" by checking `extcodesize(caller) == 0`. solc emits the EXTCODESIZE
// opcode for this. Under oracle v0.1 the path halted on EXTCODESIZE, so the
// SELFDESTRUCT behind the guard was unreachable to the detector.
//
// With the EXTCODESIZE handler in place, oracle explores both sides of the
// guard and finds the reachable SELFDESTRUCT (the guard is bypassable — the
// extcodesize value is symbolic, so the `== 0` branch is satisfiable).
//
// Trigger: call destroy(target) from an account whose code size is zero.
contract ExtCodeSizeGuard {
    function destroy(address payable target) external {
        uint256 size;
        address sender = msg.sender;
        assembly {
            size := extcodesize(sender)
        }
        // guard: only "EOAs" (size 0) may proceed — trivially bypassable
        require(size == 0, "contracts not allowed");
        selfdestruct(target);
    }
}
