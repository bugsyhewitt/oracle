// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's DoS-with-failed-call detector (SWC-113).
//
// DoS VULNERABILITY ("denial of service with failed call" / "revert in loop").
// `distribute()` pays every recipient inside a single loop, and the `transfer`
// (which reverts on a failed send) is in the loop body. A single recipient that
// cannot accept ether — a contract with a reverting/expensive fallback — makes
// the whole loop revert, so NObody is ever paid. One malicious or broken entry
// permanently bricks the payout for everyone (the classic auction/airdrop DoS).
//
// The recipient list is a calldata argument (an attacker controls both its
// contents and its length), so the loop body is reachable with two or more
// iterations: oracle's bounded executor unrolls the loop and revisits the CALL
// (emitted by `transfer`) more than once on a single path. The detector flags
// that loop-bound external call — one failing callee can revert the batch. A
// pull-payment design (see dos-failed-call-safe.sol) makes a single call per
// transaction with no loop, so the failure is isolated to one recipient.
contract DosFailedCallVuln {
    function distribute(address[] calldata recipients) external {
        // external call INSIDE a loop: one reverting recipient DoSes everyone.
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(1);
        }
    }
}
