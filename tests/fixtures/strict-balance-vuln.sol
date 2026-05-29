// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's strict-balance-equality detector (SWC-132, "Unexpected
// Ether Balance").
//
// A contract's ether balance is NOT controlled solely by its own logic: any
// account can force ether in via `selfdestruct(this)` or by pre-funding a
// CREATE2 address before deployment. Neither path runs the receive/fallback
// code. A contract that *branches on* `address(this).balance` is therefore
// making an attacker-falsifiable assumption.
//
// This `game` assumes its balance can only change through `deposit()`, and
// gates the winning payout on the exact-balance invariant `balance == target`.
// An attacker force-feeds 1 wei via a self-destructing helper, the invariant
// can never be hit by honest play, and the funds are stuck (or the attacker
// arranges the off-by-wei to claim them). solc emits SELFBALANCE / BALANCE for
// `address(this).balance`, and the `==` comparison feeds a JUMPI — the
// control-flow-branch-on-balance signal the detector keys on.
//
// Trigger: any call to claim() once the balance has been nudged off `target`.
contract StrictBalanceVuln {
    uint256 public constant target = 10 ether;

    function deposit() external payable {}

    function claim() external {
        // SWC-132: the contract trusts its raw balance as an invariant. An
        // attacker can force-feed ether to make this comparison unsatisfiable
        // for honest players (or satisfiable on their terms).
        require(address(this).balance == target, "not at target");
        payable(msg.sender).transfer(address(this).balance);
    }
}
