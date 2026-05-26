// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deliberately vulnerable fixture for oracle's `selfdestruct` check.
//
// An UNGUARDED selfdestruct: any caller can destroy the contract and sweep its
// balance to an attacker-controlled address. There is no owner check, no
// access control — the path to SELFDESTRUCT is reachable from any transaction.
//
// Trigger: call kill(attacker) from any account.
contract ReachableSelfdestruct {
    function kill(address payable target) external {
        selfdestruct(target);
    }
}
