// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's reentrancy detector (POST_V01 Rank 2).
//
// Classic check-effects-interactions (CEI) VIOLATION. The contract reads the
// stored balance (SLOAD), forwards ether with a low-level call (CALL hands
// control to msg.sender), and only AFTER the call zeroes the balance (SSTORE
// to the slot read before the call). A re-entrant callee re-enters withdraw()
// while the balance is still non-zero and drains the contract — the DAO bug.
//
// A single `uint256 balance` (storage slot 0) is used rather than a mapping so
// the SLOADed and SSTOREd slot have a concrete, matchable identity under
// oracle's bounded storage model.
contract ReentrancyVuln {
    uint256 public balance;

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw() external {
        // SLOAD balance (slot 0) BEFORE the external interaction
        uint256 amount = balance;
        require(amount > 0);

        // INTERACTION: forwards ether, lets msg.sender re-enter
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);

        // EFFECT applied AFTER the interaction — too late. This SSTORE writes
        // slot 0, which was SLOADed before the call: the CEI violation.
        balance = 0;
    }
}
