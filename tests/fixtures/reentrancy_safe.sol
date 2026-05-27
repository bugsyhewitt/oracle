// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's reentrancy detector (POST_V01 Rank 2): the SAFE control.
//
// Correct check-effects-interactions (CEI) ordering: the balance slot is zeroed
// (SSTORE slot 0) BEFORE the external call forwards any ether. A re-entrant
// callee sees the already-updated (zero) balance, so the withdraw cannot be
// repeated. The detector must NOT flag this contract: the only SSTORE to the
// pre-read slot happens before the CALL, not after it.
contract ReentrancySafe {
    uint256 public balance;

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw() external {
        // SLOAD balance (slot 0)
        uint256 amount = balance;
        require(amount > 0);

        // EFFECT first: zero the balance BEFORE the interaction
        balance = 0;

        // INTERACTION last: by now slot 0 is already updated
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
