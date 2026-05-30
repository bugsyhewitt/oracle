// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's cross-function reentrancy detector (SWC-107 cross-
// function variant) — the SAFE control. Same two-function shape as the vuln
// fixture (a calling function that does an external CALL, plus a sibling
// state-mutator on the same slot), but the calling function zeroes its
// pre-read slot BEFORE the CALL. A reentered call into transfer() can still
// write the balance slot, but the in-flight withdraw has already committed
// its own update, so the reentry cannot cause withdraw to act on stale
// state. The detector must NOT flag this contract.
contract ReentrancyCrossSafe {
    uint256 public balance;

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw() external {
        uint256 amount = balance;
        require(amount > 0);

        balance = 0;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function transfer(uint256 newBalance) external {
        balance = newBalance;
    }
}
