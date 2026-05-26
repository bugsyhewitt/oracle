// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deliberately vulnerable fixture for oracle's `overflow` check.
//
// Solidity >=0.8 reverts on overflow by default, so the wraparound is placed
// inside an `unchecked` block — the classic real-world overflow bug pattern
// where a developer disabled the checked arithmetic. The ADD wraps modulo
// 2**256 when `amount` is large, which oracle detects symbolically.
//
// Trigger: call add(a) with a near 2**256-1 so the symbolic balance addition
// wraps.
contract IntegerOverflow {
    uint256 public balance;

    function add(uint256 amount) external {
        unchecked {
            balance = balance + amount;
        }
    }
}
