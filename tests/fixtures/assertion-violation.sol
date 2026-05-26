// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deliberately vulnerable fixture for oracle's `assertion` check.
//
// The function reaches a raw EVM `invalid()` (opcode 0xFE) when the caller
// supplies a specific input. A reachable INVALID is exactly what solc emits
// for a violated assert() in older toolchains, and oracle treats any
// reachable 0xFE as an assertion violation.
//
// Trigger: call check(x) with x == 66.
contract AssertionViolation {
    function check(uint256 x) external pure {
        if (x == 66) {
            assembly {
                invalid()
            }
        }
    }
}
