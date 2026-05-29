// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart for oracle's arbitrary-jump detector (SWC-127).
//
// This contract uses inline assembly with a `switch`/loop so the compiler still
// emits JUMP/JUMPI opcodes — but every jump destination is a compile-time
// constant the compiler computed, never a value read from calldata. The
// `sum()` function loops over a calldata count, which lowers to a back-edge
// JUMPI whose target is a fixed label, and branches on a calldata value, which
// lowers to a JUMPI whose target is also a fixed label. The opcodes are present,
// so this fixture proves the detector keys on a *calldata-derived* jump target,
// not on the JUMP/JUMPI opcode itself.
contract ArbitraryJumpSafe {
    function sum(uint256 n) external pure returns (uint256 total) {
        // require(n <= 100) and a bounded loop: the loop back-edge is a JUMPI to
        // a constant destination. `n` flows into the loop *condition*, never
        // into a jump *target*.
        require(n <= 100, "too big");
        for (uint256 i = 0; i < n; i++) {
            if (i % 2 == 0) {
                total += i;
            } else {
                total += 1;
            }
        }
    }
}
