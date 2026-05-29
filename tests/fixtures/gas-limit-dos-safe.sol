// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE counterpart for oracle's block-gas-limit DoS detector (SWC-128).
//
// `sumN(n)` loops, but its bound is a CALLER-SUPPLIED, range-checked argument
// (`require(n <= 100)`) — a constant ceiling, never read from contract storage.
// The loop's iteration count is bounded by a value that cannot grow with the
// contract's state, so the call cost is bounded and it can never be pushed past
// the block gas limit. The loop opcode (JUMPI back-edge) is STILL present, so
// this fixture proves the detector keys on the loop re-reading *storage* for its
// bound (an unbounded-in-state loop), not on the mere presence of a loop.
contract GasLimitDosSafe {
    uint256 public total;

    function sumN(uint256 n) external {
        // bound is a calldata argument with a hard constant ceiling: bounded,
        // and never re-read from storage inside the loop.
        require(n <= 100, "too many iterations");
        uint256 s = 0;
        for (uint256 i = 0; i < n; i++) {
            s += i;
        }
        total = s;
    }
}
