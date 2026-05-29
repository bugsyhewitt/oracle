// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's block-gas-limit DoS detector (SWC-128).
//
// DoS VULNERABILITY ("DoS with block gas limit" / "unbounded operation").
// `processN(n)` loops `n` times, and `n` is a caller-supplied, UNBOUNDED argument
// (no upper-bound check). Every iteration re-reads contract STORAGE (`step`) and
// writes contract STORAGE (`total`). The function's gas cost therefore grows
// linearly with `n`, and because `n` is unbounded a caller can drive the call's
// gas past the block gas limit, at which point the transaction always reverts on
// out-of-gas and the operation can never complete — the classic unbounded-loop /
// unbounded-operation DoS (SWC-128, "DoS With Block Gas Limit"). The same surface
// appears whenever the iteration count is bounded by a value that can grow
// without bound (an unbounded storage array's length, an unchecked parameter, a
// monotonically growing counter) while the loop body does per-iteration storage
// work.
//
// The discriminating signal oracle keys on is that the loop body re-reads
// CONTRACT STORAGE every iteration: oracle's bounded executor unrolls the loop
// and revisits the SLOAD (emitted for `step` / `total`) more than once on a
// single path. A storage-touching loop whose trip count is not bounded by a
// constant is the unbounded-operation surface. A loop whose body does NOT re-read
// storage (see the safe fixture) never recurs an SLOAD pc and is not flagged.
//
// The trip count is a calldata argument so the loop-entered path stays
// satisfiable under oracle's solver (oracle initialises storage to all-zero, so a
// loop bounded by a *storage* array length would collapse to zero iterations and
// the entered path would be unsatisfiable — the same all-zero-storage caveat the
// other detectors' fixtures account for).
contract GasLimitDosVuln {
    uint256 public total;
    uint256 public step;

    function processN(uint256 n) external {
        // `n` is unbounded (no `require(n <= MAX)`), and the body reads + writes
        // storage every iteration: gas grows with `n` until it exceeds the block
        // gas limit and the call can never complete.
        for (uint256 i = 0; i < n; i++) {
            total += step;
        }
    }
}
