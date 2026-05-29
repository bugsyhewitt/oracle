// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's timestamp-dependence detector (SWC-116, "Block values
// as a proxy for time").
//
// RANDOMNESS / DECISION VULNERABILITY. `play()` decides whether the caller
// "wins" a payout by branching on `block.timestamp` (here `% 2`). Both
// block.timestamp and block.number are set by the block proposer (miner /
// validator), who has discretion over them — a few seconds of slack on the
// timestamp and full control over transaction ordering. Branching control flow
// on a block value to gate a payout / pick a winner lets the proposer influence
// the outcome: the canonical timestamp-as-randomness gambling bug (SWC-116).
//
// The detector flags this because the contract branches control flow on a block
// value (the TIMESTAMP value flows into a comparison that feeds a JUMPI), so a
// path constraint references the symbolic `timestamp` leaf. The safe primitive
// is a commit-reveal scheme or an external randomness oracle, never a raw block
// value.
contract TimestampDependenceVuln {
    mapping(address => uint256) public winnings;

    // amount is calldata-supplied so the block-value-dependent branch is on a
    // satisfiable path rather than collapsed by oracle's all-zero initial state.
    function play(uint256 amount) external {
        // UNSAFE: control flow gated on a manipulable block value (SWC-116).
        if (block.timestamp % 2 == 0) {
            winnings[msg.sender] += amount;
        }
    }
}
