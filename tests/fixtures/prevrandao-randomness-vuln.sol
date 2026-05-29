// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's prevrandao-randomness detector (SWC-120, "Weak Sources
// of Randomness from Chain Attributes").
//
// WEAK-RANDOMNESS VULNERABILITY. `play()` decides whether the caller "wins" a
// payout by branching on `block.prevrandao` (here `% 2`). The DIFFICULTY opcode
// (0x44) is the post-Merge `block.prevrandao` (and the pre-Merge
// `block.difficulty`). It is NOT a secure source of entropy: the value is
// contributed by the block proposer (the validator who assembles the block
// supplies the RANDAO reveal) and — more cheaply — an attacker calling in the
// SAME transaction reads the exact same `block.prevrandao` the contract uses,
// so they can compute the "random" outcome in advance and only enter when they
// win. Branching control flow on `block.prevrandao` to gate a payout / pick a
// winner is the canonical prevrandao-as-randomness gambling bug (SWC-120).
//
// The detector flags this because the contract branches control flow on
// prevrandao (the DIFFICULTY value flows into a comparison that feeds a JUMPI),
// so a path constraint references the symbolic `prevrandao` leaf. The safe
// primitive is a commit-reveal scheme or an external randomness oracle (VRF),
// never a raw chain attribute.
contract PrevrandaoRandomnessVuln {
    mapping(address => uint256) public winnings;

    // amount is calldata-supplied so the prevrandao-dependent branch is on a
    // satisfiable path rather than collapsed by oracle's all-zero initial
    // state.
    function play(uint256 amount) external {
        // UNSAFE: control flow gated on a predictable/grindable chain attribute
        // (SWC-120: block.prevrandao as a randomness source).
        if (uint256(block.prevrandao) % 2 == 0) {
            winnings[msg.sender] += amount;
        }
    }
}
