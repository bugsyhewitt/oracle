// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's blockhash-randomness detector (SWC-120, "Weak Sources of
// Randomness from Chain Attributes").
//
// WEAK-RANDOMNESS VULNERABILITY. `play()` decides whether the caller "wins" a
// payout by branching on `blockhash(block.number - 1)` (here `% 2`). A block
// hash is NOT a secure source of entropy: the block proposer can influence which
// block is produced, and — more cheaply — an attacker calling in the SAME
// transaction reads the exact same `blockhash(n)` the contract uses, so they can
// compute the "random" outcome in advance and only enter when they win. Branching
// control flow on a block hash to gate a payout / pick a winner is the canonical
// blockhash-as-randomness gambling bug (SWC-120).
//
// The detector flags this because the contract branches control flow on a block
// hash (the BLOCKHASH value flows into a comparison that feeds a JUMPI), so a
// path constraint references a symbolic `blockhash_<pc>` leaf. The safe primitive
// is a commit-reveal scheme or an external randomness oracle (VRF), never a raw
// chain attribute.
contract BlockhashRandomnessVuln {
    mapping(address => uint256) public winnings;

    // amount and blockNo are calldata-supplied so the block-hash-dependent
    // branch is on a satisfiable path rather than collapsed by oracle's all-zero
    // initial state. blockNo (rather than `block.number - 1`) is used as the
    // BLOCKHASH argument so the discriminating signal is the block HASH alone —
    // no NUMBER/TIMESTAMP block-VALUE read is involved, keeping this fixture a
    // clean SWC-120 (weak randomness) case distinct from SWC-116 (time proxy).
    function play(uint256 amount, uint256 blockNo) external {
        // UNSAFE: control flow gated on a predictable/grindable block hash (SWC-120).
        if (uint256(blockhash(blockNo)) % 2 == 0) {
            winnings[msg.sender] += amount;
        }
    }
}
