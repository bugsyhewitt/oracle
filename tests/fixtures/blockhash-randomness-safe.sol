// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart for oracle's blockhash-randomness detector (SWC-120).
//
// This contract READS `blockhash(block.number - 1)` (so the BLOCKHASH opcode is
// still present in the runtime bytecode — the test asserts that, proving the
// detector keys on the block hash DECIDING control flow, not on the opcode), but
// only *returns* it: it hands the raw block hash back to the caller. No control
// flow is branched on the block hash, so no path constraint ever references a
// `blockhash_<pc>` leaf — a non-control-flow read of a block hash (a view getter)
// is harmless and must NOT be flagged. The contract's only branch is on a
// calldata argument, not on a block hash.
contract BlockhashRandomnessSafe {
    mapping(address => uint256) public balances;

    // pure read-through: returns the block hash without deciding anything on it.
    // blockNo is calldata-supplied so the BLOCKHASH read involves no NUMBER read,
    // keeping this a clean SWC-120 (blockhash) case rather than touching SWC-116.
    function hashOf(uint256 blockNo) external view returns (bytes32) {
        return blockhash(blockNo);
    }

    function deposit(uint256 amount) external {
        // SAFE: the branch gates on a calldata argument, not on a block hash.
        if (amount > 0) {
            balances[msg.sender] += amount;
        }
    }
}
