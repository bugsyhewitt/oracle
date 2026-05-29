// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart for oracle's timestamp-dependence detector (SWC-116).
//
// This contract READS `block.timestamp` (so the TIMESTAMP opcode is still
// present in the runtime bytecode — the test asserts that, proving the detector
// keys on the block value DECIDING control flow, not on the opcode), but only
// *returns* it: it hands the raw block value back to the caller. No control flow
// is branched on the block value, so no path constraint ever references the
// `timestamp` leaf — a non-control-flow read of a block value (a view getter)
// is harmless and must NOT be flagged. The contract's only branch is on a
// calldata argument, not on a block value.
contract TimestampDependenceSafe {
    mapping(address => uint256) public balances;

    // pure read-through: returns block.timestamp without deciding anything on it.
    function now_() external view returns (uint256) {
        return block.timestamp;
    }

    function deposit(uint256 amount) external {
        // SAFE: the branch gates on a calldata argument, not on a block value.
        if (amount > 0) {
            balances[msg.sender] += amount;
        }
    }
}
