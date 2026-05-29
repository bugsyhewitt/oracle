// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart for oracle's prevrandao-randomness detector (SWC-120).
//
// This contract READS `block.prevrandao` (so the DIFFICULTY opcode is still
// present in the runtime bytecode — the test asserts that, proving the detector
// keys on prevrandao DECIDING control flow, not on the opcode), but only
// *returns* it / stores it: it hands the raw value back to the caller. No
// control flow is branched on prevrandao, so no path constraint ever references
// the `prevrandao` leaf — a non-control-flow read (a view getter / book-keeping
// store) is harmless and must NOT be flagged. The contract's only branch is on
// a calldata argument, not on prevrandao.
contract PrevrandaoRandomnessSafe {
    mapping(address => uint256) public balances;
    uint256 public lastRandao;

    // pure read-through: returns prevrandao without deciding anything on it.
    function currentRandao() external view returns (uint256) {
        return block.prevrandao;
    }

    // also reads prevrandao for non-control-flow book-keeping (a storage write
    // of the raw value), again with no branch gated on it.
    function record() external {
        lastRandao = block.prevrandao;
    }

    function deposit(uint256 amount) external {
        // SAFE: the branch gates on a calldata argument, not on prevrandao.
        if (amount > 0) {
            balances[msg.sender] += amount;
        }
    }
}
