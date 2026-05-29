// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart for oracle's write-arbitrary-storage detector (SWC-124).
//
// This contract emits several SSTORE opcodes — to a compile-time constant slot
// (`owner`, `value`) and to a mapping element (`balances[msg.sender]`, whose
// slot is a `keccak256(msg.sender . slot)` — symbolic but NOT calldata-derived,
// and pinned to a per-caller index that the attacker cannot steer to overwrite
// another caller's slot). Every SSTORE key is either a constant the compiler
// fixed at compile time or a `keccak256`-derived mapping slot; none is taken
// directly from a calldata word.
//
// The detector keys on "SSTORE key is calldata-derived". A constant slot or a
// `keccak256`-derived mapping slot is ordinary, compiler-controlled storage
// access and is NOT flagged. The SSTORE opcodes are still present (many of
// them), so this fixture proves the detector keys on the *calldata-derived
// key*, not on the SSTORE opcode itself.
contract WriteArbitraryStorageSafe {
    address public owner;                       // slot 0 — constant
    uint256 public value;                       // slot 1 — constant
    mapping(address => uint256) public balances; // slot 2 — keccak256-derived

    constructor() {
        owner = msg.sender;
    }

    function setValue(uint256 v) external {
        require(msg.sender == owner, "not owner");
        value = v;                              // SSTORE to constant slot 1
    }

    function deposit() external payable {
        // SSTORE to mapping slot: key is keccak256(msg.sender . 2), symbolic
        // but compiler-controlled — not a calldata-supplied raw slot index.
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        // SSTORE to the same keccak256-derived slot; `amount` flows into the
        // VALUE, never into the KEY.
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
    }
}
