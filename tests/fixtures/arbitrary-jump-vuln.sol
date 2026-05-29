// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's arbitrary-jump detector (SWC-127, "Arbitrary Jump with
// Function Type Variable").
//
// SWC-127 VULNERABILITY. A `function` type variable holds an internal jump
// destination (a program counter). Here the destination is loaded from a
// calldata-supplied raw pointer via inline assembly and then invoked, so an
// attacker who controls `ptr` controls where execution jumps — the canonical
// "arbitrary jump with a function type variable" bug. The EVM `JUMP` it lowers
// to therefore takes an attacker-controllable, calldata-derived destination.
//
// Internal `function` calls in Solidity compile to a JUMP whose destination is
// the function's code offset. Overwriting that destination with untrusted input
// (as the assembly below does) is exactly the SWC-127 hijack: control flow can
// be redirected to any JUMPDEST in the bytecode.
//
// The detector flags a JUMP/JUMPI whose destination operand is derived from
// calldata. A function pointer that is a compile-time constant is ordinary
// control flow and is NOT flagged (see arbitrary-jump-safe.sol).
contract ArbitraryJumpVuln {
    function run(uint256 ptr) external returns (uint256) {
        // A function-type variable. Normally the compiler assigns it a constant
        // code offset; here we overwrite it with a calldata-derived pointer.
        function() internal returns (uint256) fn = good;
        assembly {
            // hijack the internal function pointer with attacker input
            fn := ptr
        }
        // invoking `fn` lowers to `JUMP` to the (now calldata-derived) pointer
        return fn();
    }

    function good() internal pure returns (uint256) {
        return 42;
    }
}
