// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deliberately vulnerable fixture for oracle's `underflow` check (SWC-101,
// "Integer Overflow and Underflow" — the underflow half).
//
// Solidity >=0.8 reverts on underflow by default, so the wraparound is placed
// inside an `unchecked` block — the classic real-world underflow bug pattern
// where a developer disabled the checked arithmetic (or a pre-0.8 / assembly
// contract that never had it). `balance - amount` wraps modulo 2**256 when
// `amount` exceeds `balance`, silently minting the caller a near-maximum
// balance instead of erroring — the canonical underflowed-accounting drain
// (the batchOverflow / proxyOverflow ERC-20 incident family).
//
// Trigger: call withdraw(amount) with `amount` greater than the (symbolic,
// uninitialised) balance so the subtraction underflows. oracle detects this
// symbolically: the SUB has a symbolic operand and the path admits `b > a`,
// which Z3 solves to a concrete trigger input.
contract IntegerUnderflowVuln {
    uint256 public balance;

    function withdraw(uint256 amount) external {
        unchecked {
            balance = balance - amount;
        }
    }
}
