// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart for oracle's `underflow` check (SWC-101).
//
// The SUB opcode is STILL present (so the test proves the detector keys on the
// underflow being *reachable*, not on the SUB opcode itself), but the
// subtraction is guarded by a `require(b <= a)` precondition. That guard
// appends a path constraint `b <= a`, which makes the detector's underflow
// condition `b > a` jointly UNSATISFIABLE — so Z3 proves the underflow is
// unreachable and the candidate is dropped. The subtraction is performed in an
// `unchecked` block precisely so the only thing preventing the underflow is the
// explicit guard (not solc's built-in 0.8 check), isolating the detector's
// reachability reasoning.
//
// Both operands are calldata arguments (symbolic) so the SUB is a genuine
// candidate that the solver must reason about, rather than a constant the
// compiler would fold away.
contract IntegerUnderflowSafe {
    function safeSub(uint256 a, uint256 b) external pure returns (uint256) {
        require(b <= a, "underflow");
        unchecked {
            return a - b;
        }
    }
}
