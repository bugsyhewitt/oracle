// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Stateful (multi-transaction) fixture for oracle's `--sequence-depth` feature.
//
// The SELFDESTRUCT is reachable ONLY across two transactions:
//
//   tx1: call arm()  — flips the `armed` storage flag from 0 to 1.
//   tx2: call blow()  — requires armed == 1, then selfdestructs.
//
// Within a SINGLE transaction starting from fresh (all-zero) storage, `armed`
// is 0, so blow()'s guard is never satisfiable and the SELFDESTRUCT path is
// unreachable. oracle v0.1 (single transaction) therefore finds nothing.
//
// With --sequence-depth 2, oracle resumes the second transaction from the
// storage state left by the first: after arm() ran, `armed == 1`, so blow()'s
// guard is satisfiable and the reachable SELFDESTRUCT is discovered.
contract StatefulSelfdestruct {
    uint256 private armed;

    function arm() external {
        armed = 1;
    }

    function blow(address payable target) external {
        require(armed == 1, "not armed");
        selfdestruct(target);
    }
}
