// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's unprotected-selfdestruct detector (SWC-106,
// "Unprotected SELFDESTRUCT Instruction").
//
// SAFE counterpart: `kill()` runs `selfdestruct(target)`, but ONLY after a
// `require(msg.sender == owner)` access-control guard. The guard compiles to a
// comparison on `msg.sender` feeding a JUMPI, so the symbolic `caller` leaf
// appears in the path constraint leading to the SELFDESTRUCT — the detector
// sees the path is caller-guarded and does NOT flag it. The SELFDESTRUCT opcode
// is still present (so the test proves the detector keys on the *missing caller
// guard*, not on the SELFDESTRUCT opcode itself — which is exactly what
// separates SWC-106 from the broader reachable-selfdestruct detector).
contract UnprotectedSelfdestructSafe {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {}

    function kill(address payable target) external {
        require(msg.sender == owner, "not owner"); // gates on the caller
        selfdestruct(target);
    }
}
