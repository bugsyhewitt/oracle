// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Negative fixture for oracle's access-control escalation detector.
//
// Ownership is set ONCE in the constructor (not a re-callable runtime function),
// and `transferOwnership` is properly gated by `require(msg.sender == owner)`.
// Every privileged operation is therefore behind a `caller`-binding guard, so
// the detector must produce ZERO findings: there is no path on which a
// privileged sink (owner SSTORE / SELFDESTRUCT) is reachable without the
// caller's identity being constrained.
//
// `owner` is storage slot 0.
contract AccessControlSafe {
    address public owner;

    constructor() {
        owner = msg.sender; // runs at deploy time only — not in runtime code
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner"); // caller-binding guard
        owner = newOwner;
    }

    function kill() external {
        require(msg.sender == owner, "not owner"); // caller-binding guard
        selfdestruct(payable(msg.sender));
    }
}
