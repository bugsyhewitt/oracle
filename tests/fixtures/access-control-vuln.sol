// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's access-control escalation detector (POST_V01 Tier 2 #5).
//
// Ownership escalation VULNERABILITY. `initialize()` sets `owner = msg.sender`
// but has NO initializer guard — it is re-callable by anyone, so any address can
// seize ownership at will. `kill()` then performs a privileged SELFDESTRUCT
// gated on `owner`, but because ownership is freely takeable the gate is
// meaningless: an attacker calls initialize() to become owner, then kill().
//
// The detector flags two things on this contract:
//   * the SSTORE setting owner = msg.sender on a path with no caller-binding
//     guard (anyone can become owner), and
//   * (when reachable) the unguarded privileged sink.
//
// `owner` is storage slot 0 so its SLOAD/SSTORE identity is concrete under
// oracle's bounded storage model.
contract AccessControlVuln {
    address public owner;

    // MISSING initializer guard: re-callable, so msg.sender can always become
    // owner. This is the classic unprotected initializer / _transferOwnership.
    function initialize() external {
        owner = msg.sender; // SSTORE slot 0 = CALLER, no `require` on caller
    }

    function kill() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(msg.sender));
    }
}
