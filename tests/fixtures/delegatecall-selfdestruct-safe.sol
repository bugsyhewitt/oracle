// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's SELFDESTRUCT-via-untrusted-delegatecall detector.
//
// SAFE counterpart. This contract delegatecalls into a HARD-CODED library
// address that no caller can influence. Even though a reachable SELFDESTRUCT
// is also present, the delegatecall target is a compile-time constant, so it
// is NOT attacker-controllable. The composition signal requires BOTH an
// untrusted delegatecall AND a reachable SELFDESTRUCT, so this contract MUST
// NOT be flagged for the delegatecall_selfdestruct category.
//
// This fixture proves the detector keys on the *untrusted target*, not on the
// mere co-presence of any delegatecall and any selfdestruct.
contract DelegatecallSelfdestructSafe {
    // A trusted, immutable library address baked into the bytecode.
    address private constant LIB =
        0x000000000000000000000000000000000000c0DE;

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Delegatecalls into a hard-coded constant -- NOT attacker-controllable.
    function run(bytes calldata data) external returns (bool) {
        (bool ok, ) = LIB.delegatecall(data);
        return ok;
    }

    // Reachable SELFDESTRUCT -- present so the fixture proves the detector
    // does NOT fire when only a safe (hard-coded-target) delegatecall exists.
    function kill(address payable recipient) external {
        selfdestruct(recipient);
    }
}
