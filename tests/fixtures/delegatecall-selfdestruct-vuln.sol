// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's SELFDESTRUCT-via-untrusted-delegatecall detector
// (SWC-112 + SWC-106 composition).
//
// VULNERABILITY: `forward()` takes a `target` address straight from calldata
// and `delegatecall`s into it. Because delegatecall runs the callee's code in
// THIS contract's storage and balance context, a malicious callee can trigger
// the `kill()` path, which calls `selfdestruct` and destroys the host contract.
//
// The contract has two functions:
//   * forward(address target, bytes data) -- delegatecalls into caller-supplied
//     target. This is the SWC-112 untrusted-callee path.
//   * kill(address payable recipient) -- calls selfdestruct. This is the
//     reachable SELFDESTRUCT that an attacker-controlled delegate can trigger.
//
// The detector flags the SELFDESTRUCT reached on a path that also executed a
// delegatecall whose target is calldata-derived.
contract DelegatecallSelfdestructVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Attacker supplies target -> attacker controls what runs in our context.
    function forward(address target, bytes calldata data) external returns (bool) {
        (bool ok, ) = target.delegatecall(data);
        return ok;
    }

    // Any caller with access can destroy this contract.
    // Combined with forward(), an attacker-supplied delegate that calls into
    // kill() destroys the contract inside the delegatecall context.
    function kill(address payable recipient) external {
        selfdestruct(recipient);
    }
}
