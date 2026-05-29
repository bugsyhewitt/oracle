// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's tx.origin-authentication detector (SWC-115).
//
// SAFE counterpart to tx-origin-vuln.sol. `withdraw()` authorizes the caller
// with `require(msg.sender == owner)` — the correct primitive. msg.sender is
// the immediate caller, so a relayed/phishing call carries the attacker's
// contract as msg.sender and the guard correctly rejects it.
//
// The contract never reads tx.origin, so no path constraint references the
// symbolic `origin` leaf and the detector MUST NOT flag it.
contract TxOriginSafe {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(address payable to) external {
        // SAFE: msg.sender authentication — not relay-bypassable.
        require(msg.sender == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
