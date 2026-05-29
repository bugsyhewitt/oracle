// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's tx.origin-authentication detector (SWC-115).
//
// AUTHENTICATION VULNERABILITY. `withdraw()` authorizes the caller with
// `require(tx.origin == owner)`. `tx.origin` is the externally-owned account
// that *started* the transaction, NOT the immediate caller, so this guard is
// bypassable by a phishing-relay attack: the owner is tricked into calling a
// malicious contract, which forwards the call into this contract. msg.sender
// is then the attacker's contract, but tx.origin is still the owner — so the
// check passes and the attacker drains the funds.
//
// The detector flags this because the contract branches control flow on
// tx.origin (the ORIGIN value flows into a comparison that feeds a JUMPI), so a
// path constraint references the symbolic `origin` leaf.
contract TxOriginVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(address payable to) external {
        // UNSAFE: tx.origin authentication (SWC-115). Phishing-relay bypassable.
        require(tx.origin == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
