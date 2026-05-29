// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's unprotected-ether-withdrawal detector (SWC-105).
//
// VULNERABILITY: `withdraw()` is a public function that forwards the contract's
// entire balance to `msg.sender` with NO access-control guard. Anyone can call
// it and drain the contract — the canonical "unprotected ether withdrawal"
// (SWC-105). The recipient is `msg.sender` (a perfectly ordinary recipient, so
// this is NOT an attacker-controlled-recipient bug — the EtherLeak detector's
// signal), yet the function is still an open drain because no `require` ever
// gates on the caller's identity. The detector flags the value-forwarding CALL
// reached on a path whose constraints never branch on `msg.sender`.
//
// `deposit()` lets the contract accumulate ether so the balance forwarded by
// `withdraw()` is real; it is a plain payable function and is not itself a
// withdrawal sink.
contract EtherWithdrawalVuln {
    function deposit() external payable {}

    // NO owner check: any caller drains the contract. The value-forwarding CALL
    // is reached with no caller-binding constraint on the path.
    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "withdraw failed");
    }
}
