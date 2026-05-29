// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's DoS-with-failed-call detector (SWC-113).
//
// SAFE counterpart: the pull-payment pattern. Instead of pushing ether to every
// recipient in a loop (where one reverting callee DoSes the batch), each account
// withdraws its OWN balance in a single, isolated external call. There is no
// loop around the call, so a single recipient's failure affects only that
// recipient and can never block anyone else. The CALL opcode is still present
// (so the test proves the detector keys on the call being *in a loop*, not on
// the call opcode itself), but it is reached at most once per transaction.
contract DosFailedCallSafe {
    mapping(address => uint256) public credit;

    function deposit(address to) external payable {
        credit[to] += msg.value;
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        credit[msg.sender] = 0;
        // single external call, no loop: one failure is isolated to the caller.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
    }
}
