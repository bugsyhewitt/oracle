// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's unprotected-ether-withdrawal detector (SWC-105).
//
// SAFE counterpart: `withdraw()` forwards the contract's balance to the owner,
// but ONLY after a `require(msg.sender == owner)` access-control guard. The
// guard compiles to a comparison on `msg.sender` feeding a JUMPI, so the
// symbolic `caller` leaf appears in the path constraint leading to the CALL —
// the detector sees the path is caller-guarded and does NOT flag it. The CALL
// opcode is still present (so the test proves the detector keys on the *missing
// caller guard*, not on the value-forwarding opcode itself).
contract EtherWithdrawalSafe {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {}

    function withdraw() external {
        require(msg.sender == owner, "not owner"); // gates on the caller
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "withdraw failed");
    }
}
