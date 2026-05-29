// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's unchecked-call-return detector (SWC-104).
//
// SAFE counterpart. `pay()` makes the same low-level `.call` but `require`s the
// boolean success word, so a failed external call reverts the whole transaction
// instead of being silently swallowed. The CALL opcode is still present (so the
// test proves the detector keys on the *discarded* success word, not on the
// call opcode), but the success word is routed into control flow (require ->
// ISZERO/JUMPI) and is never bare-POPped, so it must NOT be flagged.
contract UncheckedCallSafe {
    function pay(address to) external {
        (bool ok, ) = to.call{value: 1}("");
        require(ok, "transfer failed");
    }
}
