// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's post-call path coverage (POST_V01 Tier 1 Item 1).
//
// This contract makes an external low-level call and THEN acts on the result.
// solc emits RETURNDATASIZE / RETURNDATACOPY around the `.call` to ABI-decode
// the returned bytes. Under oracle v0.1 the path halted on the first
// RETURNDATASIZE, so the SELFDESTRUCT *after* the call was never reached and
// the `selfdestruct` detector produced no finding.
//
// With the new opcode handlers the path survives past the external call, so
// the reachable SELFDESTRUCT downstream of the call is now discoverable.
//
// Trigger: call sweep(target) from any account.
contract ReturnDataAfterCall {
    function sweep(address payable target) external {
        // external call -> solc emits RETURNDATASIZE/RETURNDATACOPY here
        (bool ok, bytes memory ret) = target.call("");
        // touch the return data length so the decoder opcodes are not pruned
        if (ret.length >= 0 || ok) {
            // reachable ONLY if exploration survived the return-data opcodes
            selfdestruct(target);
        }
    }
}
