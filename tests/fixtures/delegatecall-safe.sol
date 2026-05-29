// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's delegatecall-to-untrusted-callee detector (SWC-112).
//
// SAFE counterpart. `run()` delegatecalls into a HARD-CODED library address
// that no caller can influence. The delegatecall target is a compile-time
// constant, not derived from calldata, so it is NOT attacker-controllable and
// MUST NOT be flagged. The DELEGATECALL opcode is still present, so this pins
// that the detector keys on the *untrusted target*, not on the mere presence
// of a delegatecall.
contract DelegatecallSafe {
    // a trusted, immutable library address baked into the bytecode
    address private constant LIB =
        0x000000000000000000000000000000000000c0DE;

    function run(bytes calldata data) external returns (bool) {
        (bool ok, ) = LIB.delegatecall(data);
        return ok;
    }
}
