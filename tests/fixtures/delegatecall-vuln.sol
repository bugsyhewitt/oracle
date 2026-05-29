// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's delegatecall-to-untrusted-callee detector (SWC-112).
//
// Delegatecall VULNERABILITY. `forward()` takes a `target` address straight
// from calldata and `delegatecall`s into it. Because delegatecall runs the
// callee's code in THIS contract's storage and balance context, an attacker who
// supplies a malicious `target` can rewrite any storage slot (e.g. the owner
// slot) and drain the contract — the canonical Parity multisig wallet bug.
//
// The detector flags the DELEGATECALL whose target operand is derived from
// calldata (attacker-controllable). A hard-coded library address would NOT be
// flagged (see delegatecall-safe.sol).
contract DelegatecallVuln {
    function forward(address target, bytes calldata data) external returns (bool) {
        // target comes straight from calldata -> attacker-controllable callee
        (bool ok, ) = target.delegatecall(data);
        return ok;
    }
}
