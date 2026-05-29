// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's write-arbitrary-storage detector (SWC-124, "Write to
// Arbitrary Storage Location").
//
// SWC-124 VULNERABILITY. The EVM addresses storage by 256-bit keys. In
// well-formed Solidity output, every SSTORE key the compiler emits is either a
// compile-time constant (a top-level state variable's slot) or the keccak256 of
// some compiler-determined preimage (a `mapping(...)`/dynamic-array element's
// slot). An attacker cannot steer those keys: they are pinned by the source
// code. Inline-assembly `sstore(key, val)` with a *calldata-derived* `key`,
// however, lets an attacker write to ANY storage slot — overwriting `owner`,
// upgrading the contract to a controlled implementation, or corrupting state
// any other state variable depends on. That is the SWC registry's named
// SWC-124, "Write to Arbitrary Storage Location": the attacker steers the
// storage *key*, and a single transaction can rewrite arbitrary contract state.
//
// The detector flags an SSTORE whose key operand is derived from calldata. An
// SSTORE to a compile-time constant slot or to a `keccak256`-derived
// mapping/dynamic-array slot is ordinary control flow and is NOT flagged (see
// write-arbitrary-storage-safe.sol).
contract WriteArbitraryStorageVuln {
    uint256 public owner; // slot 0

    // `set(uint256 key, uint256 val)` lets the caller supply both the storage
    // KEY and the VALUE. The SSTORE the assembly lowers to takes a
    // calldata-supplied key — exactly the SWC-124 hijack: an attacker can
    // overwrite slot 0 (`owner`), or any other slot the contract or its
    // implementation depends on.
    function set(uint256 key, uint256 val) external {
        assembly {
            sstore(key, val)
        }
    }
}
