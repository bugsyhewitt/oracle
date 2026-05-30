// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// SignatureMalleabilityVuln — SWC-117, signature malleability.
///
/// `claim` authenticates the caller by recovering a signer from `(v, r, s)`
/// and de-duplicates by hashing the raw signature bytes into `usedSigs`. The
/// contract does NOT bound `s` to the lower half of the secp256k1 curve order
/// (EIP-2), so for every valid `(v, r, s)` an attacker can mint a second,
/// bit-different `(v', r, n-s)` that ECRECOVER accepts for the same message
/// and the same signer — the malleated twin hashes to a different
/// `usedSigs` key, so the dedup invariant is broken and the same authorised
/// action can be replayed under a fresh signature identity.
///
/// Bytecode-level signal: this contract reaches a STATICCALL to the ECRECOVER
/// precompile (address 0x01) but its runtime bytecode contains NO PUSH
/// immediate equal to `secp256k1n/2`
/// (`0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`) —
/// the unique mathematical bound for the EIP-2 malleability check — so it
/// cannot possibly enforce the canonical lower-`s`-half bound.
contract SignatureMalleabilityVuln {
    address public owner;
    mapping(bytes32 => bool) public usedSigs;

    constructor() {
        owner = msg.sender;
    }

    function claim(
        address recipient,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Dedup keyed on the raw signature bytes — exposes the malleability
        // bug because the malleated twin hashes to a different key.
        bytes32 sigKey = keccak256(abi.encodePacked(v, r, s));
        require(!usedSigs[sigKey], "sig used");
        usedSigs[sigKey] = true;
        // BUG (SWC-117): no `require(uint256(s) <= secp256k1n/2)` bound, so
        // ECRECOVER accepts both `(v, r, s)` and its malleated twin
        // `(v', r, n-s)` for the same signer.
        bytes32 h = keccak256(abi.encodePacked(recipient, amount));
        address signer = ecrecover(h, v, r, s);
        require(signer == owner, "bad sig");
        payable(recipient).transfer(amount);
    }

    receive() external payable {}
}
