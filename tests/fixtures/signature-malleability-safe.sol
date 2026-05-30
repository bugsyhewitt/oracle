// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// SignatureMalleabilitySafe — SWC-117 safe counter-fixture.
///
/// `claim` recovers a signer via `ecrecover(...)` AND enforces the EIP-2
/// lower-`s`-half malleability bound — the canonical OpenZeppelin ECDSA
/// pattern. With `s` constrained to `[1, secp256k1n/2]`, the malleated twin
/// `(v', r, n-s)` is rejected, so each valid signature has a unique
/// representation and the dedup invariant on raw signature bytes holds.
///
/// The contract still calls ECRECOVER (STATICCALL to address 0x01), so the
/// bytecode retains the call site — but it also materialises the
/// `secp256k1n/2` constant as a PUSH immediate (the comparison operand of
/// the require), proving the SWC-117 detector keys on the *absence* of
/// that constant alongside an ecrecover, not on the ecrecover call alone.
contract SignatureMalleabilitySafe {
    address public owner;
    mapping(bytes32 => bool) public usedSigs;

    // secp256k1n / 2 — the EIP-2 / SEC 1 §4.1.4 lower-half bound. Identical
    // to the constant OpenZeppelin's ECDSA library uses.
    uint256 private constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

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
        bytes32 sigKey = keccak256(abi.encodePacked(v, r, s));
        require(!usedSigs[sigKey], "sig used");
        usedSigs[sigKey] = true;
        // EIP-2 malleability bound: reject the upper-half `s` so the
        // malleated twin cannot validate.
        require(uint256(s) <= SECP256K1_HALF_N, "malleable s");
        bytes32 h = keccak256(abi.encodePacked(recipient, amount));
        address signer = ecrecover(h, v, r, s);
        require(signer == owner, "bad sig");
        payable(recipient).transfer(amount);
    }

    receive() external payable {}
}
