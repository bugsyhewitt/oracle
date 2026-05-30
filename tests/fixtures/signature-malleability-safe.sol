// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

/// SignatureMalleabilitySafe — SWC-117 safe counter-fixture.
///
/// `claim` enforces the EIP-2 / OpenZeppelin `ECDSA.recover` malleability
/// guard: it rejects any `s` value above secp256k1n / 2, so for every
/// (r, s, v) signature the malleable twin (r, n - s, v ^ 1) is forced
/// onto the low-`s` half and only one canonical form is ever accepted.
/// The signature replay attack therefore cannot be mounted by mutating the
/// `s` value.
///
/// The contract still uses `ecrecover` (STATICCALL to address 0x01), so
/// the bytecode retains the ECRECOVER call site — but it also emits a
/// `PUSH32 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`
/// for the bound constant, proving the SWC-117 detector keys on the
/// *absence* of that PUSH32 alongside an ecrecover, not on the ecrecover
/// call alone.
contract SignatureMalleabilitySafe {
    address public owner;
    mapping(bytes32 => bool) public usedSignatures;

    constructor() {
        owner = msg.sender;
    }

    function claim(
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // SAFE (EIP-2 / SWC-117 guard): reject the high-`s` half of the
        // curve, forcing every signature into its canonical low-`s` form.
        // The malleable twin (r, n-s, v ^ 1) has an `s` strictly greater
        // than n / 2, so this require() rejects it. The constant is the
        // half-order of secp256k1n, the same literal OpenZeppelin's
        // ECDSA.recover emits.
        require(
            uint256(s) <=
                0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "invalid s"
        );
        require(v == 27 || v == 28, "invalid v");

        bytes32 sigId = keccak256(abi.encodePacked(r, s, v));
        require(!usedSignatures[sigId], "sig used");
        usedSignatures[sigId] = true;

        bytes32 h = keccak256(abi.encodePacked(recipient, amount, nonce));
        address signer = ecrecover(h, v, r, s);
        require(signer == owner, "bad sig");
        payable(recipient).transfer(amount);
    }

    receive() external payable {}
}
