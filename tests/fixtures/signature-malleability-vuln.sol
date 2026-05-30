// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

/// SignatureMalleabilityVuln — SWC-117, ECDSA signature malleability.
///
/// `claim` authenticates the caller by recovering a signer from a hash of
/// (recipient, amount, nonce) and uses the *signature bytes themselves* as
/// the uniqueness key (`usedSignatures[keccak256(r,s,v)]`). The contract
/// does NOT enforce the EIP-2 `s <= secp256k1n/2` bound. For every valid
/// signature (r, s, v) the EVM's `ecrecover` precompile also accepts its
/// malleable twin (r, n-s, v ^ 1), which recovers the same signer over the
/// same message but is a different byte pattern — so an attacker observes a
/// victim's signed action, flips it to its twin, and replays it; the
/// uniqueness check sees a "new" signature and lets the payment through
/// twice.
///
/// Bytecode-level signal: this contract reaches a STATICCALL to the
/// ECRECOVER precompile (address 0x01) but its bytecode contains NO PUSH32
/// of the secp256k1n / 2 constant
/// (0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0), so
/// it demonstrably cannot enforce the EIP-2 malleability bound.
contract SignatureMalleabilityVuln {
    address public owner;
    // BUG (SWC-117): keying uniqueness off the signature bytes themselves
    // lets a malleable twin pass as a "new" signature.
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
        bytes32 sigId = keccak256(abi.encodePacked(r, s, v));
        require(!usedSignatures[sigId], "sig used");
        usedSignatures[sigId] = true;
        // BUG (SWC-117): no `require(uint256(s) <= secp256k1n/2)` guard, so
        // the malleable (r, n-s, v ^ 1) twin recovers the same signer but
        // is a different sigId — the usedSignatures check passes twice.
        bytes32 h = keccak256(abi.encodePacked(recipient, amount, nonce));
        address signer = ecrecover(h, v, r, s);
        require(signer == owner, "bad sig");
        payable(recipient).transfer(amount);
    }

    receive() external payable {}
}
