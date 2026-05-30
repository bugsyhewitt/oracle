// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

/// SignatureReplaySafe — SWC-121 safe counter-fixture.
///
/// `claim` binds the signed payload to `block.chainid`, so a signature
/// produced for one chain does not verify on any other chain. The contract
/// still uses `ecrecover` (STATICCALL to address 0x01), so the bytecode
/// retains the ECRECOVER call site — but it also emits the CHAINID (0x46)
/// opcode, proving the SWC-121 detector keys on the *absence* of CHAINID
/// alongside an ecrecover, not on the ecrecover call alone.
contract SignatureReplaySafe {
    address public owner;
    mapping(uint256 => bool) public usedNonces;

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
        require(!usedNonces[nonce], "nonce used");
        usedNonces[nonce] = true;
        // SAFE: the signed payload includes block.chainid, binding the
        // signature to this deploy chain (EIP-155 / EIP-1344 style).
        bytes32 h = keccak256(
            abi.encodePacked(block.chainid, recipient, amount, nonce)
        );
        address signer = ecrecover(h, v, r, s);
        require(signer == owner, "bad sig");
        payable(recipient).transfer(amount);
    }

    receive() external payable {}
}
