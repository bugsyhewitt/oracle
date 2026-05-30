// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

/// SignatureReplayVuln — SWC-121, cross-chain signature replay.
///
/// `claim` authenticates the caller by recovering a signer from a hash of
/// (recipient, amount, nonce) and comparing it to the contract owner. The
/// hash does NOT include `block.chainid`, so the same signature is replayable
/// on every chain the contract is deployed to (the canonical post-fork wallet
/// drain class — Ethereum mainnet ↔ a fork chain, or any L2 ↔ mainnet).
///
/// Bytecode-level signal: this contract reaches a STATICCALL to the ECRECOVER
/// precompile (address 0x01) but its bytecode contains NO CHAINID (0x46)
/// opcode at all, so it cannot possibly bind a signature to its deploy chain.
contract SignatureReplayVuln {
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
        // BUG (SWC-121): the signed payload omits block.chainid, so the same
        // (sig, nonce) tuple is valid on every chain this contract is on.
        bytes32 h = keccak256(abi.encodePacked(recipient, amount, nonce));
        address signer = ecrecover(h, v, r, s);
        require(signer == owner, "bad sig");
        payable(recipient).transfer(amount);
    }

    receive() external payable {}
}
