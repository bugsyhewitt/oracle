// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart for oracle's transaction-order-dependence detector (SWC-114).
//
// This contract still READS `tx.gasprice` (the GASPRICE opcode is present, so
// the test proves the detector keys on the gas price *deciding control flow*,
// not on the opcode), but it never branches on it: `currentGasPrice()` simply
// returns the observed gas price (a read-through view getter), and the only
// control-flow branch — in `deposit()` — is gated on a calldata argument. No
// path constraint references the `gasprice` leaf, so the contract MUST NOT be
// flagged.
contract TxOrderSafe {
    mapping(address => uint256) public deposits;

    // gasprice is read and returned (non-control-flow), never gated on.
    function currentGasPrice() external view returns (uint256) {
        return tx.gasprice; // read-through getter, harmless
    }

    // SAFE: the branch is on a calldata argument, not on tx.gasprice.
    function deposit(uint256 amount) external {
        if (amount > 0) {
            deposits[msg.sender] += amount;
        }
    }
}
