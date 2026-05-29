// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's transaction-order-dependence detector (SWC-114,
// "Transaction Order Dependence").
//
// ORDERING-DEPENDENCE VULNERABILITY. `claim()` gates a reward by branching on
// `tx.gasprice` — the canonical (and misguided) "gas-price ceiling to deter
// front-running" anti-pattern. The ordering of transactions inside a block is
// chosen by the block proposer / searcher by fee, not by the contract, so any
// logic that trusts `tx.gasprice` is deciding a security-relevant outcome on a
// value the transaction sender sets freely and that is precisely the lever used
// to reorder transactions (front-running / sandwich attacks). Branching control
// flow on `tx.gasprice` is the direct on-chain signal of SWC-114.
//
// The detector flags this because the contract branches control flow on the gas
// price (the GASPRICE value flows into a comparison that feeds a JUMPI), so a
// path constraint references the `gasprice` leaf. The safe primitives are
// commit-reveal schemes, batch auctions, or slippage bounds — never logic that
// trusts gas price or transaction order.
contract TxOrderVuln {
    mapping(address => uint256) public rewards;

    // maxGasPrice and amount are calldata-supplied so the gas-price-dependent
    // branch sits on a satisfiable path rather than being collapsed by oracle's
    // all-zero initial state.
    function claim(uint256 maxGasPrice, uint256 amount) external {
        // UNSAFE: control flow gated on tx.gasprice (transaction-order
        // dependence, SWC-114). A would-be front-runner simply bids within the
        // ceiling; an outcome decided on gas price is decided on ordering.
        if (tx.gasprice <= maxGasPrice) {
            rewards[msg.sender] += amount;
        }
    }
}
