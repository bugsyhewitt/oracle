// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's cross-function reentrancy detector (SWC-107, the
// cross-function variant). The same-function CEI detector (ReentrancyDetector)
// must NOT fire here — the writer to the pre-call-read slot lives on a
// SIBLING function, not on the calling function's path.
//
// Shape:
//   * withdraw(): SLOAD balance, CALL forwarding ether. NO post-CALL SSTORE
//     to balance on this path — the calling function never updates the slot
//     it read before handing control to the attacker.
//   * transfer(): SSTORE balance to a caller-supplied value. Pure state
//     mutator: NO external CALL on this path, so the cross-function detector
//     recognises it as the sibling-writer half of the reentrancy gadget.
//
// An attacker reenters via transfer() during withdraw()'s call, mutating the
// balance the in-flight withdraw read before the CALL — DAO-class drain, but
// the writer is on a different selector dispatch path.
//
// Storage: a single `uint256 balance` (slot 0), matching the same-function
// fixture's storage shape so the SLOAD/SSTORE slot identities are concrete
// and matchable under oracle's bounded storage model.
contract ReentrancyCrossVuln {
    uint256 public balance;

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw() external {
        uint256 amount = balance;
        require(amount > 0);

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function transfer(uint256 newBalance) external {
        balance = newBalance;
    }
}
