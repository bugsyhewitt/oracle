// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's unprotected-selfdestruct detector (SWC-106,
// "Unprotected SELFDESTRUCT Instruction").
//
// VULNERABILITY: `kill()` is a public function that runs `selfdestruct(target)`
// with NO access-control guard. Any caller can destroy the contract and sweep
// its entire balance to an arbitrary address — the canonical SWC-106 bug, the
// Parity-wallet-library `kill()` class of incident that froze ~$280M. The
// detector flags the SELFDESTRUCT reached on a path whose constraints never
// branch on `msg.sender`: there is no `require(msg.sender == owner)` gate, so
// the symbolic `caller` leaf never enters a path constraint.
//
// `deposit()` lets the contract hold ether so the destruction sweeps real
// funds; it is a plain payable function and is not itself a privileged sink.
contract UnprotectedSelfdestructVuln {
    function deposit() external payable {}

    // NO owner check: any caller destroys the contract. The SELFDESTRUCT is
    // reached with no caller-binding constraint on the path.
    function kill(address payable target) external {
        selfdestruct(target);
    }
}
