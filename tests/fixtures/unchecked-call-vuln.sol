// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's unchecked-call-return detector (SWC-104).
//
// Unchecked call return VULNERABILITY. `pay()` makes a low-level `.call` and
// then *discards* the boolean success word the EVM CALL pushes. A low-level
// call does NOT revert when the callee reverts — it returns `false` and
// execution continues. By ignoring that word the contract proceeds as though
// the transfer succeeded even when it silently failed (the canonical
// "unchecked send"/SWC-104 bug, the King-of-the-Ether class of incident).
//
// The detector flags the POP that throws away the CALL success word. A checked
// call (see unchecked-call-safe.sol) routes that word into require/if, so it is
// never bare-POPped and is not flagged.
contract UncheckedCallVuln {
    function pay(address to) external {
        // low-level call; the (bool) success result is deliberately ignored.
        to.call{value: 1}("");
    }
}
