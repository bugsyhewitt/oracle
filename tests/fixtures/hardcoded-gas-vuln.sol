// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// SWC-134: Message call with hardcoded gas amount.
///
/// `transfer` lowers to a low-level CALL that forwards a fixed 2300-gas
/// stipend (Solidity emits the literal as a `PUSH2 0x08FC` immediately
/// before the call). Post-Istanbul (EIP-1884) the 2300 stipend is not
/// always enough for the recipient's fallback to run: any recipient with a
/// non-trivial receive/fallback reverts, bricking the function for any
/// destination the contract did not anticipate. The hardcoded gas amount
/// is the bug; the canonical fix is `address.call{value: x}("")` and a
/// `require(ok)`, which forwards all remaining gas.
contract HardcodedGasVuln {
    function pay(address payable to) public payable {
        // hardcoded 2300-gas stipend — the SWC-134 signature.
        to.transfer(msg.value);
    }
}
