// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Safe counterpart to hardcoded-gas-vuln.sol. Uses the
/// `address.call{value: x}("")` pattern, which lowers to a CALL whose gas
/// operand is the runtime `GAS` opcode (forwarding all remaining gas), NOT
/// a hardcoded `PUSH2 0x08FC` literal. CALL still appears in the bytecode,
/// so this fixture proves the detector keys on the literal-2300 gas
/// signature next to the call, not on the CALL opcode itself.
contract HardcodedGasSafe {
    function pay(address payable to) public payable {
        (bool ok, ) = to.call{value: msg.value}("");
        require(ok, "transfer failed");
    }
}
