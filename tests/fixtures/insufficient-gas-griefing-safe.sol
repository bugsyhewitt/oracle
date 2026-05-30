// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Safe counterpart to insufficient-gas-griefing-vuln.sol. Same relayer
/// shape, but the call forwards all remaining gas — the gas operand lowers
/// to the runtime `GAS` opcode rather than a calldata-derived value. The
/// callee receives the standard 63/64 of remaining gas (EIP-150), which
/// is the maximum the caller can give, so the relayer cannot grief by
/// underfunding the inner call. CALL is still present in the bytecode, so
/// this fixture proves the detector keys on the symbolic origin of the
/// gas operand, not on the CALL opcode itself.
contract InsufficientGasGriefingSafe {
    function relay(address to, bytes calldata data)
        external
        returns (bool)
    {
        (bool ok, ) = to.call(data);
        return ok;
    }
}
