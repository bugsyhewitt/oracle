// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// SWC-126: Insufficient Gas Griefing.
///
/// Classic relayer/forwarder pattern: a contract takes a target, a gas
/// amount, and a calldata payload from the caller, and forwards the call
/// with the caller-supplied gas. A malicious relayer can pass an
/// `gasAmt` that is small enough to OOG the inner call but lets the outer
/// transaction succeed (so the signed message is "consumed" or the queue
/// position advances, while the intended inner action never executes).
/// That is the SWC-126 griefing surface: the caller controls the gas
/// fraction forwarded to the callee, so the callee can be starved of gas
/// even when the outer transaction completes. The canonical fix is to
/// forward all remaining gas (`to.call(data)` with no `{gas: ...}`
/// modifier) or to require a minimum bound on `gasAmt` derived from the
/// signed payload.
contract InsufficientGasGriefingVuln {
    function relay(address to, uint256 gasAmt, bytes calldata data)
        external
        returns (bool)
    {
        // gas operand is calldata-derived — the SWC-126 signature.
        (bool ok, ) = to.call{gas: gasAmt}(data);
        return ok;
    }
}
