// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe counterpart to extcodesize-guard.sol for oracle's EXTCODESIZE
// caller-type-check detector.
//
// This contract gates the privileged action on an explicit owner check
// (`require(msg.sender == owner)`) and NEVER reads an account's code size, so
// it makes no trust/authorization decision on `extcodesize`. It must NOT be
// flagged by the extcodesize-check detector: the discriminating signal is a
// control-flow branch on an `extcodesize` value, which this contract never
// produces.
contract ExtCodeSizeCheckSafe {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function destroy(address payable target) external {
        require(msg.sender == owner, "not owner");
        selfdestruct(target);
    }
}
