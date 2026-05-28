// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture for oracle's arithmetic-completeness path coverage
// (POST_V01 Tier 1 Item 3: SAR / SDIV / SMOD / SIGNEXTEND).
//
// This contract gates a SELFDESTRUCT behind a chain of SIGNED arithmetic:
// a signed cast (SIGNEXTEND), a signed division (SDIV), a signed modulo
// (SMOD) and an arithmetic right shift (SAR). solc emits exactly those
// opcodes for `int*` arithmetic. Under a VM that lacked `_op_sar` /
// `_op_sdiv` / `_op_smod` / `_op_signextend` handlers the path HALTED on the
// first such opcode, so the SELFDESTRUCT behind the guard was unreachable to
// the `selfdestruct` detector — the contract produced ZERO findings.
//
// With the arithmetic handlers in place the path survives the signed
// arithmetic and the reachable SELFDESTRUCT is discoverable, with a concrete
// trigger input.
//
// Trigger: call destroy(target, x) with an x that satisfies the signed guard.
contract SignedArithGuard {
    function destroy(address payable target, int256 x) external {
        // int8 cast -> SIGNEXTEND. forces the sign-extension opcode.
        int8 narrowed = int8(x);
        // signed division and modulo -> SDIV + SMOD.
        int256 q = int256(narrowed) / 2;
        int256 r = int256(narrowed) % 3;
        // arithmetic right shift on a signed value -> SAR.
        int256 shifted = int256(narrowed) >> 1;
        // signed comparison guard. satisfiable, so the destruct is reachable
        // ONLY if exploration survived the signed-arithmetic opcodes above.
        if (q + r + shifted < 0) {
            selfdestruct(target);
        }
    }
}
