"""Detector plugins for oracle's symbolic execution engine.

Each detector subclasses DetectorHook and is invoked before every instruction
executes. When a detector identifies a potentially reachable bug, it records a
finding carrying the *path constraints* that lead there. The analysis driver
later asks Z3 whether those constraints are satisfiable; if so, the model gives
a concrete `trigger_input`.

[Worker decision: oracle implements its own detector plugin framework rather
than forking mythril's laser/plugin/ verbatim (see NOTICE). mythril's plugin
framework is tied to its laser EVM engine's state/annotation objects, which
oracle does not reuse. oracle's framework is a thin, well-defined hook API
matched to oracle's own engine.]
"""

from __future__ import annotations

from oracle.laser.smt import UGT, And, BitVec
from oracle.laser.vm import DetectorHook, _bvv


SEVERITY = {
    "assertion_violation": "medium",
    "integer_overflow": "high",
    "reachable_selfdestruct": "high",
    "unconstrained_ether_transfer": "high",
    "arbitrary_storage_write": "high",
}


class AssertionViolationDetector(DetectorHook):
    """Detects reachable INVALID (0xFE) opcodes.

    solc emits INVALID for a failing `assert()` in Solidity <0.8.0 and as the
    panic path. A reachable INVALID means there's an input that violates the
    asserted invariant.
    """

    category = "assertion_violation"

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic == "INVALID":
            self.findings.append(
                _finding(self.category, state, instruction, vm)
            )


class IntegerOverflowDetector(DetectorHook):
    """Detects integer overflow on ADD/MUL involving symbolic operands.

    Records a finding whose extra constraint asserts the overflow condition
    (a + b < a). If Z3 can satisfy path-constraints AND the overflow condition,
    the bug is reachable.
    """

    category = "integer_overflow"

    def inspect(self, vm, state, instruction) -> None:
        op = instruction.mnemonic
        if op not in ("ADD", "MUL"):
            return
        if len(state.stack) < 2:
            return
        a = state.stack[-1]
        b = state.stack[-2]
        if _is_concrete(a) and _is_concrete(b):
            return  # only flag symbolic arithmetic
        if op == "ADD":
            # 256-bit wraparound: the sum is smaller than one of the addends
            overflow = UGT(a, a + b)
        else:  # MUL
            overflow = _mul_overflow(a, b)
        f = _finding(self.category, state, instruction, vm)
        f["extra_constraint"] = overflow
        self.findings.append(f)


def _mul_overflow(a: BitVec, b: BitVec):
    # a*b overflows 256-bit when b != 0 and the wrapped product is smaller than a
    prod = a * b
    return And(b != _bvv(0), UGT(a, prod))


class ReachableSelfdestructDetector(DetectorHook):
    """Detects reachable SELFDESTRUCT opcodes."""

    category = "reachable_selfdestruct"

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic == "SELFDESTRUCT":
            self.findings.append(_finding(self.category, state, instruction, vm))


class EtherLeakDetector(DetectorHook):
    """Detects unconstrained ether transfers (CALL with attacker-influenced
    recipient and non-zero value not guarded by access control).

    Heuristic for v0.1: flag any CALL where the recipient (2nd stack arg) is
    derived from CALLER/CALLDATA — i.e. attacker-controllable — and value is
    symbolic/non-zero.
    """

    category = "unconstrained_ether_transfer"

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "CALL":
            return
        # CALL stack layout: gas, to, value, ...
        if len(state.stack) < 3:
            return
        to = state.stack[-2]
        value = state.stack[-3]
        if _is_concrete(value) and _concrete_val(value) == 0:
            return  # zero-value call carries no ether
        if not _is_concrete(to):
            self.findings.append(_finding(self.category, state, instruction, vm))


class StorageWriteDetector(DetectorHook):
    """Detects arbitrary storage writes: SSTORE where the slot key is
    attacker-controllable (symbolic, derived from calldata)."""

    category = "arbitrary_storage_write"

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "SSTORE":
            return
        if len(state.stack) < 1:
            return
        key = state.stack[-1]
        if not _is_concrete(key):
            self.findings.append(_finding(self.category, state, instruction, vm))


# ---------------------------------------------------------------------- #
# helpers
# ---------------------------------------------------------------------- #
def _finding(category: str, state, instruction, vm) -> dict:
    # report the principal symbolic transaction inputs plus every calldata word
    # the engine materialised along the way (selector + decoded arguments).
    symbols = {
        "callvalue": vm.callvalue,
        "caller": vm.caller,
    }
    for key, sym in vm._calldata_words.items():
        name = "calldata" if key == 0 else f"calldata_at_{key}"
        symbols[name] = sym
    return {
        "category": category,
        "severity": SEVERITY.get(category, "medium"),
        "pc": instruction.pc,
        "op": instruction.mnemonic,
        "depth": state.depth,
        "constraints": list(state.constraints),
        "trace": [t.to_dict() for t in state.trace],
        "symbols": symbols,
    }


def _is_concrete(bv) -> bool:
    return _concrete_val(bv) is not None


def _concrete_val(bv):
    try:
        import z3

        raw = bv.raw if hasattr(bv, "raw") else bv
        if isinstance(raw, z3.BitVecNumRef):
            return raw.as_long()
    except Exception:
        return None
    return None


# registry mapping the CLI --check token to the detector class
DETECTOR_REGISTRY = {
    "assertion": AssertionViolationDetector,
    "overflow": IntegerOverflowDetector,
    "selfdestruct": ReachableSelfdestructDetector,
    "ether-leak": EtherLeakDetector,
    "storage-write": StorageWriteDetector,
}
