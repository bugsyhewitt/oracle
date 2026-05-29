"""Tests for the concrete-input replay / counterexample validator.

POST_V01 Tier 3 item #7. oracle's symbolic engine produces a `trigger_input`
for every satisfiable finding; the validator re-executes that input against the
bytecode in a self-contained concrete EVM and confirms whether the finding's
target `pc` is actually reachable. This catches symbolic-only false positives
without adding a heavyweight EVM dependency.

These tests are entirely Z3-free: they hand-assemble tiny bytecode programs,
build finding dicts directly, and assert the validator's verdict. The concrete
interpreter's arithmetic semantics are pinned against the EVM spec so the
validator agrees with oracle's symbolic handlers (oracle/laser/vm.py).
"""

from oracle.laser.replay import (
    ConcreteReplayer,
    MASK256,
    UINT256,
    validate_finding,
    validate_findings,
    _hex_to_int,
    _to_signed,
)

MASK = MASK256


def _push32(value: int) -> str:
    return "7f" + format(value & MASK, "064x")


def _bc(hexcode: str) -> bytes:
    return bytes.fromhex(hexcode)


def _word(n: int) -> str:
    return "0x" + format(n & MASK, "064x")


# --------------------------------------------------------------------------- #
# _hex_to_int — trigger_input coercion
# --------------------------------------------------------------------------- #
def test_hex_to_int_parses_0x_word():
    assert _hex_to_int("0x" + "00" * 31 + "2a") == 42


def test_hex_to_int_none_is_zero():
    assert _hex_to_int(None) == 0


def test_hex_to_int_bare_decimal():
    assert _hex_to_int("255") == 255


def test_hex_to_int_unparseable_completes_to_zero():
    # a bare z3 expression string (not a numeral) replays as 0, matching
    # model_completion of an unconstrained input.
    assert _hex_to_int("calldata_dyn!7") == 0


def test_hex_to_int_masks_to_256_bits():
    assert _hex_to_int(UINT256 + 5) == 5


# --------------------------------------------------------------------------- #
# ConcreteReplayer.reaches — control flow
# --------------------------------------------------------------------------- #
def test_reaches_straight_line_pc():
    # PUSH1 0x01 ; PUSH1 0x02 ; ADD ; STOP
    code = _bc("6001" + "6002" + "01" + "00")
    r = ConcreteReplayer(code, {})
    # pc 4 is the ADD
    assert r.reaches(4) is True


def test_unreached_pc_after_stop():
    # PUSH1 0x00 ; STOP ; JUMPDEST(pc=3)
    code = _bc("6000" + "00" + "5b")
    r = ConcreteReplayer(code, {})
    assert r.reaches(3) is False


def test_jumpi_taken_when_calldata_nonzero():
    # require(calldata != 0) then reach a JUMPDEST guarded sink.
    #   CALLDATALOAD(off=0) ; PUSH1 dest ; JUMPI ; STOP ; JUMPDEST ; STOP
    # layout:
    #  0: PUSH1 0x00   (offset for CALLDATALOAD)
    #  2: CALLDATALOAD
    #  3: PUSH1 0x08   (jump dest)
    #  5: JUMPI        (cond = calldata word)  -- EVM JUMPI pops dest then cond
    #  6: STOP
    #  7: <pad>        actually dest is 8
    #  8: JUMPDEST
    #  9: STOP
    # JUMPI semantics in vm.py: pop dest, then cond; jumps if cond != 0.
    code = _bc("6000" + "35" + "6008" + "57" + "00" + "00" + "5b" + "00")
    target = 8  # the guarded JUMPDEST

    reached = ConcreteReplayer(code, {"calldata": _word(1)})
    assert reached.reaches(target) is True

    not_reached = ConcreteReplayer(code, {"calldata": _word(0)})
    assert not_reached.reaches(target) is False


def test_invalid_jump_destination_halts():
    # JUMP to a non-JUMPDEST address must halt (a real EVM reverts).
    #  0: PUSH1 0x05  (not a JUMPDEST)
    #  2: JUMP
    #  3: STOP
    #  4: <unused>
    #  5: STOP        (byte 0x00 at pc 5 — not a JUMPDEST)
    code = _bc("6005" + "56" + "00" + "00" + "00")
    r = ConcreteReplayer(code, {})
    assert r.reaches(5) is False


def test_step_cap_reported_as_unreached():
    # JUMPDEST ; PUSH1 0x00 ; JUMP back -> infinite loop, capped, never reaches
    # an out-of-loop target.
    #  0: JUMPDEST
    #  1: PUSH1 0x00
    #  3: JUMP
    code = _bc("5b" + "6000" + "56")
    r = ConcreteReplayer(code, {})
    # pc 99 doesn't exist; the loop spins until MAX_STEPS, then returns False
    assert r.reaches(99) is False


def test_unmodelled_opcode_halts_cleanly():
    # SHA3 (0x20) isn't modelled concretely; replay should halt, not raise.
    #  0: PUSH1 0x00 ; PUSH1 0x00 ; SHA3 ; JUMPDEST(pc=5)
    code = _bc("6000" + "6000" + "20" + "00" + "00" + "5b")
    r = ConcreteReplayer(code, {})
    # the JUMPDEST after SHA3 is never reached because SHA3 halts the replay
    assert r.reaches(5) is False


# --------------------------------------------------------------------------- #
# Concrete arithmetic agrees with the EVM spec (mirrors vm.py handlers)
# --------------------------------------------------------------------------- #
def _eval_binop(op_hex: str, a: int, b: int) -> int:
    """Assemble PUSH32 b ; PUSH32 a ; <op> ; PUSH1 0x00 ; SLOAD ; ... and read
    the result by storing it: PUSH32 b ; PUSH32 a ; op ; PUSH1 0 ; SSTORE.

    Easier: run and inspect via a fresh replayer's state through SSTORE to slot
    0, then SLOAD it is overkill — instead drive the internal state directly.
    """
    code = _bc(_push32(b) + _push32(a) + op_hex + "00")
    r = ConcreteReplayer(code, {})
    # reach the STOP after the op, capturing final stack via a custom run
    from oracle.laser.replay import _ConcreteState

    st = _ConcreteState()
    while not st.halted:
        inst = r.disasm.by_pc.get(st.pc)
        if inst is None or inst.mnemonic == "STOP":
            break
        r._step(st, inst, r.disasm.jumpdests)
    return st.stack[-1]


def test_concrete_sdiv_signed():
    # SDIV(-4, 2) = -2  (operands signed)
    neg4 = (-4) & MASK
    assert _to_signed(_eval_binop("05", neg4, 2)) == -2


def test_concrete_sdiv_by_zero_is_zero():
    assert _eval_binop("05", 10, 0) == 0


def test_concrete_smod_takes_dividend_sign():
    # SMOD(-7, 3): magnitude 7 % 3 = 1, sign of dividend -> -1
    neg7 = (-7) & MASK
    assert _to_signed(_eval_binop("07", neg7, 3)) == -1


def test_concrete_sar_arithmetic_shift():
    # SAR(shift=1, value=-8) = -4. _eval_binop pushes b then a; for SAR the
    # spec pops shift (top) then value, and our op pops a=shift first.
    # _eval_binop computes op(a, b) with a on top, so a=shift, b=value.
    neg8 = (-8) & MASK
    assert _to_signed(_eval_binop("1d", 1, neg8)) == -4


def test_concrete_addmod_no_overflow():
    # ADDMOD takes 3 operands; drive it directly.
    code = _bc(_push32(5) + _push32(MASK) + _push32(MASK) + "08" + "00")
    from oracle.laser.replay import _ConcreteState

    r = ConcreteReplayer(code, {})
    st = _ConcreteState()
    while not st.halted:
        inst = r.disasm.by_pc.get(st.pc)
        if inst is None or inst.mnemonic == "STOP":
            break
        r._step(st, inst, r.disasm.jumpdests)
    # (MASK + MASK) % 5 ; MASK == 2**256 - 1
    assert st.stack[-1] == (MASK + MASK) % 5


def test_concrete_signextend():
    # SIGNEXTEND(0, 0xff) sign-extends the 1-byte value 0xff -> all ones.
    code = _bc(_push32(0xFF) + _push32(0) + "0b" + "00")
    from oracle.laser.replay import _ConcreteState

    r = ConcreteReplayer(code, {})
    st = _ConcreteState()
    while not st.halted:
        inst = r.disasm.by_pc.get(st.pc)
        if inst is None or inst.mnemonic == "STOP":
            break
        r._step(st, inst, r.disasm.jumpdests)
    assert st.stack[-1] == MASK


# --------------------------------------------------------------------------- #
# validate_finding / validate_findings — finding enrichment
# --------------------------------------------------------------------------- #
def _finding(pc: int, trigger: dict) -> dict:
    return {
        "category": "assertion_violation",
        "severity": "high",
        "pc": pc,
        "op": "INVALID",
        "depth": 0,
        "trace": [],
        "trigger_input": trigger,
        "confidence": "confirmed",
    }


def test_validate_finding_confirmed():
    # calldata != 0 reaches the guarded JUMPDEST at pc 8.
    code = _bc("6000" + "35" + "6008" + "57" + "00" + "00" + "5b" + "00")
    f = _finding(8, {"calldata": _word(1)})
    out = validate_finding(code, f)
    assert out["validated"] is True
    assert out["validation"] == "confirmed"
    # original finding untouched
    assert "validated" not in f


def test_validate_finding_unreachable():
    code = _bc("6000" + "35" + "6008" + "57" + "00" + "00" + "5b" + "00")
    f = _finding(8, {"calldata": _word(0)})
    out = validate_finding(code, f)
    assert out["validated"] is False
    assert out["validation"] == "unreachable"


def test_validate_finding_skipped_without_trigger():
    code = _bc("00")
    f = _finding(0, {})
    f["confidence"] = "timeout"
    out = validate_finding(code, f)
    assert out["validated"] is False
    assert out["validation"] == "skipped"


def test_validate_finding_skipped_without_pc():
    code = _bc("00")
    f = _finding(0, {"calldata": _word(1)})
    f["pc"] = None
    out = validate_finding(code, f)
    assert out["validation"] == "skipped"


def test_validate_findings_batch_preserves_order_and_count():
    code = _bc("6000" + "35" + "6008" + "57" + "00" + "00" + "5b" + "00")
    findings = [
        _finding(8, {"calldata": _word(1)}),
        _finding(8, {"calldata": _word(0)}),
    ]
    out = validate_findings(code, findings)
    assert len(out) == 2
    assert out[0]["validation"] == "confirmed"
    assert out[1]["validation"] == "unreachable"
