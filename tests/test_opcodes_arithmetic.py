"""Unit tests for the arithmetic / bit-manipulation opcode handlers.

These exercise the EVM-spec semantics of SAR, SDIV, SMOD, ADDMOD, MULMOD,
SIGNEXTEND and BYTE with concrete operands. They drive the VM directly with
hand-assembled bytecode (no Z3 solving, no fixtures) and assert the concrete
word left on the stack.

EVM stack convention: for a binary op the FIRST popped operand (`a`) is the top
of the stack, i.e. the *last* value pushed. So to compute `op(a, b)` the
bytecode pushes `b` first, then `a`.
"""

from oracle.laser.smt import simplify
from oracle.laser.state import MachineState, WorldState
from oracle.laser.vm import SymbolicVM

TT256 = 2 ** 256
MASK = TT256 - 1


def _push32(value: int) -> str:
    return "7f" + format(value & MASK, "064x")


def _run(hexcode: str) -> MachineState:
    """Execute straight-line bytecode until STOP / end / branch, return state."""
    vm = SymbolicVM(bytes.fromhex(hexcode))
    state = MachineState(WorldState())
    while True:
        inst = vm.disasm.by_pc.get(state.pc)
        if inst is None or inst.mnemonic == "STOP":
            break
        succ = vm._step(state, inst)
        if not succ:
            break
        state = succ[0]
    return state


def _top(state: MachineState) -> int:
    val = SymbolicVM._concrete(simplify(state.stack[-1]))
    assert val is not None, "expected a concrete result on the stack"
    return val


def _binop(opcode_hex: str, a: int, b: int) -> int:
    """Assemble PUSH32 b ; PUSH32 a ; <op> and return the concrete result."""
    code = _push32(b) + _push32(a) + opcode_hex + "00"
    return _top(_run(code))


# --------------------------------------------------------------------------- #
# SAR (0x1d): arithmetic right shift. stack: [shift(top? no)]
# EVM SAR pops shift first (top), then value: SAR(shift, value).
# bytecode pushes value first, then shift.
# --------------------------------------------------------------------------- #
def _sar(shift: int, value: int) -> int:
    code = _push32(value) + _push32(shift) + "1d" + "00"
    return _top(_run(code))


def test_sar_positive():
    # 8 >> 1 = 4 (positive value, sign bit 0)
    assert _sar(1, 8) == 4


def test_sar_negative_fills_sign_bit():
    # -2 (two's complement) >> 1 = -1. Sign bit replicated.
    neg2 = TT256 - 2
    assert _sar(1, neg2) == (TT256 - 1)


def test_sar_negative_large_shift_saturates_to_minus_one():
    neg8 = TT256 - 8
    # shifting a negative value right by >= 255 saturates to all-ones (-1)
    assert _sar(255, neg8) == (TT256 - 1)


# --------------------------------------------------------------------------- #
# SDIV (0x05): signed division, sign-aware, div-by-zero -> 0
# --------------------------------------------------------------------------- #
def test_sdiv_neg_by_pos():
    assert _binop("05", TT256 - 4, 2) == (TT256 - 2)  # -4 / 2 = -2


def test_sdiv_neg_by_neg():
    assert _binop("05", TT256 - 4, TT256 - 2) == 2  # -4 / -2 = 2


def test_sdiv_pos():
    assert _binop("05", 7, 2) == 3  # truncates toward zero


def test_sdiv_by_zero_is_zero():
    assert _binop("05", 12345, 0) == 0


# --------------------------------------------------------------------------- #
# SMOD (0x07): signed modulo, sign of dividend, mod-by-zero -> 0
# --------------------------------------------------------------------------- #
def test_smod_neg_dividend():
    # -8 % 3 = -2 (result takes sign of dividend)
    assert _binop("07", TT256 - 8, 3) == (TT256 - 2)


def test_smod_pos():
    assert _binop("07", 8, 3) == 2


def test_smod_by_zero_is_zero():
    assert _binop("07", 8, 0) == 0


# --------------------------------------------------------------------------- #
# ADDMOD (0x08): (a + b) % N with 256-bit-overflow-safe intermediate
# stack order: a (top), b, N. push N, b, a.
# --------------------------------------------------------------------------- #
def _addmod(a: int, b: int, n: int) -> int:
    code = _push32(n) + _push32(b) + _push32(a) + "08" + "00"
    return _top(_run(code))


def test_addmod_basic():
    assert _addmod(10, 10, 8) == 4  # 20 % 8


def test_addmod_overflow_intermediate():
    # (2^256-1) + 2 = 2^256+1, mod 5 -> the true sum is 2^256+1; (2^256+1)%5
    a = TT256 - 1
    assert _addmod(a, 2, 5) == ((a + 2) % 5)


def test_addmod_by_zero_is_zero():
    assert _addmod(4, 5, 0) == 0


# --------------------------------------------------------------------------- #
# MULMOD (0x09): (a * b) % N with 512-bit-safe intermediate
# --------------------------------------------------------------------------- #
def _mulmod(a: int, b: int, n: int) -> int:
    code = _push32(n) + _push32(b) + _push32(a) + "09" + "00"
    return _top(_run(code))


def test_mulmod_basic():
    assert _mulmod(10, 10, 8) == 4  # 100 % 8


def test_mulmod_overflow_intermediate():
    a = TT256 - 1
    assert _mulmod(a, a, 12) == ((a * a) % 12)


def test_mulmod_by_zero_is_zero():
    assert _mulmod(4, 5, 0) == 0


# --------------------------------------------------------------------------- #
# SIGNEXTEND (0x0b): SIGNEXTEND(b, x) sign-extends the (b+1)-byte value x.
# stack: b (top), x. push x, b.
# --------------------------------------------------------------------------- #
def _signextend(b: int, x: int) -> int:
    code = _push32(x) + _push32(b) + "0b" + "00"
    return _top(_run(code))


def test_signextend_negative_byte():
    # b=0 -> treat low byte as int8. 0xFF -> -1 extended to 256 bits.
    assert _signextend(0, 0xFF) == (TT256 - 1)


def test_signextend_positive_byte():
    # 0x7F is positive int8, stays 0x7F.
    assert _signextend(0, 0x7F) == 0x7F


def test_signextend_two_bytes_negative():
    # b=1 -> int16. 0xFFFE = -2 in two bytes.
    assert _signextend(1, 0xFFFE) == (TT256 - 2)


def test_signextend_noop_for_large_b():
    # b >= 31 leaves x unchanged
    assert _signextend(31, 0x1234) == 0x1234


# --------------------------------------------------------------------------- #
# BYTE (0x1a): BYTE(i, x) selects byte i (big-endian, 0 = MSB) of x.
# stack: i (top), x. push x, i.
# --------------------------------------------------------------------------- #
def _byte(i: int, x: int) -> int:
    code = _push32(x) + _push32(i) + "1a" + "00"
    return _top(_run(code))


def test_byte_most_significant():
    x = 0xAB << 248  # 0xAB in the top byte
    assert _byte(0, x) == 0xAB


def test_byte_least_significant():
    assert _byte(31, 0x00000000000000000000000000000000000000000000000000000000000000CD) == 0xCD


def test_byte_middle():
    x = 0xDE << (248 - 8 * 5)  # byte index 5 from the top
    assert _byte(5, x) == 0xDE


def test_byte_out_of_range_is_zero():
    assert _byte(32, 0xFFFFFFFF) == 0
    assert _byte(100, 0xFFFFFFFF) == 0
