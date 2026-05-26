"""Unit tests for the return-data / ext-code / copy opcode handlers.

These verify the *stack effect* and *path survival* of the conservative-sound
opcodes added for post-call path coverage:

  RETURNDATASIZE, RETURNDATACOPY, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH,
  CALLDATACOPY, CODECOPY, CODESIZE

The key property is that none of them halt the path (v0.1 halted on every
unhandled opcode). They drive the VM directly on hand-assembled bytecode.
"""

from oracle.laser.smt import simplify
from oracle.laser.state import MachineState, WorldState
from oracle.laser.vm import SymbolicVM

MASK = (2 ** 256) - 1


def _push32(value: int) -> str:
    return "7f" + format(value & MASK, "064x")


def _run(hexcode: str):
    vm = SymbolicVM(bytes.fromhex(hexcode))
    state = MachineState(WorldState())
    while True:
        inst = vm.disasm.by_pc.get(state.pc)
        if inst is None or inst.mnemonic == "STOP":
            break
        succ = vm._step(state, inst)
        if not succ:
            return vm, state, False  # path halted/empty
        state = succ[0]
        if state.halted or state.reverted:
            return vm, state, False
    return vm, state, True


def _is_symbolic(bv) -> bool:
    return SymbolicVM._concrete(simplify(bv)) is None


# --------------------------------------------------------------------------- #
# RETURNDATASIZE (0x3d): pushes a fresh symbolic word, no pops.
# --------------------------------------------------------------------------- #
def test_returndatasize_pushes_symbol_and_continues():
    vm, state, ok = _run("3d" + "00")  # RETURNDATASIZE STOP
    assert ok
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


# --------------------------------------------------------------------------- #
# RETURNDATACOPY (0x3e): pops 3, pushes nothing, continues.
# --------------------------------------------------------------------------- #
def test_returndatacopy_pops_three_and_continues():
    code = _push32(2) + _push32(1) + _push32(0) + "3e" + "00"  # size off dest
    vm, state, ok = _run(code)
    assert ok
    assert state.stack == []


# --------------------------------------------------------------------------- #
# EXTCODESIZE (0x3b): pops address, pushes a fresh symbol.
# --------------------------------------------------------------------------- #
def test_extcodesize_pops_addr_pushes_symbol():
    code = _push32(0xCAFE) + "3b" + "00"
    vm, state, ok = _run(code)
    assert ok
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


# --------------------------------------------------------------------------- #
# EXTCODECOPY (0x3c): pops 4, no push.
# --------------------------------------------------------------------------- #
def test_extcodecopy_pops_four_and_continues():
    code = _push32(3) + _push32(2) + _push32(1) + _push32(0xAA) + "3c" + "00"
    vm, state, ok = _run(code)
    assert ok
    assert state.stack == []


# --------------------------------------------------------------------------- #
# EXTCODEHASH (0x3f): pops address, pushes a fresh symbol.
# --------------------------------------------------------------------------- #
def test_extcodehash_pops_addr_pushes_symbol():
    code = _push32(0xBEEF) + "3f" + "00"
    vm, state, ok = _run(code)
    assert ok
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


# --------------------------------------------------------------------------- #
# CALLDATACOPY (0x37): pops 3, no push.
# --------------------------------------------------------------------------- #
def test_calldatacopy_pops_three_and_continues():
    code = _push32(2) + _push32(1) + _push32(0) + "37" + "00"
    vm, state, ok = _run(code)
    assert ok
    assert state.stack == []


# --------------------------------------------------------------------------- #
# CODECOPY (0x39): pops 3, no push.
# --------------------------------------------------------------------------- #
def test_codecopy_pops_three_and_continues():
    code = _push32(2) + _push32(1) + _push32(0) + "39" + "00"
    vm, state, ok = _run(code)
    assert ok
    assert state.stack == []


# --------------------------------------------------------------------------- #
# CODESIZE (0x38): pushes the concrete length of the running bytecode.
# --------------------------------------------------------------------------- #
def test_codesize_is_concrete_bytecode_length():
    code = "38" + "00"  # CODESIZE STOP -> 2 bytes total
    vm, state, ok = _run(code)
    assert ok
    val = SymbolicVM._concrete(simplify(state.stack[-1]))
    assert val == len(bytes.fromhex(code))
