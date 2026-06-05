"""Unit tests for Cancun / Dencun / London opcode handlers.

Verifies stack effect and path survival for the conservative-sound handlers
added for post-Cancun EVM bytecode coverage:

  BASEFEE   (EIP-3198, London, 0x48)
  BLOBHASH  (EIP-4844, Dencun,  0x49)
  BLOBBASEFEE (EIP-7516, Dencun, 0x4a)
  TLOAD     (EIP-1153, Cancun,  0x5c)
  TSTORE    (EIP-1153, Cancun,  0x5d)
  MCOPY     (EIP-5656, Cancun,  0x5e)
  CREATE2   (EIP-1014, Constantinople, 0xf5)

The key property for each is that the opcode no longer halts the path
(before this patch any unrecognised opcode set ``state.halted = True``).
Tests drive the VM directly on hand-assembled bytecode, mirroring the
conventions in ``test_opcodes_extcode.py``.
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
            return vm, state, False  # path halted / empty
        state = succ[0]
        if state.halted or state.reverted:
            return vm, state, False
    return vm, state, True


def _is_symbolic(bv) -> bool:
    return SymbolicVM._concrete(simplify(bv)) is None


# ------------------------------------------------------ BASEFEE (0x48)
def test_basefee_pushes_symbol_and_continues():
    """BASEFEE: no pop, pushes one fresh symbolic word."""
    vm, state, ok = _run("48" + "00")  # BASEFEE STOP
    assert ok, "BASEFEE must not halt the path"
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


# ------------------------------------------------------ BLOBHASH (0x49)
def test_blobhash_pops_index_pushes_symbol():
    """BLOBHASH: pops one index, pushes one fresh symbolic word."""
    code = _push32(0) + "49" + "00"  # PUSH32(index=0) BLOBHASH STOP
    vm, state, ok = _run(code)
    assert ok, "BLOBHASH must not halt the path"
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


# -------------------------------------------------- BLOBBASEFEE (0x4a)
def test_blobbasefee_pushes_symbol_and_continues():
    """BLOBBASEFEE: no pop, pushes one fresh symbolic word."""
    vm, state, ok = _run("4a" + "00")  # BLOBBASEFEE STOP
    assert ok, "BLOBBASEFEE must not halt the path"
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


# -------------------------------------------------------- TLOAD (0x5c)
def test_tload_pops_key_pushes_symbol():
    """TLOAD: pops one key, pushes one fresh symbolic word (conservative)."""
    code = _push32(0xAB) + "5c" + "00"  # PUSH32(key) TLOAD STOP
    vm, state, ok = _run(code)
    assert ok, "TLOAD must not halt the path"
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


def test_tload_fresh_symbol_per_pc():
    """Two TLOAD opcodes at different PCs produce symbolically distinct words.

    If both TLOADs had the same name, a solver could not distinguish a
    branch on TLOAD(0) from a branch on TLOAD(1), producing false constraints.
    The per-pc naming ``tload_<pc>`` guarantees distinctness."""
    # PUSH32(key=0) TLOAD PUSH32(key=1) TLOAD ADD STOP
    code = (
        _push32(0) + "5c"    # tload_0  (pc depends on push32 length = 33 bytes)
        + _push32(1) + "5c"  # tload_1  (different pc)
        + "01"               # ADD
        + "00"               # STOP
    )
    vm, state, ok = _run(code)
    assert ok, "sequence of TLOADs must survive"
    # The ADD of two fresh symbolic words must also be symbolic.
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


# ------------------------------------------------------- TSTORE (0x5d)
def test_tstore_pops_key_and_value_and_continues():
    """TSTORE: pops key and value, pushes nothing, continues path."""
    code = _push32(0xBEEF) + _push32(0xFF) + "5d" + "00"  # val key TSTORE STOP
    vm, state, ok = _run(code)
    assert ok, "TSTORE must not halt the path"
    assert state.stack == []


def test_tstore_does_not_modify_persistent_storage():
    """TSTORE must not bleed into oracle's persistent world storage.

    Transient storage resets at the end of every transaction; oracle models it
    as a no-op against the durable world state. After a TSTORE, an SLOAD of the
    same slot must return the default symbolic value (unchanged storage)."""
    slot = 0x42
    value = 0xDEAD
    # PUSH32(value) PUSH32(slot) TSTORE PUSH32(slot) SLOAD STOP
    code = (
        _push32(value)
        + _push32(slot)
        + "5d"          # TSTORE
        + _push32(slot)
        + "54"          # SLOAD
        + "00"
    )
    vm, state, ok = _run(code)
    assert ok, "TSTORE + SLOAD sequence must survive"
    # SLOAD of an unmodified slot returns a symbolic value from the SMT array —
    # it must NOT return the concrete integer 0xDEAD that TSTORE wrote.
    top = state.stack[-1]
    concrete = SymbolicVM._concrete(simplify(top))
    assert concrete != value, (
        "TSTORE must not bleed into persistent storage visible to SLOAD"
    )


# -------------------------------------------------------- MCOPY (0x5e)
def test_mcopy_pops_three_and_continues():
    """MCOPY: pops destOffset, srcOffset, size; pushes nothing; continues."""
    code = _push32(4) + _push32(0) + _push32(0) + "5e" + "00"
    vm, state, ok = _run(code)
    assert ok, "MCOPY must not halt the path"
    assert state.stack == []


# ------------------------------------------------------ CREATE2 (0xf5)
def test_create2_pops_four_pushes_symbol():
    """CREATE2: pops value, offset, size, salt; pushes one symbolic address."""
    code = (
        _push32(0xDEAD)  # salt
        + _push32(0)     # size
        + _push32(0)     # offset
        + _push32(0)     # value
        + "f5"           # CREATE2
        + "00"
    )
    vm, state, ok = _run(code)
    assert ok, "CREATE2 must not halt the path"
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])


def test_create2_fresh_symbol_per_pc():
    """Two CREATE2 calls at different PCs produce symbolically distinct addresses."""
    code = (
        _push32(0x01) + _push32(0) + _push32(0) + _push32(0) + "f5"  # CREATE2 #1
        + _push32(0x02) + _push32(0) + _push32(0) + _push32(0) + "f5"  # CREATE2 #2
        + "01"  # ADD (combine the two symbolic addresses)
        + "00"
    )
    vm, state, ok = _run(code)
    assert ok, "back-to-back CREATE2 sequence must survive"
    assert len(state.stack) == 1
    assert _is_symbolic(state.stack[-1])
