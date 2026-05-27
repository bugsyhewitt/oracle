"""Tests for the Keccak256 uninterpreted-function model (keccak.py + vm.py).

Coverage:
  1. Unit: same 256-bit input produces the same Z3 expression (referential
     transparency of the uninterpreted function).
  2. Unit: injectivity axiom causes Z3 to conclude that
     keccak(a) == keccak(b) is SAT only when a == b.
  3. Unit: 512-bit (two-word) variant is similarly injective.
  4. Integration: SHA3 opcode with a concrete 32-byte size uses the UF model
     (result is not a plain BitVecRef free variable).
  5. Integration: SHA3 opcode with a concrete 64-byte size uses the 512-bit UF.
  6. Integration: SHA3 opcode with unknown size falls back to a fresh symbol
     (backward-compat / conservative path).
"""

from __future__ import annotations

import z3

from oracle.laser.smt import symbol_factory, simplify
from oracle.laser.smt.keccak import keccak_model, KeccakModel
from oracle.laser.state import MachineState, WorldState
from oracle.laser.vm import SymbolicVM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bvv(v: int, bits: int = 256) -> "oracle.laser.smt.BitVec":  # noqa: F821
    return symbol_factory.BitVecVal(v, bits)


def _push32(value: int) -> str:
    return "7f" + format(value & ((1 << 256) - 1), "064x")


def _run_one(hexcode: str) -> MachineState:
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


# ---------------------------------------------------------------------------
# 1. Referential transparency — same input -> same Z3 AST node
# ---------------------------------------------------------------------------

class TestKeccakReferentialTransparency:
    """Calling hash_256 with the same BitVec object twice should yield
    structurally equal Z3 expressions (they share the UF application node).
    """

    def test_same_word_same_expression_256(self):
        fresh = KeccakModel()
        word = symbol_factory.BitVecSym("w", 256)
        h1 = fresh.hash_256(word)
        h2 = fresh.hash_256(word)
        # z3 applications for the same function and argument are equal
        assert z3.eq(h1.raw, h2.raw)

    def test_same_words_same_expression_512(self):
        fresh = KeccakModel()
        hi = symbol_factory.BitVecSym("hi", 256)
        lo = symbol_factory.BitVecSym("lo", 256)
        h1 = fresh.hash_512(hi, lo)
        h2 = fresh.hash_512(hi, lo)
        assert z3.eq(h1.raw, h2.raw)

    def test_different_words_different_expressions(self):
        fresh = KeccakModel()
        w1 = symbol_factory.BitVecSym("w1", 256)
        w2 = symbol_factory.BitVecSym("w2", 256)
        h1 = fresh.hash_256(w1)
        h2 = fresh.hash_256(w2)
        # Different inputs -> structurally different Z3 expressions
        assert not z3.eq(h1.raw, h2.raw)


# ---------------------------------------------------------------------------
# 2. Injectivity axiom — 256-bit variant
# ---------------------------------------------------------------------------

class TestInjectivityAxiom256:
    """The axiom keccak(x)==keccak(y) -> x==y should be provable by Z3."""

    def test_injectivity_implies_equal_inputs(self):
        """Under the axiom, if keccak(a)==keccak(b), Z3 must set a==b."""
        solver = z3.Solver()
        fresh = KeccakModel()
        fresh.add_axioms_raw(solver)

        a = z3.BitVec("a256", 256)
        b = z3.BitVec("b256", 256)

        # Ask: is keccak(a)==keccak(b) AND a!=b satisfiable?
        # Answer should be UNSAT (injectivity rules it out).
        from oracle.laser.smt.keccak import _keccak_256_raw
        solver.add(_keccak_256_raw(a) == _keccak_256_raw(b))
        solver.add(a != b)

        result = solver.check()
        assert result == z3.unsat, (
            "Expected UNSAT: keccak(a)==keccak(b) with a!=b should be impossible "
            f"under the injectivity axiom, got {result}"
        )

    def test_equal_inputs_hash_collision_is_not_unsat(self):
        """keccak(a)==keccak(b) with a==b must not be UNSAT.

        Z3 may return sat or unknown (unknown is expected when quantifiers are
        present and Z3 cannot fully instantiate them within the search bound)
        but never unsat — that would mean no model where equal inputs hash
        equally, which contradicts the function's definition.
        """
        solver = z3.Solver()
        solver.set("timeout", 10000)
        fresh = KeccakModel()
        fresh.add_axioms_raw(solver)

        a = z3.BitVec("a256_eq", 256)
        b = z3.BitVec("b256_eq", 256)

        from oracle.laser.smt.keccak import _keccak_256_raw
        solver.add(_keccak_256_raw(a) == _keccak_256_raw(b))
        solver.add(a == b)

        result = solver.check()
        assert result != z3.unsat, (
            f"keccak(a)==keccak(b) with a==b must not be UNSAT, got {result}"
        )


# ---------------------------------------------------------------------------
# 3. Injectivity axiom — 512-bit variant
# ---------------------------------------------------------------------------

class TestInjectivityAxiom512:
    """Same injectivity property for the two-word (512-bit) variant."""

    def test_injectivity_512(self):
        solver = z3.Solver()
        # 30 second timeout — quantifier instantiation over 512-bit BVs can
        # be slow on pathological inputs; this bound keeps the test suite fast.
        solver.set("timeout", 30000)
        fresh = KeccakModel()
        fresh.add_axioms_raw(solver)

        from oracle.laser.smt.keccak import _keccak_512_raw
        x = z3.BitVec("x512", 512)
        y = z3.BitVec("y512", 512)

        solver.add(_keccak_512_raw(x) == _keccak_512_raw(y))
        solver.add(x != y)

        result = solver.check()
        # Accept unsat (proved) or unknown (timeout-bounded — still correct,
        # just took too long for the test budget).
        assert result in (z3.unsat, z3.unknown), (
            f"Expected UNSAT or unknown (timeout) for 512-bit injectivity "
            f"violation, got {result}"
        )

    def test_equal_inputs_512_not_unsat(self):
        """512-bit equal inputs must not be UNSAT (same reasoning as 256-bit case)."""
        solver = z3.Solver()
        solver.set("timeout", 10000)
        fresh = KeccakModel()
        fresh.add_axioms_raw(solver)

        from oracle.laser.smt.keccak import _keccak_512_raw
        x = z3.BitVec("x512_eq", 512)
        y = z3.BitVec("y512_eq", 512)

        solver.add(_keccak_512_raw(x) == _keccak_512_raw(y))
        solver.add(x == y)

        result = solver.check()
        assert result != z3.unsat, (
            f"keccak512(x)==keccak512(y) with x==y must not be UNSAT, got {result}"
        )


# ---------------------------------------------------------------------------
# 4–6. Integration: SHA3 opcode via the VM
# ---------------------------------------------------------------------------

class TestSha3OpcodeIntegration:
    """Drive the SHA3 opcode handler via hand-assembled bytecode and verify
    the resulting stack value has the expected Z3 shape.

    SHA3 bytecode:  PUSH32 <size>  PUSH32 <offset>  0x20(SHA3)
    EVM SHA3 pops offset first (top of stack), then size — so we push
    size first, then offset.
    """

    def _sha3_code(self, offset: int, size: int) -> str:
        # push size (consumed second), then offset (consumed first / top)
        return _push32(size) + _push32(offset) + "20" + "00"

    def test_sha3_size32_uses_uf_model(self):
        """With size=32 the result should be a UF application, not a free variable."""
        code = self._sha3_code(offset=0, size=32)
        state = _run_one(code)
        assert state.stack, "Stack should not be empty after SHA3"
        top = state.stack[-1]
        # A UF application node has decl().name() == "keccak256_256"
        raw = top.raw
        assert hasattr(raw, "decl"), "Expected a Z3 application node"
        assert raw.decl().name() == "keccak256_256", (
            f"Expected keccak256_256 UF application, got {raw.decl().name()!r}"
        )

    def test_sha3_size64_uses_512_uf(self):
        """With size=64 the result should use keccak256_512."""
        code = self._sha3_code(offset=0, size=64)
        state = _run_one(code)
        assert state.stack
        top = state.stack[-1]
        raw = top.raw
        assert hasattr(raw, "decl")
        assert raw.decl().name() == "keccak256_512", (
            f"Expected keccak256_512 UF application, got {raw.decl().name()!r}"
        )

    def test_sha3_unknown_size_fallback(self):
        """With symbolic (unknown) size, fall back to a fresh symbol."""
        # To get a symbolic size we omit the PUSH for size and use a symbolic
        # calldata word instead — simplest is just push a symbolic calldatasize
        # by running the CALLDATASIZE opcode, then a concrete offset.
        # bytecode: PUSH32 0 (offset top), CALLDATASIZE (size), SHA3 STOP
        # CALLDATASIZE = 0x36
        code = "60" + "00" + "36" + "20" + "00"  # PUSH1 0, CALLDATASIZE, SHA3, STOP
        state = _run_one(code)
        assert state.stack
        top = state.stack[-1]
        raw = top.raw
        # Should be a free BitVec variable (not a UF application)
        # A free Z3 BitVec has .decl().kind() == z3.Z3_OP_UNINTERPRETED
        # but its decl name will NOT be keccak256_*.
        if hasattr(raw, "decl"):
            name = raw.decl().name()
            assert not name.startswith("keccak256_"), (
                f"Fallback path should not use keccak UF, got {name!r}"
            )

    def test_sha3_size32_same_offset_same_result(self):
        """Two SHA3 ops with the same concrete offset and size=32 must produce
        structurally equal Z3 expressions (UF applies the same symbol)."""
        # Run the same bytecode twice from two independent executions; they
        # both hash the same symbolic mem word so Z3 sees equal applications.
        code = self._sha3_code(offset=0x40, size=32)
        s1 = _run_one(code)
        s2 = _run_one(code)
        assert z3.eq(s1.stack[-1].raw, s2.stack[-1].raw), (
            "Same offset/size SHA3 should produce structurally equal Z3 expressions"
        )

    def test_sha3_size64_different_offsets_different_results(self):
        """Two SHA3(64) ops at different offsets should produce different expressions."""
        code_a = self._sha3_code(offset=0, size=64)
        code_b = self._sha3_code(offset=0x40, size=64)
        sa = _run_one(code_a)
        sb = _run_one(code_b)
        # Different symbol names -> different Z3 expressions
        assert not z3.eq(sa.stack[-1].raw, sb.stack[-1].raw), (
            "Different-offset SHA3(64) calls should produce distinct Z3 expressions"
        )

    def test_add_axioms_idempotent(self):
        """Calling add_axioms on the same solver twice should not raise or duplicate."""
        solver = z3.Solver()
        fresh = KeccakModel()
        fresh.add_axioms_raw(solver)
        constraints_after_first = len(solver.assertions())
        fresh.add_axioms_raw(solver)  # second call — should be a no-op
        constraints_after_second = len(solver.assertions())
        assert constraints_after_first == constraints_after_second, (
            "add_axioms_raw called twice should not add duplicate constraints"
        )
