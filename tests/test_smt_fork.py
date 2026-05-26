"""Sanity tests for the forked mythril SMT module (oracle.laser.smt).

These exercise the BitVec/Bool/Solver wrapper directly. They DO touch z3 (the
wrapper is a thin shell over it) but are tiny and fast; they are marked slow so
the strictly-no-Z3 default run stays clean per criterion 8.
"""

import pytest

from oracle.laser.smt import And, BitVec, Bool, Or, Solver, simplify, symbol_factory


@pytest.mark.slow
def test_bitvec_solver_roundtrip():
    x = symbol_factory.BitVecSym("x", 256)
    s = Solver()
    s.add(x > 5)
    s.add(x < 8)
    import z3

    assert s.check() == z3.sat


@pytest.mark.slow
def test_constant_bitvec_arithmetic():
    a = symbol_factory.BitVecVal(3, 256)
    b = symbol_factory.BitVecVal(4, 256)
    res = simplify(a + b)
    assert res.raw.as_long() == 7
