"""Keccak256 modelled as a Z3 uninterpreted function with an injectivity axiom.

Rationale
---------
oracle v0.1 treated every SHA3 opcode as a fresh unconstrained symbol.  That
is sound (we never assert two hashes are equal when they shouldn't be) but
imprecise: Z3 has no information about the relationship between outputs so it
cannot reason about mapping-slot collisions.

Solidity mapping slots are computed as::

    slot = keccak256(abi.encode(key, mapping_slot))   # 64-byte input

By modelling keccak256 as a Z3 *uninterpreted function* with the injectivity
axiom ``keccak256(x) != keccak256(y)  when  x != y``, Z3 gains enough
knowledge to track "two different inputs produce two different slots" while
still keeping all hash outputs fully unconstrained in value.

Variable-length input handling
-------------------------------
Real keccak takes variable-length bytes.  We model the 80 % case:

* 256-bit (32-byte) single-word inputs   — direct ``keccak256_256(w)``
* 512-bit (64-byte) two-word inputs      — ``keccak256_512(hi || lo)``

These cover the single-value hash and the mapping-slot ``keccak(key, slot)``
patterns respectively.  The SHA3 opcode handler in vm.py selects the
appropriate overload based on the memory size operand it sees (when
concrete).

Usage
-----
The module exposes a single :class:`KeccakModel` instance ``keccak_model``
that the VM imports.  On first use, the injectivity axioms are injected into
any :class:`oracle.laser.smt.solver.solver.Solver` via
``keccak_model.add_axioms(solver)``.
"""

from __future__ import annotations

import z3

from oracle.laser.smt.bitvec import BitVec


# ---------------------------------------------------------------------------
# Two Z3 uninterpreted functions:
#   keccak256_256 : BitVec(256) -> BitVec(256)   (single 32-byte word input)
#   keccak256_512 : BitVec(512) -> BitVec(256)   (two 32-byte words concatenated)
# ---------------------------------------------------------------------------

_keccak_256_raw: z3.FuncDeclRef = z3.Function(
    "keccak256_256",
    z3.BitVecSort(256),
    z3.BitVecSort(256),
)

_keccak_512_raw: z3.FuncDeclRef = z3.Function(
    "keccak256_512",
    z3.BitVecSort(512),
    z3.BitVecSort(256),
)


def _make_injectivity_256() -> z3.BoolRef:
    """ForAll x, y: keccak256_256(x) == keccak256_256(y) -> x == y."""
    x = z3.BitVec("_k256_x", 256)
    y = z3.BitVec("_k256_y", 256)
    return z3.ForAll(
        [x, y],
        z3.Implies(_keccak_256_raw(x) == _keccak_256_raw(y), x == y),
    )


def _make_injectivity_512() -> z3.BoolRef:
    """ForAll x, y: keccak256_512(x) == keccak256_512(y) -> x == y."""
    x = z3.BitVec("_k512_x", 512)
    y = z3.BitVec("_k512_y", 512)
    return z3.ForAll(
        [x, y],
        z3.Implies(_keccak_512_raw(x) == _keccak_512_raw(y), x == y),
    )


class KeccakModel:
    """Manages the keccak256 uninterpreted functions and their axioms.

    One instance is shared across the entire oracle session
    (``keccak_model`` module-level singleton below).

    The axioms are *lazy*: we add them to a concrete solver instance the first
    time they are needed for that solver.  This keeps the common case (no SHA3
    in a contract) zero-cost.
    """

    def __init__(self) -> None:
        # IDs of solvers that already have the axioms injected, to avoid
        # duplicating them across solver.add() calls.
        self._axiom_injected: set[int] = set()

    # ------------------------------------------------------------------
    # Public API used by vm.py
    # ------------------------------------------------------------------

    def hash_256(self, word: BitVec) -> BitVec:
        """Apply keccak256 to a single 256-bit word (32 bytes).

        Returns a 256-bit BitVec wrapping the Z3 application expression.
        The same ``word`` always maps to the same Z3 expression, enabling
        the solver to track equality across paths.
        """
        raw = _keccak_256_raw(word.raw)
        return BitVec(raw, annotations=set(word.annotations))

    def hash_512(self, hi: BitVec, lo: BitVec) -> BitVec:
        """Apply keccak256 to the concatenation of two 256-bit words (64 bytes).

        This covers the Solidity mapping-slot pattern::

            slot_key = keccak256(abi.encode(mapping_key, mapping_slot))

        where ``hi`` is the key and ``lo`` is the mapping slot number.
        """
        import z3 as _z3
        combined = _z3.Concat(hi.raw, lo.raw)  # 512-bit
        raw = _keccak_512_raw(combined)
        annotations = set(hi.annotations) | set(lo.annotations)
        return BitVec(raw, annotations=annotations)

    def add_axioms(self, solver) -> None:
        """Inject the injectivity axioms into *solver* if not already present.

        ``solver`` must be an :class:`oracle.laser.smt.solver.solver.Solver`
        (or any object whose ``.raw`` is a ``z3.Solver``).
        """
        sid = id(solver)
        if sid in self._axiom_injected:
            return
        self._axiom_injected.add(sid)
        solver.raw.add(_make_injectivity_256())
        solver.raw.add(_make_injectivity_512())

    def add_axioms_raw(self, z3_solver: z3.Solver) -> None:
        """Inject axioms directly into a raw ``z3.Solver`` instance."""
        sid = id(z3_solver)
        if sid in self._axiom_injected:
            return
        self._axiom_injected.add(sid)
        z3_solver.add(_make_injectivity_256())
        z3_solver.add(_make_injectivity_512())


# Module-level singleton — import this in vm.py
keccak_model = KeccakModel()
