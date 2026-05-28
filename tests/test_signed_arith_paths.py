"""Integration tests for signed-arithmetic path coverage (POST_V01 Tier 1 #3).

The concrete-value unit tests in `test_opcodes_arithmetic.py` prove each
arithmetic handler computes the right EVM-spec result. These tests prove the
complementary, end-to-end property the handlers actually exist *for*:
exploration no longer halts when a contract's reachable path runs through
signed arithmetic.

`signed-arith-guard.sol` gates a `SELFDESTRUCT` behind a chain of `int*`
operations that solc lowers to `SIGNEXTEND` (the int8 cast), `SDIV`, `SMOD`
and `SAR`. Before those handlers existed the VM stopped the path at the first
such opcode (treating it as unsupported), so the downstream `SELFDESTRUCT` was
unreachable and the detector returned ZERO findings. With the handlers in
place the path survives and the reachable destruct is discoverable.

Default (Z3-mocked) tests assert the finding shape and dispatch; `slow` tests
re-run against the real solver to confirm satisfiability + trigger input.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.disassembler import Disassembly

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


# --------------------------------------------------------------------------- #
# The fixture must actually contain the signed-arithmetic opcodes under test
# (guards against a future solc change silently optimising them away — without
# them the test would pass vacuously).
# --------------------------------------------------------------------------- #
def test_signed_arith_fixture_emits_signed_opcodes():
    d = Disassembly(_bc("signed-arith-guard"))
    mnems = {i.mnemonic for i in d.instructions}
    assert "SIGNEXTEND" in mnems  # int8 cast
    assert "SDIV" in mnems  # signed division
    assert "SMOD" in mnems  # signed modulo
    assert "SAR" in mnems  # arithmetic right shift
    assert "SELFDESTRUCT" in mnems  # the downstream sink


# --------------------------------------------------------------------------- #
# The core property: exploration survives the signed-arithmetic opcodes and
# reaches the downstream SELFDESTRUCT. A VM without these handlers would halt
# the path at the first SIGNEXTEND/SDIV/SMOD/SAR and return [] here.
# --------------------------------------------------------------------------- #
def test_path_survives_signed_arithmetic():
    findings = analyze(_bc("signed-arith-guard"), ["selfdestruct"], max_depth=16)
    assert findings, "path should survive SIGNEXTEND/SDIV/SMOD/SAR"
    assert findings[0]["category"] == "reachable_selfdestruct"
    assert findings[0]["trace"]


# --------------------------------------------------------------------------- #
# Real-Z3 confirmation: the signed guard is satisfiable and Z3 yields a
# concrete trigger input.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_path_survives_signed_arithmetic_real_z3():
    findings = analyze(_bc("signed-arith-guard"), ["selfdestruct"], max_depth=16)
    assert findings
    assert findings[0]["category"] == "reachable_selfdestruct"
    assert "trigger_input" in findings[0]
