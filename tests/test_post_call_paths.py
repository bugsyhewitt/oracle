"""Integration tests for post-call path coverage (POST_V01 Tier 1 Item 1).

These prove that paths no longer halt on the return-data / ext-code opcodes
that solc emits around external calls and access-control guards. Before the new
opcode handlers, exploration stopped at the first RETURNDATASIZE / EXTCODESIZE
and the SELFDESTRUCT downstream was never reached — these fixtures would have
produced ZERO findings. They now produce the reachable-selfdestruct finding.

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
# The fixtures must actually contain the opcodes under test (guards against a
# future solc change silently optimising them away).
# --------------------------------------------------------------------------- #
def test_returndata_fixture_emits_returndata_opcodes():
    d = Disassembly(_bc("returndata-after-call"))
    mnems = {i.mnemonic for i in d.instructions}
    assert "RETURNDATASIZE" in mnems
    assert "RETURNDATACOPY" in mnems
    assert "SELFDESTRUCT" in mnems


def test_extcodesize_fixture_emits_extcodesize():
    d = Disassembly(_bc("extcodesize-guard"))
    mnems = {i.mnemonic for i in d.instructions}
    assert "EXTCODESIZE" in mnems
    assert "SELFDESTRUCT" in mnems


# --------------------------------------------------------------------------- #
# The core property: exploration survives the post-call opcodes and reaches the
# downstream SELFDESTRUCT. v0.1 would have returned [] here.
# --------------------------------------------------------------------------- #
def test_path_survives_returndata_opcodes():
    findings = analyze(_bc("returndata-after-call"), ["selfdestruct"], max_depth=12)
    assert findings, "path should survive RETURNDATASIZE/RETURNDATACOPY"
    assert findings[0]["category"] == "reachable_selfdestruct"
    assert findings[0]["trace"]


def test_extcodesize_guard_bypass_is_found():
    findings = analyze(_bc("extcodesize-guard"), ["selfdestruct"], max_depth=12)
    assert findings, "extcodesize guard should be explorable and bypassable"
    assert findings[0]["category"] == "reachable_selfdestruct"
    assert findings[0]["trace"]


# --------------------------------------------------------------------------- #
# Real-Z3 confirmation.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_path_survives_returndata_opcodes_real_z3():
    findings = analyze(_bc("returndata-after-call"), ["selfdestruct"], max_depth=12)
    assert findings
    assert findings[0]["category"] == "reachable_selfdestruct"
    assert "trigger_input" in findings[0]


@pytest.mark.slow
def test_extcodesize_guard_bypass_real_z3():
    findings = analyze(_bc("extcodesize-guard"), ["selfdestruct"], max_depth=12)
    assert findings
    assert findings[0]["category"] == "reachable_selfdestruct"
    assert "trigger_input" in findings[0]
