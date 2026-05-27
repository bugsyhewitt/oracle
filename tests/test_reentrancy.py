"""Tests for oracle's reentrancy detector (POST_V01 Rank 2).

The detector flags a check-effects-interactions (CEI) violation: a value-
forwarding external CALL/CALLCODE/DELEGATECALL followed, on the same path, by an
SSTORE to a storage slot that was already SLOADed *before* the call. That is the
classic withdraw-before-update bug (the DAO pattern).

Two fixtures pin the behaviour:
  * reentrancy_vuln.sol — SLOAD balance, CALL (forwards ether), SSTORE balance.
    MUST be flagged.
  * reentrancy_safe.sol — SLOAD balance, SSTORE balance, CALL. Correct CEI
    ordering. MUST NOT be flagged.

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm against the
real engine that the *candidate* is generated for the vulnerable contract and
not for the safe one (detector-level, independent of the storage-model
reachability conservatism that the mocked boundary stands in for).
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, ReentrancyDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=18):
    """Run only the reentrancy detector and return its raw candidate findings
    (before the Z3 reachability boundary). This isolates the detector logic
    from the solver/storage-model conservatism."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = ReentrancyDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_reentrancy_detector_is_registered():
    assert "reentrancy" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["reentrancy"] is ReentrancyDetector


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the CALL/SSTORE away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_call_and_sstore():
    mnems = {i.mnemonic for i in Disassembly(_bc("reentrancy_vuln")).instructions}
    assert "CALL" in mnems
    assert "SLOAD" in mnems
    assert "SSTORE" in mnems


def test_safe_fixture_emits_call_and_sstore():
    mnems = {i.mnemonic for i in Disassembly(_bc("reentrancy_safe")).instructions}
    assert "CALL" in mnems
    assert "SLOAD" in mnems
    assert "SSTORE" in mnems


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the CEI violation is detected for the
# vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_reentrancy_candidate():
    cands = _candidates("reentrancy_vuln")
    assert cands, "withdraw-before-update must produce a reentrancy candidate"
    assert all(c["category"] == "reentrancy" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] == "SSTORE" for c in cands)


def test_safe_produces_no_reentrancy_candidate():
    assert _candidates("reentrancy_safe") == [], (
        "correct CEI ordering (SSTORE before CALL) must not be flagged"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary,
# matching the rest of the suite): vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("reentrancy_vuln"), ["reentrancy"], max_depth=18)
    assert findings, "vulnerable contract should yield a reentrancy finding"
    assert findings[0]["category"] == "reentrancy"
    assert findings[0]["severity"] == "high"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("reentrancy_safe"), ["reentrancy"], max_depth=18)
    assert findings == [], "safe (correct CEI) contract must not be flagged"


def test_reentrancy_not_triggered_for_unrelated_contract():
    # a contract with a CALL but no pre-call-SLOAD'd slot written after it
    # should not be flagged (no false positive on plain external calls).
    findings = analyze(_bc("returndata-after-call"), ["reentrancy"], max_depth=12)
    assert findings == []


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# (Detector candidates do not invoke Z3; this guards the full bytecode walk.)
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("reentrancy_vuln"), "real-engine walk must find the CEI bug"


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("reentrancy_safe") == []
