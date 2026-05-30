"""Tests for oracle's cross-function reentrancy detector (SWC-107 variant).

Distinct from the same-function CEI detector (`reentrancy`): this one flags
the case where the SLOADed slot's writer lives on a SIBLING function (no
external CALL on the writer's path), so a reentered call into the sibling
mutates state the in-flight caller already read.

Two fixtures pin the behaviour:
  * reentrancy_cross_vuln.sol — withdraw() reads `balance` + CALL, transfer()
    writes `balance`. MUST be flagged by reentrancy-cross-function and MUST
    NOT be flagged by the base reentrancy detector (the calling function has
    no post-CALL SSTORE to the slot).
  * reentrancy_cross_safe.sol — same two-function shape, but withdraw()
    zeroes `balance` BEFORE the CALL (the calling function fixes its own
    CEI). MUST NOT be flagged by reentrancy-cross-function (the call path
    falls into the base same-function pattern and is suppressed here to
    avoid double-reporting).

The existing single-function fixtures (`reentrancy_vuln`, `reentrancy_safe`)
also serve as negative controls: neither has a sibling no-call writer, so
the cross-function detector must stay silent on both.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    CrossFunctionReentrancyDetector,
    ReentrancyDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, detector_cls=CrossFunctionReentrancyDetector, max_depth=18):
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = detector_cls()
    vm.register(det)
    vm.run()
    det.finalize(vm)
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the new detector is wired into the CLI/analysis registry and
# does not collide with the existing single-function reentrancy detector.
# --------------------------------------------------------------------------- #
def test_cross_function_reentrancy_detector_is_registered():
    assert "reentrancy-cross-function" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["reentrancy-cross-function"] is CrossFunctionReentrancyDetector


def test_base_reentrancy_detector_still_registered():
    assert "reentrancy" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["reentrancy"] is ReentrancyDetector


def test_categories_are_distinct():
    assert CrossFunctionReentrancyDetector.category == "reentrancy_cross_function"
    assert ReentrancyDetector.category == "reentrancy"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test.
# --------------------------------------------------------------------------- #
def test_cross_vuln_fixture_has_call_sload_sstore():
    mnems = {i.mnemonic for i in Disassembly(_bc("reentrancy_cross_vuln")).instructions}
    assert "CALL" in mnems
    assert "SLOAD" in mnems
    assert "SSTORE" in mnems


def test_cross_safe_fixture_has_call_sload_sstore():
    mnems = {i.mnemonic for i in Disassembly(_bc("reentrancy_cross_safe")).instructions}
    assert "CALL" in mnems
    assert "SLOAD" in mnems
    assert "SSTORE" in mnems


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the cross-function bug is detected on
# the vuln fixture and not on any of the negative controls.
# --------------------------------------------------------------------------- #
def test_cross_vuln_produces_candidate():
    cands = _candidates("reentrancy_cross_vuln")
    assert cands, "cross-function reentrancy must produce a candidate"
    assert all(c["category"] == "reentrancy_cross_function" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] in ("CALL", "CALLCODE", "DELEGATECALL") for c in cands)


def test_cross_safe_produces_no_candidate():
    # withdraw() fixes its own CEI; the calling-path pattern collapses to the
    # base ReentrancyDetector's territory and is suppressed here.
    assert _candidates("reentrancy_cross_safe") == []


def test_base_reentrancy_fixtures_emit_no_cross_function_candidate():
    # the single-function vuln/safe fixtures have only one external-call-
    # carrying function; with no sibling writer the cross-function detector
    # must stay silent on both.
    assert _candidates("reentrancy_vuln") == []
    assert _candidates("reentrancy_safe") == []


# --------------------------------------------------------------------------- #
# Suppression: on the cross-function vuln, the base ReentrancyDetector must
# NOT fire (the SSTORE-after-CALL on the calling path is absent). On the
# cross-function safe, the base detector also must not fire (CEI is correct).
# This guarantees no double-reporting between the two reentrancy categories.
# --------------------------------------------------------------------------- #
def test_base_detector_silent_on_cross_function_vuln():
    cands = _candidates("reentrancy_cross_vuln", detector_cls=ReentrancyDetector)
    assert cands == [], (
        "base same-function CEI detector must not fire on the cross-function "
        "fixture — the calling function never SSTOREs after the CALL"
    )


def test_base_detector_silent_on_cross_function_safe():
    cands = _candidates("reentrancy_cross_safe", detector_cls=ReentrancyDetector)
    assert cands == []


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_cross_vuln_is_flagged_end_to_end():
    findings = analyze(
        _bc("reentrancy_cross_vuln"), ["reentrancy-cross-function"], max_depth=18
    )
    assert findings, "vulnerable contract should yield a cross-function finding"
    assert findings[0]["category"] == "reentrancy_cross_function"
    assert findings[0]["severity"] == "high"
    assert findings[0]["trace"]


def test_cross_safe_is_not_flagged_end_to_end():
    findings = analyze(
        _bc("reentrancy_cross_safe"), ["reentrancy-cross-function"], max_depth=18
    )
    assert findings == []


def test_running_all_checks_includes_cross_function():
    # `--check all` must dispatch the new detector. The cross-function vuln
    # fixture is the highest-signal smoke test: at least one cross-function
    # finding must appear in the aggregate output.
    findings = analyze(_bc("reentrancy_cross_vuln"), ["all"], max_depth=18)
    cats = {f["category"] for f in findings}
    assert "reentrancy_cross_function" in cats


# --------------------------------------------------------------------------- #
# slow: real-engine re-confirmation of the detector-level discrimination.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_cross_vuln_candidate_real_engine():
    assert _candidates("reentrancy_cross_vuln"), (
        "real-engine walk must find the cross-function reentrancy gadget"
    )


@pytest.mark.slow
def test_cross_safe_candidate_real_engine():
    assert _candidates("reentrancy_cross_safe") == []
