"""Tests for oracle's unchecked-call-return detector (SWC-104).

Every EVM call opcode (`CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`) does
NOT revert when the callee reverts — it pushes a boolean success word and
execution continues. A low-level `addr.call(...)` / `addr.send(...)` whose
result is *discarded* lets a failed external call pass silently; the contract
proceeds as though it succeeded (SWC-104, the canonical "unchecked send" bug).

The discriminating signal is that the call's success word reaches a `POP`
WITHOUT ever having been branched on (it appears in no path constraint). A
`require(ok)` / `if (!ok)` guarded call routes the word through ISZERO/JUMPI, so
the call-result symbol shows up in a path constraint — even though Solidity also
POPs the duplicated original during stack cleanup — and must NOT be flagged.

Two fixtures pin the behaviour:
  * unchecked-call-vuln.sol — `to.call{value: 1}("")` discards the success
    result. MUST be flagged.
  * unchecked-call-safe.sol — `(bool ok, ) = to.call(...); require(ok)`. The
    CALL opcode is still present (so the test proves the detector keys on the
    *discarded, unbranched* word, not the opcode). MUST NOT be flagged.

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm against the
real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, UncheckedCallReturnDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=24):
    """Run only the unchecked-call detector and return its raw candidates
    (before the Z3 reachability boundary), isolating detector logic from the
    solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = UncheckedCallReturnDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_unchecked_call_detector_is_registered():
    assert "unchecked-call" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["unchecked-call"] is UncheckedCallReturnDetector


def test_unchecked_call_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "unchecked-call" in CHECK_CHOICES


def test_unchecked_call_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["unchecked_call_return"] == "medium"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the call away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_call_and_pop():
    mnems = {i.mnemonic for i in Disassembly(_bc("unchecked-call-vuln")).instructions}
    assert "CALL" in mnems, "the vulnerable fixture must make a low-level call"
    assert "POP" in mnems, "the discarded success word must be POPped"


def test_safe_fixture_emits_call():
    mnems = {i.mnemonic for i in Disassembly(_bc("unchecked-call-safe")).instructions}
    assert "CALL" in mnems, (
        "the safe fixture must still CALL (with the result checked) so the test "
        "proves the detector keys on the unbranched, discarded word, not the op"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the discarded, unbranched success word is
# detected for the vulnerable contract and NOT for the safe (require-guarded) one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("unchecked-call-vuln")
    assert cands, "a discarded, unchecked call result must produce a candidate"
    assert all(c["category"] == "unchecked_call_return" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)
    assert all(c["op"] == "POP" for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("unchecked-call-safe") == [], (
        "a low-level call whose success is require()-checked branches on the "
        "result, so it must not be flagged as unchecked"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("unchecked-call-vuln"), ["unchecked-call"], max_depth=24)
    assert findings, "vulnerable contract should yield an unchecked-call finding"
    assert findings[0]["category"] == "unchecked_call_return"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("unchecked-call-safe"), ["unchecked-call"], max_depth=24)
    assert findings == [], "require()-checked call must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guard: a contract with no low-level call at all (the tx-origin
# fixture reads ORIGIN but never makes a low-level call) must not be flagged.
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_call():
    findings = analyze(_bc("tx-origin-vuln"), ["unchecked-call"], max_depth=20)
    assert findings == [], (
        "a contract that never makes a low-level call must not be flagged "
        "for SWC-104"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_unchecked_call_surfaces_under_all_checks():
    findings = analyze(_bc("unchecked-call-vuln"), ["all"], max_depth=24)
    cats = {f["category"] for f in findings}
    assert "unchecked_call_return" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_unchecked_call_has_report_title():
    from oracle.report import _TITLE

    assert "unchecked_call_return" in _TITLE
    assert "Unchecked Call Return" in _TITLE["unchecked_call_return"]
    assert "SWC-104" in _TITLE["unchecked_call_return"]


def test_unchecked_call_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("unchecked-call-vuln"), ["unchecked-call"], max_depth=24)
    md = format_h1md(findings, "unchecked-call-vuln.sol")
    assert "Unchecked Call Return Value" in md


def test_unchecked_call_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("unchecked-call-vuln"), ["unchecked-call"], max_depth=24)
    doc = json.loads(format_sarif(findings, "unchecked-call-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "unchecked_call_return" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "unchecked_call_return" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("unchecked-call-vuln"), (
        "real-engine walk must find the discarded, unchecked call result"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("unchecked-call-safe") == []
