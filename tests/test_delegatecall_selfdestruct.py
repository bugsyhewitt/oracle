"""Tests for oracle's SELFDESTRUCT-via-untrusted-delegatecall detector
(SWC-112 + SWC-106 composition).

A contract that (a) delegatecalls to an attacker-controllable target AND
(b) has a reachable SELFDESTRUCT on any execution path is exploitable: an
attacker deploys a malicious library that calls `selfdestruct(attacker)`,
supplies its address to the untrusted delegatecall, and the host contract is
destroyed and drained in one transaction — because DELEGATECALL runs the
callee's code in THIS contract's context.

Detection is a cross-path composition signal: oracle explores ALL dispatch
paths. If any path has an untrusted delegatecall AND any path has a reachable
SELFDESTRUCT, the contract has both necessary components. This mirrors
CrossFunctionReentrancyDetector's `finalize()` architecture.

Two fixtures pin the behaviour:
  * delegatecall-selfdestruct-vuln.sol — has `forward(address target, ...)`
    (calldata-supplied target delegatecall) AND a `kill()` function that calls
    SELFDESTRUCT. MUST be flagged.
  * delegatecall-selfdestruct-safe.sol — delegatecalls into a hard-coded
    constant library address (NOT attacker-controllable) AND has a `kill()`
    with SELFDESTRUCT. MUST NOT be flagged (no untrusted delegatecall signal).
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, DelegatecallSelfdestructDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=24):
    """Run only the delegatecall-selfdestruct detector and return its findings
    (after finalize), isolating detector logic from the Z3 solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = DelegatecallSelfdestructDetector()
    vm.register(det)
    vm.run()
    det.finalize(vm)
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_delegatecall_selfdestruct_detector_is_registered():
    assert "delegatecall-selfdestruct" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["delegatecall-selfdestruct"] is DelegatecallSelfdestructDetector


def test_delegatecall_selfdestruct_exposed_on_cli_choices():
    from oracle.cli import CHECK_CHOICES

    assert "delegatecall-selfdestruct" in CHECK_CHOICES


def test_delegatecall_selfdestruct_severity_is_high():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["delegatecall_selfdestruct"] == "high"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the opcodes away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_delegatecall():
    mnems = {i.mnemonic for i in Disassembly(_bc("delegatecall-selfdestruct-vuln")).instructions}
    assert "DELEGATECALL" in mnems, "the vulnerable fixture must delegatecall"
    assert "CALLDATALOAD" in mnems, "the delegatecall target must come from calldata"


def test_vuln_fixture_emits_selfdestruct():
    mnems = {i.mnemonic for i in Disassembly(_bc("delegatecall-selfdestruct-vuln")).instructions}
    assert "SELFDESTRUCT" in mnems, "the vulnerable fixture must have a SELFDESTRUCT"


def test_safe_fixture_emits_delegatecall():
    mnems = {i.mnemonic for i in Disassembly(_bc("delegatecall-selfdestruct-safe")).instructions}
    assert "DELEGATECALL" in mnems, (
        "the safe fixture must still delegatecall (to a hard-coded target) so "
        "the test proves the detector keys on the untrusted target"
    )


def test_safe_fixture_emits_selfdestruct():
    mnems = {i.mnemonic for i in Disassembly(_bc("delegatecall-selfdestruct-safe")).instructions}
    assert "SELFDESTRUCT" in mnems, (
        "the safe fixture must still have a SELFDESTRUCT so the test proves the "
        "detector requires the delegatecall co-signal, not just the SELFDESTRUCT"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the composition is detected for the
# vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_delegatecall_selfdestruct_candidate():
    cands = _candidates("delegatecall-selfdestruct-vuln")
    assert cands, (
        "a contract with a calldata-supplied delegatecall AND a reachable "
        "SELFDESTRUCT must produce a finding"
    )
    assert all(c["category"] == "delegatecall_selfdestruct" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] == "SELFDESTRUCT" for c in cands)


def test_safe_produces_no_delegatecall_selfdestruct_candidate():
    assert _candidates("delegatecall-selfdestruct-safe") == [], (
        "a contract with a hard-coded-target delegatecall and a SELFDESTRUCT "
        "must NOT be flagged — the delegatecall target is not attacker-controllable"
    )


def test_vuln_finding_count_is_one_per_selfdestruct_pc():
    """Each distinct SELFDESTRUCT program counter is reported exactly once."""
    cands = _candidates("delegatecall-selfdestruct-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each SELFDESTRUCT pc must be reported once"


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("delegatecall-selfdestruct-vuln"), ["delegatecall-selfdestruct"], max_depth=24)
    assert findings, "vulnerable contract should yield a delegatecall_selfdestruct finding"
    assert findings[0]["category"] == "delegatecall_selfdestruct"
    assert findings[0]["severity"] == "high"


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("delegatecall-selfdestruct-safe"), ["delegatecall-selfdestruct"], max_depth=24)
    assert findings == [], (
        "hard-coded-target delegatecall + SELFDESTRUCT must not be flagged for "
        "delegatecall_selfdestruct"
    )


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that have only one of the two components
# must not be flagged.
# --------------------------------------------------------------------------- #
def test_no_false_positive_delegatecall_without_selfdestruct():
    """A contract with an untrusted delegatecall but no SELFDESTRUCT is
    flagged by DelegatecallUntrustedDetector but NOT by this detector."""
    findings = analyze(_bc("delegatecall-vuln"), ["delegatecall-selfdestruct"], max_depth=24)
    assert findings == [], (
        "a contract with an untrusted delegatecall but no SELFDESTRUCT must not "
        "be flagged for delegatecall_selfdestruct"
    )


def test_no_false_positive_selfdestruct_without_delegatecall():
    """A contract with a reachable SELFDESTRUCT but no untrusted delegatecall
    must not be flagged for this composition category."""
    findings = analyze(_bc("reachable-selfdestruct"), ["delegatecall-selfdestruct"], max_depth=24)
    assert findings == [], (
        "a contract with a reachable SELFDESTRUCT but no untrusted delegatecall "
        "must not be flagged for delegatecall_selfdestruct"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_delegatecall_selfdestruct_surfaces_under_all_checks():
    findings = analyze(_bc("delegatecall-selfdestruct-vuln"), ["all"], max_depth=24)
    cats = {f["category"] for f in findings}
    assert "delegatecall_selfdestruct" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_delegatecall_selfdestruct_has_report_title():
    from oracle.report import _TITLE

    assert "delegatecall_selfdestruct" in _TITLE
    assert "SELFDESTRUCT" in _TITLE["delegatecall_selfdestruct"]
    assert "SWC-112" in _TITLE["delegatecall_selfdestruct"]


def test_delegatecall_selfdestruct_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("delegatecall-selfdestruct-vuln"), ["delegatecall-selfdestruct"], max_depth=24)
    md = format_h1md(findings, "delegatecall-selfdestruct-vuln.sol")
    assert "SELFDESTRUCT reachable via Untrusted Delegatecall" in md


def test_delegatecall_selfdestruct_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("delegatecall-selfdestruct-vuln"), ["delegatecall-selfdestruct"], max_depth=24)
    doc = json.loads(format_sarif(findings, "delegatecall-selfdestruct-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "delegatecall_selfdestruct" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "delegatecall_selfdestruct" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("delegatecall-selfdestruct-vuln"), (
        "real-engine walk must find the composition finding"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("delegatecall-selfdestruct-safe") == []
