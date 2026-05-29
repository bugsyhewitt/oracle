"""Tests for oracle's delegatecall-to-untrusted-callee detector (SWC-112).

`DELEGATECALL` runs the callee's code in *this* contract's storage and balance
context. If the target address is derived from untrusted input (a function
argument, i.e. calldata) an attacker can supply a malicious library and run
arbitrary code against the contract's own state — the canonical Parity multisig
wallet bug.

The discriminating signal is that the delegatecall *target operand* is derived
from calldata (attacker-controllable). A hard-coded / immutable library address
is a compile-time constant and is NOT attacker-controllable, so it must not be
flagged.

Two fixtures pin the behaviour:
  * delegatecall-vuln.sol — `forward(address target, ...)` delegatecalls into a
    calldata-supplied `target`. MUST be flagged.
  * delegatecall-safe.sol — delegatecalls into a hard-coded constant library
    address. MUST NOT be flagged (the DELEGATECALL opcode is still present, so
    this proves the detector keys on the untrusted target, not the opcode).

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm against the
real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, DelegatecallUntrustedDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=24):
    """Run only the delegatecall detector and return its raw candidates (before
    the Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = DelegatecallUntrustedDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_delegatecall_detector_is_registered():
    assert "delegatecall" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["delegatecall"] is DelegatecallUntrustedDetector


def test_delegatecall_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "delegatecall" in CHECK_CHOICES


def test_delegatecall_severity_is_high():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["delegatecall_untrusted_callee"] == "high"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the delegatecall away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_delegatecall():
    mnems = {i.mnemonic for i in Disassembly(_bc("delegatecall-vuln")).instructions}
    assert "DELEGATECALL" in mnems, "the vulnerable fixture must delegatecall"
    assert "CALLDATALOAD" in mnems, "the target must come from calldata"


def test_safe_fixture_emits_delegatecall():
    mnems = {i.mnemonic for i in Disassembly(_bc("delegatecall-safe")).instructions}
    assert "DELEGATECALL" in mnems, (
        "the safe fixture must still delegatecall (to a hard-coded target) so "
        "the test proves the detector keys on the untrusted target, not the op"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the untrusted-target delegatecall is
# detected for the vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_delegatecall_candidate():
    cands = _candidates("delegatecall-vuln")
    assert cands, "a calldata-supplied delegatecall target must produce a candidate"
    assert all(c["category"] == "delegatecall_untrusted_callee" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] == "DELEGATECALL" for c in cands)


def test_safe_produces_no_delegatecall_candidate():
    assert _candidates("delegatecall-safe") == [], (
        "a delegatecall to a hard-coded constant library address is not "
        "attacker-controllable and must not be flagged"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("delegatecall-vuln"), ["delegatecall"], max_depth=24)
    assert findings, "vulnerable contract should yield a delegatecall finding"
    assert findings[0]["category"] == "delegatecall_untrusted_callee"
    assert findings[0]["severity"] == "high"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("delegatecall-safe"), ["delegatecall"], max_depth=24)
    assert findings == [], "hard-coded-target delegatecall must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guard: a contract with no delegatecall at all (the
# access-control / tx-origin fixtures read CALLER/ORIGIN but never delegatecall
# to a calldata target) must not be flagged.
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_untrusted_delegatecall():
    findings = analyze(_bc("tx-origin-vuln"), ["delegatecall"], max_depth=20)
    assert findings == [], (
        "a contract that never delegatecalls to a calldata-derived target must "
        "not be flagged for SWC-112"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_delegatecall_surfaces_under_all_checks():
    findings = analyze(_bc("delegatecall-vuln"), ["all"], max_depth=24)
    cats = {f["category"] for f in findings}
    assert "delegatecall_untrusted_callee" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_delegatecall_has_report_title():
    from oracle.report import _TITLE

    assert "delegatecall_untrusted_callee" in _TITLE
    assert "Delegatecall" in _TITLE["delegatecall_untrusted_callee"]
    assert "SWC-112" in _TITLE["delegatecall_untrusted_callee"]


def test_delegatecall_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("delegatecall-vuln"), ["delegatecall"], max_depth=24)
    md = format_h1md(findings, "delegatecall-vuln.sol")
    assert "Delegatecall to Untrusted Callee" in md


def test_delegatecall_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("delegatecall-vuln"), ["delegatecall"], max_depth=24)
    doc = json.loads(format_sarif(findings, "delegatecall-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "delegatecall_untrusted_callee" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "delegatecall_untrusted_callee" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("delegatecall-vuln"), (
        "real-engine walk must find the untrusted-callee delegatecall"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("delegatecall-safe") == []
