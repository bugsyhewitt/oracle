"""Tests for oracle's unprotected-selfdestruct detector (SWC-106, "Unprotected
SELFDESTRUCT Instruction").

A contract that reaches a `selfdestruct` from a public function with NO
access-control guard lets any address destroy it and sweep its entire balance —
the canonical SWC-106 bug (the Parity wallet-library `kill()` incident). The
discriminating signal is a `SELFDESTRUCT` reached on a path whose accumulated
constraints never branch on the caller's identity: a genuine
`require(msg.sender == owner)` guard compiles to a comparison on the symbolic
`caller` leaf feeding a JUMPI, so a guarded path carries `caller` in a
constraint; an unguarded path leaves `caller` entirely free.

Two fixtures pin the behaviour:
  * unprotected-selfdestruct-vuln.sol — public `kill()` runs
    `selfdestruct(target)` with no owner check. The SELFDESTRUCT is reached with
    no caller-binding constraint. MUST be flagged.
  * unprotected-selfdestruct-safe.sol — `kill()` runs `selfdestruct(target)`
    only after a `require(msg.sender == owner)` guard. The SELFDESTRUCT opcode is
    still present (so the test proves the detector keys on the *missing caller
    guard*, not the opcode), but the path branches on `caller`. MUST NOT be
    flagged.

The detector is deliberately distinct from the two neighbouring
SELFDESTRUCT-aware detectors:
  * `reachable_selfdestruct` fires on ANY reachable SELFDESTRUCT — including a
    correctly owner-gated one — so it flags BOTH fixtures; SWC-106 is the
    narrower "can an *unauthorised* caller destroy it?" question and stays silent
    on the guarded fixture.
  * `access_control_escalation` also flags the unguarded case but bundles it into
    a broad escalation category; SWC-106 reports under its own
    `unprotected_selfdestruct` category / SWC-106 title for clean per-bug-class
    triage (the same carve-out precedent as SWC-105 ether-withdrawal).

Like the rest of oracle's suite, the default run asserts the detector's
candidate/finding behaviour; the `slow` tests re-confirm against the real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    UnprotectedSelfdestructDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Depth at which the SELFDESTRUCT is reached on a path.
DEPTH = 30


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=DEPTH):
    """Run only the unprotected-selfdestruct detector and return its raw
    candidates (before the Z3 reachability boundary), isolating detector logic
    from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = UnprotectedSelfdestructDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_unprotected_selfdestruct_detector_is_registered():
    assert "unprotected-selfdestruct" in DETECTOR_REGISTRY
    assert (
        DETECTOR_REGISTRY["unprotected-selfdestruct"]
        is UnprotectedSelfdestructDetector
    )


def test_unprotected_selfdestruct_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "unprotected-selfdestruct" in CHECK_CHOICES


def test_unprotected_selfdestruct_severity_is_high():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["unprotected_selfdestruct"] == "high"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the SELFDESTRUCT / guard away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_selfdestruct():
    mnems = {
        i.mnemonic
        for i in Disassembly(_bc("unprotected-selfdestruct-vuln")).instructions
    }
    assert "SELFDESTRUCT" in mnems, "the vulnerable fixture must self-destruct"


def test_safe_fixture_emits_selfdestruct_and_branch():
    mnems = {
        i.mnemonic
        for i in Disassembly(_bc("unprotected-selfdestruct-safe")).instructions
    }
    assert "SELFDESTRUCT" in mnems, (
        "the safe fixture must still self-destruct so the test proves the "
        "detector keys on the missing caller guard, not the opcode"
    )
    assert "JUMPI" in mnems, "the safe fixture must branch (the require guard)"
    assert "CALLER" in mnems, "the safe fixture must read msg.sender for its guard"


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): an unguarded SELFDESTRUCT is detected for
# the vulnerable contract and NOT for the caller-guarded one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("unprotected-selfdestruct-vuln")
    assert cands, "an unguarded selfdestruct must produce a candidate"
    assert all(c["category"] == "unprotected_selfdestruct" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] == "SELFDESTRUCT" for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("unprotected-selfdestruct-safe") == [], (
        "a selfdestruct gated on require(msg.sender == owner) must not be flagged"
    )


def test_vuln_flags_each_site_once():
    # the per-detector flagged-pc set must dedupe a SELFDESTRUCT site reached on
    # many paths down to a single finding per pc.
    cands = _candidates("unprotected-selfdestruct-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each unprotected selfdestruct reported once"


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(
        _bc("unprotected-selfdestruct-vuln"),
        ["unprotected-selfdestruct"],
        max_depth=DEPTH,
    )
    assert findings, "vulnerable contract should yield an unprotected-selfdestruct finding"
    assert findings[0]["category"] == "unprotected_selfdestruct"
    assert findings[0]["severity"] == "high"
    assert findings[0]["op"] == "SELFDESTRUCT"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(
        _bc("unprotected-selfdestruct-safe"),
        ["unprotected-selfdestruct"],
        max_depth=DEPTH,
    )
    assert findings == [], "a caller-guarded selfdestruct must not be flagged"


# --------------------------------------------------------------------------- #
# The defining distinction from the broader reachable-selfdestruct detector:
# reachable_selfdestruct fires on a CORRECTLY GUARDED selfdestruct too (it only
# asks "is it reachable?"); the SWC-106 detector stays silent on the guarded one.
# This is precisely why SWC-106 is worth carving out as its own detector.
# --------------------------------------------------------------------------- #
def test_distinct_from_reachable_selfdestruct_on_safe_fixture():
    reachable = analyze(
        _bc("unprotected-selfdestruct-safe"), ["selfdestruct"], max_depth=DEPTH
    )
    unprotected = analyze(
        _bc("unprotected-selfdestruct-safe"),
        ["unprotected-selfdestruct"],
        max_depth=DEPTH,
    )
    assert any(f["category"] == "reachable_selfdestruct" for f in reachable), (
        "the broad detector flags a reachable selfdestruct even when guarded"
    )
    assert unprotected == [], (
        "the SWC-106 detector keys on the MISSING caller guard, so a guarded "
        "selfdestruct is not an SWC-106 finding"
    )


# --------------------------------------------------------------------------- #
# False-positive guards. SWC-106 is distinct from neighbouring detectors:
#   * a contract that never self-destructs must be clean;
#   * a selfdestruct gated on require(msg.sender == owner) is access-controlled,
#     not SWC-106 (covered by the safe fixture and the access-control-safe
#     contract, which never destructs at all).
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_selfdestruct():
    findings = analyze(
        _bc("access-control-safe"),
        ["unprotected-selfdestruct"],
        max_depth=20,
    )
    assert findings == [], (
        "a contract that never self-destructs must not be flagged for SWC-106"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_unprotected_selfdestruct_surfaces_under_all_checks():
    findings = analyze(
        _bc("unprotected-selfdestruct-vuln"), ["all"], max_depth=DEPTH
    )
    cats = {f["category"] for f in findings}
    assert "unprotected_selfdestruct" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_unprotected_selfdestruct_has_report_title():
    from oracle.report import _TITLE

    assert "unprotected_selfdestruct" in _TITLE
    assert "Unprotected SELFDESTRUCT" in _TITLE["unprotected_selfdestruct"]
    assert "SWC-106" in _TITLE["unprotected_selfdestruct"]


def test_unprotected_selfdestruct_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(
        _bc("unprotected-selfdestruct-vuln"),
        ["unprotected-selfdestruct"],
        max_depth=DEPTH,
    )
    md = format_h1md(findings, "unprotected-selfdestruct-vuln.sol")
    assert "Unprotected SELFDESTRUCT" in md


def test_unprotected_selfdestruct_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(
        _bc("unprotected-selfdestruct-vuln"),
        ["unprotected-selfdestruct"],
        max_depth=DEPTH,
    )
    doc = json.loads(format_sarif(findings, "unprotected-selfdestruct-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "unprotected_selfdestruct" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "unprotected_selfdestruct" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("unprotected-selfdestruct-vuln"), (
        "real-engine walk must find the unguarded selfdestruct"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("unprotected-selfdestruct-safe") == []
