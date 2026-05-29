"""Tests for oracle's arbitrary-jump detector (SWC-127, "Arbitrary Jump with
Function Type Variable").

A `function` type variable holds an internal jump destination (a code offset) as
an ordinary 256-bit value. If that value is influenced by untrusted input — read
from calldata, overwritten via inline assembly, or loaded from an
attacker-writable slot — then invoking it lets an attacker redirect EVM control
flow to any JUMPDEST in the bytecode, bypassing access checks or re-entering
privileged code. That is SWC-127.

The discriminating signal is that the JUMP/JUMPI *destination operand* is derived
from calldata (attacker-controllable). A jump to a compile-time-constant
destination is ordinary, compiler-generated control flow and must NOT be flagged.

Two fixtures pin the behaviour:
  * arbitrary-jump-vuln.sol — `run(uint256 ptr)` overwrites a function pointer
    with a calldata-derived value and invokes it, lowering to a JUMP whose
    destination comes from calldata. MUST be flagged.
  * arbitrary-jump-safe.sol — `sum(uint256 n)` loops/branches; the compiler emits
    JUMP/JUMPI opcodes but every destination is a fixed label, never calldata.
    MUST NOT be flagged (the JUMP/JUMPI opcodes are still present, so this proves
    the detector keys on the calldata-derived target, not the opcode).

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm against the
real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import ArbitraryJumpDetector, DETECTOR_REGISTRY
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=40):
    """Run only the arbitrary-jump detector and return its raw candidates (before
    the Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = ArbitraryJumpDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_arbitrary_jump_detector_is_registered():
    assert "arbitrary-jump" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["arbitrary-jump"] is ArbitraryJumpDetector


def test_arbitrary_jump_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "arbitrary-jump" in CHECK_CHOICES


def test_arbitrary_jump_severity_is_high():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["arbitrary_jump"] == "high"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the jump away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_jump_from_calldata():
    mnems = {i.mnemonic for i in Disassembly(_bc("arbitrary-jump-vuln")).instructions}
    assert "JUMP" in mnems, "the vulnerable fixture must JUMP"
    assert "CALLDATALOAD" in mnems, "the jump target must come from calldata"


def test_safe_fixture_emits_jump():
    mnems = {i.mnemonic for i in Disassembly(_bc("arbitrary-jump-safe")).instructions}
    assert "JUMP" in mnems or "JUMPI" in mnems, (
        "the safe fixture must still emit JUMP/JUMPI (to fixed labels) so the "
        "test proves the detector keys on the calldata-derived target, not the op"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the calldata-derived jump is detected for
# the vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_arbitrary_jump_candidate():
    cands = _candidates("arbitrary-jump-vuln")
    assert cands, "a calldata-supplied jump target must produce a candidate"
    assert all(c["category"] == "arbitrary_jump" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] in ("JUMP", "JUMPI") for c in cands)


def test_safe_produces_no_arbitrary_jump_candidate():
    assert _candidates("arbitrary-jump-safe") == [], (
        "a contract whose every jump destination is a compile-time constant is "
        "not attacker-steerable and must not be flagged"
    )


def test_vuln_candidate_is_deduped_per_pc():
    # The same jump site reached via multiple paths must be reported once.
    cands = _candidates("arbitrary-jump-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each jump site should be flagged at most once"


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("arbitrary-jump-vuln"), ["arbitrary-jump"], max_depth=40)
    assert findings, "vulnerable contract should yield an arbitrary-jump finding"
    assert findings[0]["category"] == "arbitrary_jump"
    assert findings[0]["severity"] == "high"
    assert findings[0]["op"] in ("JUMP", "JUMPI")
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("arbitrary-jump-safe"), ["arbitrary-jump"], max_depth=40)
    assert findings == [], "constant-target jumps must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guard: a contract whose jumps are all compiler-controlled (the
# delegatecall fixture jumps for dispatch/loops but never to a calldata target)
# must not be flagged for SWC-127.
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_calldata_jump():
    findings = analyze(_bc("delegatecall-vuln"), ["arbitrary-jump"], max_depth=24)
    assert findings == [], (
        "a contract whose jumps are all compiler-determined must not be flagged "
        "for SWC-127, even if it has another vulnerability class"
    )


# --------------------------------------------------------------------------- #
# Cross-detector separation: the delegatecall (SWC-112) detector keys on the
# delegatecall *target*, not on a jump destination, so it must not claim the
# arbitrary-jump fixture (which has no delegatecall).
# --------------------------------------------------------------------------- #
def test_delegatecall_detector_does_not_claim_arbitrary_jump():
    findings = analyze(_bc("arbitrary-jump-vuln"), ["delegatecall"], max_depth=40)
    assert findings == [], (
        "the arbitrary-jump fixture makes no delegatecall, so SWC-112 must stay "
        "silent — the two detectors key on different sinks"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_arbitrary_jump_surfaces_under_all_checks():
    findings = analyze(_bc("arbitrary-jump-vuln"), ["all"], max_depth=40)
    cats = {f["category"] for f in findings}
    assert "arbitrary_jump" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_arbitrary_jump_has_report_title():
    from oracle.report import _TITLE

    assert "arbitrary_jump" in _TITLE
    assert "Arbitrary Jump" in _TITLE["arbitrary_jump"]
    assert "SWC-127" in _TITLE["arbitrary_jump"]


def test_arbitrary_jump_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("arbitrary-jump-vuln"), ["arbitrary-jump"], max_depth=40)
    md = format_h1md(findings, "arbitrary-jump-vuln.sol")
    assert "Arbitrary Jump with Function Type Variable" in md


def test_arbitrary_jump_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("arbitrary-jump-vuln"), ["arbitrary-jump"], max_depth=40)
    doc = json.loads(format_sarif(findings, "arbitrary-jump-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "arbitrary_jump" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "arbitrary_jump" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("arbitrary-jump-vuln"), (
        "real-engine walk must find the calldata-derived JUMP"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("arbitrary-jump-safe") == []
