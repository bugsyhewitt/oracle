"""Tests for oracle's integer-underflow detector (SWC-101, "Integer Overflow
and Underflow" — the underflow half).

EVM arithmetic is modular over 256 bits with no native bounds checking, so
`a - b` where `b > a` does not error — it wraps to `2**256 - (b - a)`, a near-
maximum value. A `balances[msg.sender] -= amount` that underflows silently mints
the caller an astronomical balance and drains the contract (the batchOverflow /
underflowed-accounting incident family). This detector is the mirror of the
ADD/MUL `IntegerOverflowDetector`: it records a candidate on a SUB whose operands
involve symbolic program data, carrying the underflow condition `b > a` as an
`extra_constraint`, and the analysis driver asks Z3 whether the path constraints
AND that condition are jointly satisfiable — only a genuinely reachable underflow
becomes a finding.

The detector deliberately screens out solc's ABI/memory *plumbing* subtractions
(the `calldatasize - 4` dispatcher length check and free-memory-pointer math over
oracle's coarse `mem_*` symbols), which fire on every contract and are not
program-data arithmetic. The remaining filter is Z3 reachability: a guarded
subtraction (`require(b <= a)`) is proved unsatisfiable and dropped.

Two fixtures pin the behaviour:
  * integer-underflow-vuln.sol — `withdraw(uint256)` does `balance - amount` in an
    `unchecked` block. `amount` can exceed the (uninitialised) balance, so the
    subtraction underflows; the underflow condition is satisfiable. MUST be
    flagged.
  * integer-underflow-safe.sol — `safeSub(a, b)` does `a - b` in an `unchecked`
    block but guards it with `require(b <= a)`. The SUB opcode is still present
    (so the test proves the detector keys on the underflow being *reachable*, not
    on the opcode), but the guard makes `b > a` unsatisfiable, so under the real
    solver it MUST NOT be flagged.

Like the rest of oracle's suite, the default run asserts the detector's
candidate behaviour and the vulnerable end-to-end finding (Z3 is mocked to treat
every candidate as satisfiable); the `slow` tests re-confirm the
satisfiable/unsatisfiable discrimination against the real Z3 solver — which is
the only place the safe fixture's guard can actually be proved to hold.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    IntegerUnderflowDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

DEPTH = 12


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=DEPTH):
    """Run only the underflow detector and return its raw candidates (before the
    Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = IntegerUnderflowDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_underflow_detector_is_registered():
    assert "underflow" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["underflow"] is IntegerUnderflowDetector


def test_underflow_exposed_on_cli_choices():
    from oracle.cli import CHECK_CHOICES

    assert "underflow" in CHECK_CHOICES


def test_underflow_severity_is_high():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["integer_underflow"] == "high"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcode under test (guards against a future solc
# change silently optimising the SUB away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_sub():
    mnems = {i.mnemonic for i in Disassembly(_bc("integer-underflow-vuln")).instructions}
    assert "SUB" in mnems, "the vulnerable fixture must perform a subtraction"


def test_safe_fixture_emits_sub():
    mnems = {i.mnemonic for i in Disassembly(_bc("integer-underflow-safe")).instructions}
    assert "SUB" in mnems, (
        "the safe fixture must still perform a subtraction (so the test proves "
        "the detector keys on the underflow being reachable, not on the opcode)"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): a program-data subtraction produces a
# candidate carrying the underflow extra-constraint; the compiler's ABI/memory
# plumbing subtractions (calldatasize length check, free-memory-pointer math) are
# screened out so they do NOT pollute the candidate set.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("integer-underflow-vuln")
    assert cands, "a symbolic program-data subtraction must produce a candidate"
    assert all(c["category"] == "integer_underflow" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] == "SUB" for c in cands)


def test_candidate_carries_underflow_extra_constraint():
    cands = _candidates("integer-underflow-vuln")
    assert cands
    assert all("extra_constraint" in c for c in cands), (
        "an underflow candidate must carry the b>a condition for Z3 to solve"
    )


def test_plumbing_subtractions_are_filtered_out():
    # The vulnerable fixture's only program-data subtraction is `balance - amount`
    # (one site). solc also emits a `calldatasize - 4` dispatch check and
    # free-memory-pointer math, which must NOT appear as candidates.
    cands = _candidates("integer-underflow-vuln")
    assert len(cands) == 1, (
        "only the program-data subtraction should be a candidate; the "
        "calldatasize length check and memory-pointer math must be filtered"
    )


def test_no_underflow_candidate_on_overflow_only_fixture():
    # The integer-overflow fixture's only program-data arithmetic is an ADD; its
    # subtractions are all compiler plumbing, so the underflow detector must not
    # produce any candidate for it (no cross-contamination between the two
    # arithmetic-direction detectors).
    assert _candidates("integer-overflow") == [], (
        "a contract whose only data arithmetic is ADD must yield no underflow "
        "candidate — solc's plumbing subtractions are filtered"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (Z3 mocked by default): the vulnerable
# subtraction is reported as an integer_underflow finding.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("integer-underflow-vuln"), ["underflow"], max_depth=DEPTH)
    assert findings, "vulnerable contract should yield an integer-underflow finding"
    assert findings[0]["category"] == "integer_underflow"
    assert findings[0]["severity"] == "high"
    assert findings[0]["op"] == "SUB"
    assert findings[0]["trace"]


# --------------------------------------------------------------------------- #
# Cross-detector separation: the overflow detector must not claim an underflow,
# and the underflow detector must not claim the ADD-overflow fixture.
# --------------------------------------------------------------------------- #
def test_overflow_detector_does_not_emit_underflow_category():
    # The ADD/MUL overflow detector only ever emits the `integer_overflow`
    # category; the underflow direction is a separate detector / category. (The
    # overflow detector keys on ADD/MUL, never SUB, so it cannot claim the
    # subtraction underflow.)
    findings = analyze(_bc("integer-underflow-vuln"), ["overflow"], max_depth=DEPTH)
    assert all(f["category"] == "integer_overflow" for f in findings), (
        "the overflow detector must only emit integer_overflow, never the "
        "underflow category"
    )
    assert all(f["op"] in ("ADD", "MUL") for f in findings), (
        "the overflow detector must only flag ADD/MUL sites, never a SUB"
    )


def test_underflow_detector_does_not_flag_overflow_fixture():
    findings = analyze(_bc("integer-overflow"), ["underflow"], max_depth=DEPTH)
    assert findings == [], (
        "an ADD overflow is the overflow detector's job; the SUB underflow "
        "detector must not flag it"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_underflow_surfaces_under_all_checks():
    findings = analyze(_bc("integer-underflow-vuln"), ["all"], max_depth=DEPTH)
    cats = {f["category"] for f in findings}
    assert "integer_underflow" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_underflow_has_report_title():
    from oracle.report import _TITLE

    assert "integer_underflow" in _TITLE
    assert "Underflow" in _TITLE["integer_underflow"]
    assert "SWC-101" in _TITLE["integer_underflow"]


def test_underflow_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("integer-underflow-vuln"), ["underflow"], max_depth=DEPTH)
    md = format_h1md(findings, "integer-underflow-vuln.sol")
    assert "Integer Underflow" in md


def test_underflow_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("integer-underflow-vuln"), ["underflow"], max_depth=DEPTH)
    doc = json.loads(format_sarif(findings, "integer-underflow-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "integer_underflow" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "integer_underflow" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm against the REAL Z3 solver. This is the only place the safe
# fixture's `require(b <= a)` guard can actually be proved to make the underflow
# unsatisfiable (the default run mocks the solver and treats every candidate as
# satisfiable).
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_reachable_real_z3():
    findings = analyze(_bc("integer-underflow-vuln"), ["underflow"], max_depth=DEPTH)
    assert findings, "real Z3 must confirm the unchecked underflow is reachable"
    assert findings[0]["category"] == "integer_underflow"
    # the trigger input drives the subtraction past the minuend
    assert findings[0].get("trigger_input")


@pytest.mark.slow
def test_safe_unreachable_real_z3():
    findings = analyze(_bc("integer-underflow-safe"), ["underflow"], max_depth=DEPTH)
    assert findings == [], (
        "the require(b <= a) guard makes the underflow condition b>a "
        "unsatisfiable; the real solver must prove it unreachable and drop it"
    )


@pytest.mark.slow
def test_overflow_fixture_no_underflow_real_z3():
    findings = analyze(_bc("integer-overflow"), ["underflow"], max_depth=DEPTH)
    assert findings == [], (
        "the overflow fixture's only data arithmetic is an ADD; the real solver "
        "must produce no underflow finding"
    )
