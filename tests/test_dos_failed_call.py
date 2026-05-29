"""Tests for oracle's DoS-with-failed-call detector (SWC-113).

A "push" payout that makes an external call (`transfer`/`send`/low-level call)
INSIDE a loop is a denial-of-service surface: an EVM external call hands control
to the callee, and `transfer`/`send` (or a `require`-checked low-level call)
reverts the whole transaction when the callee fails. A single recipient that
cannot accept the call therefore reverts the entire batch, so NObody is paid —
the classic auction-refund / airdrop DoS (SWC-113, "DoS with Failed Call").

The discriminating signal is that an external call op's program counter is
reached MORE THAN ONCE on a single path: oracle's bounded executor unrolls loops
by revisiting the loop body's instructions, so a recurring call pc witnesses
that the call is loop-bound. A single forwarding call or a pull-payment withdraw
reaches its call pc at most once per transaction and must NOT be flagged.

Two fixtures pin the behaviour:
  * dos-failed-call-vuln.sol — `distribute(address[] calldata)` `transfer`s to
    every recipient inside a loop. The CALL pc recurs on a path. MUST be flagged.
  * dos-failed-call-safe.sol — a pull-payment `withdraw()` makes a single,
    isolated `call`. The CALL opcode is still present (so the test proves the
    detector keys on the call being *in a loop*, not on the opcode), but its pc
    is reached at most once per path. MUST NOT be flagged.

Like the rest of oracle's suite, the default run asserts the detector's
candidate/finding behaviour; the `slow` tests re-confirm against the real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, DosFailedCallDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Depth at which the vulnerable loop unrolls past one iteration (so the CALL pc
# recurs on a path). Below ~18 the loop body is only entered once.
LOOP_DEPTH = 24


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=LOOP_DEPTH):
    """Run only the DoS detector and return its raw candidates (before the Z3
    reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = DosFailedCallDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_dos_detector_is_registered():
    assert "dos-failed-call" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["dos-failed-call"] is DosFailedCallDetector


def test_dos_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "dos-failed-call" in CHECK_CHOICES


def test_dos_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["dos_failed_call"] == "medium"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the call/loop away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_call_and_loop():
    mnems = {i.mnemonic for i in Disassembly(_bc("dos-failed-call-vuln")).instructions}
    assert "CALL" in mnems, "the vulnerable fixture must make an external call"
    assert "JUMPDEST" in mnems, "the vulnerable fixture must contain a loop"


def test_safe_fixture_emits_call():
    mnems = {i.mnemonic for i in Disassembly(_bc("dos-failed-call-safe")).instructions}
    assert "CALL" in mnems, (
        "the safe fixture must still CALL (a single isolated call) so the test "
        "proves the detector keys on the call being loop-bound, not the opcode"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): a loop-bound call is detected for the
# vulnerable contract and NOT for the safe (single-call pull-payment) one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("dos-failed-call-vuln")
    assert cands, "an external call inside a loop must produce a DoS candidate"
    assert all(c["category"] == "dos_failed_call" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)
    assert all(c["op"] in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL") for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("dos-failed-call-safe") == [], (
        "a single, isolated external call (pull payment) is reached at most once "
        "per path, so it must not be flagged as a loop-bound DoS"
    )


def test_vuln_flags_each_loop_call_site_once():
    # the per-detector flagged-pc set must dedupe a loop-bound call site reached
    # on many paths down to a single finding per pc.
    cands = _candidates("dos-failed-call-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each loop-bound call site reported once"


def test_single_iteration_does_not_flag():
    # at a depth too small for the loop body to be revisited, the call pc never
    # recurs on a path, so even the vulnerable fixture yields no candidate. This
    # pins that the signal is the *recurrence* (loop), not the call itself.
    assert _candidates("dos-failed-call-vuln", max_depth=12) == []


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("dos-failed-call-vuln"), ["dos-failed-call"], max_depth=LOOP_DEPTH)
    assert findings, "vulnerable contract should yield a DoS finding"
    assert findings[0]["category"] == "dos_failed_call"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("dos-failed-call-safe"), ["dos-failed-call"], max_depth=LOOP_DEPTH)
    assert findings == [], "single-call pull-payment must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guards: contracts whose external call is NOT loop-bound must
# not be flagged for SWC-113 (a single low-level call, a contract with no call).
# --------------------------------------------------------------------------- #
def test_no_false_positive_single_call():
    findings = analyze(_bc("unchecked-call-vuln"), ["dos-failed-call"], max_depth=LOOP_DEPTH)
    assert findings == [], (
        "a single (non-loop) low-level call must not be flagged for SWC-113"
    )


def test_no_false_positive_without_call():
    findings = analyze(_bc("tx-origin-vuln"), ["dos-failed-call"], max_depth=20)
    assert findings == [], (
        "a contract that never makes an external call must not be flagged"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_dos_surfaces_under_all_checks():
    findings = analyze(_bc("dos-failed-call-vuln"), ["all"], max_depth=LOOP_DEPTH)
    cats = {f["category"] for f in findings}
    assert "dos_failed_call" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_dos_has_report_title():
    from oracle.report import _TITLE

    assert "dos_failed_call" in _TITLE
    assert "DoS with Failed Call" in _TITLE["dos_failed_call"]
    assert "SWC-113" in _TITLE["dos_failed_call"]


def test_dos_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("dos-failed-call-vuln"), ["dos-failed-call"], max_depth=LOOP_DEPTH)
    md = format_h1md(findings, "dos-failed-call-vuln.sol")
    assert "DoS with Failed Call" in md


def test_dos_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("dos-failed-call-vuln"), ["dos-failed-call"], max_depth=LOOP_DEPTH)
    doc = json.loads(format_sarif(findings, "dos-failed-call-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "dos_failed_call" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "dos_failed_call" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("dos-failed-call-vuln"), (
        "real-engine walk must find the loop-bound external call"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("dos-failed-call-safe") == []
