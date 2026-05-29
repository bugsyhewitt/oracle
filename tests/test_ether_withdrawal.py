"""Tests for oracle's unprotected-ether-withdrawal detector (SWC-105,
"Unprotected Ether Withdrawal").

A contract that forwards its ether out (`transfer`/`send`/value-bearing low-level
`call`) from a public function with NO access-control guard lets any address
drain it — the canonical SWC-105 "anyone can empty the contract" bug. The
discriminating signal is a value-forwarding call op (`CALL`/`CALLCODE`) reached
on a path whose accumulated constraints never branch on the caller's identity: a
genuine `require(msg.sender == owner)` guard compiles to a comparison on the
symbolic `caller` leaf feeding a JUMPI, so a guarded path carries `caller` in a
constraint; an unguarded path leaves `caller` entirely free.

Two fixtures pin the behaviour:
  * ether-withdrawal-vuln.sol — public `withdraw()` sends the whole balance to
    `msg.sender` with no owner check. The recipient is `msg.sender` (an ordinary
    recipient, NOT the attacker-controlled-recipient signal of the EtherLeak
    detector), yet the call is reached with no caller-binding constraint. MUST be
    flagged.
  * ether-withdrawal-safe.sol — `withdraw()` forwards the balance only after a
    `require(msg.sender == owner)` guard. The value-forwarding CALL is still
    present (so the test proves the detector keys on the *missing caller guard*,
    not the opcode), but the path branches on `caller`. MUST NOT be flagged.

Like the rest of oracle's suite, the default run asserts the detector's
candidate/finding behaviour; the `slow` tests re-confirm against the real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    UnprotectedEtherWithdrawalDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Depth at which the value-forwarding call is reached on a path.
DEPTH = 30


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=DEPTH):
    """Run only the ether-withdrawal detector and return its raw candidates
    (before the Z3 reachability boundary), isolating detector logic from the
    solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = UnprotectedEtherWithdrawalDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_ether_withdrawal_detector_is_registered():
    assert "ether-withdrawal" in DETECTOR_REGISTRY
    assert (
        DETECTOR_REGISTRY["ether-withdrawal"] is UnprotectedEtherWithdrawalDetector
    )


def test_ether_withdrawal_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "ether-withdrawal" in CHECK_CHOICES


def test_ether_withdrawal_severity_is_high():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["unprotected_ether_withdrawal"] == "high"


def test_detector_targets_value_forwarding_call_ops():
    # SWC-105 is about forwarding the contract's OWN ether; only CALL/CALLCODE
    # can carry value. DELEGATECALL/STATICCALL cannot move the balance and are
    # deliberately out of scope.
    assert UnprotectedEtherWithdrawalDetector._VALUE_CALL_OPS == ("CALL", "CALLCODE")


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the value-forwarding CALL / guard away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_call():
    mnems = {i.mnemonic for i in Disassembly(_bc("ether-withdrawal-vuln")).instructions}
    assert "CALL" in mnems, "the vulnerable fixture must forward ether via CALL"


def test_safe_fixture_emits_call_and_branch():
    mnems = {i.mnemonic for i in Disassembly(_bc("ether-withdrawal-safe")).instructions}
    assert "CALL" in mnems, (
        "the safe fixture must still forward ether via CALL so the test proves "
        "the detector keys on the missing caller guard, not the opcode"
    )
    assert "JUMPI" in mnems, "the safe fixture must branch (the require guard)"


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): an unguarded value-forwarding call is
# detected for the vulnerable contract and NOT for the caller-guarded one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("ether-withdrawal-vuln")
    assert cands, (
        "an unguarded value-forwarding call must produce a candidate"
    )
    assert all(c["category"] == "unprotected_ether_withdrawal" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] in ("CALL", "CALLCODE") for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("ether-withdrawal-safe") == [], (
        "a value-forwarding call gated on require(msg.sender == owner) must not "
        "be flagged"
    )


def test_vuln_flags_each_call_site_once():
    # the per-detector flagged-pc set must dedupe a call site reached on many
    # paths down to a single finding per pc.
    cands = _candidates("ether-withdrawal-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each unprotected call site reported once"


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(
        _bc("ether-withdrawal-vuln"), ["ether-withdrawal"], max_depth=DEPTH
    )
    assert findings, "vulnerable contract should yield an unprotected-withdrawal finding"
    assert findings[0]["category"] == "unprotected_ether_withdrawal"
    assert findings[0]["severity"] == "high"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(
        _bc("ether-withdrawal-safe"), ["ether-withdrawal"], max_depth=DEPTH
    )
    assert findings == [], "a caller-guarded withdrawal must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guards. SWC-105 is distinct from neighbouring detectors:
#   * a contract that never forwards ether (no value-bearing CALL) must be clean;
#   * a pull-payment that only pays the caller's own entitled balance is clean
#     (its value collapses to the contract's all-zero initial storage, so there
#     is no ether to steal — the safe withdraw pattern);
#   * a caller-guarded contract that never reaches a value call is clean.
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_value_call():
    findings = analyze(
        _bc("access-control-safe"), ["ether-withdrawal"], max_depth=20
    )
    assert findings == [], (
        "a contract that never forwards ether must not be flagged for SWC-105"
    )


def test_no_false_positive_on_pull_payment():
    # dos-failed-call-safe is a pull-payment withdraw(): it pays only the
    # caller's own credited balance in a single isolated call. The CALL opcode is
    # present, but it is not an unprotected drain of the contract.
    findings = analyze(
        _bc("dos-failed-call-safe"), ["ether-withdrawal"], max_depth=DEPTH
    )
    assert findings == [], (
        "a pull-payment paying only the caller's own balance is not an "
        "unprotected ether withdrawal"
    )


def test_no_false_positive_on_caller_guarded_withdrawal():
    # tx-origin-safe gates its value-forwarding call on require(msg.sender ==
    # owner) — a genuine caller guard, so SWC-105 must not fire.
    findings = analyze(
        _bc("tx-origin-safe"), ["ether-withdrawal"], max_depth=DEPTH
    )
    assert findings == [], (
        "a withdrawal gated on msg.sender is access-controlled, not SWC-105"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_ether_withdrawal_surfaces_under_all_checks():
    findings = analyze(
        _bc("ether-withdrawal-vuln"), ["all"], max_depth=DEPTH
    )
    cats = {f["category"] for f in findings}
    assert "unprotected_ether_withdrawal" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_ether_withdrawal_has_report_title():
    from oracle.report import _TITLE

    assert "unprotected_ether_withdrawal" in _TITLE
    assert "Unprotected Ether Withdrawal" in _TITLE["unprotected_ether_withdrawal"]
    assert "SWC-105" in _TITLE["unprotected_ether_withdrawal"]


def test_ether_withdrawal_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(
        _bc("ether-withdrawal-vuln"), ["ether-withdrawal"], max_depth=DEPTH
    )
    md = format_h1md(findings, "ether-withdrawal-vuln.sol")
    assert "Unprotected Ether Withdrawal" in md


def test_ether_withdrawal_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(
        _bc("ether-withdrawal-vuln"), ["ether-withdrawal"], max_depth=DEPTH
    )
    doc = json.loads(format_sarif(findings, "ether-withdrawal-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "unprotected_ether_withdrawal" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "unprotected_ether_withdrawal" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("ether-withdrawal-vuln"), (
        "real-engine walk must find the unguarded value-forwarding call"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("ether-withdrawal-safe") == []
