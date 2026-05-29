"""Tests for oracle's strict-balance-equality detector (SWC-132, "Unexpected
Ether Balance").

A contract's ether balance is not controlled solely by its own logic: any
account can force ether in via `selfdestruct(this)` or by pre-funding a CREATE2
address before deployment, neither of which runs the receive/fallback code. A
contract that *branches on* `address(this).balance` (or another account's
balance) is therefore making an attacker-falsifiable assumption — the canonical
`require(address(this).balance == expected)` game/state-machine invariant
(SWC-132). The safe design tracks deposits in a dedicated storage accumulator
and never compares against the raw balance.

The discriminating signal is that the contract *branched control flow on* an
account balance: a path constraint references a `balance` (BALANCE) or
`selfbalance` (SELFBALANCE) leaf (an `if`/`require` on a balance compiles to a
comparison feeding a JUMPI). A contract that merely reads a balance for a
non-control-flow purpose — forwarding it as a call value, returning it — never
produces such a constraint.

Two fixtures pin the behaviour:
  * strict-balance-vuln.sol — `claim()` is gated by
    `require(address(this).balance == target)`. MUST be flagged.
  * strict-balance-safe.sol — same shape but gated on an internally-tracked
    `tracked` accumulator, never branching on the raw balance. MUST NOT be
    flagged.

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm against the
real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    StrictBalanceEqualityDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=24):
    """Run only the strict-balance detector and return its raw candidates
    (before the Z3 reachability boundary), isolating detector logic from the
    solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = StrictBalanceEqualityDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_strict_balance_detector_is_registered():
    assert "strict-balance" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["strict-balance"] is StrictBalanceEqualityDetector


def test_strict_balance_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "strict-balance" in CHECK_CHOICES


def test_strict_balance_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["strict_balance_equality"] == "medium"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the balance read away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_reads_a_balance():
    mnems = {i.mnemonic for i in Disassembly(_bc("strict-balance-vuln")).instructions}
    assert "SELFBALANCE" in mnems or "BALANCE" in mnems, (
        "the vulnerable fixture must read address(this).balance"
    )


def test_safe_fixture_does_not_branch_on_balance():
    # the safe fixture gates on a tracked storage accumulator, not the raw
    # balance — it must not read SELFBALANCE/BALANCE for its guard.
    mnems = {i.mnemonic for i in Disassembly(_bc("strict-balance-safe")).instructions}
    assert "SELFBALANCE" not in mnems and "BALANCE" not in mnems, (
        "the safe fixture must not read a balance for its guard"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the balance guard is detected for the
# vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_strict_balance_candidate():
    cands = _candidates("strict-balance-vuln")
    assert cands, (
        "require(address(this).balance == target) must produce a strict-balance "
        "candidate"
    )
    assert all(c["category"] == "strict_balance_equality" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)


def test_safe_produces_no_strict_balance_candidate():
    assert _candidates("strict-balance-safe") == [], (
        "a contract that gates on an internally-tracked accumulator (never the "
        "raw balance) must not be flagged"
    )


def test_detector_does_not_over_report_per_path():
    # The balance constraint persists down the path; the per-path latch must
    # keep the finding count to one-per-guarded-path, not one-per-instruction.
    cands = _candidates("strict-balance-vuln")
    assert len(cands) <= 4, (
        "the per-path balance_flagged latch must prevent re-flagging every "
        "instruction after the guard"
    )
    # each flagged pc is unique (the per-detector pc dedup)
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs))


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("strict-balance-vuln"), ["strict-balance"], max_depth=24)
    assert findings, "vulnerable contract should yield a strict-balance finding"
    assert findings[0]["category"] == "strict_balance_equality"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("strict-balance-safe"), ["strict-balance"], max_depth=24)
    assert findings == [], "safe (tracked-accumulator) contract must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guard: a contract that merely *forwards* its balance as a call
# value (a non-branching read) must not be flagged. The ether-withdrawal
# fixtures read SELFBALANCE only to forward it, never branching on it.
# --------------------------------------------------------------------------- #
def test_no_false_positive_on_balance_forwarding():
    for fixture in ("ether-withdrawal-vuln", "ether-withdrawal-safe"):
        findings = analyze(_bc(fixture), ["strict-balance"], max_depth=24)
        assert findings == [], (
            f"{fixture} reads SELFBALANCE only to forward it (non-branching) and "
            "must not be flagged for a strict balance check"
        )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_strict_balance_surfaces_under_all_checks():
    findings = analyze(_bc("strict-balance-vuln"), ["all"], max_depth=24)
    cats = {f["category"] for f in findings}
    assert "strict_balance_equality" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_strict_balance_has_report_title():
    from oracle.report import _TITLE

    assert "strict_balance_equality" in _TITLE
    assert "SWC-132" in _TITLE["strict_balance_equality"]


def test_strict_balance_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("strict-balance-vuln"), ["strict-balance"], max_depth=24)
    md = format_h1md(findings, "strict-balance-vuln.sol")
    assert "SWC-132" in md


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("strict-balance-vuln"), (
        "real-engine walk must find the strict balance-equality guard"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("strict-balance-safe") == []
