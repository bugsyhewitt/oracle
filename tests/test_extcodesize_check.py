"""Tests for oracle's EXTCODESIZE caller-type-check detector.

A widespread, flawed access-control idiom restricts a function to
externally-owned accounts by checking the caller's code size:
`require(extcodesize(msg.sender) == 0)` ("no contracts allowed"), or the
inverse `require(extcodesize(addr) > 0)` to "prove" an address is a contract.
Both are bypassable: during a contract's constructor `extcodesize` returns 0,
so an attacker calls from within their constructor and the "EOA-only" guard
passes for a contract; the mirror form is defeated by not-yet-deployed CREATE2
addresses and self-destructed contracts. No trust/authorization decision should
be made on `extcodesize`.

The discriminating signal is that the contract *branched control flow on* an
external account's code size: a path constraint references an `extcodesize_<pc>`
leaf (an `if`/`require` on extcodesize compiles to a comparison feeding a
JUMPI). A contract that authenticates via msg.sender — or never reads a code
size at all — never produces such a constraint.

Two fixtures pin the behaviour:
  * extcodesize-guard.sol — `destroy()` is gated by `require(extcodesize(sender)
    == 0)`. MUST be flagged.
  * extcodesize-check-safe.sol — same shape but gated by `require(msg.sender ==
    owner)`, never reading a code size. MUST NOT be flagged.

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
    ExtcodesizeCallerCheckDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=24):
    """Run only the extcodesize-check detector and return its raw candidates
    (before the Z3 reachability boundary), isolating detector logic from the
    solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = ExtcodesizeCallerCheckDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_extcodesize_detector_is_registered():
    assert "extcodesize-check" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["extcodesize-check"] is ExtcodesizeCallerCheckDetector


def test_extcodesize_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "extcodesize-check" in CHECK_CHOICES


def test_extcodesize_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["extcodesize_caller_check"] == "medium"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the guard away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_extcodesize():
    mnems = {i.mnemonic for i in Disassembly(_bc("extcodesize-guard")).instructions}
    assert "EXTCODESIZE" in mnems, "the vulnerable fixture must read extcodesize"


def test_safe_fixture_has_no_extcodesize():
    mnems = {
        i.mnemonic for i in Disassembly(_bc("extcodesize-check-safe")).instructions
    }
    assert "EXTCODESIZE" not in mnems, "the safe fixture must not read a code size"
    assert "CALLER" in mnems, "the safe fixture authenticates via msg.sender"


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the extcodesize guard is detected for the
# vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_extcodesize_candidate():
    cands = _candidates("extcodesize-guard")
    assert cands, (
        "require(extcodesize(sender) == 0) must produce an extcodesize-check "
        "candidate"
    )
    assert all(c["category"] == "extcodesize_caller_check" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)


def test_safe_produces_no_extcodesize_candidate():
    assert _candidates("extcodesize-check-safe") == [], (
        "a msg.sender-authenticated contract that never reads a code size must "
        "not be flagged"
    )


def test_detector_does_not_over_report_per_path():
    # The extcodesize constraint persists down the path; the per-path latch must
    # keep the finding count to one-per-guarded-path, not one-per-instruction.
    cands = _candidates("extcodesize-guard")
    assert len(cands) <= 4, (
        "the per-path extcodesize_flagged latch must prevent re-flagging every "
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
    findings = analyze(_bc("extcodesize-guard"), ["extcodesize-check"], max_depth=24)
    assert findings, "vulnerable contract should yield an extcodesize-check finding"
    assert findings[0]["category"] == "extcodesize_caller_check"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(
        _bc("extcodesize-check-safe"), ["extcodesize-check"], max_depth=24
    )
    assert findings == [], "safe (msg.sender) contract must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guard: a contract that authenticates via msg.sender (CALLER)
# and never reads a code size must not be flagged. access-control-vuln reads
# CALLER but no EXTCODESIZE.
# --------------------------------------------------------------------------- #
def test_no_false_positive_on_msg_sender_auth():
    findings = analyze(
        _bc("access-control-vuln"), ["extcodesize-check"], max_depth=20
    )
    assert findings == [], (
        "a contract that never branches on a code size must not be flagged for "
        "an extcodesize caller-type check"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_extcodesize_surfaces_under_all_checks():
    findings = analyze(_bc("extcodesize-guard"), ["all"], max_depth=24)
    cats = {f["category"] for f in findings}
    assert "extcodesize_caller_check" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_extcodesize_has_report_title():
    from oracle.report import _TITLE

    assert "extcodesize_caller_check" in _TITLE
    assert "EXTCODESIZE" in _TITLE["extcodesize_caller_check"]


def test_extcodesize_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("extcodesize-guard"), ["extcodesize-check"], max_depth=24)
    md = format_h1md(findings, "extcodesize-guard.sol")
    assert "EXTCODESIZE" in md


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("extcodesize-guard"), (
        "real-engine walk must find the extcodesize caller-type check guard"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("extcodesize-check-safe") == []
