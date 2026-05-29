"""Tests for oracle's tx.origin-authentication detector (SWC-115).

Using `tx.origin` to authorize a caller is a classic high-severity EVM bug:
`tx.origin` is the externally-owned account that *started* the transaction, not
the immediate caller, so a `require(tx.origin == owner)` guard is bypassable by
a phishing-relay attack. The safe primitive is `msg.sender`.

The discriminating signal is that the contract *branched control flow on*
`tx.origin`: a path constraint references the symbolic `origin` leaf (an
`if`/`require` on tx.origin compiles to a comparison feeding a JUMPI). A
contract that uses `msg.sender` — or never reads tx.origin at all — never
produces such a constraint.

Two fixtures pin the behaviour:
  * tx-origin-vuln.sol — `withdraw()` is gated by `require(tx.origin == owner)`.
    MUST be flagged.
  * tx-origin-safe.sol — same shape but gated by `require(msg.sender == owner)`,
    never reading tx.origin. MUST NOT be flagged.

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm against the
real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, TxOriginAuthDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=24):
    """Run only the tx.origin detector and return its raw candidates (before the
    Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = TxOriginAuthDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_tx_origin_detector_is_registered():
    assert "tx-origin" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["tx-origin"] is TxOriginAuthDetector


def test_tx_origin_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "tx-origin" in CHECK_CHOICES


def test_tx_origin_severity_is_high():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["tx_origin_authentication"] == "high"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the guard away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_origin():
    mnems = {i.mnemonic for i in Disassembly(_bc("tx-origin-vuln")).instructions}
    assert "ORIGIN" in mnems, "the vulnerable fixture must read tx.origin"


def test_safe_fixture_has_no_origin():
    mnems = {i.mnemonic for i in Disassembly(_bc("tx-origin-safe")).instructions}
    assert "ORIGIN" not in mnems, "the safe fixture must not read tx.origin"
    assert "CALLER" in mnems, "the safe fixture authenticates via msg.sender"


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the tx.origin guard is detected for the
# vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_tx_origin_candidate():
    cands = _candidates("tx-origin-vuln")
    assert cands, "require(tx.origin == owner) must produce a tx-origin candidate"
    assert all(c["category"] == "tx_origin_authentication" for c in cands)
    assert all(c["severity"] == "high" for c in cands)


def test_safe_produces_no_tx_origin_candidate():
    assert _candidates("tx-origin-safe") == [], (
        "a msg.sender-authenticated contract that never reads tx.origin must "
        "not be flagged"
    )


def test_detector_does_not_over_report_per_path():
    # The origin constraint persists down the path; the per-path latch must keep
    # the finding count to one-per-guarded-path, not one-per-instruction. The
    # single-guard fixture has a handful of paths, not 100+ instructions worth.
    cands = _candidates("tx-origin-vuln")
    assert len(cands) <= 4, (
        "the per-path tx_origin_flagged latch must prevent re-flagging every "
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
    findings = analyze(_bc("tx-origin-vuln"), ["tx-origin"], max_depth=24)
    assert findings, "vulnerable contract should yield a tx-origin finding"
    assert findings[0]["category"] == "tx_origin_authentication"
    assert findings[0]["severity"] == "high"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("tx-origin-safe"), ["tx-origin"], max_depth=24)
    assert findings == [], "safe (msg.sender) contract must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guard: a contract that authenticates via msg.sender (CALLER)
# must not be flagged as a tx.origin issue. access-control-vuln reads CALLER but
# never ORIGIN.
# --------------------------------------------------------------------------- #
def test_no_false_positive_on_msg_sender_auth():
    findings = analyze(_bc("access-control-vuln"), ["tx-origin"], max_depth=20)
    assert findings == [], (
        "a contract that gates on msg.sender (CALLER), never tx.origin, must "
        "not be flagged for tx.origin authentication"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_tx_origin_surfaces_under_all_checks():
    findings = analyze(_bc("tx-origin-vuln"), ["all"], max_depth=24)
    cats = {f["category"] for f in findings}
    assert "tx_origin_authentication" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_tx_origin_has_report_title():
    from oracle.report import _TITLE

    assert "tx_origin_authentication" in _TITLE
    assert "tx.origin" in _TITLE["tx_origin_authentication"]


def test_tx_origin_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("tx-origin-vuln"), ["tx-origin"], max_depth=24)
    md = format_h1md(findings, "tx-origin-vuln.sol")
    assert "tx.origin Authentication" in md


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("tx-origin-vuln"), (
        "real-engine walk must find the tx.origin authentication guard"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("tx-origin-safe") == []
