"""Tests for oracle's access-control escalation detector (POST_V01 Tier 2 #5).

The detector flags ownership/privilege escalation: a privileged operation that
any address can reach because the owner/admin gate is absent or ineffective. The
two canonical shapes it catches:

  * a re-callable initializer / unprotected `_transferOwnership` — a storage
    write inside a function that read `msg.sender` but never bound a constraint
    on it (so anyone can drive the write and become owner); and
  * a privileged sink (`SELFDESTRUCT` / `DELEGATECALL` / `CALLCODE`) reachable on
    a path that never constrains `caller` (no ownership check at all).

The discriminating signal is the ABSENCE of a `caller`-binding guard on the path
to the sink. A genuine `require(msg.sender == owner)` appears as a path
constraint referencing the symbolic `caller`; a missing/ineffective guard leaves
`caller` unconstrained.

Two fixtures pin the behaviour:
  * access-control-vuln.sol — `initialize()` sets `owner = msg.sender` with no
    initializer guard (re-callable). MUST be flagged.
  * access-control-safe.sol — ownership set in the constructor; every runtime
    privileged op is behind `require(msg.sender == owner)`. MUST NOT be flagged.

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm against the
real engine that the candidate is generated for the vulnerable contract and not
for the safe one.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    AccessControlEscalationDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=20):
    """Run only the access-control detector and return its raw candidates
    (before the Z3 reachability boundary), isolating detector logic from the
    solver/storage-model conservatism."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = AccessControlEscalationDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_access_control_detector_is_registered():
    assert "access-control" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["access-control"] is AccessControlEscalationDetector


def test_access_control_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "access-control" in CHECK_CHOICES


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the privileged write/sink away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_caller_and_sstore():
    mnems = {i.mnemonic for i in Disassembly(_bc("access-control-vuln")).instructions}
    assert "CALLER" in mnems
    assert "SSTORE" in mnems


def test_safe_fixture_emits_caller_and_sstore():
    mnems = {i.mnemonic for i in Disassembly(_bc("access-control-safe")).instructions}
    assert "CALLER" in mnems
    assert "SSTORE" in mnems


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the escalation is detected for the
# vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_escalation_candidate():
    cands = _candidates("access-control-vuln")
    assert cands, "re-callable owner = msg.sender must produce an escalation candidate"
    assert all(c["category"] == "access_control_escalation" for c in cands)
    assert all(c["severity"] == "high" for c in cands)


def test_safe_produces_no_escalation_candidate():
    assert _candidates("access-control-safe") == [], (
        "a constructor-set owner with require(msg.sender == owner) guards must "
        "not be flagged"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary,
# matching the rest of the suite): vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("access-control-vuln"), ["access-control"], max_depth=20)
    assert findings, "vulnerable contract should yield an escalation finding"
    assert findings[0]["category"] == "access_control_escalation"
    assert findings[0]["severity"] == "high"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("access-control-safe"), ["access-control"], max_depth=20)
    assert findings == [], "safe (guarded) contract must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guard: a contract that never touches msg.sender and writes no
# caller-derived storage must not be flagged for an SSTORE alone. The reentrancy
# safe fixture (correct CEI, owner-less) is exactly such a contract.
# --------------------------------------------------------------------------- #
def test_no_false_positive_on_senderless_storage_write():
    findings = analyze(_bc("reentrancy_safe"), ["access-control"], max_depth=18)
    assert findings == [], (
        "a storage write in a function that never reads msg.sender and is not "
        "caller-derived must not be flagged as an escalation"
    )


# --------------------------------------------------------------------------- #
# True positive on an unguarded privileged SINK: an unprotected selfdestruct is
# callable by anyone — the complementary escalation shape. returndata-after-call
# performs `selfdestruct(target)` with no ownership check.
# --------------------------------------------------------------------------- #
def test_unguarded_selfdestruct_is_an_escalation():
    findings = analyze(_bc("returndata-after-call"), ["access-control"], max_depth=12)
    cats = {f["category"] for f in findings}
    assert "access_control_escalation" in cats
    assert any(f["op"] == "SELFDESTRUCT" for f in findings)


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("access-control-vuln"), (
        "real-engine walk must find the unguarded ownership escalation"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("access-control-safe") == []
