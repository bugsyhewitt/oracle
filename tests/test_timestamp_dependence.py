"""Tests for oracle's timestamp-dependence detector (SWC-116, "Block values as
a proxy for time").

`block.timestamp` and `block.number` are set by the block proposer (miner /
validator), who has discretion over them. A contract that *branches control
flow* on a block value to gate a payout, pick a winner, or enforce a deadline is
letting the proposer influence that decision — the canonical timestamp-as-
randomness gambling bug and the deadline-manipulation class (SWC-116). Reading a
block value for display / book-keeping is harmless; the bug is specifically
deciding control flow on it.

The discriminating signal is that a path constraint references the symbolic
`timestamp` / `block_number` leaf: an `if (block.timestamp ...)` /
`require(block.number ...)` guard compiles to a comparison feeding a JUMPI, whose
branch condition carries the block-value term. A non-control-flow read never
enters a JUMPI condition, so it produces no such constraint and must NOT fire.

Two fixtures pin the behaviour:
  * timestamp-dependence-vuln.sol — `play(uint256)` gates a payout on
    `block.timestamp % 2 == 0` (a manipulable randomness source). The path
    constraint references `timestamp`. MUST be flagged.
  * timestamp-dependence-safe.sol — `now_()` *returns* `block.timestamp` (a view
    getter) and `deposit()` branches on a calldata argument. The TIMESTAMP
    opcode is still present (so the test proves the detector keys on the block
    value *deciding control flow*, not on the opcode), but no branch is gated on
    it. MUST NOT be flagged.

Like the rest of oracle's suite, the default run asserts the detector's
candidate/finding behaviour; the `slow` tests re-confirm against the real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, TimestampDependenceDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Depth at which the block-value-dependent branch is reached on a path.
DEPTH = 30


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=DEPTH):
    """Run only the timestamp detector and return its raw candidates (before the
    Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = TimestampDependenceDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_timestamp_detector_is_registered():
    assert "timestamp" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["timestamp"] is TimestampDependenceDetector


def test_timestamp_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "timestamp" in CHECK_CHOICES


def test_timestamp_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["timestamp_dependence"] == "medium"


def test_detector_covers_timestamp_and_number():
    # SWC-116 names both block.timestamp and block.number as interchangeable
    # time/randomness proxies; the detector must key on both symbol leaves.
    assert TimestampDependenceDetector._BLOCKVAL_NAMES == ("timestamp", "block_number")


# --------------------------------------------------------------------------- #
# The VM records a block-value read on TIMESTAMP and NUMBER so the detector can
# cheaply gate before its AST walk.
# --------------------------------------------------------------------------- #
def test_vm_sets_blockval_loaded_on_timestamp():
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    assert st.blockval_loaded is False
    vm = SymbolicVM(_bc("timestamp-dependence-vuln"), max_depth=DEPTH)
    # find a TIMESTAMP instruction and execute its handler directly
    ts = next(i for i in vm.disasm.instructions if i.mnemonic == "TIMESTAMP")
    vm._op_timestamp(st, ts)
    assert st.blockval_loaded is True


def test_vm_sets_blockval_loaded_on_number():
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    assert st.blockval_loaded is False
    vm = SymbolicVM(_bc("timestamp-dependence-vuln"), max_depth=DEPTH)
    num = next(i for i in vm.disasm.instructions if i.mnemonic == "TIMESTAMP")
    # NUMBER shares the handler shape; drive _op_number directly to pin the latch
    vm._op_number(st, num)
    assert st.blockval_loaded is True


def test_blockval_loaded_survives_clone():
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    st.blockval_loaded = True
    st.timestamp_flagged = True
    new = st.clone()
    assert new.blockval_loaded is True
    assert new.timestamp_flagged is True


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the TIMESTAMP read / branch away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_timestamp_and_branch():
    mnems = {i.mnemonic for i in Disassembly(_bc("timestamp-dependence-vuln")).instructions}
    assert "TIMESTAMP" in mnems, "the vulnerable fixture must read block.timestamp"
    assert "JUMPI" in mnems, "the vulnerable fixture must branch (gate on the value)"


def test_safe_fixture_emits_timestamp():
    mnems = {i.mnemonic for i in Disassembly(_bc("timestamp-dependence-safe")).instructions}
    assert "TIMESTAMP" in mnems, (
        "the safe fixture must still read block.timestamp (a view getter) so the "
        "test proves the detector keys on the value deciding control flow, not "
        "the opcode"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): a block-value-gated branch is detected
# for the vulnerable contract and NOT for the safe (read-through) one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("timestamp-dependence-vuln")
    assert cands, "branching control flow on block.timestamp must produce a candidate"
    assert all(c["category"] == "timestamp_dependence" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("timestamp-dependence-safe") == [], (
        "a read-through view getter that returns block.timestamp without gating "
        "control flow on it must not be flagged"
    )


def test_vuln_flags_each_guard_site_once():
    # the per-detector flagged-pc set must dedupe a guard site reached on many
    # paths down to a single finding per pc.
    cands = _candidates("timestamp-dependence-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each block-value guard site reported once"


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("timestamp-dependence-vuln"), ["timestamp"], max_depth=DEPTH)
    assert findings, "vulnerable contract should yield a timestamp-dependence finding"
    assert findings[0]["category"] == "timestamp_dependence"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("timestamp-dependence-safe"), ["timestamp"], max_depth=DEPTH)
    assert findings == [], "read-through block-value getter must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that never read a block value, and a contract
# that reads the sender (not a block value), must not be flagged for SWC-116.
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_block_value():
    findings = analyze(_bc("tx-origin-vuln"), ["timestamp"], max_depth=20)
    assert findings == [], (
        "a contract that never reads a block value must not be flagged for SWC-116"
    )


def test_no_false_positive_on_caller_guard():
    findings = analyze(_bc("access-control-safe"), ["timestamp"], max_depth=20)
    assert findings == [], (
        "an access-control (caller) guard is not a block-value dependence"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_timestamp_surfaces_under_all_checks():
    findings = analyze(_bc("timestamp-dependence-vuln"), ["all"], max_depth=DEPTH)
    cats = {f["category"] for f in findings}
    assert "timestamp_dependence" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_timestamp_has_report_title():
    from oracle.report import _TITLE

    assert "timestamp_dependence" in _TITLE
    assert "Block values as a proxy for time" in _TITLE["timestamp_dependence"]
    assert "SWC-116" in _TITLE["timestamp_dependence"]


def test_timestamp_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("timestamp-dependence-vuln"), ["timestamp"], max_depth=DEPTH)
    md = format_h1md(findings, "timestamp-dependence-vuln.sol")
    assert "Block values as a proxy for time" in md


def test_timestamp_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("timestamp-dependence-vuln"), ["timestamp"], max_depth=DEPTH)
    doc = json.loads(format_sarif(findings, "timestamp-dependence-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "timestamp_dependence" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "timestamp_dependence" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("timestamp-dependence-vuln"), (
        "real-engine walk must find the block-value-gated branch"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("timestamp-dependence-safe") == []
