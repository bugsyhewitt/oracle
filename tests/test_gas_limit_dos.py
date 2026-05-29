"""Tests for oracle's block-gas-limit DoS detector (SWC-128).

A loop whose iteration count is bounded by a value held in CONTRACT STORAGE that
can grow without bound (the classic `for (i = 0; i < arr.length; i++)` over a
storage array anyone can keep pushing onto) becomes a denial-of-service surface:
as the collection grows, the loop's gas cost grows until the call exceeds the
block gas limit and the function can NEVER be executed again — bricking any funds
or state it gates (SWC-128, "DoS With Block Gas Limit").

The discriminating signal is that an SLOAD's program counter is reached MORE THAN
ONCE on a single path: oracle's bounded executor unrolls loops by revisiting the
loop body's instructions, so a recurring SLOAD pc witnesses that the loop
re-reads contract storage every iteration — i.e. its work is bounded by (and
grows with) contract state. A loop bounded by a fixed constant or a calldata
argument never re-reads storage for its bound, so its SLOAD pc does not recur and
it must NOT be flagged. A single, non-loop storage read reaches its SLOAD pc at
most once per path and must NOT be flagged.

Two fixtures pin the behaviour:
  * gas-limit-dos-vuln.sol — `payAll()` loops over a `users` storage array whose
    length anyone can grow via `addUser()`; the loop re-reads storage each
    iteration. The SLOAD pc recurs on a path. MUST be flagged.
  * gas-limit-dos-safe.sol — `sumN(n)` loops, but its bound is a range-checked
    calldata argument (`require(n <= 100)`), never read from storage. The loop
    (JUMPI back-edge) is still present (so the test proves the detector keys on
    the loop re-reading *storage*, not on the loop opcode), but no SLOAD pc
    recurs. MUST NOT be flagged.

Like the rest of oracle's suite, the default run asserts the detector's
candidate/finding behaviour; the `slow` tests re-confirm against the real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, BlockGasLimitDosDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Depth at which the vulnerable loop unrolls past one iteration (so the SLOAD pc
# recurs on a path).
LOOP_DEPTH = 24


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=LOOP_DEPTH):
    """Run only the gas-limit DoS detector and return its raw candidates (before
    the Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = BlockGasLimitDosDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_gas_limit_detector_is_registered():
    assert "gas-limit-dos" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["gas-limit-dos"] is BlockGasLimitDosDetector


def test_gas_limit_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "gas-limit-dos" in CHECK_CHOICES


def test_gas_limit_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["block_gas_limit_dos"] == "medium"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the storage read / loop away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_sload_and_loop():
    mnems = {i.mnemonic for i in Disassembly(_bc("gas-limit-dos-vuln")).instructions}
    assert "SLOAD" in mnems, "the vulnerable fixture must read contract storage"
    assert "JUMPDEST" in mnems, "the vulnerable fixture must contain a loop"


def test_safe_fixture_emits_loop():
    mnems = {i.mnemonic for i in Disassembly(_bc("gas-limit-dos-safe")).instructions}
    assert "JUMPDEST" in mnems, (
        "the safe fixture must still contain a loop so the test proves the "
        "detector keys on the loop re-reading storage, not on the loop opcode"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): a storage-bounded loop is detected for the
# vulnerable contract and NOT for the safe (calldata-bounded) one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("gas-limit-dos-vuln")
    assert cands, "a storage-read inside a loop must produce a gas-limit DoS candidate"
    assert all(c["category"] == "block_gas_limit_dos" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)
    assert all(c["op"] == "SLOAD" for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("gas-limit-dos-safe") == [], (
        "a loop bounded by a range-checked calldata argument never re-reads "
        "storage for its bound, so it must not be flagged as an unbounded loop"
    )


def test_vuln_flags_each_storage_read_site_once():
    # the per-detector flagged-pc set must dedupe a loop-bound storage read
    # reached on many paths down to a single finding per pc.
    cands = _candidates("gas-limit-dos-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each loop-bound storage read reported once"


def test_single_iteration_does_not_flag():
    # at a depth too small for the loop body to be revisited, the SLOAD pc never
    # recurs on a path, so even the vulnerable fixture yields no candidate. This
    # pins that the signal is the *recurrence* (loop), not the storage read.
    assert _candidates("gas-limit-dos-vuln", max_depth=4) == []


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("gas-limit-dos-vuln"), ["gas-limit-dos"], max_depth=LOOP_DEPTH)
    assert findings, "vulnerable contract should yield a gas-limit DoS finding"
    assert findings[0]["category"] == "block_gas_limit_dos"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("gas-limit-dos-safe"), ["gas-limit-dos"], max_depth=LOOP_DEPTH)
    assert findings == [], "calldata-bounded loop must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guards: contracts whose storage read is NOT loop-bound must not
# be flagged for SWC-128 (a single storage read, a contract with no storage).
# --------------------------------------------------------------------------- #
def test_no_false_positive_single_storage_read():
    # an unprotected withdrawal reads storage but not in an iterating loop, so its
    # SLOAD pc does not recur on a path.
    findings = analyze(_bc("ether-withdrawal-vuln"), ["gas-limit-dos"], max_depth=LOOP_DEPTH)
    assert findings == [], (
        "a single (non-loop) storage read must not be flagged for SWC-128"
    )


def test_no_false_positive_without_storage():
    findings = analyze(_bc("tx-origin-vuln"), ["gas-limit-dos"], max_depth=20)
    assert findings == [], (
        "a contract whose paths do not re-read storage in a loop must not be flagged"
    )


# --------------------------------------------------------------------------- #
# Distinct from SWC-113: the gas-limit detector does NOT require an external call,
# and the DoS-with-failed-call detector does NOT fire on a callless storage loop.
# --------------------------------------------------------------------------- #
def test_distinct_from_dos_failed_call():
    # the vulnerable fixture has no external CALL, so SWC-113 stays silent while
    # SWC-128 fires — proving the two loop detectors key on different signals.
    gas_findings = analyze(_bc("gas-limit-dos-vuln"), ["gas-limit-dos"], max_depth=LOOP_DEPTH)
    call_findings = analyze(_bc("gas-limit-dos-vuln"), ["dos-failed-call"], max_depth=LOOP_DEPTH)
    assert gas_findings, "SWC-128 should fire on the storage-bounded loop"
    assert call_findings == [], "SWC-113 must not fire (no external call in the loop)"


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_gas_limit_surfaces_under_all_checks():
    findings = analyze(_bc("gas-limit-dos-vuln"), ["all"], max_depth=LOOP_DEPTH)
    cats = {f["category"] for f in findings}
    assert "block_gas_limit_dos" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_gas_limit_has_report_title():
    from oracle.report import _TITLE

    assert "block_gas_limit_dos" in _TITLE
    assert "DoS With Block Gas Limit" in _TITLE["block_gas_limit_dos"]
    assert "SWC-128" in _TITLE["block_gas_limit_dos"]


def test_gas_limit_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("gas-limit-dos-vuln"), ["gas-limit-dos"], max_depth=LOOP_DEPTH)
    md = format_h1md(findings, "gas-limit-dos-vuln.sol")
    assert "DoS With Block Gas Limit" in md


def test_gas_limit_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("gas-limit-dos-vuln"), ["gas-limit-dos"], max_depth=LOOP_DEPTH)
    doc = json.loads(format_sarif(findings, "gas-limit-dos-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "block_gas_limit_dos" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "block_gas_limit_dos" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("gas-limit-dos-vuln"), (
        "real-engine walk must find the loop-bound storage read"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("gas-limit-dos-safe") == []
