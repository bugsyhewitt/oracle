"""Tests for oracle's write-arbitrary-storage detector (SWC-124, "Write to
Arbitrary Storage Location").

The EVM addresses storage by 256-bit keys. In well-formed compiler output every
SSTORE key is either a compile-time constant (a top-level state variable's
slot) or a `keccak256`-derived word (a `mapping(...)` / dynamic-array element's
slot, whose preimage is compiler-controlled). An attacker cannot steer those
keys. Inline-assembly `sstore(key, val)` with a calldata-supplied `key`, or any
path that loads a raw storage slot index from calldata and stores through it,
lets an attacker write to ANY slot — overwriting `owner`, upgrading a
contract's implementation, or corrupting arbitrary state. That is SWC-124.

The discriminating signal is that the SSTORE *key operand* is derived from
calldata (attacker-controllable). An SSTORE to a compile-time constant slot or
to a `keccak256`-derived mapping slot is ordinary, compiler-generated control
flow and must NOT be flagged.

Two fixtures pin the behaviour:
  * write-arbitrary-storage-vuln.sol — `set(uint256 key, uint256 val)` lowers
    to an SSTORE whose key is loaded directly from calldata. MUST be flagged.
  * write-arbitrary-storage-safe.sol — several SSTOREs to a constant slot and
    to mapping (keccak-derived) slots; no SSTORE key is taken from calldata.
    MUST NOT be flagged (the SSTORE opcodes are still present, so this proves
    the detector keys on the calldata-derived key, not the opcode).

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
    WriteArbitraryStorageDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=40):
    """Run only the write-arbitrary-storage detector and return its raw
    candidates (before the Z3 reachability boundary), isolating detector logic
    from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = WriteArbitraryStorageDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_write_arbitrary_storage_detector_is_registered():
    assert "write-arbitrary-storage" in DETECTOR_REGISTRY
    assert (
        DETECTOR_REGISTRY["write-arbitrary-storage"]
        is WriteArbitraryStorageDetector
    )


def test_write_arbitrary_storage_exposed_on_cli_choices():
    from oracle.cli import CHECK_CHOICES

    assert "write-arbitrary-storage" in CHECK_CHOICES


def test_write_arbitrary_storage_severity_is_high():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["write_arbitrary_storage"] == "high"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test.
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_sstore_and_calldataload():
    mnems = {
        i.mnemonic
        for i in Disassembly(_bc("write-arbitrary-storage-vuln")).instructions
    }
    assert "SSTORE" in mnems, "the vulnerable fixture must SSTORE"
    assert "CALLDATALOAD" in mnems, "the SSTORE key must come from calldata"


def test_safe_fixture_emits_sstore():
    mnems = [
        i.mnemonic
        for i in Disassembly(_bc("write-arbitrary-storage-safe")).instructions
    ]
    assert mnems.count("SSTORE") >= 1, (
        "the safe fixture must still emit SSTORE (to constant / keccak-derived "
        "slots) so the test proves the detector keys on the calldata-derived "
        "key, not the opcode"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the calldata-derived SSTORE key is
# detected for the vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_write_arbitrary_storage_candidate():
    cands = _candidates("write-arbitrary-storage-vuln")
    assert cands, "a calldata-supplied SSTORE key must produce a candidate"
    assert all(c["category"] == "write_arbitrary_storage" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] == "SSTORE" for c in cands)


def test_safe_produces_no_write_arbitrary_storage_candidate():
    assert _candidates("write-arbitrary-storage-safe") == [], (
        "SSTOREs to compile-time-constant slots and to keccak256-derived "
        "mapping slots are not attacker-steerable and must not be flagged"
    )


def test_vuln_candidate_is_deduped_per_pc():
    cands = _candidates("write-arbitrary-storage-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), (
        "each SSTORE site should be flagged at most once across paths"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(
        _bc("write-arbitrary-storage-vuln"),
        ["write-arbitrary-storage"],
        max_depth=40,
    )
    assert findings, (
        "vulnerable contract should yield a write-arbitrary-storage finding"
    )
    assert findings[0]["category"] == "write_arbitrary_storage"
    assert findings[0]["severity"] == "high"
    assert findings[0]["op"] == "SSTORE"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(
        _bc("write-arbitrary-storage-safe"),
        ["write-arbitrary-storage"],
        max_depth=40,
    )
    assert findings == [], (
        "constant-slot and keccak-derived-slot SSTOREs must not be flagged"
    )


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that have other vulnerability classes but
# whose SSTOREs are all compiler-controlled must not be flagged for SWC-124.
# --------------------------------------------------------------------------- #
def test_no_false_positive_on_access_control_fixture():
    # access-control-vuln SSTOREs `owner = msg.sender` to a constant slot —
    # a different bug class (SWC-115/105 family) but not SWC-124.
    findings = analyze(
        _bc("access-control-vuln"), ["write-arbitrary-storage"], max_depth=24
    )
    assert findings == [], (
        "an unprotected `owner = msg.sender` SSTORE writes to a constant slot "
        "(its own state-variable slot), not to a calldata-supplied key — that "
        "is SWC-105/115, not SWC-124"
    )


def test_no_false_positive_on_arbitrary_jump_fixture():
    # arbitrary-jump-vuln overwrites a function pointer (a JUMP target),
    # not an SSTORE key.
    findings = analyze(
        _bc("arbitrary-jump-vuln"), ["write-arbitrary-storage"], max_depth=40
    )
    assert findings == [], (
        "a calldata-derived JUMP destination is SWC-127, not SWC-124 — the "
        "two detectors key on different sinks"
    )


# --------------------------------------------------------------------------- #
# Cross-detector separation: the broader `storage-write` detector (which flags
# *any* symbolic SSTORE key including keccak-derived mapping slots) and the
# new SWC-124 detector key on different signals. The vuln fixture trips both
# (its key is symbolic AND calldata-derived); the safe fixture must trip
# neither for SWC-124 — but `storage-write` may fire on the keccak-derived
# mapping access. We only assert that SWC-124 stays quiet on safe.
# --------------------------------------------------------------------------- #
def test_storage_write_and_write_arbitrary_storage_are_distinct():
    # On the safe fixture: SWC-124 must be silent (proven above). The broader
    # `storage-write` detector keys on any symbolic key, so the keccak-derived
    # mapping slot fires — confirming the two detectors carve different bands.
    swc124 = analyze(
        _bc("write-arbitrary-storage-safe"),
        ["write-arbitrary-storage"],
        max_depth=40,
    )
    broad = analyze(
        _bc("write-arbitrary-storage-safe"), ["storage-write"], max_depth=40
    )
    assert swc124 == [], "SWC-124 must not flag a keccak-derived mapping slot"
    assert broad, (
        "the broader `storage-write` detector keys on any symbolic key, so it "
        "should fire on the keccak-derived mapping slot — proving the two "
        "detectors carve different signal bands"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_write_arbitrary_storage_surfaces_under_all_checks():
    findings = analyze(
        _bc("write-arbitrary-storage-vuln"), ["all"], max_depth=40
    )
    cats = {f["category"] for f in findings}
    assert "write_arbitrary_storage" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_write_arbitrary_storage_has_report_title():
    from oracle.report import _TITLE

    assert "write_arbitrary_storage" in _TITLE
    assert "Write to Arbitrary Storage Location" in _TITLE[
        "write_arbitrary_storage"
    ]
    assert "SWC-124" in _TITLE["write_arbitrary_storage"]


def test_write_arbitrary_storage_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(
        _bc("write-arbitrary-storage-vuln"),
        ["write-arbitrary-storage"],
        max_depth=40,
    )
    md = format_h1md(findings, "write-arbitrary-storage-vuln.sol")
    assert "Write to Arbitrary Storage Location" in md


def test_write_arbitrary_storage_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(
        _bc("write-arbitrary-storage-vuln"),
        ["write-arbitrary-storage"],
        max_depth=40,
    )
    doc = json.loads(
        format_sarif(findings, "write-arbitrary-storage-vuln.sol")
    )
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "write_arbitrary_storage" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "write_arbitrary_storage" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("write-arbitrary-storage-vuln"), (
        "real-engine walk must find the calldata-derived SSTORE key"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("write-arbitrary-storage-safe") == []
