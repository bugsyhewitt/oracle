"""Tests for oracle's blockhash-randomness detector (SWC-120, "Weak Sources of
Randomness from Chain Attributes").

`blockhash(n)` is a cheap, tempting on-chain "random" source — lotteries,
raffles, NFT-mint orderings, and games reach for it to pick a winner or gate a
payout. It is not secure entropy: the block proposer can influence which block
is produced, and an attacker calling in the *same* transaction reads the same
`blockhash(n)` the victim contract uses, so they can compute the "random"
outcome in advance and only enter when they win. A contract that *branches
control flow* on a block hash is making a security decision an attacker can
predict or grind (SWC-120). Reading a block hash for display / book-keeping is
harmless; the bug is specifically deciding control flow on it.

The discriminating signal is that a path constraint references a symbolic
`blockhash_<pc>` leaf: an `if (uint(blockhash(n)) % N == ...)` guard compiles to
a comparison feeding a JUMPI, whose branch condition carries the block-hash
term. A non-control-flow read never enters a JUMPI condition, so it produces no
such constraint and must NOT fire.

Two fixtures pin the behaviour:
  * blockhash-randomness-vuln.sol — `play(uint256)` gates a payout on
    `uint256(blockhash(block.number - 1)) % 2 == 0` (a predictable/grindable
    randomness source). The path constraint references a `blockhash_<pc>` leaf.
    MUST be flagged.
  * blockhash-randomness-safe.sol — `lastHash()` *returns* the block hash (a view
    getter) and `deposit()` branches on a calldata argument. The BLOCKHASH opcode
    is still present (so the test proves the detector keys on the block hash
    *deciding control flow*, not on the opcode), but no branch is gated on it.
    MUST NOT be flagged.

This is the SWC-120 weak-randomness construct that the SWC-116
timestamp-dependence detector deliberately excluded (BLOCKHASH is a distinct
construct with its own remediation — commit-reveal / VRF). The two detectors
key on different symbol families and different SWC ids.

Like the rest of oracle's suite, the default run asserts the detector's
candidate/finding behaviour; the `slow` tests re-confirm against the real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, BlockhashRandomnessDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Depth at which the block-hash-dependent branch is reached on a path.
DEPTH = 40


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=DEPTH):
    """Run only the blockhash detector and return its raw candidates (before the
    Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = BlockhashRandomnessDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_blockhash_detector_is_registered():
    assert "blockhash-randomness" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["blockhash-randomness"] is BlockhashRandomnessDetector


def test_blockhash_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "blockhash-randomness" in CHECK_CHOICES


def test_blockhash_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["blockhash_randomness"] == "medium"


# --------------------------------------------------------------------------- #
# The opcode table now knows BLOCKHASH (0x40); before this rotation it was
# absent, so paths halted at it and a blockhash-gated branch was unreachable.
# --------------------------------------------------------------------------- #
def test_blockhash_opcode_in_table():
    from oracle.laser.opcodes import OPCODES

    assert 0x40 in OPCODES
    assert OPCODES[0x40][0] == "BLOCKHASH"


def test_disasm_decodes_blockhash():
    mnems = {i.mnemonic for i in Disassembly(_bc("blockhash-randomness-vuln")).instructions}
    assert "BLOCKHASH" in mnems, "0x40 must disassemble to BLOCKHASH, not UNKNOWN"


# --------------------------------------------------------------------------- #
# The VM records a block-hash read on BLOCKHASH so the detector can cheaply gate
# before its AST walk, and keeps the stack balanced (pops the block-number arg).
# --------------------------------------------------------------------------- #
def test_vm_sets_blockhash_loaded_on_blockhash():
    from oracle.laser.state import MachineState, WorldState
    from oracle.laser.vm import _bvv

    st = MachineState(WorldState())
    assert st.blockhash_loaded is False
    st.push(_bvv(7))  # the blockNumber operand BLOCKHASH consumes
    vm = SymbolicVM(_bc("blockhash-randomness-vuln"), max_depth=DEPTH)
    bh = next(i for i in vm.disasm.instructions if i.mnemonic == "BLOCKHASH")
    before = len(st.stack)
    vm._op_blockhash(st, bh)
    assert st.blockhash_loaded is True
    # net stack effect is zero: pops blockNumber, pushes the hash symbol.
    assert len(st.stack) == before


def test_blockhash_loaded_survives_clone():
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    st.blockhash_loaded = True
    st.blockhash_flagged = True
    new = st.clone()
    assert new.blockhash_loaded is True
    assert new.blockhash_flagged is True


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the BLOCKHASH read / branch away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_blockhash_and_branch():
    mnems = {i.mnemonic for i in Disassembly(_bc("blockhash-randomness-vuln")).instructions}
    assert "BLOCKHASH" in mnems, "the vulnerable fixture must read a block hash"
    assert "JUMPI" in mnems, "the vulnerable fixture must branch (gate on the value)"


def test_safe_fixture_emits_blockhash():
    mnems = {i.mnemonic for i in Disassembly(_bc("blockhash-randomness-safe")).instructions}
    assert "BLOCKHASH" in mnems, (
        "the safe fixture must still read a block hash (a view getter) so the "
        "test proves the detector keys on the value deciding control flow, not "
        "the opcode"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): a block-hash-gated branch is detected
# for the vulnerable contract and NOT for the safe (read-through) one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("blockhash-randomness-vuln")
    assert cands, "branching control flow on a block hash must produce a candidate"
    assert all(c["category"] == "blockhash_randomness" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("blockhash-randomness-safe") == [], (
        "a read-through view getter that returns blockhash(n) without gating "
        "control flow on it must not be flagged"
    )


def test_vuln_flags_each_guard_site_once():
    # the per-detector flagged-pc set must dedupe a guard site reached on many
    # paths down to a single finding per pc.
    cands = _candidates("blockhash-randomness-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each block-hash guard site reported once"


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("blockhash-randomness-vuln"), ["blockhash-randomness"], max_depth=DEPTH)
    assert findings, "vulnerable contract should yield a blockhash-randomness finding"
    assert findings[0]["category"] == "blockhash_randomness"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("blockhash-randomness-safe"), ["blockhash-randomness"], max_depth=DEPTH)
    assert findings == [], "read-through block-hash getter must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that never read a block hash, and a contract
# that reads the sender / a block value (not a block hash), must not be flagged.
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_blockhash():
    findings = analyze(_bc("tx-origin-vuln"), ["blockhash-randomness"], max_depth=20)
    assert findings == [], (
        "a contract that never reads a block hash must not be flagged for SWC-120"
    )


def test_no_false_positive_on_timestamp_guard():
    # SWC-120 is distinct from SWC-116: a block-VALUE (timestamp/number) guard is
    # not a block-HASH guard and must not be flagged by the blockhash detector.
    findings = analyze(_bc("timestamp-dependence-vuln"), ["blockhash-randomness"], max_depth=DEPTH)
    assert findings == [], (
        "a block-value (timestamp) dependence is SWC-116, not the blockhash "
        "weak-randomness construct (SWC-120)"
    )


# --------------------------------------------------------------------------- #
# Cross-detector separation: the timestamp detector must NOT claim a blockhash
# guard, keeping the two SWC ids cleanly separated.
# --------------------------------------------------------------------------- #
def test_timestamp_detector_does_not_flag_blockhash():
    findings = analyze(_bc("blockhash-randomness-vuln"), ["timestamp"], max_depth=DEPTH)
    assert findings == [], (
        "a blockhash weak-randomness dependence is SWC-120, not the block-value "
        "time proxy (SWC-116)"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_blockhash_surfaces_under_all_checks():
    findings = analyze(_bc("blockhash-randomness-vuln"), ["all"], max_depth=DEPTH)
    cats = {f["category"] for f in findings}
    assert "blockhash_randomness" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_blockhash_has_report_title():
    from oracle.report import _TITLE

    assert "blockhash_randomness" in _TITLE
    assert "Weak Randomness" in _TITLE["blockhash_randomness"]
    assert "SWC-120" in _TITLE["blockhash_randomness"]


def test_blockhash_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("blockhash-randomness-vuln"), ["blockhash-randomness"], max_depth=DEPTH)
    md = format_h1md(findings, "blockhash-randomness-vuln.sol")
    assert "Weak Randomness from Chain Attributes" in md


def test_blockhash_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("blockhash-randomness-vuln"), ["blockhash-randomness"], max_depth=DEPTH)
    doc = json.loads(format_sarif(findings, "blockhash-randomness-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "blockhash_randomness" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "blockhash_randomness" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("blockhash-randomness-vuln"), (
        "real-engine walk must find the block-hash-gated branch"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("blockhash-randomness-safe") == []
