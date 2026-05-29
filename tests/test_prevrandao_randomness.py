"""Tests for oracle's prevrandao-randomness detector (SWC-120, "Weak Sources of
Randomness from Chain Attributes").

`block.prevrandao` (the post-Merge name for the `DIFFICULTY` opcode, 0x44;
`block.difficulty` pre-Merge) is the single most-reached-for on-chain "random"
number after the Merge: lotteries, raffles, NFT-mint orderings, coin-flip
games, and airdrop selectors gate a winner / payout on it. It is not secure
entropy: the block proposer contributes the RANDAO reveal that produces the
value, and an attacker calling in the *same* transaction reads the same
`block.prevrandao` the victim contract uses, so they can compute the "random"
outcome in advance and only enter when they win. A contract that *branches
control flow* on prevrandao is making a security decision an attacker can
predict or grind (SWC-120). Reading prevrandao for display / book-keeping is
harmless; the bug is specifically deciding control flow on it.

The discriminating signal is that a path constraint references the symbolic
`prevrandao` leaf: an `if (block.prevrandao % N == ...)` guard compiles to a
comparison feeding a JUMPI, whose branch condition carries the prevrandao term.
A non-control-flow read never enters a JUMPI condition, so it produces no such
constraint and must NOT fire.

Two fixtures pin the behaviour:
  * prevrandao-randomness-vuln.sol — `play(uint256)` gates a payout on
    `uint256(block.prevrandao) % 2 == 0` (a predictable/grindable randomness
    source). The path constraint references the `prevrandao` leaf. MUST be
    flagged.
  * prevrandao-randomness-safe.sol — `currentRandao()` *returns*
    `block.prevrandao` (a view getter), `record()` stores it without branching
    on it, and `deposit()` branches on a calldata argument. The DIFFICULTY
    opcode is still present (so the test proves the detector keys on the value
    *deciding control flow*, not on the opcode), but no branch is gated on it.
    MUST NOT be flagged.

This is the SWC-120 weak-randomness construct keyed on a chain attribute
distinct from BLOCKHASH (the sibling SWC-120 detector keys on
`blockhash_<pc>`). `block.prevrandao` and `blockhash(n)` are different chain
attributes minted from different opcodes into different symbol families, and a
contract can misuse one without the other. Keeping the two detectors separate
keeps each keyed to one opcode and lets a triage team see exactly which chain
attribute a contract gambled on.

Like the rest of oracle's suite, the default run asserts the detector's
candidate/finding behaviour; the `slow` tests re-confirm against the real
engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import DETECTOR_REGISTRY, PrevrandaoRandomnessDetector
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Depth at which the prevrandao-dependent branch is reached on a path.
DEPTH = 40


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=DEPTH):
    """Run only the prevrandao detector and return its raw candidates (before
    the Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = PrevrandaoRandomnessDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_prevrandao_detector_is_registered():
    assert "prevrandao-randomness" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["prevrandao-randomness"] is PrevrandaoRandomnessDetector


def test_prevrandao_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "prevrandao-randomness" in CHECK_CHOICES


def test_prevrandao_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["prevrandao_randomness"] == "medium"


# --------------------------------------------------------------------------- #
# The opcode table already knows DIFFICULTY (0x44); this rotation gives it a
# dedicated detector instead of leaving it as an unflagged generic-env read.
# --------------------------------------------------------------------------- #
def test_difficulty_opcode_in_table():
    from oracle.laser.opcodes import OPCODES

    assert 0x44 in OPCODES
    assert OPCODES[0x44][0] == "DIFFICULTY"


def test_disasm_decodes_difficulty():
    mnems = {i.mnemonic for i in Disassembly(_bc("prevrandao-randomness-vuln")).instructions}
    assert "DIFFICULTY" in mnems, (
        "0x44 must disassemble to DIFFICULTY (block.prevrandao post-Merge)"
    )


# --------------------------------------------------------------------------- #
# The VM records a prevrandao read on DIFFICULTY so the detector can cheaply
# gate before its AST walk, and mints the stable `prevrandao` symbol name (the
# replay validator's env pusher is renamed in lockstep).
# --------------------------------------------------------------------------- #
def test_vm_sets_prevrandao_loaded_on_difficulty():
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    assert st.prevrandao_loaded is False
    vm = SymbolicVM(_bc("prevrandao-randomness-vuln"), max_depth=DEPTH)
    diff = next(i for i in vm.disasm.instructions if i.mnemonic == "DIFFICULTY")
    before = len(st.stack)
    vm._op_difficulty(st, diff)
    assert st.prevrandao_loaded is True
    # net stack effect is +1: DIFFICULTY pushes the prevrandao symbol.
    assert len(st.stack) == before + 1


def test_vm_mints_prevrandao_symbol_name():
    # the symbol family the detector greps for must be the stable `prevrandao`
    # leaf, not the legacy generic `difficulty` name.
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    vm = SymbolicVM(_bc("prevrandao-randomness-vuln"), max_depth=DEPTH)
    diff = next(i for i in vm.disasm.instructions if i.mnemonic == "DIFFICULTY")
    vm._op_difficulty(st, diff)
    pushed = st.stack[-1]
    # the symbol's printable form should mention "prevrandao".
    assert "prevrandao" in str(pushed)


def test_prevrandao_loaded_survives_clone():
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    st.prevrandao_loaded = True
    st.prevrandao_flagged = True
    new = st.clone()
    assert new.prevrandao_loaded is True
    assert new.prevrandao_flagged is True


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the DIFFICULTY read / branch away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_difficulty_and_branch():
    mnems = {i.mnemonic for i in Disassembly(_bc("prevrandao-randomness-vuln")).instructions}
    assert "DIFFICULTY" in mnems, (
        "the vulnerable fixture must read block.prevrandao (DIFFICULTY)"
    )
    assert "JUMPI" in mnems, "the vulnerable fixture must branch (gate on the value)"


def test_safe_fixture_emits_difficulty():
    mnems = {i.mnemonic for i in Disassembly(_bc("prevrandao-randomness-safe")).instructions}
    assert "DIFFICULTY" in mnems, (
        "the safe fixture must still read block.prevrandao (a view getter / "
        "book-keeping store) so the test proves the detector keys on the value "
        "deciding control flow, not the opcode"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): a prevrandao-gated branch is detected
# for the vulnerable contract and NOT for the safe (read-through) one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("prevrandao-randomness-vuln")
    assert cands, "branching control flow on prevrandao must produce a candidate"
    assert all(c["category"] == "prevrandao_randomness" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("prevrandao-randomness-safe") == [], (
        "a read-through view getter / non-branching store of block.prevrandao "
        "must not be flagged"
    )


def test_vuln_flags_each_guard_site_once():
    # the per-detector flagged-pc set must dedupe a guard site reached on many
    # paths down to a single finding per pc.
    cands = _candidates("prevrandao-randomness-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each prevrandao guard site reported once"


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("prevrandao-randomness-vuln"), ["prevrandao-randomness"], max_depth=DEPTH)
    assert findings, "vulnerable contract should yield a prevrandao-randomness finding"
    assert findings[0]["category"] == "prevrandao_randomness"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("prevrandao-randomness-safe"), ["prevrandao-randomness"], max_depth=DEPTH)
    assert findings == [], "read-through prevrandao getter / store must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that never read prevrandao, and contracts
# that read a different chain attribute (a block-VALUE or BLOCKHASH), must not
# be flagged by the prevrandao detector.
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_prevrandao():
    findings = analyze(_bc("tx-origin-vuln"), ["prevrandao-randomness"], max_depth=20)
    assert findings == [], (
        "a contract that never reads block.prevrandao must not be flagged for "
        "the prevrandao-randomness construct"
    )


def test_no_false_positive_on_timestamp_guard():
    # SWC-120-prevrandao is distinct from SWC-116: a block-VALUE
    # (timestamp/number) guard is not a prevrandao guard and must not be flagged
    # by the prevrandao detector.
    findings = analyze(_bc("timestamp-dependence-vuln"), ["prevrandao-randomness"], max_depth=DEPTH)
    assert findings == [], (
        "a block-value (timestamp) dependence is SWC-116, not the prevrandao "
        "weak-randomness construct"
    )


def test_no_false_positive_on_blockhash_guard():
    # the two SWC-120 detectors key on different chain attributes (DIFFICULTY vs
    # BLOCKHASH); a blockhash-gated branch must NOT be flagged by the prevrandao
    # detector.
    findings = analyze(_bc("blockhash-randomness-vuln"), ["prevrandao-randomness"], max_depth=DEPTH)
    assert findings == [], (
        "a blockhash weak-randomness dependence is the BLOCKHASH construct, "
        "not the prevrandao construct — different opcode, different symbol "
        "family"
    )


# --------------------------------------------------------------------------- #
# Cross-detector separation: the blockhash and timestamp detectors must NOT
# claim a prevrandao guard, keeping the chain-attribute constructs cleanly
# separated.
# --------------------------------------------------------------------------- #
def test_blockhash_detector_does_not_flag_prevrandao():
    findings = analyze(_bc("prevrandao-randomness-vuln"), ["blockhash-randomness"], max_depth=DEPTH)
    assert findings == [], (
        "a prevrandao weak-randomness dependence is the DIFFICULTY construct, "
        "not the BLOCKHASH construct"
    )


def test_timestamp_detector_does_not_flag_prevrandao():
    findings = analyze(_bc("prevrandao-randomness-vuln"), ["timestamp"], max_depth=DEPTH)
    assert findings == [], (
        "a prevrandao weak-randomness dependence is SWC-120, not the block-"
        "value time proxy (SWC-116)"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_prevrandao_surfaces_under_all_checks():
    findings = analyze(_bc("prevrandao-randomness-vuln"), ["all"], max_depth=DEPTH)
    cats = {f["category"] for f in findings}
    assert "prevrandao_randomness" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_prevrandao_has_report_title():
    from oracle.report import _TITLE

    assert "prevrandao_randomness" in _TITLE
    assert "prevrandao" in _TITLE["prevrandao_randomness"]
    assert "SWC-120" in _TITLE["prevrandao_randomness"]


def test_prevrandao_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("prevrandao-randomness-vuln"), ["prevrandao-randomness"], max_depth=DEPTH)
    md = format_h1md(findings, "prevrandao-randomness-vuln.sol")
    assert "prevrandao" in md


def test_prevrandao_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("prevrandao-randomness-vuln"), ["prevrandao-randomness"], max_depth=DEPTH)
    doc = json.loads(format_sarif(findings, "prevrandao-randomness-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "prevrandao_randomness" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "prevrandao_randomness" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("prevrandao-randomness-vuln"), (
        "real-engine walk must find the prevrandao-gated branch"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("prevrandao-randomness-safe") == []
