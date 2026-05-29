"""Tests for oracle's transaction-order-dependence detector (SWC-114,
"Transaction Order Dependence").

The order in which transactions execute inside a block is chosen by the block
proposer / searcher (by fee), not by the contract. A contract whose outcome
depends on transaction ordering is exposed to front-running and sandwich
attacks. The single most direct on-chain signal of that exposure is a contract
that *branches control flow on `tx.gasprice`*: a misguided gas-price ceiling
meant to deter front-running (`require(tx.gasprice <= max)`) or a gas-price-
derived outcome. `tx.gasprice` is set freely by the sender and is the exact
lever that governs ordering, so gating logic on it is a security decision driven
by an attacker-controlled, ordering-determining value (SWC-114). Reading the gas
price for book-keeping / a view getter is harmless; the bug is deciding control
flow on it.

The discriminating signal is that a path constraint references the symbolic
`gasprice` leaf: an `if (tx.gasprice <= max)` guard compiles to a comparison
feeding a JUMPI, whose branch condition carries the gas-price term. A
non-control-flow read never enters a JUMPI condition, so it produces no such
constraint and must NOT fire.

Two fixtures pin the behaviour:
  * tx-order-vuln.sol — `claim(uint256,uint256)` gates a reward on
    `tx.gasprice <= maxGasPrice` (an ordering-dependent guard). The path
    constraint references the `gasprice` leaf. MUST be flagged.
  * tx-order-safe.sol — `currentGasPrice()` *returns* the gas price (a
    read-through view getter) and `deposit()` branches on a calldata argument.
    The GASPRICE opcode is still present (so the test proves the detector keys on
    the gas price *deciding control flow*, not on the opcode), but no branch is
    gated on it. MUST NOT be flagged.

This is distinct from the SWC-116 timestamp-dependence and SWC-120 blockhash
detectors: those key on a proposer-chosen time proxy / a randomness source;
SWC-114 is the *ordering* bug class, witnessed here by a gas-price-gated branch,
with its own remediation (commit-reveal / batch auctions). The detectors key on
different symbol families and different SWC ids.

Like the rest of oracle's suite, the default run asserts the detector's
candidate/finding behaviour; the `slow` tests re-confirm against the real engine.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    TransactionOrderDependenceDetector,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Depth at which the gas-price-dependent branch is reached on a path.
DEPTH = 40


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=DEPTH):
    """Run only the tx-order detector and return its raw candidates (before the
    Z3 reachability boundary), isolating detector logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = TransactionOrderDependenceDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_tx_order_detector_is_registered():
    assert "tx-order" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["tx-order"] is TransactionOrderDependenceDetector


def test_tx_order_exposed_on_cli_choices():
    # the CLI derives --check choices from the registry; the new token must show
    from oracle.cli import CHECK_CHOICES

    assert "tx-order" in CHECK_CHOICES


def test_tx_order_severity_is_medium():
    from oracle.laser.detectors import SEVERITY

    assert SEVERITY["transaction_order_dependence"] == "medium"


# --------------------------------------------------------------------------- #
# The VM records a gas-price read on GASPRICE so the detector can cheaply gate
# before its AST walk; the symbol name (`gasprice`) is unchanged.
# --------------------------------------------------------------------------- #
def test_vm_sets_gasprice_loaded_on_gasprice():
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    assert st.gasprice_loaded is False
    vm = SymbolicVM(_bc("tx-order-vuln"), max_depth=DEPTH)
    gp = next(i for i in vm.disasm.instructions if i.mnemonic == "GASPRICE")
    before = len(st.stack)
    vm._op_gasprice(st, gp)
    assert st.gasprice_loaded is True
    # GASPRICE pushes one word (no operand consumed).
    assert len(st.stack) == before + 1


def test_gasprice_loaded_survives_clone():
    from oracle.laser.state import MachineState, WorldState

    st = MachineState(WorldState())
    st.gasprice_loaded = True
    st.gasprice_flagged = True
    new = st.clone()
    assert new.gasprice_loaded is True
    assert new.gasprice_flagged is True


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the GASPRICE read / branch away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_gasprice_and_branch():
    mnems = {i.mnemonic for i in Disassembly(_bc("tx-order-vuln")).instructions}
    assert "GASPRICE" in mnems, "the vulnerable fixture must read the gas price"
    assert "JUMPI" in mnems, "the vulnerable fixture must branch (gate on the value)"


def test_safe_fixture_emits_gasprice():
    mnems = {i.mnemonic for i in Disassembly(_bc("tx-order-safe")).instructions}
    assert "GASPRICE" in mnems, (
        "the safe fixture must still read the gas price (a view getter) so the "
        "test proves the detector keys on the value deciding control flow, not "
        "the opcode"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): a gas-price-gated branch is detected for
# the vulnerable contract and NOT for the safe (read-through) one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_candidate():
    cands = _candidates("tx-order-vuln")
    assert cands, "branching control flow on tx.gasprice must produce a candidate"
    assert all(c["category"] == "transaction_order_dependence" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)


def test_safe_produces_no_candidate():
    assert _candidates("tx-order-safe") == [], (
        "a read-through view getter that returns tx.gasprice without gating "
        "control flow on it must not be flagged"
    )


def test_vuln_flags_each_guard_site_once():
    # the per-detector flagged-pc set must dedupe a guard site reached on many
    # paths down to a single finding per pc.
    cands = _candidates("tx-order-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), "each gas-price guard site reported once"


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("tx-order-vuln"), ["tx-order"], max_depth=DEPTH)
    assert findings, "vulnerable contract should yield a transaction-order finding"
    assert findings[0]["category"] == "transaction_order_dependence"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("tx-order-safe"), ["tx-order"], max_depth=DEPTH)
    assert findings == [], "read-through gas-price getter must not be flagged"


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that never read the gas price, and contracts
# that read a different chain attribute (timestamp / blockhash), must not be
# flagged by the gas-price detector.
# --------------------------------------------------------------------------- #
def test_no_false_positive_without_gasprice():
    findings = analyze(_bc("tx-origin-vuln"), ["tx-order"], max_depth=20)
    assert findings == [], (
        "a contract that never reads tx.gasprice must not be flagged for SWC-114"
    )


def test_no_false_positive_on_timestamp_guard():
    # SWC-114 is distinct from SWC-116: a block-value (timestamp) guard is not a
    # gas-price guard and must not be flagged by the tx-order detector.
    findings = analyze(_bc("timestamp-dependence-vuln"), ["tx-order"], max_depth=DEPTH)
    assert findings == [], (
        "a block-value (timestamp) dependence is SWC-116, not the gas-price "
        "transaction-order construct (SWC-114)"
    )


def test_no_false_positive_on_blockhash_guard():
    # SWC-114 is distinct from SWC-120: a blockhash randomness guard is not a
    # gas-price guard and must not be flagged by the tx-order detector.
    findings = analyze(_bc("blockhash-randomness-vuln"), ["tx-order"], max_depth=DEPTH)
    assert findings == [], (
        "a blockhash weak-randomness dependence is SWC-120, not the gas-price "
        "transaction-order construct (SWC-114)"
    )


# --------------------------------------------------------------------------- #
# Cross-detector separation: the timestamp / blockhash detectors must NOT claim
# a gas-price guard, keeping the SWC ids cleanly separated.
# --------------------------------------------------------------------------- #
def test_timestamp_detector_does_not_flag_gasprice():
    findings = analyze(_bc("tx-order-vuln"), ["timestamp"], max_depth=DEPTH)
    assert findings == [], (
        "a gas-price transaction-order dependence is SWC-114, not the block-value "
        "time proxy (SWC-116)"
    )


def test_blockhash_detector_does_not_flag_gasprice():
    findings = analyze(_bc("tx-order-vuln"), ["blockhash-randomness"], max_depth=DEPTH)
    assert findings == [], (
        "a gas-price transaction-order dependence is SWC-114, not the blockhash "
        "weak-randomness construct (SWC-120)"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_tx_order_surfaces_under_all_checks():
    findings = analyze(_bc("tx-order-vuln"), ["all"], max_depth=DEPTH)
    cats = {f["category"] for f in findings}
    assert "transaction_order_dependence" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_tx_order_has_report_title():
    from oracle.report import _TITLE

    assert "transaction_order_dependence" in _TITLE
    assert "Transaction Order Dependence" in _TITLE["transaction_order_dependence"]
    assert "SWC-114" in _TITLE["transaction_order_dependence"]


def test_tx_order_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("tx-order-vuln"), ["tx-order"], max_depth=DEPTH)
    md = format_h1md(findings, "tx-order-vuln.sol")
    assert "Transaction Order Dependence" in md


def test_tx_order_renders_in_sarif():
    import json

    from oracle.report import format_sarif

    findings = analyze(_bc("tx-order-vuln"), ["tx-order"], max_depth=DEPTH)
    doc = json.loads(format_sarif(findings, "tx-order-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "transaction_order_dependence" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "transaction_order_dependence" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("tx-order-vuln"), (
        "real-engine walk must find the gas-price-gated branch"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("tx-order-safe") == []
