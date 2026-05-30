"""Tests for oracle's signature-replay detector (SWC-121, "Missing Protection
against Signature Replay Attacks" — the cross-chain replay surface).

A contract that authenticates via `ecrecover(...)` over a payload that does
NOT include `block.chainid` accepts the same signature on every chain it is
deployed on. An attacker lifts a sig from one chain and replays it on another
(mainnet → fork chain, L1 → L2 mirror, post-fork wallet → its twin — the
canonical post-DAO-fork drain class).

The discriminating signal is a bytecode-level conjunction:
  (1) the contract reaches a STATICCALL / CALL whose concrete target address
      is `1` (the ECRECOVER precompile), AND
  (2) the contract's disassembly contains NO `CHAINID` (0x46) opcode anywhere
      — so the contract cannot possibly bind a signature to its deploy chain.

Two fixtures pin the behaviour:
  * signature-replay-vuln.sol — `claim(...)` recovers a signer over a hash
    that omits `block.chainid`. Bytecode: ECRECOVER present, CHAINID absent.
    MUST be flagged.
  * signature-replay-safe.sol — `claim(...)` recovers a signer over a hash
    that includes `block.chainid`. Bytecode: ECRECOVER present, CHAINID
    present. MUST NOT be flagged (the STATICCALL to address 1 is still in
    the bytecode, so this test proves the detector keys on the *absence* of
    CHAINID alongside the ecrecover, not on the ecrecover call alone).

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm against
the real engine.
"""

import json
import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    SEVERITY,
    SignatureReplayDetector,
    _has_chainid_opcode,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=64):
    """Run only the signature-replay detector and return its raw candidates
    (before the Z3 reachability boundary), isolating detector logic from the
    solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = SignatureReplayDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_signature_replay_detector_is_registered():
    assert "signature-replay" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["signature-replay"] is SignatureReplayDetector


def test_signature_replay_exposed_on_cli_choices():
    from oracle.cli import CHECK_CHOICES

    assert "signature-replay" in CHECK_CHOICES


def test_signature_replay_severity_is_high():
    assert SEVERITY["signature_replay"] == "high"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes under test (guards against a future
# solc change silently optimising the precompile call or chain-id read away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_calls_ecrecover_without_chainid():
    mnems = [i.mnemonic for i in Disassembly(_bc("signature-replay-vuln")).instructions]
    assert "STATICCALL" in mnems, "the vulnerable fixture must STATICCALL ecrecover"
    assert "CHAINID" not in mnems, (
        "the vulnerable fixture must emit NO CHAINID — that absence is "
        "exactly the SWC-121 impossibility signal the detector keys on"
    )


def test_safe_fixture_calls_ecrecover_with_chainid():
    mnems = [i.mnemonic for i in Disassembly(_bc("signature-replay-safe")).instructions]
    assert "STATICCALL" in mnems, "the safe fixture must still STATICCALL ecrecover"
    assert "CHAINID" in mnems, (
        "the safe fixture must emit CHAINID — proves the detector keys on "
        "the *absence* of CHAINID alongside the ecrecover, not on ecrecover"
    )


# --------------------------------------------------------------------------- #
# _has_chainid_opcode helper: cached scan of the disassembly.
# --------------------------------------------------------------------------- #
def test_has_chainid_opcode_helper_discriminates():
    vm_vuln = SymbolicVM(_bc("signature-replay-vuln"), max_depth=4)
    vm_safe = SymbolicVM(_bc("signature-replay-safe"), max_depth=4)
    assert _has_chainid_opcode(vm_vuln) is False
    assert _has_chainid_opcode(vm_safe) is True


def test_has_chainid_opcode_is_cached_on_vm():
    vm = SymbolicVM(_bc("signature-replay-safe"), max_depth=4)
    assert not hasattr(vm, "_chainid_present")
    _has_chainid_opcode(vm)
    assert vm._chainid_present is True
    # second call returns the cached value, not a fresh scan
    vm._chainid_present = "sentinel"
    assert _has_chainid_opcode(vm) == "sentinel"


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the ecrecover-without-chainid is
# detected for the vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_signature_replay_candidate():
    cands = _candidates("signature-replay-vuln")
    assert cands, "ecrecover without CHAINID must produce a candidate"
    assert all(c["category"] == "signature_replay" for c in cands)
    assert all(c["severity"] == "high" for c in cands)
    assert all(c["op"] in ("STATICCALL", "CALL") for c in cands)


def test_safe_produces_no_signature_replay_candidate():
    assert _candidates("signature-replay-safe") == [], (
        "a contract whose bytecode emits CHAINID has the capacity to bind a "
        "signature to its chain — the SWC-121 impossibility proof does not "
        "apply and the contract must not be flagged"
    )


def test_vuln_candidate_is_deduped_per_pc():
    # The same ecrecover call site reached via multiple paths must be reported
    # once across paths.
    cands = _candidates("signature-replay-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), (
        "each ecrecover call site should be flagged at most once across paths"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(_bc("signature-replay-vuln"), ["signature-replay"], max_depth=64)
    assert findings, "vulnerable contract should yield a signature-replay finding"
    assert findings[0]["category"] == "signature_replay"
    assert findings[0]["severity"] == "high"
    assert findings[0]["op"] in ("STATICCALL", "CALL")
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(_bc("signature-replay-safe"), ["signature-replay"], max_depth=64)
    assert findings == [], (
        "an ecrecover-using contract that emits CHAINID must not be flagged"
    )


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that make external calls but never call
# the ECRECOVER precompile must not be flagged, regardless of whether their
# bytecode emits CHAINID.
# --------------------------------------------------------------------------- #
def test_no_false_positive_external_call_to_non_precompile():
    # ether-withdrawal-vuln makes a value-forwarding CALL to msg.sender (not
    # to a precompile address). It also does not emit CHAINID. SWC-121 must
    # stay silent — the bug there is the missing caller guard (SWC-105), not
    # an absent signature chain bind.
    findings = analyze(_bc("ether-withdrawal-vuln"), ["signature-replay"], max_depth=40)
    assert findings == [], (
        "a contract whose external calls do not target the ECRECOVER "
        "precompile must not be flagged for SWC-121"
    )


def test_no_false_positive_delegatecall():
    # delegatecall-vuln has DELEGATECALL with a calldata-derived target. The
    # detector's scope is STATICCALL/CALL only — DELEGATECALL/CALLCODE cannot
    # usefully invoke a precompile in the Solidity-source sense, so SWC-121
    # must stay silent here. The bug there is SWC-112.
    findings = analyze(_bc("delegatecall-vuln"), ["signature-replay"], max_depth=24)
    assert findings == []


def test_no_false_positive_contract_that_makes_no_external_call():
    # arbitrary-jump-vuln exercises inline assembly and JUMPs but makes no
    # external call at all. SWC-121 must stay silent.
    findings = analyze(_bc("arbitrary-jump-vuln"), ["signature-replay"], max_depth=40)
    assert findings == []


# --------------------------------------------------------------------------- #
# Cross-detector separation: the SWC-121 vuln fixture does not (and should
# not) light up the SWC-112 delegatecall detector or the unrelated SWC-114
# tx-order detector — each detector keys on its own sink.
# --------------------------------------------------------------------------- #
def test_delegatecall_detector_does_not_claim_signature_replay():
    findings = analyze(_bc("signature-replay-vuln"), ["delegatecall"], max_depth=64)
    assert findings == [], (
        "the signature-replay fixture makes no delegatecall, so SWC-112 must "
        "stay silent — the two detectors key on different sinks"
    )


def test_tx_order_detector_does_not_claim_signature_replay():
    findings = analyze(_bc("signature-replay-vuln"), ["tx-order"], max_depth=64)
    assert findings == [], (
        "the signature-replay fixture does not gate on tx.gasprice, so "
        "SWC-114 must stay silent"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_signature_replay_surfaces_under_all_checks():
    findings = analyze(_bc("signature-replay-vuln"), ["all"], max_depth=64)
    cats = {f["category"] for f in findings}
    assert "signature_replay" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_signature_replay_has_report_title():
    from oracle.report import _TITLE

    assert "signature_replay" in _TITLE
    assert "SWC-121" in _TITLE["signature_replay"]


def test_signature_replay_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(_bc("signature-replay-vuln"), ["signature-replay"], max_depth=64)
    md = format_h1md(findings, "signature-replay-vuln.sol")
    assert "SWC-121" in md


def test_signature_replay_renders_in_sarif():
    from oracle.report import format_sarif

    findings = analyze(_bc("signature-replay-vuln"), ["signature-replay"], max_depth=64)
    doc = json.loads(format_sarif(findings, "signature-replay-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "signature_replay" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "signature_replay" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("signature-replay-vuln"), (
        "real-engine walk must find the ecrecover-without-chainid"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("signature-replay-safe") == []
