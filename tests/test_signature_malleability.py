"""Tests for oracle's signature-malleability detector (SWC-117, "Signature
Malleability").

An ECDSA signature over secp256k1 is malleable: for every valid `(v, r, s)`
the negation `(v', r, n-s)` is also a valid signature for the same message
and the same signer. Any contract that uses the raw signature bytes as an
identity (e.g. a `mapping(bytes32 => bool) usedSigs` keyed on `keccak256(sig)`)
must enforce the EIP-2 lower-`s`-half bound to make each valid signature
uniquely representable; without that bound an attacker can mint a bit-different
twin of any authorised signature and replay the action.

The discriminating signal is a bytecode-level conjunction (mirrors the R31
SWC-121 SignatureReplayDetector's structural impossibility approach, applied
to a different absent bytecode signal):
  (1) the contract reaches a STATICCALL / CALL whose concrete target address
      is `1` (the ECRECOVER precompile), AND
  (2) the contract's disassembly contains NO PUSH-family immediate equal to
      `secp256k1n/2`
      (`0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`)
      — the unique EIP-2 / SEC 1 §4.1.4 malleability bound — so it cannot
      possibly enforce the canonical lower-`s`-half check.

Two fixtures pin the behaviour:
  * signature-malleability-vuln.sol — `claim(...)` recovers a signer over a
    hash with no `s`-bound check. Bytecode: ECRECOVER present, secp256k1n/2
    absent. MUST be flagged.
  * signature-malleability-safe.sol — `claim(...)` recovers a signer after a
    `require(uint256(s) <= secp256k1n/2)`. Bytecode: ECRECOVER present,
    secp256k1n/2 present as a PUSH32 immediate. MUST NOT be flagged (the
    STATICCALL to address 1 is still in the bytecode, so this test proves the
    detector keys on the *absence* of the bound constant alongside the
    ecrecover, not on the ecrecover call alone).

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
    SignatureMalleabilityDetector,
    _has_secp256k1_half_n,
    _SECP256K1_HALF_N,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=64):
    """Run only the signature-malleability detector and return its raw
    candidates (before the Z3 reachability boundary), isolating detector
    logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = SignatureMalleabilityDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Constant pins the exact mathematical value the detector keys on. A typo or
# a refactor that drifts off the canonical EIP-2 bound silently breaks every
# `safe` fixture acquittal in oracle's history.
# --------------------------------------------------------------------------- #
def test_secp256k1_half_n_constant():
    assert _SECP256K1_HALF_N == (
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    )


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_signature_malleability_detector_is_registered():
    assert "signature-malleability" in DETECTOR_REGISTRY
    assert (
        DETECTOR_REGISTRY["signature-malleability"]
        is SignatureMalleabilityDetector
    )


def test_signature_malleability_exposed_on_cli_choices():
    from oracle.cli import CHECK_CHOICES

    assert "signature-malleability" in CHECK_CHOICES


def test_signature_malleability_severity_is_medium():
    # SWC-117 is medium: the bug requires the contract to *use* raw signature
    # bytes as an identity (a dedup mapping, an off-chain relayer queue keyed
    # on sig bytes, etc.) — a real and named vulnerability class but narrower
    # than the immediate-fund-loss high-severity classes.
    assert SEVERITY["signature_malleability"] == "medium"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes / constants under test (guards
# against a future solc change silently optimising the precompile call or
# the bound constant away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_calls_ecrecover_without_bound():
    insts = Disassembly(_bc("signature-malleability-vuln")).instructions
    mnems = [i.mnemonic for i in insts]
    assert "STATICCALL" in mnems, (
        "the vulnerable fixture must STATICCALL ecrecover"
    )
    assert not any(
        getattr(i, "operand", None) == _SECP256K1_HALF_N for i in insts
    ), (
        "the vulnerable fixture must emit NO PUSH of secp256k1n/2 — that "
        "absence is exactly the SWC-117 impossibility signal"
    )


def test_safe_fixture_calls_ecrecover_with_bound():
    insts = Disassembly(_bc("signature-malleability-safe")).instructions
    mnems = [i.mnemonic for i in insts]
    assert "STATICCALL" in mnems, (
        "the safe fixture must still STATICCALL ecrecover"
    )
    assert any(
        getattr(i, "operand", None) == _SECP256K1_HALF_N for i in insts
    ), (
        "the safe fixture must emit secp256k1n/2 as a PUSH immediate — "
        "proves the detector keys on the *absence* of the bound constant "
        "alongside the ecrecover, not on the ecrecover call alone"
    )


# --------------------------------------------------------------------------- #
# _has_secp256k1_half_n helper: cached scan of the disassembly.
# --------------------------------------------------------------------------- #
def test_has_secp256k1_half_n_helper_discriminates():
    vm_vuln = SymbolicVM(_bc("signature-malleability-vuln"), max_depth=4)
    vm_safe = SymbolicVM(_bc("signature-malleability-safe"), max_depth=4)
    assert _has_secp256k1_half_n(vm_vuln) is False
    assert _has_secp256k1_half_n(vm_safe) is True


def test_has_secp256k1_half_n_is_cached_on_vm():
    vm = SymbolicVM(_bc("signature-malleability-safe"), max_depth=4)
    assert not hasattr(vm, "_secp_half_n_present")
    _has_secp256k1_half_n(vm)
    assert vm._secp_half_n_present is True
    # second call returns the cached value, not a fresh scan
    vm._secp_half_n_present = "sentinel"
    assert _has_secp256k1_half_n(vm) == "sentinel"


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): the ecrecover-without-bound is
# detected for the vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_signature_malleability_candidate():
    cands = _candidates("signature-malleability-vuln")
    assert cands, (
        "ecrecover without secp256k1n/2 must produce a candidate"
    )
    assert all(c["category"] == "signature_malleability" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)
    assert all(c["op"] in ("STATICCALL", "CALL") for c in cands)


def test_safe_produces_no_signature_malleability_candidate():
    assert _candidates("signature-malleability-safe") == [], (
        "a contract whose bytecode emits secp256k1n/2 has the capacity to "
        "enforce the EIP-2 malleability bound — the SWC-117 impossibility "
        "proof does not apply and the contract must not be flagged"
    )


def test_vuln_candidate_is_deduped_per_pc():
    # The same ecrecover call site reached via multiple paths must be reported
    # once across paths.
    cands = _candidates("signature-malleability-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), (
        "each ecrecover call site should be flagged at most once across "
        "paths"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(
        _bc("signature-malleability-vuln"),
        ["signature-malleability"],
        max_depth=64,
    )
    assert findings, (
        "vulnerable contract should yield a signature-malleability finding"
    )
    assert findings[0]["category"] == "signature_malleability"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["op"] in ("STATICCALL", "CALL")
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(
        _bc("signature-malleability-safe"),
        ["signature-malleability"],
        max_depth=64,
    )
    assert findings == [], (
        "an ecrecover-using contract that emits secp256k1n/2 must not be "
        "flagged"
    )


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that make external calls but never call
# the ECRECOVER precompile must not be flagged, regardless of whether their
# bytecode contains the bound constant.
# --------------------------------------------------------------------------- #
def test_no_false_positive_external_call_to_non_precompile():
    # ether-withdrawal-vuln makes a value-forwarding CALL to msg.sender (not
    # to a precompile address) and contains no secp256k1n/2 constant. SWC-117
    # must stay silent — the bug there is the missing caller guard (SWC-105),
    # not an absent malleability bound.
    findings = analyze(
        _bc("ether-withdrawal-vuln"),
        ["signature-malleability"],
        max_depth=40,
    )
    assert findings == [], (
        "a contract whose external calls do not target the ECRECOVER "
        "precompile must not be flagged for SWC-117"
    )


def test_no_false_positive_delegatecall():
    # delegatecall-vuln has DELEGATECALL with a calldata-derived target. The
    # detector's scope is STATICCALL/CALL only — DELEGATECALL/CALLCODE cannot
    # usefully invoke a precompile in the Solidity-source sense, so SWC-117
    # must stay silent. The bug there is SWC-112.
    findings = analyze(
        _bc("delegatecall-vuln"),
        ["signature-malleability"],
        max_depth=24,
    )
    assert findings == []


def test_no_false_positive_contract_that_makes_no_external_call():
    # arbitrary-jump-vuln exercises inline assembly and JUMPs but makes no
    # external call at all. SWC-117 must stay silent.
    findings = analyze(
        _bc("arbitrary-jump-vuln"),
        ["signature-malleability"],
        max_depth=40,
    )
    assert findings == []


# --------------------------------------------------------------------------- #
# Cross-detector separation: SWC-117 and SWC-121 fire on the same call sink
# (ECRECOVER) but for orthogonal bugs with orthogonal remediations.
#
#   * signature-replay-vuln: ECRECOVER + no CHAINID + no secp256k1n/2.
#     BOTH detectors fire (the contract is missing both a chain bind and a
#     malleability bound).
#   * signature-replay-safe: ECRECOVER + CHAINID present + no secp256k1n/2.
#     ONLY SWC-117 fires (binds to chain, but still accepts malleable sigs).
#   * signature-malleability-safe: ECRECOVER + no CHAINID + secp256k1n/2.
#     ONLY SWC-121 fires (bound enforced, but no chain bind).
# --------------------------------------------------------------------------- #
def test_swc121_fixture_also_lights_up_swc117():
    # The SWC-121 vuln fixture binds neither chain nor s-half, so both
    # detectors fire — confirms they are independent absent-signal checks
    # over the same call sink.
    findings = analyze(
        _bc("signature-replay-vuln"),
        ["signature-malleability"],
        max_depth=64,
    )
    assert findings, (
        "the SWC-121 vuln fixture also lacks the malleability bound and "
        "must light up SWC-117"
    )
    assert findings[0]["category"] == "signature_malleability"


def test_swc121_safe_still_lights_up_swc117():
    # The SWC-121 safe fixture binds the chain but does NOT enforce the
    # malleability bound. SWC-117 must still fire on it — proves the
    # detector is checking the bound constant, not co-incidentally tracking
    # CHAINID.
    findings = analyze(
        _bc("signature-replay-safe"),
        ["signature-malleability"],
        max_depth=64,
    )
    assert findings, (
        "SWC-121's safe fixture still lacks the EIP-2 bound, so SWC-117 "
        "must independently flag it"
    )


def test_signature_replay_detector_silent_on_swc117_safe():
    # signature-malleability-safe binds no chain (no CHAINID), so SWC-121
    # fires on it. This proves the two detectors check independent signals:
    # SWC-117 acquits the safe-malleability fixture; SWC-121 still flags it.
    findings = analyze(
        _bc("signature-malleability-safe"),
        ["signature-replay"],
        max_depth=64,
    )
    assert findings, (
        "signature-malleability-safe has ECRECOVER + no CHAINID, so SWC-121 "
        "fires — proves SWC-117 and SWC-121 key on orthogonal absent "
        "signals"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_signature_malleability_surfaces_under_all_checks():
    findings = analyze(
        _bc("signature-malleability-vuln"), ["all"], max_depth=64
    )
    cats = {f["category"] for f in findings}
    assert "signature_malleability" in cats


# --------------------------------------------------------------------------- #
# Report rendering: the new category has a human title in h1md and SARIF.
# --------------------------------------------------------------------------- #
def test_signature_malleability_has_report_title():
    from oracle.report import _TITLE

    assert "signature_malleability" in _TITLE
    assert "SWC-117" in _TITLE["signature_malleability"]


def test_signature_malleability_renders_in_h1md():
    from oracle.report import format_h1md

    findings = analyze(
        _bc("signature-malleability-vuln"),
        ["signature-malleability"],
        max_depth=64,
    )
    md = format_h1md(findings, "signature-malleability-vuln.sol")
    assert "SWC-117" in md


def test_signature_malleability_renders_in_sarif():
    from oracle.report import format_sarif

    findings = analyze(
        _bc("signature-malleability-vuln"),
        ["signature-malleability"],
        max_depth=64,
    )
    doc = json.loads(
        format_sarif(findings, "signature-malleability-vuln.sol")
    )
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "signature_malleability" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "signature_malleability" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("signature-malleability-vuln"), (
        "real-engine walk must find the ecrecover-without-bound"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("signature-malleability-safe") == []
