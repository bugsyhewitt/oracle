"""Tests for oracle's signature-malleability detector (SWC-117, "Signature
Malleability").

A contract that authenticates via `ecrecover(...)` and treats the raw
`(r, s, v)` signature triple as a uniqueness key, without enforcing the
EIP-2 `s <= secp256k1n / 2` bound, accepts both a valid signature and its
malleable twin `(r, n - s, v ^ 1)` as distinct "fresh" signatures. The
twin recovers the same signer over the same message, so an attacker
observes a victim's signed action, flips the signature to its twin, and
replays it past the uniqueness check (the canonical SWC-117 nonce-by-sig
bug).

The discriminating signal is a bytecode-level conjunction (the same shape
as the SWC-121 `SignatureReplayDetector`, with a different structural
literal):
  (1) the contract reaches a STATICCALL / CALL whose concrete target
      address is `1` (the ECRECOVER precompile), AND
  (2) the contract's disassembly contains NO `PUSH32` of the
      secp256k1n / 2 constant
      (0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)
      anywhere — so the contract demonstrably cannot enforce the EIP-2
      malleability bound.

Two fixtures pin the behaviour:
  * signature-malleability-vuln.sol — `claim(...)` recovers a signer and
    keys uniqueness off `keccak256(r,s,v)` with no `s`-bound check.
    Bytecode: ECRECOVER present, PUSH32 of n / 2 absent. MUST be flagged.
  * signature-malleability-safe.sol — `claim(...)` enforces
    `require(uint256(s) <= secp256k1n/2)` before the recover. Bytecode:
    ECRECOVER present, PUSH32 of n / 2 present. MUST NOT be flagged (the
    STATICCALL to address 1 is still in the bytecode, so this test proves
    the detector keys on the *absence* of the n / 2 PUSH32 alongside the
    ecrecover, not on the ecrecover call alone).

Like the rest of oracle's suite, the default (Z3-mocked) run asserts the
detector's candidate/finding behaviour; the `slow` tests re-confirm
against the real engine.
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
    _SECP256K1N_HALF,
    _has_secp256k1n_half_constant,
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
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_signature_malleability_detector_is_registered():
    assert "signature-malleability" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["signature-malleability"] is SignatureMalleabilityDetector


def test_signature_malleability_exposed_on_cli_choices():
    from oracle.cli import CHECK_CHOICES

    assert "signature-malleability" in CHECK_CHOICES


def test_signature_malleability_severity_is_medium():
    # SWC-117 is a medium-severity replay enabler: the bug does not let an
    # attacker forge a signature out of thin air, it lets them produce a
    # second valid bit-form of one they have already observed, bypassing a
    # naive sig-bytes-as-nonce uniqueness check.
    assert SEVERITY["signature_malleability"] == "medium"


# --------------------------------------------------------------------------- #
# Fixtures actually contain the bytecode signal under test (guards against a
# future solc change silently optimising the PUSH32 of the bound constant
# away, or stripping the ecrecover STATICCALL).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_calls_ecrecover_without_s_bound_constant():
    insts = Disassembly(_bc("signature-malleability-vuln")).instructions
    mnems = [i.mnemonic for i in insts]
    assert "STATICCALL" in mnems, "the vulnerable fixture must STATICCALL ecrecover"
    hits = [i for i in insts if i.mnemonic == "PUSH32" and i.operand == _SECP256K1N_HALF]
    assert hits == [], (
        "the vulnerable fixture must emit NO PUSH32 of secp256k1n/2 — that "
        "absence is exactly the SWC-117 impossibility signal the detector "
        "keys on"
    )


def test_safe_fixture_calls_ecrecover_with_s_bound_constant():
    insts = Disassembly(_bc("signature-malleability-safe")).instructions
    mnems = [i.mnemonic for i in insts]
    assert "STATICCALL" in mnems, "the safe fixture must still STATICCALL ecrecover"
    hits = [i for i in insts if i.mnemonic == "PUSH32" and i.operand == _SECP256K1N_HALF]
    assert len(hits) >= 1, (
        "the safe fixture must emit at least one PUSH32 of secp256k1n/2 — "
        "proves the detector keys on the *absence* of that PUSH32 alongside "
        "the ecrecover, not on the ecrecover call alone"
    )


# --------------------------------------------------------------------------- #
# _has_secp256k1n_half_constant helper: cached scan of the disassembly.
# --------------------------------------------------------------------------- #
def test_secp256k1n_half_helper_discriminates():
    vm_vuln = SymbolicVM(_bc("signature-malleability-vuln"), max_depth=4)
    vm_safe = SymbolicVM(_bc("signature-malleability-safe"), max_depth=4)
    assert _has_secp256k1n_half_constant(vm_vuln) is False
    assert _has_secp256k1n_half_constant(vm_safe) is True


def test_secp256k1n_half_helper_is_cached_on_vm():
    vm = SymbolicVM(_bc("signature-malleability-safe"), max_depth=4)
    assert not hasattr(vm, "_secp256k1n_half_present")
    _has_secp256k1n_half_constant(vm)
    assert vm._secp256k1n_half_present is True
    # second call returns the cached value, not a fresh scan
    vm._secp256k1n_half_present = "sentinel"
    assert _has_secp256k1n_half_constant(vm) == "sentinel"


def test_secp256k1n_half_constant_value():
    # Pin the constant — this is the EIP-2 / OpenZeppelin ECDSA half-order
    # of secp256k1n. Changing it silently would invalidate every safe
    # fixture's acquittal and every vulnerable fixture's flag.
    assert _SECP256K1N_HALF == (
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): ecrecover-without-s-bound is detected
# for the vulnerable contract and NOT for the safe one.
# --------------------------------------------------------------------------- #
def test_vuln_produces_signature_malleability_candidate():
    cands = _candidates("signature-malleability-vuln")
    assert cands, "ecrecover without secp256k1n/2 PUSH32 must produce a candidate"
    assert all(c["category"] == "signature_malleability" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)
    assert all(c["op"] in ("STATICCALL", "CALL") for c in cands)


def test_safe_produces_no_signature_malleability_candidate():
    assert _candidates("signature-malleability-safe") == [], (
        "a contract whose bytecode emits the secp256k1n/2 PUSH32 has the "
        "capacity to enforce the EIP-2 malleability bound — the SWC-117 "
        "impossibility proof does not apply and the contract must not be "
        "flagged"
    )


def test_vuln_candidate_is_deduped_per_pc():
    # The same ecrecover call site reached via multiple paths must be
    # reported once across paths (matches the SWC-121 sibling detector).
    cands = _candidates("signature-malleability-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), (
        "each ecrecover call site should be flagged at most once across paths"
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
        "an ecrecover-using contract that emits the secp256k1n/2 PUSH32 "
        "must not be flagged"
    )


# --------------------------------------------------------------------------- #
# False-positive guards: contracts that make external calls but never call
# the ECRECOVER precompile must not be flagged, regardless of whether their
# bytecode happens to push secp256k1n/2.
# --------------------------------------------------------------------------- #
def test_no_false_positive_external_call_to_non_precompile():
    # ether-withdrawal-vuln makes a value-forwarding CALL to msg.sender (not
    # to a precompile address) and does not push secp256k1n/2. SWC-117 must
    # stay silent — the bug there is the missing caller guard (SWC-105),
    # not a missing malleability bound on an ECRECOVER call.
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
    # delegatecall-vuln has DELEGATECALL with a calldata-derived target.
    # The detector's scope is STATICCALL/CALL only — DELEGATECALL/CALLCODE
    # cannot usefully invoke a precompile in the Solidity-source sense, so
    # SWC-117 must stay silent here. The bug there is SWC-112.
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
# Cross-detector separation: SWC-117 and SWC-121 are independent. The SWC-117
# vuln fixture happens to also omit CHAINID (no chain bind), so it is also
# vulnerable to SWC-121 — and conversely, the existing SWC-121 safe fixture
# (which does include CHAINID but does *not* check `s`) IS vulnerable to
# SWC-117. These tests pin the two detectors as independently keyed bug
# classes, exactly the SWC-105 / SWC-106 carve-out precedent.
# --------------------------------------------------------------------------- #
def test_swc121_safe_fixture_is_swc117_vulnerable():
    # signature-replay-safe binds the signed payload to block.chainid (so
    # SWC-121 is clean) but does not enforce `s <= secp256k1n/2`, so a
    # malleable twin can replay past its `usedNonces` uniqueness check —
    # which keys uniqueness off the nonce, not the sig bytes, so the
    # malleability surface here is the (chain-bound) "valid sig replays
    # under different bit form" reading of SWC-117. The SWC-117 detector
    # keys structurally on the *absent* secp256k1n/2 PUSH32 alongside an
    # ecrecover — that absence holds for signature-replay-safe, so this
    # detector flags it. This is the desired carve-out behaviour: the same
    # contract can be safe under one SWC and unsafe under another, and a
    # triage team gets one finding per bug class.
    findings = analyze(
        _bc("signature-replay-safe"),
        ["signature-malleability"],
        max_depth=64,
    )
    assert findings, (
        "signature-replay-safe enforces CHAINID (so SWC-121 is clean) but "
        "does NOT enforce the EIP-2 s-bound — SWC-117 must flag the "
        "ecrecover call site"
    )
    assert all(f["category"] == "signature_malleability" for f in findings)


def test_swc121_detector_does_not_claim_swc117_safe():
    # signature-malleability-safe enforces the EIP-2 s-bound (so SWC-117
    # is clean) but does NOT include block.chainid in the signed hash, so
    # SWC-121 must flag it. The two detectors are independent — this
    # contract is the SWC-121 surface even though it is SWC-117-safe.
    findings = analyze(
        _bc("signature-malleability-safe"),
        ["signature-replay"],
        max_depth=64,
    )
    assert findings, (
        "signature-malleability-safe omits CHAINID, so SWC-121 must flag "
        "the ecrecover call site — proving the two detectors are "
        "independently keyed"
    )
    assert all(f["category"] == "signature_replay" for f in findings)


def test_swc117_detector_does_not_claim_swc121_vuln_on_chainid_signal():
    # signature-replay-vuln (which also lacks the s-bound) is vulnerable to
    # both. Each detector reports under its own category — they do not
    # share findings. The SWC-117 detector's finding has category
    # `signature_malleability`, not `signature_replay`, even though the
    # same call site lights both up.
    findings = analyze(
        _bc("signature-replay-vuln"),
        ["signature-malleability"],
        max_depth=64,
    )
    assert findings
    assert all(f["category"] == "signature_malleability" for f in findings), (
        "SWC-117 reports under signature_malleability, never under "
        "signature_replay — the categories are the carve-out boundary"
    )


# --------------------------------------------------------------------------- #
# The detector participates in an `all`-checks run alongside the others.
# --------------------------------------------------------------------------- #
def test_signature_malleability_surfaces_under_all_checks():
    findings = analyze(
        _bc("signature-malleability-vuln"),
        ["all"],
        max_depth=64,
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
    doc = json.loads(format_sarif(findings, "signature-malleability-vuln.sol"))
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "signature_malleability" in rule_ids
    result_rules = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "signature_malleability" in result_rules


# --------------------------------------------------------------------------- #
# slow: re-confirm the detector-level discrimination against the real
# engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_candidate_real_engine():
    assert _candidates("signature-malleability-vuln"), (
        "real-engine walk must find the ecrecover-without-s-bound"
    )


@pytest.mark.slow
def test_safe_candidate_real_engine():
    assert _candidates("signature-malleability-safe") == []
