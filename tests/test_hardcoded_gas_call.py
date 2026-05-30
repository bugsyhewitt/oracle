"""Tests for oracle's hardcoded-gas-call detector (SWC-134, "Message call
with hardcoded gas amount").

Solidity's `address.transfer(x)` and `address.send(x)` lower to a CALL whose
gas operand is the fixed 2300-gas EIP-150 stipend, materialised by solc as a
`PUSH2 0x08FC` immediate in the preceding instructions. Post-Istanbul
(EIP-1884, Dec 2019) 2300 gas is not guaranteed to be enough for a recipient
fallback to complete on non-trivial wallets (proxies, multisigs, AA wallets,
Gnosis Safe), so a `transfer`-using payout permanently bricks on any
unanticipated recipient. SWC-134 names the bug; the canonical fix is
`address.call{value: x}("")` with a `require(ok)`, which forwards all
remaining gas.

The discriminating signal is a bytecode-level structural conjunction
(mirrors the SWC-117 / SWC-121 detectors' structural approach):
  (1) a CALL/CALLCODE is reached, AND
  (2) its preceding 24-instruction window contains a `PUSH2 0x08FC` (2300)
      immediate AND no `GAS` opcode.

Two fixtures pin the behaviour:
  * hardcoded-gas-vuln.sol — `pay()` uses `to.transfer(msg.value)`.
    Bytecode: CALL present, PUSH2 0x08FC present in the call's window, no
    GAS in the window. MUST be flagged.
  * hardcoded-gas-safe.sol — `pay()` uses
    `(bool ok,) = to.call{value: msg.value}(""); require(ok, ...)`.
    Bytecode: CALL still present, no PUSH2 0x08FC anywhere, GAS opcode
    immediately precedes the CALL (forwarding all remaining gas). MUST
    NOT be flagged (the CALL is in the bytecode, so this fixture proves
    the detector keys on the literal-2300 gas signature next to the call,
    not on the CALL opcode itself).

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
    HardcodedGasCallDetector,
    SEVERITY,
    _HARDCODED_GAS_WINDOW,
    _TRANSFER_GAS_STIPEND,
    _call_has_hardcoded_gas,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=64):
    """Run only the hardcoded-gas-call detector and return its raw
    candidates (before the Z3 reachability boundary), isolating detector
    logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = HardcodedGasCallDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Constant pin: a typo or a refactor that drifts off the 2300 EIP-150 stipend
# would silently break every safe-fixture acquittal in oracle's history.
# --------------------------------------------------------------------------- #
def test_transfer_gas_stipend_constant():
    assert _TRANSFER_GAS_STIPEND == 0x08FC == 2300


def test_hardcoded_gas_window_is_a_small_positive_int():
    # The window must be small enough to scope to a single call site (avoid
    # false-positives from an unrelated 2300 literal elsewhere in the program)
    # and large enough to span solc's `transfer` lowering interleavings.
    assert 4 <= _HARDCODED_GAS_WINDOW <= 64


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_hardcoded_gas_detector_is_registered():
    assert "hardcoded-gas" in DETECTOR_REGISTRY
    assert DETECTOR_REGISTRY["hardcoded-gas"] is HardcodedGasCallDetector


def test_hardcoded_gas_exposed_on_cli_choices():
    from oracle.cli import CHECK_CHOICES

    assert "hardcoded-gas" in CHECK_CHOICES


def test_hardcoded_gas_severity_is_medium():
    # SWC-134 is medium: the bug is an availability / brick-the-function
    # surface rather than a direct fund-loss class. A `transfer`-using
    # payout reverts on any recipient whose fallback exceeds 2300 gas,
    # bricking the function for that destination — bad, but not a direct
    # high-severity fund-loss like an unprotected withdrawal or a SWC-106
    # SELFDESTRUCT.
    assert SEVERITY["hardcoded_gas_call"] == "medium"


def test_hardcoded_gas_in_report_title_map():
    from oracle.report import _TITLE

    assert _TITLE["hardcoded_gas_call"] == (
        "Message call with hardcoded gas amount (SWC-134)"
    )


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes / constants under test (guards
# against a future solc change silently optimising the 2300 literal or the
# CALL away).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_transfer_with_2300_literal_and_no_gas_op():
    insts = Disassembly(_bc("hardcoded-gas-vuln")).instructions
    mnems = [i.mnemonic for i in insts]
    assert "CALL" in mnems, (
        "the vulnerable fixture must emit a CALL (the `transfer` lowering)"
    )
    assert any(
        i.mnemonic == "PUSH2" and i.operand == _TRANSFER_GAS_STIPEND
        for i in insts
    ), (
        "the vulnerable fixture must emit a PUSH2 0x08FC literal — that "
        "is exactly the SWC-134 hardcoded-2300-gas-stipend signature"
    )
    # And the GAS opcode must NOT appear in this contract's runtime: a
    # `transfer`-only contract has no reason to read the gas counter.
    assert "GAS" not in mnems, (
        "the vulnerable fixture's `transfer` lowering must not emit GAS — "
        "if solc starts emitting GAS here the safe/vuln discriminator "
        "needs reassessment"
    )


def test_safe_fixture_emits_call_with_gas_opcode_and_no_2300_literal():
    insts = Disassembly(_bc("hardcoded-gas-safe")).instructions
    mnems = [i.mnemonic for i in insts]
    assert "CALL" in mnems, (
        "the safe fixture must still emit a CALL (proves the detector "
        "keys on the literal-2300 gas signature next to the call, not on "
        "the CALL opcode itself)"
    )
    assert "GAS" in mnems, (
        "the safe fixture's `call{value: ...}` lowering must emit a GAS "
        "opcode (forwarding all remaining gas) — that is the discrim-"
        "inator from the unsafe `transfer` pattern"
    )
    assert not any(
        i.mnemonic == "PUSH2" and i.operand == _TRANSFER_GAS_STIPEND
        for i in insts
    ), (
        "the safe fixture must not emit a PUSH2 0x08FC literal anywhere"
    )


# --------------------------------------------------------------------------- #
# _call_has_hardcoded_gas helper: per-call-site, cached on the vm.
# --------------------------------------------------------------------------- #
def test_call_has_hardcoded_gas_discriminates():
    vm_vuln = SymbolicVM(_bc("hardcoded-gas-vuln"), max_depth=4)
    vm_safe = SymbolicVM(_bc("hardcoded-gas-safe"), max_depth=4)
    # the CALL pcs were observed at 108 / 110 in the original analysis but
    # we lookup dynamically to keep this robust to fixture regeneration.
    vuln_call_pc = next(
        i.pc for i in vm_vuln.disasm.instructions if i.mnemonic == "CALL"
    )
    safe_call_pc = next(
        i.pc for i in vm_safe.disasm.instructions if i.mnemonic == "CALL"
    )
    assert _call_has_hardcoded_gas(vm_vuln, vuln_call_pc) is True
    assert _call_has_hardcoded_gas(vm_safe, safe_call_pc) is False


def test_call_has_hardcoded_gas_is_cached_on_vm():
    vm = SymbolicVM(_bc("hardcoded-gas-vuln"), max_depth=4)
    assert not hasattr(vm, "_hardcoded_gas_cache")
    pc = next(i.pc for i in vm.disasm.instructions if i.mnemonic == "CALL")
    _call_has_hardcoded_gas(vm, pc)
    assert vm._hardcoded_gas_cache[pc] is True
    # second call returns the cached value; mutate the cache to confirm
    # we are reading it rather than re-scanning.
    vm._hardcoded_gas_cache[pc] = "sentinel"
    assert _call_has_hardcoded_gas(vm, pc) == "sentinel"


def test_call_has_hardcoded_gas_returns_false_for_unknown_pc():
    vm = SymbolicVM(_bc("hardcoded-gas-vuln"), max_depth=4)
    # a pc that is not a valid instruction is treated as not-flagged rather
    # than crashing (defensive — should not happen in normal use).
    assert _call_has_hardcoded_gas(vm, 999999) is False


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_produces_hardcoded_gas_candidate():
    cands = _candidates("hardcoded-gas-vuln")
    assert cands, (
        "a `transfer`-using fixture must produce a hardcoded-gas-call "
        "candidate"
    )
    assert all(c["category"] == "hardcoded_gas_call" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)
    assert all(c["op"] in ("CALL", "CALLCODE") for c in cands)


def test_safe_produces_no_hardcoded_gas_candidate():
    assert _candidates("hardcoded-gas-safe") == [], (
        "an `address.call{value: x}('')` lowering forwards all remaining "
        "gas (the safe pattern) — the SWC-134 hardcoded-2300-gas-stipend "
        "signature is absent and the contract must not be flagged"
    )


def test_vuln_candidate_is_deduped_per_pc():
    # The same CALL pc reached via multiple paths must be reported once.
    cands = _candidates("hardcoded-gas-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), (
        "each hardcoded-gas call site should be flagged at most once "
        "across paths"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver (default run = mocked Z3 boundary):
# vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(
        _bc("hardcoded-gas-vuln"), ["hardcoded-gas"], max_depth=64
    )
    assert findings, (
        "vulnerable contract should yield a hardcoded-gas-call finding"
    )
    assert findings[0]["category"] == "hardcoded_gas_call"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["op"] in ("CALL", "CALLCODE")
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(
        _bc("hardcoded-gas-safe"), ["hardcoded-gas"], max_depth=64
    )
    assert findings == [], (
        "a `call{value: x}` payout that forwards all remaining gas must "
        "not be flagged"
    )


# --------------------------------------------------------------------------- #
# False-positive guards: the detector must stay silent on contracts that
# emit CALL for other reasons, on contracts that never CALL, and on
# DELEGATECALL/STATICCALL which cannot forward value (so the `transfer`/`send`
# source form does not lower to them).
# --------------------------------------------------------------------------- #
def test_no_false_positive_on_ordinary_value_forwarding_call():
    # ether-withdrawal-vuln uses `to.call{value: ...}(...)` which forwards
    # all gas — a CALL is present, no 2300 literal, so SWC-134 must stay
    # silent. The bug there is the missing caller guard (SWC-105), not a
    # hardcoded gas amount.
    findings = analyze(
        _bc("ether-withdrawal-vuln"),
        ["hardcoded-gas"],
        max_depth=40,
    )
    assert findings == [], (
        "an ordinary `call{value:}` payout (no 2300 stipend literal) "
        "must not be flagged for SWC-134"
    )


def test_no_false_positive_on_delegatecall_fixture():
    # delegatecall-vuln emits DELEGATECALL with a calldata-derived target.
    # The detector's scope is CALL/CALLCODE only — DELEGATECALL/STATICCALL
    # cannot forward value so the `transfer`/`send` source form does not
    # lower to them. SWC-134 must stay silent.
    findings = analyze(
        _bc("delegatecall-vuln"),
        ["hardcoded-gas"],
        max_depth=24,
    )
    assert findings == []


def test_no_false_positive_on_contract_that_never_calls():
    # assertion-violation.sol makes no external call at all. SWC-134 must
    # stay silent regardless of what other constants appear in the bytecode.
    findings = analyze(
        _bc("assertion-violation"),
        ["hardcoded-gas"],
        max_depth=24,
    )
    assert findings == []


# --------------------------------------------------------------------------- #
# Cross-detector separation: detectors that legitimately fire on the same
# CALL opcode (or on its return value, recipient, ordering, etc.) must NOT
# claim the hardcoded-gas-call signal as their own — and SWC-134 must not
# fire on their fixtures. Pins the detector to the gas-operand surface.
# --------------------------------------------------------------------------- #
def test_swc_134_does_not_fire_on_unchecked_call_fixture():
    # unchecked-call-vuln.sol uses `to.call{value: 1}(...)` and discards
    # the return word — SWC-104 fires there, but no 2300 literal, so
    # SWC-134 must stay silent.
    findings = analyze(
        _bc("unchecked-call-vuln"), ["hardcoded-gas"], max_depth=40
    )
    assert findings == []


def test_swc_134_does_not_fire_on_reentrancy_fixture():
    # reentrancy_vuln.sol uses a low-level call to forward all gas (the
    # canonical CEI-violation pattern). No 2300 stipend literal, SWC-134
    # must stay silent.
    findings = analyze(
        _bc("reentrancy_vuln"), ["hardcoded-gas"], max_depth=40
    )
    assert findings == []


# --------------------------------------------------------------------------- #
# Participation in an `all`-checks run.
# --------------------------------------------------------------------------- #
def test_hardcoded_gas_participates_in_all_checks():
    findings = analyze(
        _bc("hardcoded-gas-vuln"),
        list(DETECTOR_REGISTRY.keys()),
        max_depth=64,
    )
    cats = {f["category"] for f in findings}
    assert "hardcoded_gas_call" in cats, (
        "the SWC-134 detector must contribute a finding to a full run "
        "on the vulnerable fixture"
    )


# --------------------------------------------------------------------------- #
# Report rendering: h1md headings and SARIF rule descriptions resolve the
# SWC-134 title.
# --------------------------------------------------------------------------- #
def test_h1md_renders_swc_134_title():
    from oracle.report import format_h1md

    findings = analyze(
        _bc("hardcoded-gas-vuln"), ["hardcoded-gas"], max_depth=64
    )
    assert findings
    body = format_h1md(findings, "hardcoded-gas-vuln")
    assert "SWC-134" in body
    assert "hardcoded gas amount" in body.lower()


def test_sarif_renders_swc_134_rule():
    from oracle.report import format_sarif

    findings = analyze(
        _bc("hardcoded-gas-vuln"), ["hardcoded-gas"], max_depth=64
    )
    assert findings
    doc = json.loads(format_sarif(findings, "hardcoded-gas-vuln"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "hardcoded_gas_call" in rule_ids
    rule = next(r for r in rules if r["id"] == "hardcoded_gas_call")
    assert "SWC-134" in rule["shortDescription"]["text"]


# --------------------------------------------------------------------------- #
# Slow real-Z3 confirmation: the same observations under the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_real_z3_confirms_finding():
    findings = analyze(
        _bc("hardcoded-gas-vuln"),
        ["hardcoded-gas"],
        max_depth=64,
    )
    assert findings
    assert findings[0]["category"] == "hardcoded_gas_call"


@pytest.mark.slow
def test_safe_real_z3_confirms_no_finding():
    findings = analyze(
        _bc("hardcoded-gas-safe"),
        ["hardcoded-gas"],
        max_depth=64,
    )
    assert findings == []
