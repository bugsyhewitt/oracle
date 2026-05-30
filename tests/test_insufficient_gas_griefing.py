"""Tests for oracle's insufficient-gas-griefing detector (SWC-126).

The relayer/forwarder pattern: a contract takes a target, a payload, and a
caller-supplied gas amount, and forwards the inner call with that gas
(`to.call{gas: gasAmt}(data)`). A malicious relayer can pick a `gasAmt`
small enough to OOG the inner call while the outer transaction succeeds —
the signed message is "consumed" / the nonce burns / the queue position
advances, but the intended inner action never executes. That is SWC-126:
caller-controllable gas fraction → recipient-starvation griefing without
outright rejection. The safe pattern forwards all remaining gas (no
`{gas: ...}` modifier).

Detection signal — the gas operand on top of stack at a CALL / CALLCODE /
STATICCALL / DELEGATECALL is symbolic and derived from calldata. The same
`_mentions_calldata` discriminator the SWC-112 / SWC-124 / SWC-127
detectors use for their own operands, applied here to the gas word. A
concrete gas operand (the SWC-134 hardcoded-stipend surface) is not
flagged; the runtime `GAS` opcode lowers to a fresh symbol with no
calldata in its AST, so the safe `to.call(data)` pattern is likewise
not flagged.

Two fixtures pin the behaviour:
  * insufficient-gas-griefing-vuln.sol — `relay(to, gasAmt, data)` does
    `to.call{gas: gasAmt}(data)`. The gas operand is calldata-derived
    on the symbolic stack at the CALL. MUST be flagged.
  * insufficient-gas-griefing-safe.sol — `relay(to, data)` does
    `to.call(data)`, forwarding all remaining gas. The CALL is still
    present, the GAS opcode is emitted immediately before it (the
    discriminator from the unsafe relayer pattern), and the gas operand
    is a fresh symbol that does not mention calldata. MUST NOT be
    flagged.
"""

import json
import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode
from oracle.laser.detectors import (
    DETECTOR_REGISTRY,
    InsufficientGasGriefingDetector,
    SEVERITY,
    _mentions_calldata,
)
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def _candidates(name, max_depth=64):
    """Run only the insufficient-gas-griefing detector and return its raw
    candidates (before the Z3 reachability boundary), isolating detector
    logic from the solver."""
    vm = SymbolicVM(_bc(name), max_depth=max_depth)
    det = InsufficientGasGriefingDetector()
    vm.register(det)
    vm.run()
    return det.findings


# --------------------------------------------------------------------------- #
# Registration: the detector is wired into the CLI/analysis registry.
# --------------------------------------------------------------------------- #
def test_insufficient_gas_griefing_detector_is_registered():
    assert "insufficient-gas-griefing" in DETECTOR_REGISTRY
    assert (
        DETECTOR_REGISTRY["insufficient-gas-griefing"]
        is InsufficientGasGriefingDetector
    )


def test_insufficient_gas_griefing_exposed_on_cli_choices():
    from oracle.cli import CHECK_CHOICES

    assert "insufficient-gas-griefing" in CHECK_CHOICES


def test_insufficient_gas_griefing_severity_is_medium():
    # SWC-126 is medium: the outer transaction succeeds (no fund-loss
    # directly), but the relayer can grief the user by burning their nonce
    # / consuming their signed message without executing the intended
    # inner action. Bad availability surface, not a direct high-severity
    # fund-loss like SWC-105 / SWC-106.
    assert SEVERITY["insufficient_gas_griefing"] == "medium"


def test_insufficient_gas_griefing_in_report_title_map():
    from oracle.report import _TITLE

    assert _TITLE["insufficient_gas_griefing"] == (
        "Insufficient Gas Griefing (SWC-126)"
    )


# --------------------------------------------------------------------------- #
# Fixtures actually contain the opcodes / structure under test (guards
# against a future solc change silently optimising the relayer lowering).
# --------------------------------------------------------------------------- #
def test_vuln_fixture_emits_call_with_no_gas_opcode_preceding():
    insts = Disassembly(_bc("insufficient-gas-griefing-vuln")).instructions
    mnems = [i.mnemonic for i in insts]
    assert "CALL" in mnems, (
        "the vulnerable fixture must emit a CALL (the relayer's "
        "`to.call{gas: gasAmt}(data)` lowering)"
    )
    # the relayer lowering DUPs the gas argument from a calldata position
    # onto the stack — no runtime `GAS` opcode is emitted (the safe
    # discriminator). If solc starts emitting GAS here the safe/vuln
    # signal needs reassessment.
    assert "GAS" not in mnems, (
        "the vulnerable fixture's caller-supplied-gas lowering must not "
        "emit GAS — if it does the safe/vuln discriminator needs review"
    )


def test_safe_fixture_emits_call_with_gas_opcode_preceding():
    insts = Disassembly(_bc("insufficient-gas-griefing-safe")).instructions
    mnems = [i.mnemonic for i in insts]
    assert "CALL" in mnems, (
        "the safe fixture must still emit a CALL (proves the detector "
        "keys on the gas operand's symbolic origin, not on the CALL "
        "opcode itself)"
    )
    assert "GAS" in mnems, (
        "the safe fixture's `to.call(data)` forward-all-gas lowering "
        "must emit a GAS opcode — that is what makes the gas operand a "
        "fresh `gas_<pc>` symbol with no calldata in its AST"
    )


# --------------------------------------------------------------------------- #
# Symbolic provenance: the gas operand at the vulnerable CALL site IS
# calldata-derived; at the safe CALL site it is NOT. The detector hangs
# its discrimination on exactly this _mentions_calldata test.
# --------------------------------------------------------------------------- #
class _GasOperandProbe:
    """Captures the gas operand symbol at each CALL-family site so the
    test can assert provenance independently of the detector."""

    findings: list

    def __init__(self):
        self.findings = []
        self.captured = []
        self.category = "_probe"

    def inspect(self, vm, state, instruction):
        if instruction.mnemonic in (
            "CALL",
            "CALLCODE",
            "STATICCALL",
            "DELEGATECALL",
        ):
            if state.stack:
                self.captured.append(
                    (
                        instruction.pc,
                        state.stack[-1],
                        _mentions_calldata(state.stack[-1], vm),
                    )
                )


def _capture(name):
    vm = SymbolicVM(_bc(name), max_depth=64)
    probe = _GasOperandProbe()
    vm.register(probe)
    vm.run()
    return probe.captured, vm


def test_vuln_gas_operand_is_calldata_derived():
    captured, _ = _capture("insufficient-gas-griefing-vuln")
    assert captured, "the vulnerable fixture must reach at least one CALL"
    assert any(mentions for _, _, mentions in captured), (
        "at least one CALL site in the vulnerable fixture must have a "
        "calldata-derived gas operand (the SWC-126 signature)"
    )


def test_safe_gas_operand_is_not_calldata_derived():
    captured, _ = _capture("insufficient-gas-griefing-safe")
    assert captured, "the safe fixture must reach at least one CALL"
    assert all(not mentions for _, _, mentions in captured), (
        "no CALL site in the safe fixture may have a calldata-derived "
        "gas operand — the GAS opcode lowers to a fresh symbol"
    )


# --------------------------------------------------------------------------- #
# Detector-level (solver-independent): vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_produces_insufficient_gas_griefing_candidate():
    cands = _candidates("insufficient-gas-griefing-vuln")
    assert cands, (
        "a relayer forwarding caller-supplied gas must produce an "
        "insufficient-gas-griefing candidate"
    )
    assert all(c["category"] == "insufficient_gas_griefing" for c in cands)
    assert all(c["severity"] == "medium" for c in cands)
    assert all(
        c["op"] in ("CALL", "CALLCODE", "STATICCALL", "DELEGATECALL")
        for c in cands
    )


def test_safe_produces_no_insufficient_gas_griefing_candidate():
    assert _candidates("insufficient-gas-griefing-safe") == [], (
        "a `to.call(data)` forwarder that forwards all remaining gas "
        "must not be flagged — the gas operand is a fresh symbol with "
        "no calldata in its AST"
    )


def test_vuln_candidate_is_deduped_per_pc():
    cands = _candidates("insufficient-gas-griefing-vuln")
    pcs = [c["pc"] for c in cands]
    assert len(pcs) == len(set(pcs)), (
        "each caller-supplied-gas call site should be flagged at most "
        "once across paths"
    )


# --------------------------------------------------------------------------- #
# End-to-end through the analysis driver: vulnerable flagged, safe clean.
# --------------------------------------------------------------------------- #
def test_vuln_is_flagged_end_to_end():
    findings = analyze(
        _bc("insufficient-gas-griefing-vuln"),
        ["insufficient-gas-griefing"],
        max_depth=64,
    )
    assert findings, (
        "vulnerable relayer should yield an insufficient-gas-griefing "
        "finding"
    )
    assert findings[0]["category"] == "insufficient_gas_griefing"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["op"] in (
        "CALL",
        "CALLCODE",
        "STATICCALL",
        "DELEGATECALL",
    )
    assert findings[0]["trace"]


def test_safe_is_not_flagged_end_to_end():
    findings = analyze(
        _bc("insufficient-gas-griefing-safe"),
        ["insufficient-gas-griefing"],
        max_depth=64,
    )
    assert findings == [], (
        "a forwarder that forwards all remaining gas must not be flagged"
    )


# --------------------------------------------------------------------------- #
# False-positive guards: the detector must stay silent on every other
# call-emitting fixture in the suite. SWC-126 is the caller-supplied-gas
# surface specifically; other call-related bug classes have other signals
# and other detectors.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "fixture,max_depth",
    [
        # SWC-134 surface: hardcoded 2300 gas. Concrete operand — not SWC-126.
        ("hardcoded-gas-vuln", 64),
        # Safe `call{value:}` forwarding all gas. GAS opcode emitted — not SWC-126.
        ("hardcoded-gas-safe", 64),
        # SWC-105 surface: unguarded `to.call{value:}` — gas is `GAS` opcode.
        ("ether-withdrawal-vuln", 40),
        # SWC-107 surface: reentrancy `call` forwarding all gas.
        ("reentrancy_vuln", 40),
        # SWC-104 surface: unchecked `call` return. Gas is `GAS` opcode.
        ("unchecked-call-vuln", 40),
        # SWC-112 surface: delegatecall to calldata target. Gas is `GAS` opcode,
        # not a calldata word — the calldata-derived word is the TARGET, not
        # the gas, and the detector must not over-claim it.
        ("delegatecall-vuln", 24),
        # No call at all — must stay silent regardless of bytecode contents.
        ("assertion-violation", 24),
    ],
)
def test_no_false_positive_on_other_call_fixtures(fixture, max_depth):
    findings = analyze(
        _bc(fixture), ["insufficient-gas-griefing"], max_depth=max_depth
    )
    assert findings == [], (
        f"{fixture} has no caller-supplied-gas CALL; SWC-126 must stay "
        f"silent (the call-related bug there is a different detector's "
        f"surface)"
    )


# --------------------------------------------------------------------------- #
# Cross-detector separation: the relayer fixture must not trip detectors
# whose surfaces it does not exhibit. Pins SWC-126 to the gas-operand
# surface specifically.
# --------------------------------------------------------------------------- #
def test_vuln_does_not_trip_hardcoded_gas():
    # SWC-126's relayer lowering emits no PUSH2 0x08FC and no GAS — both
    # halves of the SWC-134 conjunction are missing.
    findings = analyze(
        _bc("insufficient-gas-griefing-vuln"),
        ["hardcoded-gas"],
        max_depth=64,
    )
    assert findings == []


def test_vuln_does_not_trip_dos_failed_call():
    # The relayer makes one CALL, not a loop-bound CALL — SWC-113 must
    # stay silent.
    findings = analyze(
        _bc("insufficient-gas-griefing-vuln"),
        ["dos-failed-call"],
        max_depth=64,
    )
    assert findings == []


# --------------------------------------------------------------------------- #
# Participation in an `all`-checks run.
# --------------------------------------------------------------------------- #
def test_insufficient_gas_griefing_participates_in_all_checks():
    findings = analyze(
        _bc("insufficient-gas-griefing-vuln"),
        list(DETECTOR_REGISTRY.keys()),
        max_depth=64,
    )
    cats = {f["category"] for f in findings}
    assert "insufficient_gas_griefing" in cats, (
        "the SWC-126 detector must contribute a finding to a full run "
        "on the vulnerable fixture"
    )


# --------------------------------------------------------------------------- #
# Report rendering: h1md headings and SARIF rule descriptions resolve the
# SWC-126 title.
# --------------------------------------------------------------------------- #
def test_h1md_renders_swc_126_title():
    from oracle.report import format_h1md

    findings = analyze(
        _bc("insufficient-gas-griefing-vuln"),
        ["insufficient-gas-griefing"],
        max_depth=64,
    )
    assert findings
    body = format_h1md(findings, "insufficient-gas-griefing-vuln")
    assert "SWC-126" in body
    assert "insufficient gas griefing" in body.lower()


def test_sarif_renders_swc_126_rule():
    from oracle.report import format_sarif

    findings = analyze(
        _bc("insufficient-gas-griefing-vuln"),
        ["insufficient-gas-griefing"],
        max_depth=64,
    )
    assert findings
    doc = json.loads(
        format_sarif(findings, "insufficient-gas-griefing-vuln")
    )
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "insufficient_gas_griefing" in rule_ids
    rule = next(
        r for r in rules if r["id"] == "insufficient_gas_griefing"
    )
    assert "SWC-126" in rule["shortDescription"]["text"]


# --------------------------------------------------------------------------- #
# Slow real-Z3 confirmation: the same observations under the real engine.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_vuln_real_z3_confirms_finding():
    findings = analyze(
        _bc("insufficient-gas-griefing-vuln"),
        ["insufficient-gas-griefing"],
        max_depth=64,
    )
    assert findings
    assert findings[0]["category"] == "insufficient_gas_griefing"


@pytest.mark.slow
def test_safe_real_z3_confirms_no_finding():
    findings = analyze(
        _bc("insufficient-gas-griefing-safe"),
        ["insufficient-gas-griefing"],
        max_depth=64,
    )
    assert findings == []
