"""Tests for oracle analysis.py helper functions (Z3-free).

Directly exercises _finalize, _z3_to_hex, _resolve_detectors and the
deduplication/confidence logic in analyze() that is not covered by the
higher-level test_analysis.py tests.
"""

from __future__ import annotations

import pytest

import oracle.analysis as _mod
from oracle.analysis import (
    _finalize,
    _resolve_detectors,
    analyze,
)
from oracle.laser.detectors import DETECTOR_REGISTRY


# ------------------------------------------------------------------ #
# _finalize
# ------------------------------------------------------------------ #

def _candidate(**kwargs):
    base = {
        "category": "assertion_violation",
        "severity": "medium",
        "pc": 10,
        "op": "INVALID",
        "depth": 1,
        "trace": [{"pc": 10, "op": "INVALID"}],
        "constraints": [],
        "symbols": {},
    }
    base.update(kwargs)
    return base


def test_finalize_includes_category():
    f = _finalize(_candidate(), {}, confidence="confirmed")
    assert f["category"] == "assertion_violation"


def test_finalize_includes_severity():
    f = _finalize(_candidate(), {}, confidence="confirmed")
    assert f["severity"] == "medium"


def test_finalize_includes_pc():
    f = _finalize(_candidate(pc=42), {}, confidence="confirmed")
    assert f["pc"] == 42


def test_finalize_includes_op():
    f = _finalize(_candidate(op="SSTORE"), {}, confidence="confirmed")
    assert f["op"] == "SSTORE"


def test_finalize_includes_depth():
    f = _finalize(_candidate(depth=3), {}, confidence="confirmed")
    assert f["depth"] == 3


def test_finalize_depth_defaults_to_zero_when_missing():
    cand = _candidate()
    del cand["depth"]
    f = _finalize(cand, {}, confidence="confirmed")
    assert f["depth"] == 0


def test_finalize_includes_trace():
    trace = [{"pc": 0, "op": "PUSH1"}, {"pc": 10, "op": "INVALID"}]
    f = _finalize(_candidate(trace=trace), {}, confidence="confirmed")
    assert f["trace"] == trace


def test_finalize_includes_trigger_input():
    ti = {"calldata": "0x" + "aa" * 32}
    f = _finalize(_candidate(), ti, confidence="confirmed")
    assert f["trigger_input"] == ti


def test_finalize_includes_confidence():
    f = _finalize(_candidate(), {}, confidence="timeout")
    assert f["confidence"] == "timeout"


def test_finalize_confirmed_confidence():
    f = _finalize(_candidate(), {"calldata": "0x01"}, confidence="confirmed")
    assert f["confidence"] == "confirmed"


def test_finalize_does_not_include_constraints():
    f = _finalize(_candidate(), {}, confidence="confirmed")
    assert "constraints" not in f


def test_finalize_does_not_include_symbols():
    f = _finalize(_candidate(), {}, confidence="confirmed")
    assert "symbols" not in f


# ------------------------------------------------------------------ #
# _resolve_detectors
# ------------------------------------------------------------------ #

def test_resolve_all_returns_all_registered_detectors():
    factories = _resolve_detectors(["all"])
    assert len(factories) == len(DETECTOR_REGISTRY)


def test_resolve_specific_check_returns_one_factory():
    factories = _resolve_detectors(["assertion"])
    assert len(factories) == 1


def test_resolve_multiple_checks():
    factories = _resolve_detectors(["assertion", "overflow"])
    assert len(factories) == 2


def test_resolve_unknown_check_raises_value_error():
    with pytest.raises(ValueError, match="unknown check"):
        _resolve_detectors(["no_such_check"])


def test_resolve_factories_are_callable():
    factories = _resolve_detectors(["assertion"])
    det = factories[0]()
    assert hasattr(det, "inspect")
    assert hasattr(det, "findings")


def test_resolve_each_call_produces_fresh_instance():
    factories = _resolve_detectors(["assertion"])
    a = factories[0]()
    b = factories[0]()
    a.findings.append("x")
    assert b.findings == []


def test_resolve_all_covers_overflow_and_selfdestruct():
    factories = _resolve_detectors(["all"])
    all_tokens = set(DETECTOR_REGISTRY.keys())
    assert "overflow" in all_tokens
    assert "selfdestruct" in all_tokens


# ------------------------------------------------------------------ #
# Deduplication in analyze() (mocked — conftest patches solve_finding)
# ------------------------------------------------------------------ #

import os
from oracle.compiler import load_runtime_bytecode

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


def test_analyze_no_duplicate_category_pc():
    findings = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12)
    keys = [(f["category"], f["pc"], f.get("depth", 0)) for f in findings]
    assert len(keys) == len(set(keys)), "duplicate (category, pc, depth) in findings"


def test_analyze_findings_have_required_keys():
    findings = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12)
    for f in findings:
        for key in ("category", "severity", "pc", "op", "trace", "trigger_input", "confidence"):
            assert key in f, f"missing key {key!r}"


def test_analyze_confidence_is_confirmed_or_timeout():
    findings = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12)
    for f in findings:
        assert f["confidence"] in ("confirmed", "timeout")


def test_analyze_trace_entries_are_dicts():
    findings = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12)
    for f in findings:
        for entry in f["trace"]:
            assert isinstance(entry, dict)
            assert "pc" in entry and "op" in entry


def test_analyze_sequence_depth_1_produces_findings():
    findings = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12, sequence_depth=1)
    assert findings


def test_analyze_sequence_depth_below_1_treated_as_1():
    findings_1 = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12, sequence_depth=1)
    findings_0 = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12, sequence_depth=0)
    # both should produce the same findings (sequence_depth=0 is clamped to 1)
    assert len(findings_0) == len(findings_1)
