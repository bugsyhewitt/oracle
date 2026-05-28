"""Tests for the per-query Z3 timeout (POST_V01 Tier 3 #9, --timeout flag).

These exercise three things WITHOUT invoking real Z3:

  1. The CLI surface (`--timeout` parses, defaults to 30, validates >= 0).
  2. The analysis boundary: `solve_finding` sets the solver timeout, maps a
     `z3.unknown` result to a `confidence == "timeout"` finding (kept, not
     dropped), an `unsat` to None, and a `sat` to a `confidence == "confirmed"`
     finding.
  3. The h1md report renders the timeout confidence banner.

A single slow test confirms the timeout is actually applied to a real solver.
"""

import json
import os

import pytest

import oracle.analysis as analysis
from oracle.analysis import DEFAULT_TIMEOUT_SECONDS, analyze, solve_finding
from oracle.cli import build_parser, main
from oracle.report import format_h1md

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# --------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------- #
def test_timeout_defaults_to_30():
    parser = build_parser()
    ns = parser.parse_args(["--contract", "x.bin", "--input-type", "bytecode"])
    assert ns.timeout == 30


def test_timeout_is_parsed():
    parser = build_parser()
    ns = parser.parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--timeout", "5"]
    )
    assert ns.timeout == 5


def test_timeout_zero_allowed():
    parser = build_parser()
    ns = parser.parse_args(
        ["--contract", "x.bin", "--input-type", "bytecode", "--timeout", "0"]
    )
    assert ns.timeout == 0


def test_help_lists_timeout(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--timeout" in out


def test_negative_timeout_exits_2(capsys):
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
            "--timeout",
            "-1",
        ]
    )
    assert rc == 2


def test_cli_json_carries_confidence(capsys):
    # default run is Z3-mocked -> stub returns confidence=confirmed
    rc = main(
        [
            "--contract",
            os.path.join(FIXTURES, "assertion-violation.sol"),
            "--input-type",
            "sol",
            "--check",
            "assertion",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["confidence"] == "confirmed"


# --------------------------------------------------------------------- #
# solve_finding behaviour against a fake solver (no real Z3)
# --------------------------------------------------------------------- #
class _FakeSolver:
    """Records timeout/constraints and returns a pre-programmed check() result."""

    last_instance = None

    def __init__(self, result):
        import z3

        self._result = getattr(z3, result)
        self.timeout_ms = None
        self.added = 0
        self._model_obj = _FakeModel()
        _FakeSolver.last_instance = self

    def set_timeout(self, ms):
        self.timeout_ms = ms

    def add(self, c):
        self.added += 1

    def check(self):
        return self._result

    def model(self):
        return self._model_obj


class _FakeModel:
    def eval(self, raw, model_completion=True):
        return raw


def _candidate():
    return {
        "category": "assertion_violation",
        "severity": "medium",
        "pc": 10,
        "op": "INVALID",
        "depth": 0,
        "trace": [{"pc": 0, "op": "CALLVALUE"}],
        "constraints": [],
        "symbols": {},
    }


def _patch_solver(monkeypatch, result):
    # solve_finding is mocked by autouse fixture for non-slow tests; restore the
    # real implementation here, then swap the Solver class for a fake.
    monkeypatch.setattr(analysis, "solve_finding", solve_finding)
    monkeypatch.setattr(analysis, "Solver", lambda: _FakeSolver(result))


def test_unknown_result_becomes_timeout_finding(monkeypatch):
    _patch_solver(monkeypatch, "unknown")
    out = analysis.solve_finding(_candidate(), timeout=7)
    assert out is not None, "unknown must be kept, not dropped"
    assert out["confidence"] == "timeout"
    assert out["trigger_input"] == {}
    # 7 seconds -> 7000 ms on the solver
    assert _FakeSolver.last_instance.timeout_ms == 7000


def test_unsat_result_is_dropped(monkeypatch):
    _patch_solver(monkeypatch, "unsat")
    assert analysis.solve_finding(_candidate(), timeout=7) is None


def test_sat_result_is_confirmed(monkeypatch):
    _patch_solver(monkeypatch, "sat")
    out = analysis.solve_finding(_candidate(), timeout=7)
    assert out is not None
    assert out["confidence"] == "confirmed"


def test_zero_timeout_does_not_set_solver_timeout(monkeypatch):
    _patch_solver(monkeypatch, "sat")
    analysis.solve_finding(_candidate(), timeout=0)
    assert _FakeSolver.last_instance.timeout_ms is None


def test_default_timeout_constant_is_30():
    assert DEFAULT_TIMEOUT_SECONDS == 30


def test_analyze_threads_timeout_into_solver(monkeypatch):
    # End-to-end through analyze(): a timeout-causing solver yields a kept,
    # timeout-confidence finding rather than nothing.
    _patch_solver(monkeypatch, "unknown")
    bc = _bc("assertion-violation")
    findings = analyze(bc, ["assertion"], max_depth=12, timeout=3)
    assert findings, "timeout findings must still be reported"
    assert all(f["confidence"] == "timeout" for f in findings)
    assert _FakeSolver.last_instance.timeout_ms == 3000


# --------------------------------------------------------------------- #
# report rendering
# --------------------------------------------------------------------- #
def test_h1md_renders_timeout_banner():
    finding = {
        "category": "assertion_violation",
        "severity": "medium",
        "pc": 10,
        "op": "INVALID",
        "depth": 0,
        "trace": [{"pc": 0, "op": "CALLVALUE"}],
        "trigger_input": {},
        "confidence": "timeout",
    }
    out = format_h1md([finding], "x.sol")
    assert "timeout" in out
    assert "--timeout" in out


def test_h1md_renders_confirmed_confidence():
    finding = {
        "category": "assertion_violation",
        "severity": "medium",
        "pc": 10,
        "op": "INVALID",
        "depth": 0,
        "trace": [{"pc": 0, "op": "CALLVALUE"}],
        "trigger_input": {"calldata": "0x" + "00" * 32},
        "confidence": "confirmed",
    }
    out = format_h1md([finding], "x.sol")
    assert "confirmed" in out


# --------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------- #
def _bc(name):
    from oracle.compiler import load_runtime_bytecode

    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


# --------------------------------------------------------------------- #
# slow: real Z3 honours the timeout and still confirms a solvable finding
# --------------------------------------------------------------------- #
@pytest.mark.slow
def test_real_z3_with_generous_timeout_confirms():
    findings = analyze(
        _bc("assertion-violation"), ["assertion"], max_depth=12, timeout=30
    )
    assert findings
    assert findings[0]["confidence"] == "confirmed"
