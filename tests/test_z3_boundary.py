"""Verify the Z3 mocking boundary (criterion 8).

The default run must never call the real solver. We prove it by spying on
z3.Solver.check during a default (mocked) analysis and asserting it is not
invoked.
"""

import os

import pytest

from oracle.analysis import analyze
from oracle.compiler import load_runtime_bytecode

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_default_run_does_not_invoke_z3(monkeypatch):
    import z3

    calls = {"check": 0}
    orig = z3.Solver.check

    def spy(self, *a, **k):
        calls["check"] += 1
        return orig(self, *a, **k)

    monkeypatch.setattr(z3.Solver, "check", spy)

    bc = load_runtime_bytecode(os.path.join(FIXTURES, "assertion-violation.sol"))
    findings = analyze(bc, ["assertion"], max_depth=12)
    assert findings  # mocked solve still yields findings
    assert calls["check"] == 0, "default run must not invoke z3.Solver.check"


@pytest.mark.slow
def test_slow_run_does_invoke_z3(monkeypatch):
    import z3

    calls = {"check": 0}
    orig = z3.Solver.check

    def spy(self, *a, **k):
        calls["check"] += 1
        return orig(self, *a, **k)

    monkeypatch.setattr(z3.Solver, "check", spy)

    bc = load_runtime_bytecode(os.path.join(FIXTURES, "assertion-violation.sol"))
    analyze(bc, ["assertion"], max_depth=12)
    assert calls["check"] > 0, "slow run should invoke the real solver"
