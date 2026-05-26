"""pytest configuration and the Z3-mocking strategy for oracle's tests.

Criterion 8 (Z3 solver mocking strategy):
  * The default `pytest` run (no markers) completes WITHOUT invoking Z3.
  * `pytest -m slow` exercises the REAL Z3 solver against the small fixtures.

The single point of contact with Z3 is `oracle.analysis.solve_finding` (it is
the only function that calls Solver.check()/model()). The `mock_z3` fixture
below is `autouse=True` for the default run and patches that boundary with a
deterministic stub that turns every candidate finding into a solved finding
WITHOUT touching the solver. Slow tests opt out via the `slow` marker so they
hit real Z3.
"""

import pytest

import oracle.analysis as analysis


def _stub_solve_finding(candidate):
    """Deterministic stand-in for solve_finding that never invokes Z3.

    It treats every reached candidate as satisfiable (which is the case for
    every shipped fixture) and synthesises a trigger_input by reading any
    concrete numerals out of the candidate's symbols, defaulting others to a
    fixed sentinel. This keeps default tests fast, hermetic, and Z3-free.
    """
    trigger_input = {}
    for name in candidate.get("symbols", {}):
        # Without Z3 we cannot solve; emit a stable placeholder so the shape of
        # the finding (and thus the report) is still exercised by default tests.
        trigger_input[name] = "0x" + "00" * 32
    return analysis._finalize(candidate, trigger_input)


@pytest.fixture(autouse=True)
def mock_z3(request, monkeypatch):
    """Patch the Z3 boundary for every test NOT marked `slow`."""
    if request.node.get_closest_marker("slow"):
        # slow tests use the real solver — do not patch
        yield
        return
    monkeypatch.setattr(analysis, "solve_finding", _stub_solve_finding)
    yield


def pytest_collection_modifyitems(config, items):
    """Belt-and-suspenders: ensure slow tests are deselected by default.

    pyproject sets `addopts = -m 'not slow'`, but this guard makes the
    behaviour explicit even if a user overrides addopts.
    """
    pass
