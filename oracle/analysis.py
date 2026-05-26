"""Analysis driver: run the symbolic VM, solve candidate findings with Z3.

A detector records *candidate* findings (a path it reached, plus optional extra
constraint). This module asks Z3 whether `path_constraints AND extra_constraint`
is satisfiable. Only satisfiable candidates become real findings, each enriched
with a `trigger_input` — the concrete model Z3 produced.

The single point of contact with Z3's check()/model() is `solve_finding`. The
test suite mocks exactly this boundary (see tests/conftest.py) so the default
`pytest` run never invokes Z3; `pytest -m slow` exercises the real solver.
"""

from __future__ import annotations

from typing import List, Optional

from oracle.laser.detectors import DETECTOR_REGISTRY
from oracle.laser.disassembler import parse_bytecode
from oracle.laser.smt import Solver
from oracle.laser.vm import SymbolicVM


def solve_finding(candidate: dict) -> Optional[dict]:
    """Return an enriched finding if reachable, else None.

    THIS is the Z3 boundary. Tests mock this function (or `Solver`) to avoid
    invoking the solver in the default run.
    """
    solver = Solver()
    for c in candidate.get("constraints", []):
        solver.add(c)
    if "extra_constraint" in candidate:
        solver.add(candidate["extra_constraint"])

    result = solver.check()
    # z3 returns z3.sat / z3.unsat / z3.unknown
    import z3

    if result != z3.sat:
        return None

    model = solver.model()
    trigger_input = {}
    for name, sym in candidate.get("symbols", {}).items():
        try:
            val = model.eval(sym.raw, model_completion=True)
            trigger_input[name] = _z3_to_hex(val)
        except Exception:
            trigger_input[name] = None

    return _finalize(candidate, trigger_input)


def _z3_to_hex(val) -> str:
    try:
        n = val.as_long()
    except Exception:
        return str(val)
    return f"0x{n:064x}"


def _finalize(candidate: dict, trigger_input: dict) -> dict:
    return {
        "category": candidate["category"],
        "severity": candidate["severity"],
        "pc": candidate["pc"],
        "op": candidate["op"],
        "depth": candidate.get("depth", 0),
        "trace": candidate["trace"],
        "trigger_input": trigger_input,
    }


def analyze(
    bytecode_input,
    checks: List[str],
    max_depth: int = 12,
) -> List[dict]:
    """Run the requested checks over the bytecode and return solved findings.

    `checks` is a list of CLI check tokens (e.g. ["assertion"]) or ["all"].
    """
    bytecode = parse_bytecode(bytecode_input)
    if "all" in checks:
        check_tokens = list(DETECTOR_REGISTRY.keys())
    else:
        check_tokens = checks

    vm = SymbolicVM(bytecode, max_depth=max_depth)
    detectors = []
    for token in check_tokens:
        det_cls = DETECTOR_REGISTRY.get(token)
        if det_cls is None:
            raise ValueError(f"unknown check: {token}")
        det = det_cls()
        detectors.append(det)
        vm.register(det)

    vm.run()

    findings: List[dict] = []
    seen = set()
    for det in detectors:
        for candidate in det.findings:
            solved = solve_finding(candidate)
            if solved is None:
                continue
            # de-duplicate findings at the same pc/category
            key = (solved["category"], solved["pc"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(solved)
    return findings
