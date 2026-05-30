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
from oracle.laser.disassembler import Disassembly, parse_bytecode
from oracle.laser.smt import Solver
from oracle.laser.vm import SymbolicVM

# Default per-query Z3 timeout in seconds. A single hard query on a
# constraint-dense contract can otherwise hang oracle indefinitely. mythril uses
# 25s; oracle defaults to 30s. 0 disables the per-query timeout entirely.
DEFAULT_TIMEOUT_SECONDS = 30


def solve_finding(candidate: dict, timeout: Optional[int] = None) -> Optional[dict]:
    """Return an enriched finding if reachable, else None.

    THIS is the Z3 boundary. Tests mock this function (or `Solver`) to avoid
    invoking the solver in the default run.

    `timeout` is the per-query Z3 budget in seconds. When a query exhausts that
    budget (or Z3 otherwise returns `unknown`) the candidate is not dropped: it
    is reported with `confidence == "timeout"` and no trigger input, so a
    constraint-dense path is surfaced for manual review rather than silently
    lost. A satisfiable query yields a finding with `confidence == "confirmed"`.
    A timeout of 0 (or None) disables the per-query limit.
    """
    solver = Solver()
    if timeout:
        # BaseSolver.set_timeout takes milliseconds.
        solver.set_timeout(int(timeout) * 1000)
    for c in candidate.get("constraints", []):
        solver.add(c)
    if "extra_constraint" in candidate:
        solver.add(candidate["extra_constraint"])

    result = solver.check()
    # z3 returns z3.sat / z3.unsat / z3.unknown
    import z3

    if result == z3.unsat:
        return None

    if result == z3.unknown:
        # Timed out (or otherwise undecided): keep the candidate but flag it so
        # the operator knows the trigger input could not be solved.
        return _finalize(candidate, {}, confidence="timeout")

    model = solver.model()
    trigger_input = {}
    for name, sym in candidate.get("symbols", {}).items():
        try:
            val = model.eval(sym.raw, model_completion=True)
            trigger_input[name] = _z3_to_hex(val)
        except Exception:
            trigger_input[name] = None

    return _finalize(candidate, trigger_input, confidence="confirmed")


def _z3_to_hex(val) -> str:
    try:
        n = val.as_long()
    except Exception:
        return str(val)
    return f"0x{n:064x}"


def _finalize(
    candidate: dict, trigger_input: dict, confidence: str = "confirmed"
) -> dict:
    return {
        "category": candidate["category"],
        "severity": candidate["severity"],
        "pc": candidate["pc"],
        "op": candidate["op"],
        "depth": candidate.get("depth", 0),
        "trace": candidate["trace"],
        "trigger_input": trigger_input,
        "confidence": confidence,
    }


# Bound on the number of terminal world-states carried forward from one
# transaction into the next. Multi-transaction exploration is combinatorial; a
# fan-out cap keeps a deep sequence from exploding while still covering the
# distinct end-states that matter (e.g. "init() succeeded" vs "init() reverted").
MAX_SEQUENCE_FANOUT = 16


def _resolve_detectors(checks: List[str]):
    """Map CLI check tokens to fresh detector instances (factory closures).

    Returns a list of zero-arg factories so each transaction in a sequence gets
    its own detector instances with independent per-path tracking — sharing a
    single instance across transactions would leak reentrancy slot state.
    """
    if "all" in checks:
        check_tokens = list(DETECTOR_REGISTRY.keys())
    else:
        check_tokens = checks
    factories = []
    for token in check_tokens:
        det_cls = DETECTOR_REGISTRY.get(token)
        if det_cls is None:
            raise ValueError(f"unknown check: {token}")
        factories.append(det_cls)
    return factories


def analyze(
    bytecode_input,
    checks: List[str],
    max_depth: int = 12,
    sequence_depth: int = 1,
    timeout: Optional[int] = DEFAULT_TIMEOUT_SECONDS,
    validate: bool = False,
) -> List[dict]:
    """Run the requested checks over the bytecode and return solved findings.

    `checks` is a list of CLI check tokens (e.g. ["assertion"]) or ["all"].

    `sequence_depth` controls multi-transaction (stateful) exploration:
      * 1 (default) — explore a single transaction (v0.1 behaviour).
      * N > 1 — explore sequences of up to N transactions, where each
        transaction resumes from a terminal storage state of the previous one
        with fresh symbolic inputs. This surfaces bugs that require setup +
        trigger across separate calls (e.g. `init()` then `admin()`), composing
        the path constraints of every transaction in the sequence.

    `timeout` bounds each individual Z3 query (in seconds). A query that exceeds
    it is reported with `confidence == "timeout"` rather than dropped, so dense
    paths surface for manual review instead of hanging the run. 0 disables it.

    `validate` (False by default) runs a concrete-replay counterexample check on
    each solved finding: the finding's `trigger_input` is executed against the
    bytecode in a self-contained concrete EVM, and the finding is enriched with
    `"validated": bool` / `"validation": str` recording whether the vulnerable
    `pc` is actually reachable on the concrete path. This catches symbolic-only
    false positives without affecting the set of findings returned.
    """
    bytecode = parse_bytecode(bytecode_input)
    factories = _resolve_detectors(checks)
    if sequence_depth < 1:
        sequence_depth = 1

    candidates = _explore_sequence(
        bytecode, factories, max_depth, sequence_depth
    )

    findings: List[dict] = []
    seen = set()
    for candidate in candidates:
        solved = solve_finding(candidate, timeout=timeout)
        if solved is None:
            continue
        # de-duplicate findings at the same pc/category/depth so the same
        # vulnerability isn't double-reported across overlapping sequences.
        key = (solved["category"], solved["pc"], solved.get("depth", 0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(solved)

    if validate:
        from oracle.laser.replay import validate_findings

        findings = validate_findings(bytecode, findings)
    return findings


def compute_coverage(
    bytecode_input,
    checks: List[str],
    max_depth: int = 12,
    sequence_depth: int = 1,
) -> dict:
    """Explore the contract and report which instructions were reached.

    Coverage answers the question a "0 findings" run leaves open: did oracle
    actually explore the contract, or did it prune early (depth cap, a halting
    opcode, reverts)? It runs the *same* bounded symbolic exploration `analyze`
    uses — registering the same detectors so the explored paths are identical —
    but records the set of program counters visited across every path instead
    of solving findings. No Z3 is involved: coverage is a pure property of the
    exploration, so it is available even when the solver is mocked.

    Returns a dict::

        {
          "total_instructions": int,   # disassembled instructions
          "covered_instructions": int, # distinct instructions reached
          "coverage_pct": float,       # covered / total * 100 (0.0 if empty)
          "covered_pcs": [int, ...],   # sorted reached program counters
          "uncovered_pcs": [int, ...], # sorted instruction pcs never reached
        }
    """
    bytecode = parse_bytecode(bytecode_input)
    factories = _resolve_detectors(checks)
    if sequence_depth < 1:
        sequence_depth = 1

    disasm = Disassembly(bytecode)
    all_pcs = {inst.pc for inst in disasm.instructions}

    visited: set = set()
    frontier = [(None, [])]
    for tx_index in range(sequence_depth):
        epoch = "" if tx_index == 0 else f"tx{tx_index + 1}_"
        next_frontier = []
        for initial_world, seed_constraints in frontier:
            vm = SymbolicVM(
                bytecode,
                max_depth=max_depth,
                epoch=epoch,
                initial_world=initial_world,
                seed_constraints=seed_constraints,
            )
            for f in factories:
                vm.register(f())
            vm.run()
            for det in vm.detectors:
                det.finalize(vm)
            visited |= vm.visited_pcs
            if tx_index + 1 < sequence_depth:
                for term in vm.terminal_states[:MAX_SEQUENCE_FANOUT]:
                    next_frontier.append((term.world, list(term.constraints)))
        frontier = next_frontier
        if not frontier:
            break

    covered = visited & all_pcs
    total = len(all_pcs)
    pct = (len(covered) / total * 100.0) if total else 0.0
    return {
        "total_instructions": total,
        "covered_instructions": len(covered),
        "coverage_pct": round(pct, 2),
        "covered_pcs": sorted(covered),
        "uncovered_pcs": sorted(all_pcs - covered),
    }


def _explore_sequence(bytecode, factories, max_depth, sequence_depth):
    """Run transactions 1..sequence_depth, collecting all candidate findings.

    Returns a flat list of candidate finding dicts (constraints already
    composed across the transactions that led to each one). Detector instances
    are created per transaction-run so per-path state never leaks between
    independent sequences.
    """
    candidates: List[dict] = []

    # `frontier` is the list of starting points for the current transaction:
    # each entry is (initial_world_or_None, seed_constraints). Transaction 1
    # starts from a single fresh world with no inherited constraints.
    frontier = [(None, [])]

    for tx_index in range(sequence_depth):
        epoch = "" if tx_index == 0 else f"tx{tx_index + 1}_"
        next_frontier = []
        for initial_world, seed_constraints in frontier:
            vm = SymbolicVM(
                bytecode,
                max_depth=max_depth,
                epoch=epoch,
                initial_world=initial_world,
                seed_constraints=seed_constraints,
            )
            detectors = [f() for f in factories]
            for det in detectors:
                vm.register(det)
            vm.run()

            for det in detectors:
                det.finalize(vm)
            for det in detectors:
                candidates.extend(det.findings)

            # Prepare hand-off states for the next transaction (if any).
            if tx_index + 1 < sequence_depth:
                for term in vm.terminal_states[:MAX_SEQUENCE_FANOUT]:
                    next_frontier.append((term.world, list(term.constraints)))
        frontier = next_frontier
        if not frontier:
            break

    return candidates
