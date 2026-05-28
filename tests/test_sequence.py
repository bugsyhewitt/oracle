"""Tests for multi-transaction stateful exploration (--sequence-depth N).

POST_V01 item #4. oracle v0.1 models a single transaction starting from fresh
all-zero storage. Some vulnerabilities only become reachable after an earlier
transaction mutates persistent storage — e.g. a guard `require(armed == 1)`
where `armed` is set by a *separate* call. `--sequence-depth N` chains up to N
symbolic transactions: each later transaction resumes from a terminal storage
state of the previous one (with fresh symbolic inputs), composing the path
constraints across the whole sequence.

The discriminating fixture is `stateful-selfdestruct.sol`:
  * arm()  flips storage slot `armed` 0 -> 1.
  * blow() requires armed == 1, then SELFDESTRUCTs.
Single-transaction analysis (depth 1) cannot satisfy the guard from fresh
storage, so real Z3 finds nothing. With depth 2 the second transaction starts
from the post-arm() storage and the SELFDESTRUCT becomes reachable.

Following the suite convention: default (Z3-mocked) tests pin the DRIVER
mechanics (transaction sequencing, terminal-state hand-off, epoch-namespaced
symbols, constraint composition) which are solver-independent. The `slow` tests
re-confirm the real-Z3 discrimination (depth 1 clean, depth 2 finds the bug).
"""

import os

import pytest

from oracle.analysis import (
    MAX_SEQUENCE_FANOUT,
    _explore_sequence,
    _resolve_detectors,
    analyze,
)
from oracle.compiler import load_runtime_bytecode
from oracle.laser.disassembler import Disassembly
from oracle.laser.vm import SymbolicVM

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _bc(name):
    return load_runtime_bytecode(os.path.join(FIXTURES, name + ".sol"))


# --------------------------------------------------------------------------- #
# Fixture sanity: the stateful fixture really contains the guarded SELFDESTRUCT.
# --------------------------------------------------------------------------- #
def test_stateful_fixture_has_sstore_and_selfdestruct():
    mnems = {i.mnemonic for i in Disassembly(_bc("stateful-selfdestruct")).instructions}
    assert "SSTORE" in mnems, "arm() must write storage"
    assert "SLOAD" in mnems, "blow() must read the armed flag"
    assert "SELFDESTRUCT" in mnems, "blow() must self-destruct"


# --------------------------------------------------------------------------- #
# Backwards compatibility: sequence_depth defaults to 1 (single transaction)
# and depth 1 is byte-for-byte the old behaviour.
# --------------------------------------------------------------------------- #
def test_default_sequence_depth_is_single_transaction():
    a = analyze(_bc("reachable-selfdestruct"), ["selfdestruct"], max_depth=12)
    b = analyze(
        _bc("reachable-selfdestruct"), ["selfdestruct"], max_depth=12, sequence_depth=1
    )
    assert [(f["category"], f["pc"]) for f in a] == [(f["category"], f["pc"]) for f in b]


def test_depth_below_one_is_clamped_to_one():
    findings = analyze(
        _bc("reachable-selfdestruct"), ["selfdestruct"], max_depth=12, sequence_depth=0
    )
    assert findings and findings[0]["category"] == "reachable_selfdestruct"


def test_first_transaction_keeps_bare_symbol_names():
    # epoch "" for tx1 means the principal trigger input is still "calldata".
    findings = analyze(
        _bc("reachable-selfdestruct"), ["selfdestruct"], max_depth=12, sequence_depth=1
    )
    assert findings
    assert "calldata" in findings[0]["trigger_input"]


# --------------------------------------------------------------------------- #
# VM-level: a transaction records its terminal (halted, non-reverted) world
# states so the next transaction can resume from them.
# --------------------------------------------------------------------------- #
def test_run_records_terminal_states():
    vm = SymbolicVM(_bc("stateful-selfdestruct"), max_depth=30)
    vm.run()
    assert vm.terminal_states, "a completed transaction must expose terminal worlds"
    # every terminal state is a clean (non-reverted) end of a path
    assert all(not t.reverted for t in vm.terminal_states)


def test_initial_world_resumes_prior_storage():
    # tx1 leaves some storage state; tx2 launched from it must start there.
    vm1 = SymbolicVM(_bc("stateful-selfdestruct"), max_depth=30)
    vm1.run()
    resume = vm1.terminal_states[0]
    vm2 = SymbolicVM(
        _bc("stateful-selfdestruct"),
        max_depth=30,
        epoch="tx2_",
        initial_world=resume.world,
        seed_constraints=list(resume.constraints),
    )
    vm2.run()
    # tx2's start inherits tx1's path constraints, so every terminal state of
    # tx2 carries at least as many constraints as the resume point did.
    assert vm2.terminal_states
    assert all(
        len(t.constraints) >= len(resume.constraints) for t in vm2.terminal_states
    )


def test_second_transaction_uses_epoch_namespaced_symbols():
    vm = SymbolicVM(_bc("stateful-selfdestruct"), max_depth=30, epoch="tx2_")
    # the second transaction's calldata/caller/callvalue are independent symbols
    assert "tx2_" in str(vm.caller.raw)
    assert "tx2_" in str(vm.callvalue.raw)
    assert "tx2_" in str(vm.calldata.raw)


# --------------------------------------------------------------------------- #
# Driver-level: the sequence explorer runs the requested number of transactions
# and composes candidates from each.
# --------------------------------------------------------------------------- #
def test_explore_sequence_runs_requested_depth():
    factories = _resolve_detectors(["selfdestruct"])
    bc = _bc("stateful-selfdestruct")
    one = _explore_sequence(bc, factories, max_depth=30, sequence_depth=1)
    two = _explore_sequence(bc, factories, max_depth=30, sequence_depth=2)
    # depth 2 explores strictly more (it re-runs from each tx1 terminal world),
    # so it produces at least as many raw candidates as depth 1.
    assert len(two) >= len(one)


def test_fanout_cap_is_exposed_and_positive():
    assert isinstance(MAX_SEQUENCE_FANOUT, int)
    assert MAX_SEQUENCE_FANOUT > 0


# --------------------------------------------------------------------------- #
# slow (real Z3): the core value proposition — the stateful bug is invisible to
# single-transaction analysis but found with --sequence-depth 2.
# --------------------------------------------------------------------------- #
@pytest.mark.slow
def test_stateful_bug_invisible_at_depth_one():
    findings = analyze(
        _bc("stateful-selfdestruct"), ["selfdestruct"], max_depth=30, sequence_depth=1
    )
    assert findings == [], (
        "guarded SELFDESTRUCT must be unreachable in a single transaction "
        "(armed flag is 0 in fresh storage)"
    )


@pytest.mark.slow
def test_stateful_bug_found_at_depth_two():
    findings = analyze(
        _bc("stateful-selfdestruct"), ["selfdestruct"], max_depth=30, sequence_depth=2
    )
    assert findings, "two-transaction sequence must reach the guarded SELFDESTRUCT"
    assert findings[0]["category"] == "reachable_selfdestruct"


@pytest.mark.slow
def test_no_regression_single_tx_fixtures_at_depth_one():
    # the classic single-transaction fixtures still resolve under the driver.
    sd = analyze(_bc("reachable-selfdestruct"), ["selfdestruct"], max_depth=12)
    assert sd and sd[0]["category"] == "reachable_selfdestruct"
    av = analyze(_bc("assertion-violation"), ["assertion"], max_depth=12)
    assert av and av[0]["category"] == "assertion_violation"
