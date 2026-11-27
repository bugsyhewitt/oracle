"""Tests for oracle's symbolic machine state (Z3-free).

Covers MachineState, WorldState, TraceEntry, stack boundary conditions,
clone(), and fork_world() — all logic that lives in oracle/laser/state.py
but had no dedicated test file.
"""

from __future__ import annotations

import pytest

from oracle.laser.state import (
    MachineState,
    StackOverflowError,
    StackUnderflowError,
    TraceEntry,
    WorldState,
)
from oracle.laser.smt import symbol_factory


def _bvv(n: int, size: int = 256):
    return symbol_factory.BitVecVal(n, size)


# ------------------------------------------------------------------ #
# TraceEntry
# ------------------------------------------------------------------ #

def test_trace_entry_stores_pc_and_op():
    e = TraceEntry(pc=42, op="JUMPDEST")
    assert e.pc == 42
    assert e.op == "JUMPDEST"


def test_trace_entry_to_dict_shape():
    e = TraceEntry(pc=10, op="INVALID")
    d = e.to_dict()
    assert d == {"pc": 10, "op": "INVALID"}


def test_trace_entry_to_dict_zero_pc():
    e = TraceEntry(pc=0, op="STOP")
    assert e.to_dict()["pc"] == 0


def test_trace_entry_dataclass_equality():
    a = TraceEntry(pc=5, op="ADD")
    b = TraceEntry(pc=5, op="ADD")
    assert a == b


def test_trace_entry_dataclass_inequality():
    a = TraceEntry(pc=5, op="ADD")
    b = TraceEntry(pc=5, op="MUL")
    assert a != b


# ------------------------------------------------------------------ #
# WorldState
# ------------------------------------------------------------------ #

def test_world_state_has_storage():
    w = WorldState()
    assert w.storage is not None


def test_world_state_storage_is_symbolic():
    from oracle.laser.smt import BaseArray
    w = WorldState()
    assert isinstance(w.storage, BaseArray)


# ------------------------------------------------------------------ #
# MachineState construction
# ------------------------------------------------------------------ #

def test_machine_state_initial_pc_zero():
    ms = MachineState(WorldState())
    assert ms.pc == 0


def test_machine_state_initial_depth_zero():
    ms = MachineState(WorldState())
    assert ms.depth == 0


def test_machine_state_initial_stack_empty():
    ms = MachineState(WorldState())
    assert ms.stack == []


def test_machine_state_initial_halted_false():
    ms = MachineState(WorldState())
    assert ms.halted is False


def test_machine_state_initial_reverted_false():
    ms = MachineState(WorldState())
    assert ms.reverted is False


def test_machine_state_initial_trace_empty():
    ms = MachineState(WorldState())
    assert ms.trace == []
    assert ms.trace_pcs == set()


def test_machine_state_initial_constraints_empty():
    ms = MachineState(WorldState())
    assert ms.constraints == []


def test_machine_state_initial_caller_loaded_false():
    ms = MachineState(WorldState())
    assert ms.caller_loaded is False


def test_machine_state_initial_origin_loaded_false():
    ms = MachineState(WorldState())
    assert ms.origin_loaded is False


def test_machine_state_initial_detector_flags_false():
    ms = MachineState(WorldState())
    for attr in (
        "tx_origin_flagged",
        "blockval_loaded",
        "timestamp_flagged",
        "extcodesize_flagged",
        "balance_flagged",
        "blockhash_loaded",
        "blockhash_flagged",
        "gasprice_loaded",
        "gasprice_flagged",
        "prevrandao_loaded",
        "prevrandao_flagged",
        "delegatecall_untrusted_seen",
    ):
        assert getattr(ms, attr) is False, f"{attr} should start False"


def test_machine_state_initial_last_call_pc_negative():
    ms = MachineState(WorldState())
    assert ms.last_call_pc == -1


# ------------------------------------------------------------------ #
# push / pop
# ------------------------------------------------------------------ #

def test_push_adds_to_stack():
    ms = MachineState(WorldState())
    v = _bvv(1)
    ms.push(v)
    assert len(ms.stack) == 1


def test_pop_removes_from_stack():
    ms = MachineState(WorldState())
    v = _bvv(99)
    ms.push(v)
    out = ms.pop()
    assert ms.stack == []
    assert out is v


def test_pop_on_empty_raises_underflow():
    ms = MachineState(WorldState())
    with pytest.raises(StackUnderflowError):
        ms.pop()


def test_stack_overflow_at_1024():
    ms = MachineState(WorldState())
    for i in range(1024):
        ms.push(_bvv(i))
    with pytest.raises(StackOverflowError):
        ms.push(_bvv(1025))


def test_push_exactly_1024_does_not_raise():
    ms = MachineState(WorldState())
    for i in range(1024):
        ms.push(_bvv(i))
    assert len(ms.stack) == 1024


# ------------------------------------------------------------------ #
# clone()
# ------------------------------------------------------------------ #

def test_clone_copies_pc():
    ms = MachineState(WorldState())
    ms.pc = 77
    c = ms.clone()
    assert c.pc == 77


def test_clone_copies_depth():
    ms = MachineState(WorldState())
    ms.depth = 5
    c = ms.clone()
    assert c.depth == 5


def test_clone_stack_is_independent():
    ms = MachineState(WorldState())
    ms.push(_bvv(10))
    c = ms.clone()
    # mutating original stack does not affect clone
    ms.push(_bvv(20))
    assert len(c.stack) == 1


def test_clone_constraints_are_independent():
    ms = MachineState(WorldState())
    ms.constraints.append("x > 0")
    c = ms.clone()
    ms.constraints.append("y > 0")
    assert len(c.constraints) == 1


def test_clone_trace_is_independent():
    ms = MachineState(WorldState())
    ms.trace.append(TraceEntry(pc=0, op="STOP"))
    c = ms.clone()
    ms.trace.append(TraceEntry(pc=1, op="ADD"))
    assert len(c.trace) == 1


def test_clone_trace_pcs_are_independent():
    ms = MachineState(WorldState())
    ms.trace_pcs.add(10)
    c = ms.clone()
    ms.trace_pcs.add(20)
    assert 20 not in c.trace_pcs


def test_clone_shares_world_reference_before_fork():
    ms = MachineState(WorldState())
    c = ms.clone()
    # before fork_world(), both point at the same WorldState object
    assert c.world is ms.world


def test_clone_copies_caller_loaded():
    ms = MachineState(WorldState())
    ms.caller_loaded = True
    c = ms.clone()
    assert c.caller_loaded is True


def test_clone_copies_delegatecall_untrusted_seen():
    ms = MachineState(WorldState())
    ms.delegatecall_untrusted_seen = True
    c = ms.clone()
    assert c.delegatecall_untrusted_seen is True


def test_clone_sloads_seen_is_independent():
    ms = MachineState(WorldState())
    ms.sloads_seen.add("slot_a")
    c = ms.clone()
    ms.sloads_seen.add("slot_b")
    assert "slot_b" not in c.sloads_seen


# ------------------------------------------------------------------ #
# fork_world()
# ------------------------------------------------------------------ #

def test_fork_world_creates_new_world_object():
    ms = MachineState(WorldState())
    original_world = ms.world
    ms.fork_world()
    assert ms.world is not original_world


def test_fork_world_original_world_is_unmodified():
    ms = MachineState(WorldState())
    clone = ms.clone()
    # fork the clone; the original ms.world must be a different object
    clone.fork_world()
    assert clone.world is not ms.world
