"""Symbolic machine state for oracle's EVM engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from oracle.laser.smt import BaseArray, BitVec, K


@dataclass
class TraceEntry:
    """One executed EVM operation, recorded for finding traces."""

    pc: int
    op: str

    def to_dict(self) -> dict:
        return {"pc": self.pc, "op": self.op}


class WorldState:
    """Persistent contract storage, shared across a single path."""

    def __init__(self):
        # storage: symbolic mapping slot(256) -> value(256), default 0.
        # K takes a plain python int for the default value.
        self.storage: BaseArray = K(256, 256, 0)


class MachineState:
    """Volatile per-path machine state: stack, memory, pc, depth."""

    def __init__(self, world: WorldState):
        self.world = world
        self.stack: List[BitVec] = []
        # memory modelled as symbolic byte array address(256) -> byte(8)
        self.memory: BaseArray = K(256, 8, 0)
        self.pc: int = 0
        self.depth: int = 0
        # path constraints accumulated along this execution
        self.constraints: List = []
        self.trace: List[TraceEntry] = []
        self.halted: bool = False
        self.reverted: bool = False

    def clone(self) -> "MachineState":
        new = MachineState.__new__(MachineState)
        new.world = self.world  # storage object reference; copied on write below
        new.stack = list(self.stack)
        new.memory = self.memory
        new.pc = self.pc
        new.depth = self.depth
        new.constraints = list(self.constraints)
        new.trace = list(self.trace)
        new.halted = self.halted
        new.reverted = self.reverted
        return new

    def fork_world(self) -> None:
        """Copy-on-write the world so branches don't share storage mutations.

        The storage array is backed by an immutable z3 expression in `.raw`;
        wrapping it in a fresh BaseArray gives an independent handle whose
        `__setitem__` rebinds `.raw` without affecting the original.
        """
        clone = WorldState()
        clone.storage = BaseArray(self.world.storage.raw)
        self.world = clone

    def push(self, value: BitVec) -> None:
        if len(self.stack) >= 1024:
            raise StackOverflowError()
        self.stack.append(value)

    def pop(self) -> BitVec:
        if not self.stack:
            raise StackUnderflowError()
        return self.stack.pop()


class StackUnderflowError(Exception):
    pass


class StackOverflowError(Exception):
    pass
