"""Symbolic machine state for oracle's EVM engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Set

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
        # O(1) membership test counterpart to `trace` — contains the same PCs.
        # Maintained alongside trace in vm._step so detectors can check whether
        # a PC recurred on this path without a linear scan of the trace list.
        self.trace_pcs: Set[int] = set()
        self.halted: bool = False
        self.reverted: bool = False
        # Reentrancy tracking (consumed by ReentrancyDetector). These live on
        # the machine state so they propagate correctly across path forks: a
        # set of storage-slot identity keys SLOADed so far on this path, a flag
        # marking that a value-forwarding external CALL has occurred, and the
        # snapshot of slots that had been read *before* that call.
        self.sloads_seen: Set[str] = set()
        self.call_checkpoint: bool = False
        self.sloads_before_call: Set[str] = set()
        # slot identities SSTOREd so far on this path (consumed by the
        # CrossFunctionReentrancyDetector to recognise the calling
        # function's own pre-call CEI fix and suppress a finding when the
        # caller updates its pre-read slot before the external CALL).
        self.sstores_seen: Set[str] = set()
        self.sstores_before_call: Set[str] = set()
        # pc of the most recent value-forwarding CALL on this path
        # (consumed by CrossFunctionReentrancyDetector to identify the
        # call-site whose CEI an SSTORE-after-CALL is patching, since the
        # CALL forks the state and the post-call branch is a different
        # MachineState object than the one inspected at CALL time).
        self.last_call_pc: int = -1
        # Access-control tracking (consumed by AccessControlEscalationDetector):
        # set once this path has executed a CALLER (the function read msg.sender).
        # A privileged write/sink reached on a path that read the sender but never
        # bound a constraint on it is an unguarded-ownership escalation. This
        # lives on the machine state so it propagates across path forks.
        self.caller_loaded: bool = False
        # tx.origin tracking (consumed by TxOriginAuthDetector): set once this
        # path has executed an ORIGIN (the function read tx.origin). Using
        # tx.origin in an authorization check is unsafe (phishing-relay attack).
        # Lives on the machine state so it propagates across path forks.
        self.origin_loaded: bool = False
        # Set once this path has been flagged for a tx.origin guard, so the same
        # guard is reported exactly once per path rather than on every
        # subsequent instruction (the origin constraint persists down the path).
        self.tx_origin_flagged: bool = False
        # block-value-as-time tracking (consumed by TimestampDependenceDetector):
        # set once this path has executed a TIMESTAMP/NUMBER (the function read a
        # block value). Using block.timestamp/block.number as a randomness or
        # decision source is manipulable by miners/validators (SWC-116). Lives on
        # the machine state so it propagates across path forks.
        self.blockval_loaded: bool = False
        # Set once this path has been flagged for a block-value-dependent branch,
        # so the same guard is reported exactly once per path rather than on every
        # subsequent instruction (the block-value constraint persists down the
        # path).
        self.timestamp_flagged: bool = False
        # Set once this path has been flagged for an EXTCODESIZE-based caller-type
        # check (consumed by ExtcodesizeCallerCheckDetector): a control-flow branch
        # on `extcodesize(addr)` is a bypassable "is the caller a contract / an
        # EOA?" guard (a contract's constructor reports codesize 0). The
        # extcodesize constraint persists down the path, so a per-path latch keeps
        # the finding to one-per-guarded-path. Lives on the machine state so it
        # propagates across path forks.
        self.extcodesize_flagged: bool = False
        # Set once this path has been flagged for a strict balance-equality check
        # (consumed by StrictBalanceEqualityDetector): a control-flow branch on
        # `address(this).balance` / an account's BALANCE is an SWC-132 "unexpected
        # ether balance" assumption — an attacker can force-feed ether via
        # `selfdestruct` or by pre-funding a CREATE2 address, so the balance can
        # never be assumed to equal an internally-tracked value. The balance
        # constraint persists down the path, so a per-path latch keeps the finding
        # to one-per-guarded-path. Lives on the machine state so it propagates
        # across path forks.
        self.balance_flagged: bool = False
        # set once this path has executed a BLOCKHASH (the function read a block
        # hash). Using `blockhash(n)` as a randomness source is a weak source of
        # entropy — the block proposer can influence which block is produced and
        # an attacker in the same transaction sees the same value (SWC-120).
        # Lives on the machine state so it propagates across path forks.
        self.blockhash_loaded: bool = False
        # Set once this path has been flagged for a block-hash-dependent branch
        # (consumed by BlockhashRandomnessDetector), so the same guard is reported
        # exactly once per path rather than on every subsequent instruction (the
        # blockhash constraint persists down the path).
        self.blockhash_flagged: bool = False
        # set once this path has executed a GASPRICE (the function read
        # `tx.gasprice`). Branching control flow on `tx.gasprice` is a
        # transaction-order-dependence smell (SWC-114): the gas price is chosen
        # by the transaction sender and is the lever miners/searchers use to
        # reorder transactions in a block, so gating logic on it (a gas-price
        # ceiling meant to deter front-running, or a gas-price-derived outcome)
        # is decided by a value an attacker freely sets and that determines
        # ordering. Lives on the machine state so it propagates across path forks.
        self.gasprice_loaded: bool = False
        # Set once this path has been flagged for a gas-price-dependent branch
        # (consumed by TransactionOrderDependenceDetector), so the same guard is
        # reported exactly once per path rather than on every subsequent
        # instruction (the gasprice constraint persists down the path).
        self.gasprice_flagged: bool = False
        # set once this path has executed a DIFFICULTY/PREVRANDAO (0x44) — the
        # function read `block.prevrandao` (post-Merge) / `block.difficulty`
        # (pre-Merge). It is a weak source of randomness (SWC-120): the value is
        # set by the block proposer and is observable by an attacker in the same
        # transaction, so gating a payout / picking a winner on it is a security
        # decision an attacker can predict or grind. Distinct from BLOCKHASH
        # (a different chain attribute / symbol family). Lives on the machine
        # state so it propagates across path forks.
        self.prevrandao_loaded: bool = False
        # Set once this path has been flagged for a prevrandao-dependent branch
        # (consumed by PrevrandaoRandomnessDetector), so the same guard is
        # reported exactly once per path rather than on every subsequent
        # instruction (the prevrandao constraint persists down the path).
        self.prevrandao_flagged: bool = False
        # Set once this path has executed a DELEGATECALL/CALLCODE whose target
        # is calldata-derived (attacker-controllable). Consumed by
        # DelegatecallSelfdestructDetector: a subsequent SELFDESTRUCT on the
        # same path — in the same execution context — means the callee code run
        # via the untrusted delegatecall could trigger a contract-destroying
        # path that the attacker fully controls.
        self.delegatecall_untrusted_seen: bool = False

    def clone(self) -> "MachineState":
        new = MachineState.__new__(MachineState)
        new.world = self.world  # storage object reference; copied on write below
        new.stack = list(self.stack)
        new.memory = self.memory
        new.pc = self.pc
        new.depth = self.depth
        new.constraints = list(self.constraints)
        new.trace = list(self.trace)
        new.trace_pcs = set(self.trace_pcs)
        new.halted = self.halted
        new.reverted = self.reverted
        # copy reentrancy tracking so each forked path carries its own history
        new.sloads_seen = set(self.sloads_seen)
        new.call_checkpoint = self.call_checkpoint
        new.sloads_before_call = set(self.sloads_before_call)
        new.sstores_seen = set(self.sstores_seen)
        new.sstores_before_call = set(self.sstores_before_call)
        new.last_call_pc = self.last_call_pc
        new.caller_loaded = self.caller_loaded
        new.origin_loaded = self.origin_loaded
        new.tx_origin_flagged = self.tx_origin_flagged
        new.blockval_loaded = self.blockval_loaded
        new.timestamp_flagged = self.timestamp_flagged
        new.extcodesize_flagged = self.extcodesize_flagged
        new.balance_flagged = self.balance_flagged
        new.blockhash_loaded = self.blockhash_loaded
        new.blockhash_flagged = self.blockhash_flagged
        new.gasprice_loaded = self.gasprice_loaded
        new.gasprice_flagged = self.gasprice_flagged
        new.prevrandao_loaded = self.prevrandao_loaded
        new.prevrandao_flagged = self.prevrandao_flagged
        new.delegatecall_untrusted_seen = self.delegatecall_untrusted_seen
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
