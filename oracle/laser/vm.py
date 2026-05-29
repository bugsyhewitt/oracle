"""Symbolic EVM interpreter for oracle.

A bounded, depth-limited symbolic executor. It explores execution paths over
symbolic calldata/caller/callvalue, accumulating Z3 path constraints. Detector
plugins are invoked before each instruction is executed and may record
findings (each finding carries the path constraints, which the analysis driver
solves with Z3 to obtain a concrete trigger input).

Scope is deliberately bounded to the opcodes oracle's v0.1 detectors need.
Unhandled opcodes are treated conservatively (path stops) so analysis stays
sound-by-omission rather than crashing.
"""

from __future__ import annotations

from typing import List, Optional

from oracle.laser.disassembler import Disassembly
from oracle.laser.smt import (
    UDiv,
    UGT,
    ULT,
    URem,
    If,
    LShR,
    AShr,
    SDiv,
    SMod,
    SignExt,
    Concat,
    Extract,
    BitVec,
    simplify,
    symbol_factory,
)
from oracle.laser.smt.keccak import keccak_model
from oracle.laser.state import (
    MachineState,
    StackOverflowError,
    StackUnderflowError,
    TraceEntry,
    WorldState,
)

TT256 = 2 ** 256
TT256M1 = (2 ** 256) - 1


def _bvv(value: int) -> BitVec:
    return symbol_factory.BitVecVal(value % TT256, 256)


class DetectorHook:
    """A detector plugin: inspects a state before an op executes.

    Subclasses implement `inspect(vm, state, instruction)` and append to
    `self.findings`. A finding is a dict with at least:
    category, severity, pc, op, constraints (list of Bool), and a
    `symbol` mapping name->BitVec for which Z3 input should be reported.
    """

    category = "abstract"

    def __init__(self):
        self.findings: List[dict] = []

    def inspect(self, vm: "SymbolicVM", state: MachineState, instruction) -> None:
        raise NotImplementedError


class SymbolicVM:
    """Bounded symbolic executor over a single contract's runtime bytecode.

    A single `SymbolicVM` instance models exactly ONE transaction. Multi-
    transaction (stateful) exploration is composed by the analysis driver,
    which chains several VMs: the terminal `WorldState` snapshots of one
    transaction become the initial worlds of the next. Each transaction gets a
    distinct `epoch` tag that prefixes every symbol the VM mints, so the same
    PC executing in two different transactions yields *independent* symbolic
    inputs (calldata, caller, callvalue, memory reads, call return values, …)
    rather than being conflated into one shared symbol.
    """

    def __init__(
        self,
        bytecode: bytes,
        max_depth: int = 12,
        epoch: str = "",
        initial_world: Optional[WorldState] = None,
        seed_constraints: Optional[List] = None,
    ):
        self.disasm = Disassembly(bytecode)
        self.max_depth = max_depth
        self.detectors: List[DetectorHook] = []
        # Per-transaction symbol namespace. Empty for the first (or only)
        # transaction so the v0.1 trigger-input names ("calldata", "caller",
        # "callvalue") are unchanged; later transactions use "txN_" prefixes.
        self.epoch = epoch
        # The storage state this transaction starts from. For tx1 this is a
        # fresh all-zero world; for tx2+ it is a terminal snapshot of tx1.
        self.initial_world = initial_world
        # Path constraints inherited from prior transactions in the sequence.
        self.seed_constraints = list(seed_constraints) if seed_constraints else []
        # Terminal (halted, non-reverted) states collected by run(); these are
        # the hand-off points to the next transaction in a sequence.
        self.terminal_states: List[MachineState] = []
        # Set of program counters this VM actually executed an instruction at,
        # across every explored path. Populated in `_step`. Compared against the
        # full disassembly to report how much of the contract the symbolic
        # exploration reached vs. pruned (max-depth, halting opcodes, reverts).
        self.visited_pcs: set = set()
        # symbolic transaction inputs
        # calldata is modelled as a word-indexed family of symbols: each
        # distinct CALLDATALOAD offset yields its own independent symbol so the
        # ABI selector word and argument words are never conflated. `calldata`
        # is the offset-0 word (the function selector + leading args region),
        # reported as the principal trigger input.
        self._calldata_words = {}
        self.calldata = self._calldata_word(0)
        self.callvalue = symbol_factory.BitVecSym(self._sym("callvalue"), 256)
        self.caller = symbol_factory.BitVecSym(self._sym("caller"), 256)
        # tx.origin — the externally-owned account that started the transaction.
        # A *stable, named* symbol (like `caller`) rather than a fresh anonymous
        # one per ORIGIN execution, so a guard that branches on `tx.origin`
        # always references the same leaf and the tx-origin-auth detector can
        # recognise it in the path constraints (mirrors how `caller` is matched
        # by the access-control detector).
        self.origin = symbol_factory.BitVecSym(self._sym("origin"), 256)
        self.calldatasize = symbol_factory.BitVecSym(self._sym("calldatasize"), 256)
        self.work_count = 0
        # bound on total worklist iterations to guarantee termination
        self.max_work = 200000

    def _sym(self, name: str) -> str:
        """Namespace a symbol name with this transaction's epoch prefix.

        The first transaction (epoch == "") keeps bare names so existing
        single-transaction trigger-input reporting is byte-for-byte unchanged.
        """
        return f"{self.epoch}{name}" if self.epoch else name

    def _calldata_word(self, offset) -> BitVec:
        """Return the symbolic 256-bit word at a calldata offset.

        Concrete offsets are cached so repeated loads of the same offset return
        the same symbol (consistency). Symbolic offsets get a fresh symbol.
        """
        key = self._concrete(offset) if not isinstance(offset, int) else offset
        if key is None:
            return symbol_factory.BitVecSym(self._sym("calldata_dyn"), 256)
        if key not in self._calldata_words:
            name = "calldata" if key == 0 else f"calldata_{key}"
            self._calldata_words[key] = symbol_factory.BitVecSym(self._sym(name), 256)
        return self._calldata_words[key]

    def register(self, detector: DetectorHook) -> None:
        self.detectors.append(detector)

    def run(self) -> None:
        """Depth-first exploration of all paths up to max_depth.

        Records every terminal (halted, non-reverted) path end in
        `self.terminal_states` so a multi-transaction driver can resume from
        each resulting world state.
        """
        if self.initial_world is not None:
            # resume from a prior transaction's storage; carry it copy-on-write
            # so this transaction's SSTOREs don't mutate the source snapshot.
            world = WorldState()
            world.storage = self.initial_world.storage
            start = MachineState(world)
            start.fork_world()
        else:
            world = WorldState()
            start = MachineState(world)
        # inherit the path constraints accumulated by earlier transactions
        start.constraints = list(self.seed_constraints)
        worklist: List[MachineState] = [start]
        while worklist:
            self.work_count += 1
            if self.work_count > self.max_work:
                break
            state = worklist.pop()
            if state.reverted:
                continue
            if state.halted:
                self.terminal_states.append(state)
                continue
            inst = self.disasm.by_pc.get(state.pc)
            if inst is None:
                # ran off the end of code => implicit STOP (a terminal state)
                self.terminal_states.append(state)
                continue

            # detector hook BEFORE executing the instruction
            for det in self.detectors:
                det.inspect(self, state, inst)

            try:
                successors = self._step(state, inst)
            except (StackUnderflowError, StackOverflowError):
                continue
            # A handler that halts cleanly (STOP / RETURN / implicit end) mutates
            # `state` in place and returns no successors; such a state is a valid
            # terminal world to resume a later transaction from. A reverted state
            # is discarded (its storage effects are rolled back on the EVM).
            if not successors:
                if state.halted and not state.reverted:
                    self.terminal_states.append(state)
                continue
            for succ in successors:
                if succ.reverted:
                    continue
                if succ.halted:
                    self.terminal_states.append(succ)
                    continue
                if succ.depth <= self.max_depth:
                    worklist.append(succ)

    # ------------------------------------------------------------------ #
    # instruction dispatch
    # ------------------------------------------------------------------ #
    def _step(self, state: MachineState, inst) -> List[MachineState]:
        op = inst.mnemonic
        # record that this instruction was reached on some explored path
        self.visited_pcs.add(inst.pc)
        state.trace.append(TraceEntry(pc=inst.pc, op=op))
        handler = getattr(self, f"_op_{op.lower()}", None)

        if handler is None:
            if op.startswith("PUSH"):
                return self._op_push(state, inst)
            if op.startswith("DUP"):
                return self._op_dup(state, inst)
            if op.startswith("SWAP"):
                return self._op_swap(state, inst)
            if op.startswith("LOG"):
                return self._op_log(state, inst)
            # Unknown / unsupported opcode: stop this path conservatively.
            state.halted = True
            return []
        return handler(state, inst)

    def _advance(self, state: MachineState, inst) -> MachineState:
        state.pc = inst.pc + 1 + (len(self._imm(inst)))
        return state

    @staticmethod
    def _imm(inst) -> bytes:
        if inst.mnemonic.startswith("PUSH") and inst.operand is not None:
            n = int(inst.mnemonic[4:]) if inst.mnemonic != "PUSH0" else 0
            return b"\x00" * n
        return b""

    # ---- stack/const ops ----
    def _op_push(self, state, inst):
        if inst.mnemonic == "PUSH0":
            state.push(_bvv(0))
        else:
            state.push(_bvv(inst.operand or 0))
        n = int(inst.mnemonic[4:]) if inst.mnemonic != "PUSH0" else 0
        state.pc = inst.pc + 1 + n
        return [state]

    def _op_push0(self, state, inst):
        state.push(_bvv(0))
        state.pc = inst.pc + 1
        return [state]

    def _op_dup(self, state, inst):
        n = int(inst.mnemonic[3:])
        if len(state.stack) < n:
            raise StackUnderflowError()
        state.push(state.stack[-n])
        state.pc = inst.pc + 1
        return [state]

    def _op_swap(self, state, inst):
        n = int(inst.mnemonic[4:])
        if len(state.stack) < n + 1:
            raise StackUnderflowError()
        state.stack[-1], state.stack[-1 - n] = state.stack[-1 - n], state.stack[-1]
        state.pc = inst.pc + 1
        return [state]

    def _op_pop(self, state, inst):
        state.pop()
        state.pc = inst.pc + 1
        return [state]

    def _op_log(self, state, inst):
        n = int(inst.mnemonic[3:])
        for _ in range(2 + n):
            if state.stack:
                state.pop()
        state.pc = inst.pc + 1
        return [state]

    # ---- arithmetic ----
    def _binop(self, state, inst, fn):
        a = state.pop()
        b = state.pop()
        state.push(simplify(fn(a, b)))
        state.pc = inst.pc + 1
        return [state]

    def _op_add(self, state, inst):
        return self._binop(state, inst, lambda a, b: a + b)

    def _op_sub(self, state, inst):
        return self._binop(state, inst, lambda a, b: a - b)

    def _op_mul(self, state, inst):
        return self._binop(state, inst, lambda a, b: a * b)

    def _op_div(self, state, inst):
        a = state.pop()
        b = state.pop()
        # EVM: division by zero yields 0
        state.push(simplify(If(b == _bvv(0), _bvv(0), UDiv(a, b))))
        state.pc = inst.pc + 1
        return [state]

    def _op_mod(self, state, inst):
        a = state.pop()
        b = state.pop()
        state.push(simplify(If(b == _bvv(0), _bvv(0), URem(a, b))))
        state.pc = inst.pc + 1
        return [state]

    def _op_exp(self, state, inst):
        a = state.pop()
        b = state.pop()
        # model EXP conservatively as a fresh symbol-free product when concrete,
        # else multiply once (sufficient for fixtures that don't rely on EXP).
        state.push(simplify(a * b))
        state.pc = inst.pc + 1
        return [state]

    # ---- comparisons / bitwise ----
    def _bool_to_bv(self, cond) -> BitVec:
        return If(cond, _bvv(1), _bvv(0))

    def _op_lt(self, state, inst):
        a = state.pop()
        b = state.pop()
        state.push(simplify(self._bool_to_bv(ULT(a, b))))
        state.pc = inst.pc + 1
        return [state]

    def _op_gt(self, state, inst):
        a = state.pop()
        b = state.pop()
        state.push(simplify(self._bool_to_bv(UGT(a, b))))
        state.pc = inst.pc + 1
        return [state]

    def _op_slt(self, state, inst):
        a = state.pop()
        b = state.pop()
        state.push(simplify(self._bool_to_bv(a < b)))
        state.pc = inst.pc + 1
        return [state]

    def _op_sgt(self, state, inst):
        a = state.pop()
        b = state.pop()
        state.push(simplify(self._bool_to_bv(a > b)))
        state.pc = inst.pc + 1
        return [state]

    def _op_eq(self, state, inst):
        a = state.pop()
        b = state.pop()
        state.push(simplify(self._bool_to_bv(a == b)))
        state.pc = inst.pc + 1
        return [state]

    def _op_iszero(self, state, inst):
        a = state.pop()
        state.push(simplify(self._bool_to_bv(a == _bvv(0))))
        state.pc = inst.pc + 1
        return [state]

    def _op_and(self, state, inst):
        return self._binop(state, inst, lambda a, b: a & b)

    def _op_or(self, state, inst):
        return self._binop(state, inst, lambda a, b: a | b)

    def _op_xor(self, state, inst):
        return self._binop(state, inst, lambda a, b: a ^ b)

    def _op_not(self, state, inst):
        a = state.pop()
        state.push(simplify(_bvv(TT256M1) - a))
        state.pc = inst.pc + 1
        return [state]

    def _op_shl(self, state, inst):
        shift = state.pop()
        value = state.pop()
        state.push(simplify(value << shift))
        state.pc = inst.pc + 1
        return [state]

    def _op_shr(self, state, inst):
        shift = state.pop()
        value = state.pop()
        state.push(simplify(LShR(value, shift)))
        state.pc = inst.pc + 1
        return [state]

    def _op_sar(self, state, inst):
        # SAR: arithmetic (sign-preserving) right shift. EVM stack is
        # [shift, value] with shift on top, like SHR.
        shift = state.pop()
        value = state.pop()
        state.push(simplify(AShr(value, shift)))
        state.pc = inst.pc + 1
        return [state]

    def _op_sdiv(self, state, inst):
        # signed division; EVM defines division by zero as 0.
        a = state.pop()
        b = state.pop()
        state.push(simplify(If(b == _bvv(0), _bvv(0), SDiv(a, b))))
        state.pc = inst.pc + 1
        return [state]

    def _op_smod(self, state, inst):
        # signed modulo; EVM defines modulo by zero as 0. The result takes the
        # sign of the dividend (z3 SRem semantics, via SMod).
        a = state.pop()
        b = state.pop()
        state.push(simplify(If(b == _bvv(0), _bvv(0), SMod(a, b))))
        state.pc = inst.pc + 1
        return [state]

    def _op_addmod(self, state, inst):
        # (a + b) % N computed without 256-bit intermediate overflow, then
        # truncated back to 256 bits. EVM: modulo by zero yields 0.
        a = state.pop()
        b = state.pop()
        n = state.pop()
        a512 = Concat(_bvv(0), a)
        b512 = Concat(_bvv(0), b)
        n512 = Concat(_bvv(0), n)
        summed = a512 + b512
        wide = URem(summed, n512)
        result = Extract(255, 0, wide)
        state.push(simplify(If(n == _bvv(0), _bvv(0), result)))
        state.pc = inst.pc + 1
        return [state]

    def _op_mulmod(self, state, inst):
        # (a * b) % N computed in a 512-bit intermediate to avoid wraparound,
        # then truncated to 256 bits. EVM: modulo by zero yields 0.
        a = state.pop()
        b = state.pop()
        n = state.pop()
        a512 = Concat(_bvv(0), a)
        b512 = Concat(_bvv(0), b)
        n512 = Concat(_bvv(0), n)
        product = a512 * b512
        wide = URem(product, n512)
        result = Extract(255, 0, wide)
        state.push(simplify(If(n == _bvv(0), _bvv(0), result)))
        state.pc = inst.pc + 1
        return [state]

    def _op_signextend(self, state, inst):
        # SIGNEXTEND(b, x): treat x as a (b+1)-byte two's-complement value and
        # sign-extend it to 256 bits. For b >= 31 the value is unchanged.
        b = state.pop()
        x = state.pop()
        bc = self._concrete(simplify(b))
        if bc is None or bc >= 31:
            # symbolic byte index, or no-op extension: leave x unchanged
            state.push(x)
            state.pc = inst.pc + 1
            return [state]
        # bit index of the sign bit being extended from
        sign_bit = bc * 8 + 7
        low = Extract(sign_bit, 0, x)
        extended = SignExt(255 - sign_bit, low)
        state.push(simplify(extended))
        state.pc = inst.pc + 1
        return [state]

    def _op_byte(self, state, inst):
        # BYTE(i, x): the i-th byte of x counting from the most-significant
        # (big-endian). i >= 32 yields 0. Result is zero-extended to 256 bits.
        i = state.pop()
        x = state.pop()
        ic = self._concrete(simplify(i))
        if ic is None:
            # symbolic index: (x >> (248 - i*8)) & 0xff, computed symbolically
            shift = _bvv(248) - (i * _bvv(8))
            byte = LShR(x, shift) & _bvv(0xFF)
            # if i >= 32 the shift amount wraps; mask the out-of-range case to 0
            result = If(ULT(i, _bvv(32)), byte, _bvv(0))
            state.push(simplify(result))
            state.pc = inst.pc + 1
            return [state]
        if ic >= 32:
            state.push(_bvv(0))
            state.pc = inst.pc + 1
            return [state]
        high = 255 - ic * 8
        low = high - 7
        sel = Extract(high, low, x)  # the selected 8-bit byte
        # zero-extend the 8-bit byte to 256 bits (248 zero high bits + byte)
        result = Concat(symbol_factory.BitVecVal(0, 248), sel)
        state.push(simplify(result))
        state.pc = inst.pc + 1
        return [state]

    # ---- environment ----
    def _op_calldataload(self, state, inst):
        offset = simplify(state.pop())
        state.push(self._calldata_word(offset))
        state.pc = inst.pc + 1
        return [state]

    def _op_calldatasize(self, state, inst):
        state.push(self.calldatasize)
        state.pc = inst.pc + 1
        return [state]

    def _op_callvalue(self, state, inst):
        state.push(self.callvalue)
        state.pc = inst.pc + 1
        return [state]

    def _op_caller(self, state, inst):
        # record that this path read msg.sender (consumed by the access-control
        # escalation detector to tell "function looked at the sender" apart from
        # functions that never touch it).
        state.caller_loaded = True
        state.push(self.caller)
        state.pc = inst.pc + 1
        return [state]

    def _op_address(self, state, inst):
        state.push(symbol_factory.BitVecSym(self._sym("address_this"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_origin(self, state, inst):
        # record that this path read tx.origin (consumed by the tx-origin-auth
        # detector to tell "function looked at tx.origin" apart from functions
        # that never touch it). Push the stable, named `origin` symbol so a
        # later guard branching on it is recognisable in the path constraints.
        state.origin_loaded = True
        state.push(self.origin)
        state.pc = inst.pc + 1
        return [state]

    def _op_balance(self, state, inst):
        state.pop()
        state.push(symbol_factory.BitVecSym(self._sym("balance"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_selfbalance(self, state, inst):
        state.push(symbol_factory.BitVecSym(self._sym("selfbalance"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_timestamp(self, state, inst):
        # record that this path read block.timestamp (consumed by the timestamp-
        # dependence detector to tell "function looked at a block value" apart
        # from functions that never touch it). Using block.timestamp as a
        # randomness/decision source is miner/validator-manipulable (SWC-116).
        state.blockval_loaded = True
        state.push(symbol_factory.BitVecSym(self._sym("timestamp"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_number(self, state, inst):
        # block.number is likewise a block value used as a (manipulable) proxy
        # for time / randomness; record the read for the SWC-116 detector.
        state.blockval_loaded = True
        state.push(symbol_factory.BitVecSym(self._sym("block_number"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_blockhash(self, state, inst):
        # BLOCKHASH(blockNumber) — the hash of a recent block. It is used (and
        # mis-used) as a cheap on-chain "random" source: a contract that branches
        # on `blockhash(n)` to pick a winner / gate a payout is deriving a secret
        # from a chain attribute that the block proposer can influence or that an
        # attacker observes in the same block (SWC-120, "Weak Sources of
        # Randomness from Chain Attributes"). Record the read so the
        # BlockhashRandomnessDetector can tell "the function looked at a block
        # hash" apart from functions that never touch it, and mint a fresh
        # per-pc `blockhash_<pc>` symbol so a later guard branching on it is
        # recognisable in the path constraints. Popping the block-number operand
        # keeps the stack balanced (previously BLOCKHASH had no handler and the
        # path halted at this opcode).
        state.pop()  # blockNumber
        state.blockhash_loaded = True
        state.push(symbol_factory.BitVecSym(self._sym(f"blockhash_{inst.pc}"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_gasprice(self, state, inst):
        # GASPRICE pushes `tx.gasprice`. Record the read so the
        # TransactionOrderDependenceDetector can tell "the function looked at the
        # gas price" apart from functions that never touch it. Branching control
        # flow on `tx.gasprice` is a transaction-order-dependence smell (SWC-114):
        # the gas price is set by the transaction sender and is precisely the
        # lever used to reorder transactions within a block, so gating logic on it
        # is a decision driven by a value an attacker freely controls and that
        # governs ordering (a gas-price ceiling meant to deter front-running, or a
        # gas-price-derived outcome). The stable, named `gasprice` symbol is pushed
        # so a later guard branching on it is recognisable in the path constraints.
        state.gasprice_loaded = True
        state.push(symbol_factory.BitVecSym(self._sym("gasprice"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _generic_env(self, state, inst, name):
        state.push(symbol_factory.BitVecSym(self._sym(name), 256))
        state.pc = inst.pc + 1
        return [state]

    _op_gas = lambda self, s, i: self._generic_env(s, i, "gas")
    _op_gaslimit = lambda self, s, i: self._generic_env(s, i, "gaslimit")
    _op_coinbase = lambda self, s, i: self._generic_env(s, i, "coinbase")
    _op_chainid = lambda self, s, i: self._generic_env(s, i, "chainid")
    _op_msize = lambda self, s, i: self._generic_env(s, i, "msize")

    def _op_difficulty(self, state, inst):
        # DIFFICULTY (0x44) pushes `block.prevrandao` (post-Merge) or
        # `block.difficulty` (pre-Merge). Record the read so the
        # PrevrandaoRandomnessDetector can tell "the function read prevrandao"
        # apart from functions that never touch it. Branching control flow on
        # `block.prevrandao` is a weak-randomness smell (SWC-120, "Weak Sources of
        # Randomness from Chain Attributes"): the value is supplied by the block
        # proposer and is observable by an attacker calling in the same
        # transaction, so a contract that gates a payout / picks a winner on it is
        # making a security decision an attacker can predict or grind. The stable,
        # named `prevrandao` symbol (formerly the generic "difficulty" name) is
        # pushed so a later guard branching on it is recognisable in the path
        # constraints. Distinct from BLOCKHASH (a different chain attribute keyed
        # by the BlockhashRandomnessDetector's `blockhash_<pc>` family).
        state.prevrandao_loaded = True
        state.push(symbol_factory.BitVecSym(self._sym("prevrandao"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_codesize(self, state, inst):
        # CODESIZE is the concrete length of the running contract's bytecode.
        state.push(_bvv(len(self.disasm.bytecode)))
        state.pc = inst.pc + 1
        return [state]

    def _op_returndatasize(self, state, inst):
        # Size of the return data from the most recent external call. Unknown
        # statically, so a fresh symbolic word (conservative-sound): the path
        # continues rather than halting.
        state.push(symbol_factory.BitVecSym(self._sym(f"returndatasize_{inst.pc}"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_returndatacopy(self, state, inst):
        # RETURNDATACOPY destOffset, offset, size — copies return data into
        # memory. Memory is modelled coarsely (MLOAD returns fresh symbols), so
        # this is a sound no-op that keeps the path alive.
        state.pop()  # destOffset
        state.pop()  # offset
        state.pop()  # size
        state.pc = inst.pc + 1
        return [state]

    def _op_extcodesize(self, state, inst):
        # EXTCODESIZE addr — code size of an external account. Fresh symbol so
        # access-control guards like `extcodesize(x) == 0` stay explorable.
        state.pop()  # address
        state.push(symbol_factory.BitVecSym(self._sym(f"extcodesize_{inst.pc}"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_extcodecopy(self, state, inst):
        # EXTCODECOPY addr, destOffset, offset, size — copies external code into
        # memory. No-op against the coarse memory model; continue the path.
        state.pop()  # address
        state.pop()  # destOffset
        state.pop()  # offset
        state.pop()  # size
        state.pc = inst.pc + 1
        return [state]

    def _op_extcodehash(self, state, inst):
        # EXTCODEHASH addr — keccak of external account code. Fresh symbol.
        state.pop()  # address
        state.push(symbol_factory.BitVecSym(self._sym(f"extcodehash_{inst.pc}"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_calldatacopy(self, state, inst):
        # CALLDATACOPY destOffset, offset, size — copies calldata into memory.
        # Memory is modelled coarsely, so this is a sound no-op that keeps the
        # path alive instead of halting on the unhandled opcode.
        state.pop()  # destOffset
        state.pop()  # offset
        state.pop()  # size
        state.pc = inst.pc + 1
        return [state]

    def _op_codecopy(self, state, inst):
        # CODECOPY destOffset, offset, size — copies the running contract's own
        # code into memory. Code is not analysed as data here; no-op + continue.
        state.pop()  # destOffset
        state.pop()  # offset
        state.pop()  # size
        state.pc = inst.pc + 1
        return [state]

    def _op_pc(self, state, inst):
        state.push(_bvv(inst.pc))
        state.pc = inst.pc + 1
        return [state]

    # ---- memory ----
    def _op_mload(self, state, inst):
        state.pop()  # offset; memory modelled coarsely
        state.push(symbol_factory.BitVecSym(self._sym(f"mem_{inst.pc}"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_mstore(self, state, inst):
        state.pop()
        state.pop()
        state.pc = inst.pc + 1
        return [state]

    def _op_mstore8(self, state, inst):
        state.pop()
        state.pop()
        state.pc = inst.pc + 1
        return [state]

    def _op_sha3(self, state, inst):
        """SHA3 / KECCAK256: pop (offset, size) from stack, push the hash.

        We use the keccak uninterpreted-function model so Z3 can reason about
        hash relationships (injectivity) rather than treating each call as an
        independent fresh symbol.

        Dispatch logic (based on the concrete byte-size operand):
        * size == 32  → single 256-bit word; read one word from memory and
                        apply keccak256_256(word).
        * size == 64  → two 256-bit words (Solidity mapping-slot pattern);
                        read two words and apply keccak256_512(hi || lo).
        * otherwise   → fall back to a fresh symbol (conservative / sound).

        Memory is modelled coarsely (MLOAD returns a per-PC symbol), so for
        fixed sizes we look up the symbolic memory words at the given offsets.
        """
        mem_offset = state.pop()
        mem_size = state.pop()
        size_c = self._concrete(simplify(mem_size))
        offset_c = self._concrete(simplify(mem_offset))

        if size_c == 32:
            # Single 256-bit word: create a symbolic memory read at the offset
            # or generate a fresh word symbol when the offset is also symbolic.
            if offset_c is not None:
                word = symbol_factory.BitVecSym(self._sym(f"mem_sha3_{offset_c}"), 256)
            else:
                word = symbol_factory.BitVecSym(self._sym(f"mem_sha3_{inst.pc}_w"), 256)
            result = keccak_model.hash_256(word)
        elif size_c == 64:
            # Two 256-bit words (e.g. keccak256(abi.encode(key, slot))).
            if offset_c is not None:
                hi = symbol_factory.BitVecSym(self._sym(f"mem_sha3_{offset_c}_hi"), 256)
                lo = symbol_factory.BitVecSym(self._sym(f"mem_sha3_{offset_c + 32}_lo"), 256)
            else:
                hi = symbol_factory.BitVecSym(self._sym(f"mem_sha3_{inst.pc}_hi"), 256)
                lo = symbol_factory.BitVecSym(self._sym(f"mem_sha3_{inst.pc}_lo"), 256)
            result = keccak_model.hash_512(hi, lo)
        else:
            # Unknown / variable size — conservative fresh symbol (sound).
            result = symbol_factory.BitVecSym(self._sym(f"sha3_{inst.pc}"), 256)

        state.push(result)
        state.pc = inst.pc + 1
        return [state]

    # ---- storage ----
    def _op_sload(self, state, inst):
        key = state.pop()
        state.push(simplify(state.world.storage[key]))
        state.pc = inst.pc + 1
        return [state]

    def _op_sstore(self, state, inst):
        key = state.pop()
        value = state.pop()
        state.fork_world()
        state.world.storage[key] = value  # rebinds the cloned array's .raw
        state.pc = inst.pc + 1
        return [state]

    # ---- control flow ----
    def _op_jump(self, state, inst):
        dest = state.pop()
        dest_s = simplify(dest)
        target = self._concrete(dest_s)
        if target is None or target not in self.disasm.jumpdests:
            state.halted = True
            return []
        state.pc = target
        return [state]

    def _op_jumpi(self, state, inst):
        dest = state.pop()
        cond = state.pop()
        target = self._concrete(simplify(dest))
        successors: List[MachineState] = []

        # branch TAKEN: cond != 0 and target is a valid jumpdest
        if target is not None and target in self.disasm.jumpdests:
            taken = state.clone()
            taken.constraints.append(cond != _bvv(0))
            taken.pc = target
            taken.depth += 1
            successors.append(taken)

        # branch NOT taken: cond == 0, fall through
        nottaken = state.clone()
        nottaken.constraints.append(cond == _bvv(0))
        nottaken.pc = inst.pc + 1
        nottaken.depth += 1
        successors.append(nottaken)
        return successors

    def _op_jumpdest(self, state, inst):
        state.pc = inst.pc + 1
        return [state]

    # ---- halting ----
    def _op_stop(self, state, inst):
        state.halted = True
        return []

    def _op_return(self, state, inst):
        state.halted = True
        return []

    def _op_revert(self, state, inst):
        state.reverted = True
        return []

    def _op_invalid(self, state, inst):
        # 0xFE — the opcode solc emits for failed assert() in <0.8.0.
        state.halted = True
        return []

    def _op_selfdestruct(self, state, inst):
        # handled by detector hook before execution; just halt here
        if state.stack:
            state.pop()
        state.halted = True
        return []

    def _op_call(self, state, inst):
        # gas, to, value, inoff, insize, outoff, outsize
        for _ in range(7):
            if state.stack:
                state.pop()
        state.push(symbol_factory.BitVecSym(self._sym(f"callretval_{inst.pc}"), 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_staticcall(self, state, inst):
        for _ in range(6):
            if state.stack:
                state.pop()
        state.push(symbol_factory.BitVecSym(self._sym(f"staticretval_{inst.pc}"), 256))
        state.pc = inst.pc + 1
        return [state]

    _op_delegatecall = _op_staticcall
    _op_callcode = _op_call

    # ------------------------------------------------------------------ #
    @staticmethod
    def _concrete(bv) -> Optional[int]:
        """Return python int if the BitVec is a concrete numeral, else None."""
        try:
            import z3

            raw = bv.raw if hasattr(bv, "raw") else bv
            if isinstance(raw, z3.BitVecNumRef):
                return raw.as_long()
        except Exception:
            return None
        return None
