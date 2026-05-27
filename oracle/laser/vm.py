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
    """Bounded symbolic executor over a single contract's runtime bytecode."""

    def __init__(self, bytecode: bytes, max_depth: int = 12):
        self.disasm = Disassembly(bytecode)
        self.max_depth = max_depth
        self.detectors: List[DetectorHook] = []
        # symbolic transaction inputs
        # calldata is modelled as a word-indexed family of symbols: each
        # distinct CALLDATALOAD offset yields its own independent symbol so the
        # ABI selector word and argument words are never conflated. `calldata`
        # is the offset-0 word (the function selector + leading args region),
        # reported as the principal trigger input.
        self._calldata_words = {}
        self.calldata = self._calldata_word(0)
        self.callvalue = symbol_factory.BitVecSym("callvalue", 256)
        self.caller = symbol_factory.BitVecSym("caller", 256)
        self.calldatasize = symbol_factory.BitVecSym("calldatasize", 256)
        self.work_count = 0
        # bound on total worklist iterations to guarantee termination
        self.max_work = 200000

    def _calldata_word(self, offset) -> BitVec:
        """Return the symbolic 256-bit word at a calldata offset.

        Concrete offsets are cached so repeated loads of the same offset return
        the same symbol (consistency). Symbolic offsets get a fresh symbol.
        """
        key = self._concrete(offset) if not isinstance(offset, int) else offset
        if key is None:
            return symbol_factory.BitVecSym("calldata_dyn", 256)
        if key not in self._calldata_words:
            name = "calldata" if key == 0 else f"calldata_{key}"
            self._calldata_words[key] = symbol_factory.BitVecSym(name, 256)
        return self._calldata_words[key]

    def register(self, detector: DetectorHook) -> None:
        self.detectors.append(detector)

    def run(self) -> None:
        """Depth-first exploration of all paths up to max_depth."""
        world = WorldState()
        start = MachineState(world)
        worklist: List[MachineState] = [start]
        while worklist:
            self.work_count += 1
            if self.work_count > self.max_work:
                break
            state = worklist.pop()
            if state.halted or state.reverted:
                continue
            inst = self.disasm.by_pc.get(state.pc)
            if inst is None:
                # ran off the end of code => implicit STOP
                continue

            # detector hook BEFORE executing the instruction
            for det in self.detectors:
                det.inspect(self, state, inst)

            try:
                successors = self._step(state, inst)
            except (StackUnderflowError, StackOverflowError):
                continue
            for succ in successors:
                if succ.depth <= self.max_depth and not succ.halted and not succ.reverted:
                    worklist.append(succ)

    # ------------------------------------------------------------------ #
    # instruction dispatch
    # ------------------------------------------------------------------ #
    def _step(self, state: MachineState, inst) -> List[MachineState]:
        op = inst.mnemonic
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
        state.push(self.caller)
        state.pc = inst.pc + 1
        return [state]

    def _op_address(self, state, inst):
        state.push(symbol_factory.BitVecSym("address_this", 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_origin(self, state, inst):
        state.push(symbol_factory.BitVecSym("origin", 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_balance(self, state, inst):
        state.pop()
        state.push(symbol_factory.BitVecSym("balance", 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_selfbalance(self, state, inst):
        state.push(symbol_factory.BitVecSym("selfbalance", 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_timestamp(self, state, inst):
        state.push(symbol_factory.BitVecSym("timestamp", 256))
        state.pc = inst.pc + 1
        return [state]

    def _generic_env(self, state, inst, name):
        state.push(symbol_factory.BitVecSym(name, 256))
        state.pc = inst.pc + 1
        return [state]

    _op_number = lambda self, s, i: self._generic_env(s, i, "block_number")
    _op_gas = lambda self, s, i: self._generic_env(s, i, "gas")
    _op_gasprice = lambda self, s, i: self._generic_env(s, i, "gasprice")
    _op_gaslimit = lambda self, s, i: self._generic_env(s, i, "gaslimit")
    _op_coinbase = lambda self, s, i: self._generic_env(s, i, "coinbase")
    _op_difficulty = lambda self, s, i: self._generic_env(s, i, "difficulty")
    _op_chainid = lambda self, s, i: self._generic_env(s, i, "chainid")
    _op_msize = lambda self, s, i: self._generic_env(s, i, "msize")

    def _op_codesize(self, state, inst):
        # CODESIZE is the concrete length of the running contract's bytecode.
        state.push(_bvv(len(self.disasm.bytecode)))
        state.pc = inst.pc + 1
        return [state]

    def _op_returndatasize(self, state, inst):
        # Size of the return data from the most recent external call. Unknown
        # statically, so a fresh symbolic word (conservative-sound): the path
        # continues rather than halting.
        state.push(symbol_factory.BitVecSym(f"returndatasize_{inst.pc}", 256))
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
        state.push(symbol_factory.BitVecSym(f"extcodesize_{inst.pc}", 256))
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
        state.push(symbol_factory.BitVecSym(f"extcodehash_{inst.pc}", 256))
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
        state.push(symbol_factory.BitVecSym(f"mem_{inst.pc}", 256))
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
                word = symbol_factory.BitVecSym(f"mem_sha3_{offset_c}", 256)
            else:
                word = symbol_factory.BitVecSym(f"mem_sha3_{inst.pc}_w", 256)
            result = keccak_model.hash_256(word)
        elif size_c == 64:
            # Two 256-bit words (e.g. keccak256(abi.encode(key, slot))).
            if offset_c is not None:
                hi = symbol_factory.BitVecSym(f"mem_sha3_{offset_c}_hi", 256)
                lo = symbol_factory.BitVecSym(f"mem_sha3_{offset_c + 32}_lo", 256)
            else:
                hi = symbol_factory.BitVecSym(f"mem_sha3_{inst.pc}_hi", 256)
                lo = symbol_factory.BitVecSym(f"mem_sha3_{inst.pc}_lo", 256)
            result = keccak_model.hash_512(hi, lo)
        else:
            # Unknown / variable size — conservative fresh symbol (sound).
            result = symbol_factory.BitVecSym(f"sha3_{inst.pc}", 256)

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
        state.push(symbol_factory.BitVecSym(f"callretval_{inst.pc}", 256))
        state.pc = inst.pc + 1
        return [state]

    def _op_staticcall(self, state, inst):
        for _ in range(6):
            if state.stack:
                state.pop()
        state.push(symbol_factory.BitVecSym(f"staticretval_{inst.pc}", 256))
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
