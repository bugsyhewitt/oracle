"""Concrete-input replay / counterexample validator (POST_V01 Tier 3 #7).

oracle's symbolic engine produces a `trigger_input` for every satisfiable
finding — the concrete model Z3 computed for the transaction inputs (calldata
words, caller, callvalue, …). That model is a *claim*: "feed the contract these
inputs and the vulnerable opcode at `pc` becomes reachable". Until now oracle
never checked the claim against a deterministic executor, so a finding rested
entirely on the symbolic path constraints being faithful to EVM semantics.

This module closes that loop with a small, self-contained **concrete** EVM
interpreter. Given a contract's runtime bytecode and a finding's `trigger_input`,
it executes the bytecode with every symbolic input bound to its concrete model
value and reports whether the finding's target `pc` is actually reached on the
concrete path. A finding whose `pc` is reached is enriched with
`"validated": true`; one that is not reachable concretely is flagged
`"validated": false` (a candidate false positive worth manual review).

Design choices (deliberately bounded — this is a validator, not a second
analysis engine):

  * **No new dependency.** POST_V01 #7 suggested py-evm; oracle's value
    proposition is "install-clean on modern Python", so a heavyweight EVM
    dependency is the wrong trade. This is the "~200-line concrete interpreter"
    fallback the spec also names. The opcode semantics mirror oracle's own
    symbolic handlers (`oracle/laser/vm.py`) so the two engines agree.
  * **Concrete only.** Every input the symbolic engine left symbolic is read
    from `trigger_input`; any input absent from the model (e.g. an environment
    value the model did not pin) defaults to 0, exactly as Z3's
    `model_completion=True` would.
  * **Bounded.** Execution is capped at `MAX_STEPS` instructions so a
    pathological loop in attacker-shaped calldata cannot hang the validator.
    Hitting the cap is reported as "not reached" (conservative).
  * **Unknown opcodes don't crash.** Any opcode oracle's table doesn't model
    concretely halts the replay cleanly; the finding stays unvalidated rather
    than raising. A validator must never be noisier than the analysis it checks.

The validator is intentionally read-only with respect to findings: it returns
new enriched dicts and never mutates the input list.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from oracle.laser.disassembler import Disassembly

# 256-bit modulus and mask for two's-complement / wraparound arithmetic.
UINT256 = 1 << 256
MASK256 = UINT256 - 1
SIGN_BIT = 1 << 255

# Hard cap on executed instructions. A trigger model that induces a long loop
# (or an adversarially crafted calldata) must not hang the validator. The cap is
# generous relative to oracle's symbolic max-depth (default 12 *branches*, which
# unrolls to far fewer than this many straight-line instructions in practice).
MAX_STEPS = 100_000


def _to_signed(v: int) -> int:
    return v - UINT256 if v & SIGN_BIT else v


def _to_unsigned(v: int) -> int:
    return v & MASK256


def _hex_to_int(value) -> int:
    """Coerce a trigger_input value to a concrete 256-bit unsigned int.

    trigger_input values are produced by `analysis._z3_to_hex`, which yields a
    `0x…64-hex-digit` string for integer models and a bare `str(expr)` for
    anything it could not turn into a long. Bare-string (non-hex) values can't
    be replayed concretely, so they read as 0 — the same completion Z3 would
    apply to an unconstrained input.
    """
    if value is None:
        return 0
    if isinstance(value, int):
        return value & MASK256
    s = str(value).strip()
    try:
        if s.lower().startswith("0x"):
            return int(s, 16) & MASK256
        return int(s) & MASK256
    except ValueError:
        return 0


class _ConcreteState:
    """Volatile concrete machine state: stack, memory, storage, pc."""

    __slots__ = ("stack", "memory", "storage", "pc", "halted")

    def __init__(self) -> None:
        self.stack: List[int] = []
        self.memory: bytearray = bytearray()
        self.storage: Dict[int, int] = {}
        self.pc: int = 0
        self.halted: bool = False

    def push(self, v: int) -> None:
        self.stack.append(v & MASK256)

    def pop(self) -> int:
        return self.stack.pop()

    def _ensure_mem(self, end: int) -> None:
        if end > len(self.memory):
            self.memory.extend(b"\x00" * (end - len(self.memory)))


class ConcreteReplayer:
    """Re-execute bytecode with concrete inputs and record visited program counters.

    `inputs` is a finding's `trigger_input` dict (symbol-name -> hex value). The
    replayer reads the inputs the contract requests (calldata words, caller,
    callvalue, …) from this map. Any input not in the map completes to 0.
    """

    def __init__(self, bytecode: bytes, inputs: Optional[Dict[str, object]] = None):
        self.disasm = Disassembly(bytecode)
        self.inputs = inputs or {}
        self.visited_pcs: set = set()
        self._calldatasize = self._infer_calldatasize()

    def _infer_calldatasize(self) -> int:
        """Pick a CALLDATASIZE consistent with the calldata words supplied.

        The symbolic engine reports calldata words in `trigger_input` but does
        not pin CALLDATASIZE itself (it is rarely the discriminating input). A
        finding's path almost always passes a `require(msg.data.length >= 4 + …)`
        ABI-decoder gate, so a CALLDATASIZE of 0 would spuriously fail every such
        gate and make every finding look unreachable. We instead derive a size
        large enough to cover the highest calldata offset the model provides:
        the largest `calldata_at_<offset>` key + 32, with a floor of 4 (room for
        the ABI selector) whenever any calldata is present, and an explicit
        `calldatasize` model value taking precedence if one was solved.
        """
        explicit = self.inputs.get("calldatasize")
        if explicit is not None:
            return _hex_to_int(explicit)
        max_end = 0
        has_calldata = False
        for key in self.inputs:
            if key == "calldata":
                has_calldata = True
                max_end = max(max_end, 32)
            elif key.startswith("calldata_at_"):
                has_calldata = True
                try:
                    off = int(key[len("calldata_at_") :])
                except ValueError:
                    continue
                max_end = max(max_end, off + 32)
        if not has_calldata:
            return 0
        return max(max_end, 4)

    # -- input resolution ---------------------------------------------------
    def _input(self, name: str) -> int:
        return _hex_to_int(self.inputs.get(name))

    def _calldata_word(self, offset: int) -> int:
        """The 32-byte calldata word at `offset`, matching the *trigger_input* keys.

        The detector reports calldata words in `trigger_input` keyed as the VM
        materialised them: offset 0 is `calldata`, every other CALLDATALOAD
        offset is `calldata_at_<offset>` (see `detectors._finding`). A symbolic
        offset the engine could not pin becomes `calldata_dyn`. The replayer
        must read by these exact names so the concrete inputs line up with the
        words Z3 solved for.
        """
        if offset == 0:
            return self._input("calldata")
        return self._input(f"calldata_at_{offset}")

    # -- main loop ----------------------------------------------------------
    def reaches(self, target_pc: int) -> bool:
        """True if `target_pc` is reached when the bytecode runs on the inputs."""
        st = _ConcreteState()
        steps = 0
        by_pc = self.disasm.by_pc
        jumpdests = self.disasm.jumpdests

        while not st.halted and steps < MAX_STEPS:
            steps += 1
            inst = by_pc.get(st.pc)
            if inst is None:
                # ran off the end of the code, or into a PUSH immediate: stop.
                break
            self.visited_pcs.add(st.pc)
            if st.pc == target_pc:
                return True
            try:
                self._step(st, inst, jumpdests)
            except (IndexError, ValueError, ZeroDivisionError):
                # Stack underflow or an unmodelled concrete edge case: a real
                # EVM would revert/throw here. Stop cleanly — the target was not
                # reached on this path.
                break
        return False

    def _step(self, st: _ConcreteState, inst, jumpdests) -> None:
        op = inst.mnemonic
        handler = _HANDLERS.get(op)
        if handler is not None:
            handler(self, st, inst, jumpdests)
            return
        # PUSH/DUP/SWAP/LOG families are handled by prefix below.
        if op.startswith("PUSH"):
            st.push(inst.operand or 0)
            st.pc = inst.pc + 1 + (inst.opcode - 0x5F if inst.opcode >= 0x60 else 0)
            return
        if op.startswith("DUP"):
            n = inst.opcode - 0x80 + 1
            st.push(st.stack[-n])
            st.pc = inst.pc + 1
            return
        if op.startswith("SWAP"):
            n = inst.opcode - 0x90 + 1
            st.stack[-1], st.stack[-1 - n] = st.stack[-1 - n], st.stack[-1]
            st.pc = inst.pc + 1
            return
        if op.startswith("LOG"):
            n = inst.opcode - 0xA0
            for _ in range(2 + n):
                st.pop()
            st.pc = inst.pc + 1
            return
        # Any opcode oracle doesn't model concretely (CREATE, CALL, SHA3, …):
        # halt the replay. The symbolic engine reasoned about these abstractly;
        # the concrete validator can't follow without a full EVM, so it stops
        # and the finding stays unvalidated rather than crashing.
        st.halted = True


# --- opcode handlers -------------------------------------------------------
# Each takes (replayer, state, inst, jumpdests) and advances state.pc. They
# mirror the EVM semantics oracle's symbolic handlers implement in vm.py.


def _h_stop(r, st, inst, jd):
    st.halted = True


def _h_add(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(a + b)
    st.pc = inst.pc + 1


def _h_mul(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(a * b)
    st.pc = inst.pc + 1


def _h_sub(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(a - b)
    st.pc = inst.pc + 1


def _h_div(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(0 if b == 0 else a // b)
    st.pc = inst.pc + 1


def _h_sdiv(r, st, inst, jd):
    a, b = _to_signed(st.pop()), _to_signed(st.pop())
    if b == 0:
        res = 0
    else:
        # EVM SDIV truncates toward zero; Python // floors, so use int(a/b)
        # semantics via abs + sign to match two's-complement truncation.
        q = abs(a) // abs(b)
        res = -q if (a < 0) ^ (b < 0) else q
    st.push(_to_unsigned(res))
    st.pc = inst.pc + 1


def _h_mod(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(0 if b == 0 else a % b)
    st.pc = inst.pc + 1


def _h_smod(r, st, inst, jd):
    a, b = _to_signed(st.pop()), _to_signed(st.pop())
    if b == 0:
        res = 0
    else:
        # EVM SMOD result takes the sign of the dividend.
        res = abs(a) % abs(b)
        if a < 0:
            res = -res
    st.push(_to_unsigned(res))
    st.pc = inst.pc + 1


def _h_addmod(r, st, inst, jd):
    a, b, n = st.pop(), st.pop(), st.pop()
    st.push(0 if n == 0 else (a + b) % n)
    st.pc = inst.pc + 1


def _h_mulmod(r, st, inst, jd):
    a, b, n = st.pop(), st.pop(), st.pop()
    st.push(0 if n == 0 else (a * b) % n)
    st.pc = inst.pc + 1


def _h_exp(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(pow(a, b, UINT256))
    st.pc = inst.pc + 1


def _h_signextend(r, st, inst, jd):
    b, x = st.pop(), st.pop()
    if b >= 31:
        st.push(x)
    else:
        sign_bit = b * 8 + 7
        mask = (1 << (sign_bit + 1)) - 1
        low = x & mask
        if low & (1 << sign_bit):
            low |= ~mask & MASK256
        st.push(low)
    st.pc = inst.pc + 1


def _h_lt(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(1 if a < b else 0)
    st.pc = inst.pc + 1


def _h_gt(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(1 if a > b else 0)
    st.pc = inst.pc + 1


def _h_slt(r, st, inst, jd):
    a, b = _to_signed(st.pop()), _to_signed(st.pop())
    st.push(1 if a < b else 0)
    st.pc = inst.pc + 1


def _h_sgt(r, st, inst, jd):
    a, b = _to_signed(st.pop()), _to_signed(st.pop())
    st.push(1 if a > b else 0)
    st.pc = inst.pc + 1


def _h_eq(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(1 if a == b else 0)
    st.pc = inst.pc + 1


def _h_iszero(r, st, inst, jd):
    a = st.pop()
    st.push(1 if a == 0 else 0)
    st.pc = inst.pc + 1


def _h_and(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(a & b)
    st.pc = inst.pc + 1


def _h_or(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(a | b)
    st.pc = inst.pc + 1


def _h_xor(r, st, inst, jd):
    a, b = st.pop(), st.pop()
    st.push(a ^ b)
    st.pc = inst.pc + 1


def _h_not(r, st, inst, jd):
    a = st.pop()
    st.push(MASK256 - a)
    st.pc = inst.pc + 1


def _h_byte(r, st, inst, jd):
    i, x = st.pop(), st.pop()
    if i >= 32:
        st.push(0)
    else:
        st.push((x >> (8 * (31 - i))) & 0xFF)
    st.pc = inst.pc + 1


def _h_shl(r, st, inst, jd):
    shift, value = st.pop(), st.pop()
    st.push(0 if shift >= 256 else value << shift)
    st.pc = inst.pc + 1


def _h_shr(r, st, inst, jd):
    shift, value = st.pop(), st.pop()
    st.push(0 if shift >= 256 else value >> shift)
    st.pc = inst.pc + 1


def _h_sar(r, st, inst, jd):
    shift, value = st.pop(), _to_signed(st.pop())
    if shift >= 256:
        res = -1 if value < 0 else 0
    else:
        res = value >> shift
    st.push(_to_unsigned(res))
    st.pc = inst.pc + 1


def _h_pop(r, st, inst, jd):
    st.pop()
    st.pc = inst.pc + 1


def _h_mload(r, st, inst, jd):
    offset = st.pop()
    st._ensure_mem(offset + 32)
    st.push(int.from_bytes(st.memory[offset : offset + 32], "big"))
    st.pc = inst.pc + 1


def _h_mstore(r, st, inst, jd):
    offset, value = st.pop(), st.pop()
    st._ensure_mem(offset + 32)
    st.memory[offset : offset + 32] = value.to_bytes(32, "big")
    st.pc = inst.pc + 1


def _h_mstore8(r, st, inst, jd):
    offset, value = st.pop(), st.pop()
    st._ensure_mem(offset + 1)
    st.memory[offset] = value & 0xFF
    st.pc = inst.pc + 1


def _h_sload(r, st, inst, jd):
    slot = st.pop()
    st.push(st.storage.get(slot, 0))
    st.pc = inst.pc + 1


def _h_sstore(r, st, inst, jd):
    slot, value = st.pop(), st.pop()
    st.storage[slot] = value
    st.pc = inst.pc + 1


def _h_jump(r, st, inst, jd):
    dest = st.pop()
    if dest in jd:
        st.pc = dest
    else:
        # invalid jump destination — a real EVM reverts.
        st.halted = True


def _h_jumpi(r, st, inst, jd):
    dest, cond = st.pop(), st.pop()
    if cond != 0:
        if dest in jd:
            st.pc = dest
        else:
            st.halted = True
    else:
        st.pc = inst.pc + 1


def _h_pc(r, st, inst, jd):
    st.push(inst.pc)
    st.pc = inst.pc + 1


def _h_msize(r, st, inst, jd):
    st.push(len(st.memory))
    st.pc = inst.pc + 1


def _h_jumpdest(r, st, inst, jd):
    st.pc = inst.pc + 1


def _h_push0(r, st, inst, jd):
    st.push(0)
    st.pc = inst.pc + 1


def _h_calldataload(r, st, inst, jd):
    offset = st.pop()
    st.push(r._calldata_word(offset))
    st.pc = inst.pc + 1


def _h_calldatasize(r, st, inst, jd):
    st.push(r._calldatasize)
    st.pc = inst.pc + 1


def _h_caller(r, st, inst, jd):
    st.push(r._input("caller"))
    st.pc = inst.pc + 1


def _h_callvalue(r, st, inst, jd):
    st.push(r._input("callvalue"))
    st.pc = inst.pc + 1


def _h_origin(r, st, inst, jd):
    st.push(r._input("origin"))
    st.pc = inst.pc + 1


def _h_gas(r, st, inst, jd):
    # gas is unmodelled symbolically too; push a large concrete budget.
    st.push(MASK256)
    st.pc = inst.pc + 1


def _h_revert(r, st, inst, jd):
    st.halted = True


def _h_return(r, st, inst, jd):
    st.halted = True


# Opcodes that simply push an unconstrained environment value the symbolic
# engine also leaves free; replay them from `trigger_input` (default 0).
def _make_env_pusher(name: str):
    def _h(r, st, inst, jd):
        st.push(r._input(name))
        st.pc = inst.pc + 1

    return _h


_HANDLERS = {
    "STOP": _h_stop,
    "ADD": _h_add,
    "MUL": _h_mul,
    "SUB": _h_sub,
    "DIV": _h_div,
    "SDIV": _h_sdiv,
    "MOD": _h_mod,
    "SMOD": _h_smod,
    "ADDMOD": _h_addmod,
    "MULMOD": _h_mulmod,
    "EXP": _h_exp,
    "SIGNEXTEND": _h_signextend,
    "LT": _h_lt,
    "GT": _h_gt,
    "SLT": _h_slt,
    "SGT": _h_sgt,
    "EQ": _h_eq,
    "ISZERO": _h_iszero,
    "AND": _h_and,
    "OR": _h_or,
    "XOR": _h_xor,
    "NOT": _h_not,
    "BYTE": _h_byte,
    "SHL": _h_shl,
    "SHR": _h_shr,
    "SAR": _h_sar,
    "POP": _h_pop,
    "MLOAD": _h_mload,
    "MSTORE": _h_mstore,
    "MSTORE8": _h_mstore8,
    "SLOAD": _h_sload,
    "SSTORE": _h_sstore,
    "JUMP": _h_jump,
    "JUMPI": _h_jumpi,
    "PC": _h_pc,
    "MSIZE": _h_msize,
    "JUMPDEST": _h_jumpdest,
    "PUSH0": _h_push0,
    "CALLDATALOAD": _h_calldataload,
    "CALLDATASIZE": _h_calldatasize,
    "CALLER": _h_caller,
    "CALLVALUE": _h_callvalue,
    "ORIGIN": _h_origin,
    "GAS": _h_gas,
    "REVERT": _h_revert,
    "RETURN": _h_return,
    # Environment opcodes the symbolic engine leaves unconstrained: replay each
    # from the model value (defaulting to 0), matching vm.py's symbol names.
    "ADDRESS": _make_env_pusher("address_this"),
    "BALANCE": _make_env_pusher("balance"),
    "SELFBALANCE": _make_env_pusher("selfbalance"),
    "GASPRICE": _make_env_pusher("gasprice"),
    "TIMESTAMP": _make_env_pusher("timestamp"),
    "NUMBER": _make_env_pusher("block_number"),
    "COINBASE": _make_env_pusher("coinbase"),
    "DIFFICULTY": _make_env_pusher("prevrandao"),
    "GASLIMIT": _make_env_pusher("gaslimit"),
    "CHAINID": _make_env_pusher("chainid"),
}


def validate_finding(bytecode: bytes, finding: dict) -> dict:
    """Return a copy of `finding` enriched with a concrete-replay verdict.

    Adds two keys:
      * ``validated`` (bool): True iff replaying the finding's ``trigger_input``
        concretely reaches the finding's ``pc``.
      * ``validation`` (str): a human-readable verdict —
        ``"confirmed"`` (pc reached), ``"unreachable"`` (replay completed but
        the pc was not hit — a candidate false positive), or ``"skipped"``
        (the finding carries no usable trigger input, e.g. a ``timeout``
        finding, so it cannot be replayed).
    """
    enriched = dict(finding)
    trigger = finding.get("trigger_input") or {}
    target_pc = finding.get("pc")

    # A finding with no trigger input (e.g. confidence == "timeout") or no pc
    # can't be replayed. Mark it skipped rather than guessing.
    if not trigger or target_pc is None:
        enriched["validated"] = False
        enriched["validation"] = "skipped"
        return enriched

    replayer = ConcreteReplayer(bytecode, trigger)
    reached = replayer.reaches(target_pc)
    enriched["validated"] = reached
    enriched["validation"] = "confirmed" if reached else "unreachable"
    return enriched


def validate_findings(bytecode: bytes, findings: List[dict]) -> List[dict]:
    """Validate every finding via concrete replay; return new enriched dicts."""
    return [validate_finding(bytecode, f) for f in findings]
