"""Detector plugins for oracle's symbolic execution engine.

Each detector subclasses DetectorHook and is invoked before every instruction
executes. When a detector identifies a potentially reachable bug, it records a
finding carrying the *path constraints* that lead there. The analysis driver
later asks Z3 whether those constraints are satisfiable; if so, the model gives
a concrete `trigger_input`.

[Worker decision: oracle implements its own detector plugin framework rather
than forking mythril's laser/plugin/ verbatim (see NOTICE). mythril's plugin
framework is tied to its laser EVM engine's state/annotation objects, which
oracle does not reuse. oracle's framework is a thin, well-defined hook API
matched to oracle's own engine.]
"""

from __future__ import annotations

from oracle.laser.smt import UGT, And, BitVec
from oracle.laser.vm import DetectorHook, _bvv


SEVERITY = {
    "assertion_violation": "medium",
    "integer_overflow": "high",
    "reachable_selfdestruct": "high",
    "unconstrained_ether_transfer": "high",
    "arbitrary_storage_write": "high",
    "reentrancy": "high",
    "access_control_escalation": "high",
    "tx_origin_authentication": "high",
    "delegatecall_untrusted_callee": "high",
}


class AssertionViolationDetector(DetectorHook):
    """Detects reachable INVALID (0xFE) opcodes.

    solc emits INVALID for a failing `assert()` in Solidity <0.8.0 and as the
    panic path. A reachable INVALID means there's an input that violates the
    asserted invariant.
    """

    category = "assertion_violation"

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic == "INVALID":
            self.findings.append(
                _finding(self.category, state, instruction, vm)
            )


class IntegerOverflowDetector(DetectorHook):
    """Detects integer overflow on ADD/MUL involving symbolic operands.

    Records a finding whose extra constraint asserts the overflow condition
    (a + b < a). If Z3 can satisfy path-constraints AND the overflow condition,
    the bug is reachable.
    """

    category = "integer_overflow"

    def inspect(self, vm, state, instruction) -> None:
        op = instruction.mnemonic
        if op not in ("ADD", "MUL"):
            return
        if len(state.stack) < 2:
            return
        a = state.stack[-1]
        b = state.stack[-2]
        if _is_concrete(a) and _is_concrete(b):
            return  # only flag symbolic arithmetic
        if op == "ADD":
            # 256-bit wraparound: the sum is smaller than one of the addends
            overflow = UGT(a, a + b)
        else:  # MUL
            overflow = _mul_overflow(a, b)
        f = _finding(self.category, state, instruction, vm)
        f["extra_constraint"] = overflow
        self.findings.append(f)


def _mul_overflow(a: BitVec, b: BitVec):
    # a*b overflows 256-bit when b != 0 and the wrapped product is smaller than a
    prod = a * b
    return And(b != _bvv(0), UGT(a, prod))


class ReachableSelfdestructDetector(DetectorHook):
    """Detects reachable SELFDESTRUCT opcodes."""

    category = "reachable_selfdestruct"

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic == "SELFDESTRUCT":
            self.findings.append(_finding(self.category, state, instruction, vm))


class EtherLeakDetector(DetectorHook):
    """Detects unconstrained ether transfers (CALL with attacker-influenced
    recipient and non-zero value not guarded by access control).

    Heuristic for v0.1: flag any CALL where the recipient (2nd stack arg) is
    derived from CALLER/CALLDATA — i.e. attacker-controllable — and value is
    symbolic/non-zero.
    """

    category = "unconstrained_ether_transfer"

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "CALL":
            return
        # CALL stack layout: gas, to, value, ...
        if len(state.stack) < 3:
            return
        to = state.stack[-2]
        value = state.stack[-3]
        if _is_concrete(value) and _concrete_val(value) == 0:
            return  # zero-value call carries no ether
        if not _is_concrete(to):
            self.findings.append(_finding(self.category, state, instruction, vm))


class StorageWriteDetector(DetectorHook):
    """Detects arbitrary storage writes: SSTORE where the slot key is
    attacker-controllable (symbolic, derived from calldata)."""

    category = "arbitrary_storage_write"

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "SSTORE":
            return
        if len(state.stack) < 1:
            return
        key = state.stack[-1]
        if not _is_concrete(key):
            self.findings.append(_finding(self.category, state, instruction, vm))


class ReentrancyDetector(DetectorHook):
    """Detects the classic check-effects-interactions (CEI) violation.

    The unsafe pattern is: read a storage slot, make an external CALL that
    forwards ether (so the callee can re-enter), and only *after* the call
    write back to a slot that was read *before* the call. A reentered call
    sees the stale pre-update storage and can drain funds (the DAO bug).

    Per-path tracking (state carries the history across forks):
      * `state.sloads_seen` — identity keys of every slot SLOADed so far.
      * On an ether-forwarding CALL/CALLCODE/DELEGATECALL: set `call_checkpoint`
        and snapshot the slots read up to that point into `sloads_before_call`.
      * On an SSTORE *after* a checkpoint whose slot is in `sloads_before_call`:
        emit a reentrancy finding (effect applied after the interaction).

    A slot's identity is the string form of its (possibly symbolic) key, so a
    slot read as `storage[k]` matches a later write to the same `storage[k]`.

    [Worker decision: the "forwards ether" gate. oracle initialises storage as a
    constant-0 array, so a call value derived from storage (the canonical
    `withdraw` amount) symbolically collapses to a concrete 0 — making a strict
    `value != 0` gate inert against the very pattern this detector targets. The
    sound reading: CALL / CALLCODE / DELEGATECALL can all forward value and hand
    control to an attacker, so each opens a checkpoint; only STATICCALL (which
    can neither transfer value nor mutate state, hence can never enable a
    re-entrant *effect*) is excluded — and STATICCALL is not inspected here. A
    provably non-zero concrete or symbolic value is still strictly stronger
    evidence, but absence of it is not treated as proof of a zero-value call.
    The discriminating signal is therefore the CEI ordering itself — a pre-call
    SLOAD slot written after the call — which is precisely the bug.]
    """

    category = "reentrancy"

    # opcodes that hand control to an external account while able to forward
    # value (DELEGATECALL/CALLCODE run callee code in this contract's context
    # and forward the current call's value). STATICCALL is deliberately absent.
    _CALL_OPS = ("CALL", "CALLCODE", "DELEGATECALL")

    def inspect(self, vm, state, instruction) -> None:
        op = instruction.mnemonic
        if op == "SLOAD":
            if state.stack:
                state.sloads_seen.add(_slot_key(state.stack[-1]))
            return
        if op in self._CALL_OPS:
            self._open_checkpoint(state)
            return
        if op == "SSTORE" and state.call_checkpoint:
            if not state.stack:
                return
            slot = _slot_key(state.stack[-1])
            if slot in state.sloads_before_call:
                self.findings.append(
                    _finding(self.category, state, instruction, vm)
                )

    @staticmethod
    def _open_checkpoint(state) -> None:
        state.call_checkpoint = True
        # snapshot only the slots read *before* this interaction
        state.sloads_before_call = set(state.sloads_seen)


class AccessControlEscalationDetector(DetectorHook):
    """Detects ownership/privilege escalation: a privileged operation that any
    address can reach because the owner/admin gate is absent or ineffective.

    The classic shapes this catches:
      * a re-callable initializer / unprotected `_transferOwnership` — i.e. an
        `SSTORE` that sets a storage slot to `msg.sender` (`owner = msg.sender`)
        with **no** `caller`-binding guard on the path, so anyone can seize
        ownership;
      * an `onlyOwner` guard whose owner is uninitialised (`address(0)`) or never
        compared against `caller`, leaving the privileged sink (`SELFDESTRUCT` /
        `DELEGATECALL`) reachable on a path that never constrains `caller`.

    The discriminating signal is the **absence of an access-control guard** on
    the path leading to the sink. In oracle's bitvec constraint model a genuine
    `require(msg.sender == owner)` guard appears as a path constraint that
    references the symbolic `caller`; a missing/ineffective guard leaves `caller`
    entirely unconstrained. So:

      * a sink is *guarded* iff some path constraint mentions the `caller` symbol;
      * an SSTORE whose stored value is derived from `caller` (`owner =
        msg.sender`) on a `caller`-unconstrained path is an escalation;
      * a SELFDESTRUCT or DELEGATECALL on a `caller`-unconstrained path is an
        escalation (contract destruction / takeover with no ownership check).

    [Worker decision: the detector keys on the *caller* symbol appearing in the
    path constraints rather than attempting full taint analysis on CALLER through
    the constraint set (the effort POST_V01 #5 flags as non-trivial). Matching on
    the caller symbol's presence is sound for the canonical patterns and avoids
    false positives on ordinary public functions that legitimately ignore the
    sender — those are only flagged when they additionally (a) write the sender
    into storage as the new owner, or (b) reach SELFDESTRUCT/DELEGATECALL, both
    of which are privileged sinks that an unauthenticated caller must never reach.
    STORE-to-owner-of-msg.sender, SELFDESTRUCT and DELEGATECALL are the exact
    primitives an escalation exploit needs.]
    """

    category = "access_control_escalation"

    # privileged sinks an unauthenticated caller must never reach
    _PRIV_CALL_OPS = ("DELEGATECALL", "CALLCODE")

    def inspect(self, vm, state, instruction) -> None:
        op = instruction.mnemonic
        if op == "SSTORE":
            # owner = msg.sender pattern: a storage write inside a function that
            # *read* msg.sender (CALLER executed on this path) yet never bound a
            # constraint on it => the sender is observed but not enforced, so any
            # address can drive the write (re-callable initializer / unprotected
            # _transferOwnership). Anyone can become owner.
            #
            # [Worker decision: the signal is `caller_loaded AND not guarded`
            # rather than "the SSTORE value is taint-derived from CALLER".
            # Solidity's address packing (SLOAD ; mask ; OR-in caller ; SSTORE)
            # routes the caller through EXP/MUL/OR arithmetic that oracle models
            # coarsely (EXP is approximated, packed memory roundtrips through the
            # coarse memory model), so the caller term does not reliably survive
            # onto the SSTORE operand. "The function read the sender but did not
            # gate on it, and then writes storage" is the sound, model-robust
            # statement of the same bug — and the value/key operands are still
            # checked as a stronger corroborating signal when they do survive.]
            if len(state.stack) < 2:
                return
            if _guarded_by_caller(state, vm):
                return
            key = state.stack[-1]
            value = state.stack[-2]
            caller_derived = _mentions_caller(value, vm) or _mentions_caller(key, vm)
            if state.caller_loaded or caller_derived:
                self.findings.append(_finding(self.category, state, instruction, vm))
            return
        if op == "SELFDESTRUCT" or op in self._PRIV_CALL_OPS:
            # destroying or hijacking the contract with no ownership check.
            if not _guarded_by_caller(state, vm):
                self.findings.append(_finding(self.category, state, instruction, vm))


class TxOriginAuthDetector(DetectorHook):
    """Detects `tx.origin`-based authorization (SWC-115).

    Using `tx.origin` to authorize a caller is a classic, high-severity EVM
    bug: `tx.origin` is the externally-owned account that *started* the
    transaction, not the immediate caller. A `require(tx.origin == owner)`
    guard is bypassable by a phishing-relay attack — the owner is tricked into
    calling a malicious contract, which forwards the call into the victim;
    `msg.sender` is the attacker's contract but `tx.origin` is still the owner,
    so the check passes. Solidity's own docs and every audit checklist flag any
    authentication use of `tx.origin`; the safe primitive is `msg.sender`.

    Detection signal: the contract *branched control flow on* `tx.origin` — a
    path constraint references the symbolic `origin` leaf. That is exactly the
    shape an `if (tx.origin == ...)` / `require(tx.origin == ...)` guard
    compiles to (a comparison feeding a JUMPI, whose taken/not-taken constraint
    carries the `origin` term). A contract that reads `tx.origin` for logging or
    a non-control-flow purpose never produces such a constraint, so this keys on
    the authorization use specifically rather than any ORIGIN execution.

    The detector fires once per path. A `tx.origin` guard's JUMPI appends a
    branch condition mentioning `origin`, so the first instruction whose path
    constraints reference `origin` is the guard site. The origin constraint then
    persists for the remainder of that path, so a per-path `tx_origin_flagged`
    latch (carried on the MachineState across forks) makes the detector report
    each guarded path exactly once instead of re-emitting on every subsequent
    instruction. A per-detector set of already-flagged pcs additionally dedupes
    the same guard reached via different paths.

    [Worker decision: keying on `origin` appearing in the path constraints
    (control flow branched on tx.origin) mirrors how AccessControlEscalation
    keys on `caller` in the constraints, and reuses the same `_ast_mentions`
    walk. It is sound for the canonical `require(tx.origin == X)` pattern and
    does not false-positive on contracts that merely read tx.origin without
    gating on it, because a non-branching read never enters a JUMPI condition.]
    """

    category = "tx_origin_authentication"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        # Only meaningful once tx.origin has been read on this path. Cheap gate
        # before the (more expensive) constraint AST walk.
        if not state.origin_loaded:
            return
        if state.tx_origin_flagged:
            return  # this path's tx.origin guard has already been reported
        if not state.constraints:
            return
        # The guard site is the first instruction whose path constraints branch
        # on tx.origin (control flow gated on the EOA that started the
        # transaction — the unsafe authentication pattern).
        name = _origin_symbol_name(vm)
        if any(_ast_mentions(c, name) for c in state.constraints):
            state.tx_origin_flagged = True
            if instruction.pc not in self._flagged_pcs:
                self._flagged_pcs.add(instruction.pc)
                self.findings.append(
                    _finding(self.category, state, instruction, vm)
                )


class DelegatecallUntrustedDetector(DetectorHook):
    """Detects `delegatecall` / `callcode` to an attacker-controllable target
    (SWC-112, "Delegatecall to Untrusted Callee").

    `DELEGATECALL` runs the callee's code in *this* contract's storage and
    balance context: the callee can rewrite any storage slot (including the
    owner slot) and move the contract's ether. If the call **target address**
    is derived from untrusted input (a function argument, i.e. calldata) the
    contract is letting an arbitrary attacker run arbitrary code against its own
    state — the canonical Parity multisig wallet bug (SWC-112). `CALLCODE` shares
    the same hijack surface (callee code in the caller's storage context).

    This is distinct from the access-control detector, which flags an *unguarded*
    privileged sink regardless of where the target comes from. Here the bug is
    the **untrusted target itself**: even a perfectly access-controlled
    `delegatecall(userSuppliedLib, ...)` is exploitable because the privileged
    caller can be tricked into pointing at a malicious library, and any caller
    who controls the target controls the contract.

    Detection signal — the target address operand of the DELEGATECALL/CALLCODE
    is **symbolic and derived from calldata**. The call's stack layout is
    `gas, addr, argsOffset, argsLength, retOffset, retLength`, so the target is
    the second word from the top (`stack[-2]`). A concrete target (a hard-coded
    library address, or a delegatecall to an immutable implementation) is *not*
    flagged: it is not attacker-controllable. A target read from storage that
    only an owner can set is modelled as a fresh storage symbol, not a calldata
    leaf, so it is likewise not flagged — keeping the detector to the specific
    untrusted-callee bug rather than every delegatecall.

    [Worker decision: the target must be calldata-derived (not merely symbolic).
    oracle initialises storage as a constant-0 array, so a target loaded from an
    *uninitialised* storage slot can collapse to a concrete 0 and would be missed
    by a bare "is symbolic" gate; conversely, a target read from storage that is
    not attacker-supplied should NOT be flagged as untrusted (that is the
    upgradeable-proxy pattern, where the implementation slot is owner-gated). The
    sound, low-false-positive signal for SWC-112 specifically is therefore
    "the delegatecall target is influenced by calldata" — exactly the EtherLeak
    detector's recipient test, applied to the delegatecall target.]
    """

    category = "delegatecall_untrusted_callee"

    # DELEGATECALL and CALLCODE both run callee code in the caller's storage
    # context. STATICCALL/CALL keep their own context, so they are not SWC-112.
    _OPS = ("DELEGATECALL", "CALLCODE")

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic not in self._OPS:
            return
        # stack: gas, addr, argsOffset, argsLength, retOffset, retLength
        if len(state.stack) < 2:
            return
        target = state.stack[-2]
        if _is_concrete(target):
            return  # hard-coded library / immutable implementation — trusted
        if _mentions_calldata(target, vm):
            self.findings.append(_finding(self.category, state, instruction, vm))


def _origin_symbol_name(vm) -> str:
    """The z3 leaf name of this transaction's symbolic tx.origin."""
    raw = vm.origin.raw if hasattr(vm.origin, "raw") else vm.origin
    try:
        return raw.decl().name()
    except Exception:
        return "origin"


def _caller_symbol_name(vm) -> str:
    """The z3 leaf name of this transaction's symbolic msg.sender."""
    raw = vm.caller.raw if hasattr(vm.caller, "raw") else vm.caller
    try:
        return raw.decl().name()
    except Exception:
        return "caller"


def _ast_mentions(node, target_name: str) -> bool:
    """True if the z3 AST rooted at `node` contains a leaf named `target_name`."""
    try:
        import z3
    except Exception:
        return False
    raw = node.raw if hasattr(node, "raw") else node
    if not isinstance(raw, z3.AstRef):
        return False
    stack = [raw]
    seen = set()
    while stack:
        cur = stack.pop()
        key = cur.get_id() if hasattr(cur, "get_id") else id(cur)
        if key in seen:
            continue
        seen.add(key)
        if isinstance(cur, z3.ExprRef):
            try:
                if cur.num_args() == 0 and cur.decl().name() == target_name:
                    return True
            except Exception:
                pass
            for i in range(cur.num_args()):
                stack.append(cur.arg(i))
    return False


def _mentions_caller(bv, vm) -> bool:
    """True if the bitvec value is derived from the symbolic msg.sender."""
    return _ast_mentions(bv, _caller_symbol_name(vm))


def _ast_mentions_prefix(node, prefix: str) -> bool:
    """True if the z3 AST rooted at `node` contains a leaf whose name starts
    with `prefix` — used to match the calldata symbol *family* (`calldata`,
    `calldata_<offset>`, `calldata_dyn`, and their per-epoch-prefixed variants)
    without enumerating every materialised offset."""
    try:
        import z3
    except Exception:
        return False
    raw = node.raw if hasattr(node, "raw") else node
    if not isinstance(raw, z3.AstRef):
        return False
    stack = [raw]
    seen = set()
    while stack:
        cur = stack.pop()
        key = cur.get_id() if hasattr(cur, "get_id") else id(cur)
        if key in seen:
            continue
        seen.add(key)
        if isinstance(cur, z3.ExprRef):
            try:
                if cur.num_args() == 0:
                    name = cur.decl().name()
                    # match the calldata family at the bare or epoch-prefixed
                    # form (epoch prefixes are like "tx1_"); a plain
                    # `name.startswith(prefix)` covers the bare case and any
                    # suffix (offset) case, and we additionally allow an epoch
                    # prefix before the family name.
                    if prefix in name:
                        return True
            except Exception:
                pass
            for i in range(cur.num_args()):
                stack.append(cur.arg(i))
    return False


def _mentions_calldata(bv, vm) -> bool:
    """True if the bitvec value is derived from any symbolic calldata word.

    oracle models calldata as a family of leaves (`calldata`, `calldata_<off>`,
    `calldata_dyn`), optionally namespaced with a per-transaction epoch prefix.
    A delegatecall target derived from any of them is attacker-controllable."""
    return _ast_mentions_prefix(bv, "calldata")


def _guarded_by_caller(state, vm) -> bool:
    """True if any path constraint references msg.sender — i.e. control flow has
    branched on the caller's identity (an access-control guard is present)."""
    name = _caller_symbol_name(vm)
    return any(_ast_mentions(c, name) for c in state.constraints)


def _slot_key(bv) -> str:
    """A stable identity for a storage slot key (concrete or symbolic)."""
    raw = bv.raw if hasattr(bv, "raw") else bv
    return str(raw)


# ---------------------------------------------------------------------- #
# helpers
# ---------------------------------------------------------------------- #
def _finding(category: str, state, instruction, vm) -> dict:
    # report the principal symbolic transaction inputs plus every calldata word
    # the engine materialised along the way (selector + decoded arguments).
    symbols = {
        "callvalue": vm.callvalue,
        "caller": vm.caller,
    }
    for key, sym in vm._calldata_words.items():
        name = "calldata" if key == 0 else f"calldata_at_{key}"
        symbols[name] = sym
    return {
        "category": category,
        "severity": SEVERITY.get(category, "medium"),
        "pc": instruction.pc,
        "op": instruction.mnemonic,
        "depth": state.depth,
        "constraints": list(state.constraints),
        "trace": [t.to_dict() for t in state.trace],
        "symbols": symbols,
    }


def _is_concrete(bv) -> bool:
    return _concrete_val(bv) is not None


def _concrete_val(bv):
    try:
        import z3

        raw = bv.raw if hasattr(bv, "raw") else bv
        if isinstance(raw, z3.BitVecNumRef):
            return raw.as_long()
    except Exception:
        return None
    return None


# registry mapping the CLI --check token to the detector class
DETECTOR_REGISTRY = {
    "assertion": AssertionViolationDetector,
    "overflow": IntegerOverflowDetector,
    "selfdestruct": ReachableSelfdestructDetector,
    "ether-leak": EtherLeakDetector,
    "storage-write": StorageWriteDetector,
    "reentrancy": ReentrancyDetector,
    "access-control": AccessControlEscalationDetector,
    "tx-origin": TxOriginAuthDetector,
    "delegatecall": DelegatecallUntrustedDetector,
}
