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
    "integer_underflow": "high",
    "reachable_selfdestruct": "high",
    "unconstrained_ether_transfer": "high",
    "arbitrary_storage_write": "high",
    "reentrancy": "high",
    "access_control_escalation": "high",
    "tx_origin_authentication": "high",
    "delegatecall_untrusted_callee": "high",
    "unchecked_call_return": "medium",
    "dos_failed_call": "medium",
    "timestamp_dependence": "medium",
    "unprotected_ether_withdrawal": "high",
    "block_gas_limit_dos": "medium",
    "extcodesize_caller_check": "medium",
    "strict_balance_equality": "medium",
    "blockhash_randomness": "medium",
    "transaction_order_dependence": "medium",
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


class IntegerUnderflowDetector(DetectorHook):
    """Detects unsigned integer underflow on SUB involving symbolic operands
    (SWC-101, "Integer Overflow and Underflow" — the underflow half).

    EVM arithmetic is modular over 256 bits with no native bounds checking, so
    `a - b` where `b > a` does not error — it wraps around to a huge value
    (`2**256 - (b - a)`). When `a` and `b` are `uint`s the result is silently the
    near-maximum 256-bit number rather than a negative one. This is the most
    damaging arithmetic-bug class in practice: a `balances[msg.sender] -= amount`
    (or `totalSupply - burned`, a `block.number - startBlock` window, a
    `now - lastWithdraw` cooldown) that underflows mints the attacker an
    astronomically large balance / supply / allowance and drains the contract —
    the canonical `batchOverflow` / `proxyOverflow` ERC-20 incident family and a
    long tail of "underflowed accounting" exploits. solc >= 0.8.0 inserts a
    revert on underflow (so this surfaces the `unchecked { ... }` blocks and the
    pre-0.8 / assembly contracts that opt out), and any contract compiled below
    0.8.0 has no such guard at all.

    This is the mirror of `IntegerOverflowDetector`: that detector handles the
    ADD/MUL overflow direction (the wrapped result is *smaller* than an operand);
    this one handles the SUB underflow direction (the subtrahend exceeds the
    minuend, so the wrapped result is *larger* than the minuend). They are kept as
    separate detectors keyed to distinct operations and distinct categories
    (`integer_overflow` vs `integer_underflow`) so each reports its own bug
    direction with its own SWC-aligned title and so a triage team can suppress one
    direction without the other — mirroring oracle's one-detector-per-bug-class
    house style.

    Detection signal — a `SUB` whose operands are not both concrete (so the
    subtraction involves attacker-influenced / symbolic data), recorded as a
    candidate finding whose `extra_constraint` asserts the underflow condition
    `b > a` (the subtrahend strictly exceeds the minuend). The EVM `SUB` pops
    `a` (top of stack) then `b` and pushes `a - b`, so the operands inspected here
    are `state.stack[-1]` (a) and `state.stack[-2]` (b). The analysis driver then
    asks Z3 whether the path constraints AND `b > a` are jointly satisfiable; only
    a genuinely reachable underflow becomes a finding, with a concrete trigger
    input. A subtraction over two concrete constants is skipped — the compiler
    would have folded a real constant underflow, and there is no symbolic input to
    drive — exactly as the overflow detector skips concrete ADD/MUL.

    A subtraction is skipped when either operand involves the compiler's ABI /
    memory **plumbing** rather than program data — specifically `calldatasize`
    (the dispatcher's `calldatasize - 4` argument-length check), the free-memory-
    pointer family (`mem_*`, oracle's coarse per-PC memory-read symbols), and
    `msize`. solc emits these subtractions on *every* contract as bookkeeping, and
    oracle's coarse memory model mints each `mem_*` read as an independent symbol,
    so an unfiltered "every symbolic SUB" rule would treat the calldata-length
    check and free-memory-pointer math as underflow candidates on contracts with
    no arithmetic bug at all. Filtering them keeps the detector keyed to a
    subtraction over genuine program data (calldata words, storage, callvalue,
    msg.sender) — the SWC-101 surface — rather than the ABI scaffolding.

    [Worker decision: the underflow condition is `UGT(b, a)` (unsigned `b > a`),
    reusing the same `extra_constraint` + Z3-reachability mechanism the overflow
    detector already uses for ADD/MUL — no engine change, no new dependency, no
    new VM symbol or MachineState field. SUB is the unhandled half of SWC-101:
    `IntegerOverflowDetector` explicitly covers only ADD and MUL, leaving
    subtraction underflow — the single most exploited arithmetic bug — entirely
    undetected. The symbolic-only gate alone (matching the overflow detector) is
    insufficient for SUB because solc's calldata-length check and free-memory-
    pointer arithmetic are also symbolic and fire on every contract; the operands
    are therefore additionally screened against the ABI/memory-plumbing symbol
    families (`calldatasize`, `mem`, `msize`) so the detector flags only a
    subtraction over real program data. This keeps the false-positive rate sound
    over oracle's coarse memory model — exactly the model limitation that makes a
    naive every-SUB rule unshippable — while still surfacing the genuine
    storage/calldata underflow, and Z3 reachability over the path constraints
    (including any `require(b <= a)` guard) does the final filtering: a guarded
    subtraction is proved unsatisfiable and dropped.]
    """

    category = "integer_underflow"

    # symbol families that mark a subtraction as compiler ABI/memory plumbing
    # rather than program-data arithmetic. solc emits `calldatasize - 4`
    # (argument-length dispatch) and free-memory-pointer math (`mem_*`) on every
    # contract; oracle's coarse per-PC `mem_*` symbols would otherwise read as
    # spuriously-underflowing independent values. `msize` is the same class.
    _PLUMBING_PREFIXES = ("calldatasize", "mem", "msize")

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "SUB":
            return
        if len(state.stack) < 2:
            return
        a = state.stack[-1]  # minuend (top of stack)
        b = state.stack[-2]  # subtrahend
        if _is_concrete(a) and _is_concrete(b):
            return  # only flag symbolic arithmetic (no input to drive)
        # Skip the compiler's ABI/memory plumbing (calldatasize length check,
        # free-memory-pointer math). These are symbolic but are not program-data
        # arithmetic, and over oracle's coarse memory model they would otherwise
        # produce an underflow candidate on every contract.
        if any(
            _ast_mentions_prefix(a, p) or _ast_mentions_prefix(b, p)
            for p in self._PLUMBING_PREFIXES
        ):
            return
        # 256-bit unsigned underflow: a - b wraps when the subtrahend exceeds the
        # minuend (b > a), yielding 2**256 - (b - a) instead of a negative value.
        underflow = UGT(b, a)
        f = _finding(self.category, state, instruction, vm)
        f["extra_constraint"] = underflow
        self.findings.append(f)


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


class UncheckedCallReturnDetector(DetectorHook):
    """Detects an unchecked low-level call return value (SWC-104).

    Every EVM call opcode — `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL` —
    does **not** revert when the callee reverts; it pushes a boolean success
    word (1 = ok, 0 = failed) onto the stack and execution continues. Solidity's
    high-level `transfer`/`require(... .call ...)` patterns read that word and
    revert on failure, but a low-level `addr.call(...)` / `addr.send(...)` whose
    result is *discarded* lets a failed external call pass silently. The contract
    then proceeds as though the call succeeded — funds appear sent, state appears
    updated — which is the canonical "unchecked return value" / "unchecked send"
    bug (SWC-104, the King-of-the-Ether class of incident).

    Detection signal: a `POP` discards the call's success word **and that word
    was never branched on** along the path. oracle's VM mints the word as a
    named symbol (`callretval_<pc>` for CALL/CALLCODE, `staticretval_<pc>` for
    STATICCALL/DELEGATECALL). A *checked* call routes the word through
    `ISZERO`/`JUMPI`, so the `callretval`/`staticretval` leaf appears in a path
    constraint — and Solidity still POPs the duplicated original during stack
    cleanup, so the bare POP alone is not enough to distinguish the two. An
    *unchecked* call's word never reaches a JUMPI, so it appears in **no** path
    constraint; when it is then POPped it is genuinely discarded. The detector
    therefore fires when a POP is about to discard a call-result value whose
    symbol family is absent from every accumulated path constraint.

    The detector inspects *before* the POP executes, so the value about to be
    discarded is the top of stack (`state.stack[-1]`); its AST is walked for a
    `callretval`/`staticretval` leaf with the same prefix-match machinery the
    delegatecall detector uses for the calldata family. A per-detector set of
    already-flagged pcs dedupes the same discard reached on multiple paths.

    [Worker decision: the signal is "the success word is POPped AND was never a
    branch condition" rather than "the success word is POPped" alone. Solidity's
    `(bool ok, ) = addr.call(...); require(ok)` DUPs the word for the
    require's ISZERO/JUMPI and then POPs the original local during stack cleanup,
    so a bare-POP-of-the-success-word test false-positives on correctly checked
    calls. Branched-on is decided by whether the call-result symbol family
    appears in `state.constraints` (JUMPI appends its condition there), reusing
    the same AST-walk architecture every other oracle detector uses — no engine
    change. This is sound for the canonical unchecked-send pattern and does not
    false-positive on a require/if-guarded low-level call.]
    """

    category = "unchecked_call_return"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "POP":
            return
        if not state.stack:
            return
        discarded = state.stack[-1]
        if not _mentions_call_result(discarded):
            return
        # A checked call branches on its success word, so the call-result symbol
        # family shows up in a path constraint (JUMPI appends its condition).
        # If the word being discarded was never branched on, the call result is
        # genuinely unchecked.
        if any(_mentions_call_result(c) for c in state.constraints):
            return
        if instruction.pc in self._flagged_pcs:
            return
        self._flagged_pcs.add(instruction.pc)
        self.findings.append(_finding(self.category, state, instruction, vm))


class DosFailedCallDetector(DetectorHook):
    """Detects denial-of-service via a failing external call in a loop
    (SWC-113, "DoS with Failed Call" / "revert in loop").

    The unsafe pattern is a "push" payout: a contract iterates over a list of
    recipients and makes an external call (`transfer`/`send`/low-level call)
    inside the loop body. An EVM external call hands control to the callee, and
    `transfer`/`send` (and a `require`-checked low-level call) revert the *whole*
    transaction when the callee fails. A single recipient that cannot accept the
    call — a contract with a reverting or gas-exhausting fallback — therefore
    reverts the entire batch, so **no** recipient is ever paid. One malicious or
    broken entry permanently bricks the function for everyone. This is the
    classic auction-refund / airdrop / dividend-distribution DoS, and the SWC
    registry's named SWC-113. The safe design is "pull payment": each account
    withdraws its own balance in an isolated, single call, so one failure can
    never block the others.

    Detection signal — an external call op (`CALL`/`CALLCODE`/`DELEGATECALL`/
    `STATICCALL`) whose **program counter the engine has already executed
    earlier on this same path**. oracle's bounded executor unrolls loops by
    revisiting the loop body's instructions, appending each executed `(pc, op)`
    to the per-path `state.trace`. The detector inspects *before* the
    instruction executes, so the trace does not yet contain the current pc; if
    that pc is *already* present in the trace, this call site has been reached
    before on this path — i.e. it sits inside a loop body that has iterated at
    least once. A call that is reached at most once per transaction (a pull
    payment, a single forwarding call) never repeats its pc and is not flagged.

    [Worker decision: the discriminating signal is "the call's pc recurs in the
    path trace" (the call is inside an iterating loop) rather than attempting to
    reconstruct the loop's CFG or prove the callee can revert. oracle's executor
    already unrolls loops onto the trace, so a recurring call pc is a sound,
    model-robust witness that the call is loop-bound — exactly the SWC-113
    surface, where one reverting callee in the loop DoSes the batch. It does not
    false-positive on a single forwarding call or a pull-payment withdraw (their
    call pc appears once per path), and it is independent of the unchecked-return
    (SWC-104) and ether-leak detectors, which key on the call's *return value*
    and *recipient* respectively, not on the call being loop-bound. A
    per-detector flagged-pc set reports each loop-bound call site once across
    paths.]
    """

    category = "dos_failed_call"

    _CALL_OPS = ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL")

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic not in self._CALL_OPS:
            return
        if instruction.pc in self._flagged_pcs:
            return
        # The hook runs BEFORE the instruction executes, so this pc is not yet
        # on the trace. If it is already present, the call site has been reached
        # before on this path — it is inside a loop body that has iterated.
        if any(t.pc == instruction.pc for t in state.trace):
            self._flagged_pcs.add(instruction.pc)
            self.findings.append(_finding(self.category, state, instruction, vm))


class TimestampDependenceDetector(DetectorHook):
    """Detects control flow that depends on a block value used as a proxy for
    time or randomness (SWC-116, "Block values as a proxy for time").

    `block.timestamp` and `block.number` are set by the block proposer
    (miner/validator), who has a window of discretion over them — a few seconds
    of slack on the timestamp, and full control over which transactions land in
    which block. A contract that *branches on* a block value to gate a payout, a
    deadline, a lottery winner, or a "random" outcome is letting the proposer
    influence that decision: the canonical timestamp-as-randomness gambling bug
    and the deadline-manipulation class (SWC-116). The safe primitives are a
    commit-reveal scheme or an external randomness oracle, never a raw block
    value. Reading a block value for display or an event log is harmless; the bug
    is specifically *deciding control flow* on it.

    Detection signal — the contract **branched control flow on** a block value:
    a path constraint references the symbolic `timestamp` or `block_number` leaf.
    That is exactly the shape an `if (block.timestamp > deadline)` /
    `require(block.timestamp % N == ...)` guard compiles to (a comparison feeding
    a JUMPI, whose taken/not-taken constraint carries the block-value term). A
    contract that merely reads `block.timestamp` for a non-control-flow purpose
    (storing it, emitting it) never produces such a constraint, so this keys on
    the decision use specifically rather than any TIMESTAMP/NUMBER execution.

    The detector fires once per path. A block-value guard's JUMPI appends a
    branch condition mentioning the block-value symbol, which then persists for
    the remainder of that path, so a per-path `timestamp_flagged` latch (carried
    on the MachineState across forks) reports each block-value-dependent path
    exactly once instead of re-emitting on every subsequent instruction. A
    per-detector set of already-flagged pcs additionally dedupes the same guard
    reached via different paths.

    [Worker decision: keying on a block-value symbol appearing in the path
    constraints (control flow branched on block.timestamp/block.number) mirrors
    how TxOriginAuthDetector keys on `origin` and AccessControlEscalationDetector
    keys on `caller`, and reuses the same `_ast_mentions` walk. It is sound for
    the canonical `if (block.timestamp ...)` / `require(block.number ...)`
    randomness/deadline patterns and does not false-positive on a contract that
    merely reads a block value without gating on it, because a non-branching read
    never enters a JUMPI condition. `block.timestamp` (TIMESTAMP) and
    `block.number` (NUMBER) are both flagged: both are proposer-influenced block
    values used interchangeably as a time/randomness proxy, and the SWC-116 entry
    names both. BLOCKHASH is deliberately *not* included here — past block hashes
    are a distinct (and only weakly manipulable) construct; SWC-116's named
    surface is the time/number proxy, and folding BLOCKHASH in would broaden the
    detector past one bug class.]
    """

    category = "timestamp_dependence"

    # the block-value symbol leaves a branch may key on. Both are minted by the
    # VM (TIMESTAMP -> "timestamp", NUMBER -> "block_number") and set the
    # per-path `blockval_loaded` latch when read.
    _BLOCKVAL_NAMES = ("timestamp", "block_number")

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        # Only meaningful once a block value has been read on this path. Cheap
        # gate before the (more expensive) constraint AST walk.
        if not state.blockval_loaded:
            return
        if state.timestamp_flagged:
            return  # this path's block-value guard has already been reported
        if not state.constraints:
            return
        # The guard site is the first instruction whose path constraints branch
        # on a block value (control flow gated on a proposer-influenced quantity
        # — the unsafe time/randomness-proxy pattern).
        if any(
            _ast_mentions(c, name)
            for c in state.constraints
            for name in self._BLOCKVAL_NAMES
        ):
            state.timestamp_flagged = True
            if instruction.pc not in self._flagged_pcs:
                self._flagged_pcs.add(instruction.pc)
                self.findings.append(
                    _finding(self.category, state, instruction, vm)
                )


class UnprotectedEtherWithdrawalDetector(DetectorHook):
    """Detects an unprotected ether withdrawal (SWC-105, "Unprotected Ether
    Withdrawal").

    A contract that forwards ether out (`addr.transfer(...)` / `addr.send(...)`
    / a value-bearing low-level `addr.call{value: ...}(...)`) from a **public**
    function with **no access-control guard** lets *any* address drain the
    contract's balance. The canonical shape is a public `withdraw()` /
    `sweep()` / `claim()` that pays out `address(this).balance` (or an
    attacker-supplied amount) to `msg.sender` with no `require(msg.sender ==
    owner)` / `onlyOwner` gate — the Parity-wallet `initWallet`+`withdraw` class
    and a long tail of "anyone can empty the contract" incidents. The safe
    design gates every value-forwarding function on the caller's authorisation
    or on a per-account balance the caller is provably entitled to.

    Detection signal — a value-forwarding call op (`CALL` / `CALLCODE`, which
    can carry `value`; `DELEGATECALL` / `STATICCALL` cannot transfer the
    contract's own ether, so they are out of scope) reached on a path whose
    accumulated constraints **never branch on the caller's identity**. In
    oracle's bitvec constraint model a genuine `require(msg.sender == owner)`
    guard compiles to a comparison feeding a JUMPI, so the symbolic `caller`
    leaf appears in a path constraint; a missing/ineffective guard leaves
    `caller` entirely unconstrained. So an ether-forwarding call on a
    `caller`-unconstrained path is the unprotected withdrawal. A provably
    zero-value call (the `value` operand is a concrete 0) carries no ether and
    is skipped — it is a pure data call, nothing to steal.

    This is distinct from the two neighbouring detectors:
      * EtherLeakDetector (`unconstrained_ether_transfer`) fires on a call whose
        *recipient* is attacker-controlled (a symbolic `to`); SWC-105 fires even
        when the recipient is `msg.sender` — the bug is the **absent access
        control**, not the recipient. A `withdraw()` that pays the caller their
        own (unentitled) share has a perfectly ordinary `to == caller` recipient
        yet is still an unprotected drain.
      * AccessControlEscalationDetector keys on the privileged *sinks*
        SELFDESTRUCT / DELEGATECALL and the `owner = msg.sender` SSTORE; SWC-105
        keys on an ordinary value-forwarding CALL, a different sink class.

    [Worker decision: the discriminating signal is "value-forwarding CALL on a
    caller-unconstrained path", reusing the `_guarded_by_caller` constraint walk
    that AccessControlEscalation already uses for `caller`. oracle initialises
    storage as a constant-0 array, so a withdrawal `value` derived from a storage
    balance can collapse to a concrete 0; a strict `value != 0` gate would then
    miss the very pattern this targets. The sound reading therefore skips only a
    *provably concrete-zero* value (a pure data call) and flags every other
    value-forwarding call on an unguarded path — absence of a non-zero proof is
    not treated as proof of a zero-value call. A per-detector flagged-pc set
    reports each unprotected call site once across paths. The detector does NOT
    require the recipient to be symbolic (that is EtherLeak's job): the
    discriminating SWC-105 property is the missing caller guard, which is present
    whether the payout goes to msg.sender or anywhere else.]
    """

    category = "unprotected_ether_withdrawal"

    # opcodes that forward the contract's own ether to a callee. DELEGATECALL /
    # STATICCALL cannot move the contract's balance, so they are out of scope.
    _VALUE_CALL_OPS = ("CALL", "CALLCODE")

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic not in self._VALUE_CALL_OPS:
            return
        # CALL/CALLCODE stack layout: gas, to, value, inoff, insize, outoff, outsize
        if len(state.stack) < 3:
            return
        value = state.stack[-3]
        if _is_concrete(value) and _concrete_val(value) == 0:
            return  # provably zero-value call: a pure data call, no ether to steal
        if _guarded_by_caller(state, vm):
            return  # the path branched on msg.sender — access control is present
        if instruction.pc in self._flagged_pcs:
            return
        self._flagged_pcs.add(instruction.pc)
        self.findings.append(_finding(self.category, state, instruction, vm))


class BlockGasLimitDosDetector(DetectorHook):
    """Detects a denial-of-service via an unbounded, storage-bounded loop
    (SWC-128, "DoS With Block Gas Limit").

    Every EVM transaction can only consume up to the block gas limit; a function
    whose gas cost grows without bound becomes permanently uncallable once that
    cost crosses the limit. The canonical shape is a loop whose iteration count
    is bounded by a value held in **contract storage that can grow without
    bound** — a `for (uint i = 0; i < arr.length; i++)` over a storage array
    `arr` that anyone (or ordinary usage) can keep pushing onto. As the array
    grows the loop costs more gas each call until the whole function reverts on
    out-of-gas for *everyone*, bricking any funds or state it gates. This is the
    classic unbounded-array DoS (SWC-128): airdrops, dividend sweeps, and
    "process all pending" batch functions that iterate an unbounded collection.
    The safe design caps the iteration count, paginates the work, or uses a
    pull-payment so each account touches only its own bounded slice.

    Detection signal — an `SLOAD` whose program counter the engine has already
    executed **earlier on this same path**. oracle's bounded executor unrolls
    loops by revisiting the loop body's instructions, appending each executed
    `(pc, op)` to the per-path `state.trace`. A storage-array loop re-reads
    storage every iteration (the array length for the bound and/or an element for
    the body), so its `SLOAD` pc recurs in the trace — a witness that the loop's
    work is bounded by, and re-reads, *contract state* that can grow without
    bound. The hook runs *before* the instruction executes, so the current pc is
    not yet on the trace; if that pc is *already* present, this storage read sits
    inside a loop body that has iterated at least once.

    This is deliberately distinct from the two neighbouring availability /
    loop detectors:
      * DosFailedCallDetector (`dos_failed_call`, SWC-113) keys on a recurring
        *CALL* pc — one reverting callee in a loop DoSing the batch. SWC-128
        needs no external call at all; the bug is the unbounded *iteration
        count* itself, witnessed by a recurring storage read.
      * A loop bounded by a fixed constant or a calldata argument re-reads no
        storage for its bound (the bound is a stack/calldata value), so its
        SLOAD pc never recurs and it is not flagged — the loop is bounded in
        contract state and cannot be pushed past the gas limit.

    A per-detector flagged-pc set reports each loop-bound storage-read site once
    across paths.

    [Worker decision: the discriminating signal is "an SLOAD pc recurs in the
    path trace" (a loop re-reads contract storage each iteration) rather than
    attempting to reconstruct the loop's CFG, prove the storage collection is
    attacker-growable, or trace the loop bound's operand through the constraint
    set. oracle's executor already unrolls loops onto the trace, so a recurring
    SLOAD pc is a sound, model-robust witness that the loop is bounded by
    re-read contract state — exactly the SWC-128 surface, where the iteration
    count grows with an unbounded storage collection. It mirrors the SWC-113
    DoS-with-failed-call detector's recurring-CALL-pc architecture (same trace,
    same per-pc dedupe), keeps the two detectors cleanly separated (CALL vs
    SLOAD recurrence), and does not false-positive on a constant- or
    calldata-bounded loop (whose bound is never re-read from storage) or on a
    single non-loop storage read (whose pc appears once per path). No engine
    change, no new dependency.]
    """

    category = "block_gas_limit_dos"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "SLOAD":
            return
        if instruction.pc in self._flagged_pcs:
            return
        # The hook runs BEFORE the instruction executes, so this pc is not yet
        # on the trace. If it is already present, the storage read has been
        # reached before on this path — it is inside a loop body that has
        # iterated, so the loop re-reads contract state every iteration and is
        # unbounded in that (growable) state: a block-gas-limit DoS.
        if any(t.pc == instruction.pc for t in state.trace):
            self._flagged_pcs.add(instruction.pc)
            self.findings.append(_finding(self.category, state, instruction, vm))


class ExtcodesizeCallerCheckDetector(DetectorHook):
    """Detects a bypassable EXTCODESIZE-based caller-type check.

    A widespread (and flawed) access-control idiom tries to restrict a function
    to externally-owned accounts — "no contracts allowed" — by checking the
    caller's code size: `require(extcodesize(msg.sender) == 0)` (or the inverse,
    `require(extcodesize(addr) > 0)` to "prove" an address is a deployed
    contract). Both are unsound. During a contract's **constructor** its code is
    not yet stored on-chain, so `extcodesize` of the address being deployed
    returns 0: an attacker simply performs the call from within their
    constructor and the "EOA-only" guard passes for a contract. The mirror form
    is equally weak — a future deployment, a self-destructed contract, or a
    not-yet-deployed CREATE2 address can all make `extcodesize > 0` return the
    "wrong" answer, so the check cannot be relied on for authorization. The SWC
    registry and every audit checklist flag any *authorization or trust*
    decision made on `extcodesize`; the safe primitives are explicit
    allow/deny lists, signature checks, or simply not distinguishing EOAs from
    contracts at all.

    Detection signal — the contract **branched control flow on** an external
    account's code size: a path constraint references an `extcodesize_<pc>` leaf.
    oracle's VM mints a fresh `extcodesize_<pc>` symbol for every EXTCODESIZE,
    and an `if (extcodesize(x) ...)` / `require(extcodesize(x) ...)` guard
    compiles to a comparison feeding a JUMPI, whose taken/not-taken constraint
    carries the `extcodesize_<pc>` term. A contract that reads a code size for a
    non-control-flow purpose (storing it, returning it) never produces such a
    constraint, so this keys on the *decision* use specifically rather than any
    EXTCODESIZE execution.

    The detector fires once per path. The extcodesize-guard constraint persists
    for the remainder of the path, so a per-path `extcodesize_flagged` latch
    (carried on the MachineState across forks) reports each code-size-dependent
    path exactly once instead of re-emitting on every subsequent instruction. A
    per-detector set of already-flagged pcs additionally dedupes the same guard
    reached via different paths.

    [Worker decision: keying on an `extcodesize_<pc>` symbol family appearing in
    the path constraints (control flow branched on a caller/account code size)
    mirrors how TimestampDependenceDetector keys on the block-value symbol and
    TxOriginAuthDetector keys on `origin`, and reuses the same prefix AST-walk
    (`_ast_mentions_prefix`) the unchecked-call detector uses for its symbol
    family. The symbols are minted per-pc (`extcodesize_<pc>`), so a prefix match
    over the `extcodesize` family catches every code-size read without
    enumerating program counters. It is sound for the canonical
    `require(extcodesize(x) == 0)` / `> 0` patterns and does not false-positive
    on a contract that merely reads a code size without gating on it, because a
    non-branching read never enters a JUMPI condition. No engine change, no new
    dependency — the VM already mints the extcodesize symbol.]
    """

    category = "extcodesize_caller_check"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if state.extcodesize_flagged:
            return  # this path's extcodesize guard has already been reported
        if not state.constraints:
            return
        # The guard site is the first instruction whose path constraints branch
        # on an external code size (control flow gated on a bypassable
        # is-it-a-contract / is-it-an-EOA test).
        if any(_ast_mentions_prefix(c, "extcodesize") for c in state.constraints):
            state.extcodesize_flagged = True
            if instruction.pc not in self._flagged_pcs:
                self._flagged_pcs.add(instruction.pc)
                self.findings.append(
                    _finding(self.category, state, instruction, vm)
                )


class StrictBalanceEqualityDetector(DetectorHook):
    """Detects control flow that depends on a strict account-balance check
    (SWC-132, "Unexpected Ether Balance").

    A contract's ether balance is **not** controlled solely by the contract's
    own logic: any account can force ether into it without invoking any of its
    functions. Two on-chain primitives bypass the receive/fallback path
    entirely — `selfdestruct(victim)` transfers the destroyed contract's whole
    balance to `victim` and runs no code, and a `CREATE2` address can be
    pre-funded before the contract is even deployed. A contract that *branches
    on* its own (or another account's) balance — the canonical
    `require(address(this).balance == expected)` invariant, or a
    `if (address(this).balance >= threshold)` gate used as a state machine
    transition — is making an assumption an attacker can falsify for a few wei.
    The classic shape is a "game" that assumes nobody can change its balance
    except through `play()`, or a contract that treats `this.balance` as a
    trustworthy accumulator; force-feeding it breaks the invariant and bricks or
    drains the contract. This is the SWC registry's named SWC-132. The safe
    design tracks deposits in a dedicated storage variable and never compares
    against the raw `address(this).balance`.

    Detection signal — the contract **branched control flow on** an account
    balance: a path constraint references a `balance` or `selfbalance` leaf.
    oracle's VM mints a `balance` symbol for `BALANCE` (`address(x).balance`)
    and a `selfbalance` symbol for `SELFBALANCE` (the gas-cheap
    `address(this).balance`); an `if (... .balance ...)` /
    `require(... .balance ...)` guard compiles to a comparison feeding a JUMPI,
    whose taken/not-taken constraint carries the balance term. A contract that
    reads a balance for a non-control-flow purpose (returning it, emitting it,
    forwarding it as a call value) never produces such a constraint, so this
    keys on the *decision* use specifically rather than any BALANCE/SELFBALANCE
    execution.

    The detector fires once per path. The balance-guard constraint persists for
    the remainder of the path, so a per-path `balance_flagged` latch (carried on
    the MachineState across forks) reports each balance-dependent path exactly
    once instead of re-emitting on every subsequent instruction. A per-detector
    set of already-flagged pcs additionally dedupes the same guard reached via
    different paths.

    [Worker decision: keying on a `balance`/`selfbalance` symbol appearing in the
    path constraints (control flow branched on an account balance) mirrors how
    TimestampDependenceDetector keys on the block-value symbol,
    ExtcodesizeCallerCheckDetector keys on the `extcodesize` family, and
    TxOriginAuthDetector keys on `origin`, and reuses the same prefix AST-walk
    (`_ast_mentions_prefix`). Both `balance` (BALANCE) and `selfbalance`
    (SELFBALANCE) share the substring `balance`, so a single prefix match over
    the `balance` family catches both the `address(x).balance` and the
    `address(this).balance` forms without enumerating the two symbol names. It is
    sound for the canonical `require(address(this).balance == X)` /
    `if (address(this).balance >= X)` patterns and does not false-positive on a
    contract that merely reads a balance without gating on it, because a
    non-branching read never enters a JUMPI condition. This is distinct from the
    ether-leak / unprotected-withdrawal detectors, which key on a value-forwarding
    CALL's recipient and on a missing caller guard respectively; here the bug is
    the *balance-as-trusted-invariant assumption* itself, independent of any
    ether movement. No engine change, no new dependency — the VM already mints
    the balance symbols.]
    """

    category = "strict_balance_equality"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if state.balance_flagged:
            return  # this path's balance guard has already been reported
        if not state.constraints:
            return
        # The guard site is the first instruction whose path constraints branch
        # on an account balance (control flow gated on a force-feedable quantity
        # — the unsafe balance-as-invariant pattern). `balance` (BALANCE) and
        # `selfbalance` (SELFBALANCE) both contain the substring `balance`.
        if any(_ast_mentions_prefix(c, "balance") for c in state.constraints):
            state.balance_flagged = True
            if instruction.pc not in self._flagged_pcs:
                self._flagged_pcs.add(instruction.pc)
                self.findings.append(
                    _finding(self.category, state, instruction, vm)
                )


class BlockhashRandomnessDetector(DetectorHook):
    """Detects control flow that depends on a block hash used as a randomness
    source (SWC-120, "Weak Sources of Randomness from Chain Attributes").

    `blockhash(n)` (and the related `block.prevrandao` / `block.difficulty`
    family) is a cheap, tempting on-chain "random" number — lotteries, raffles,
    NFT-mint orderings, and games reach for it to pick a winner or gate a payout.
    It is **not** a secure source of entropy. The value of a recent block hash is
    influenced by the block proposer (a validator who dislikes the outcome can
    drop or reorder the block), and — more cheaply — any attacker calling in the
    *same* transaction reads the exact same `blockhash(n)` the victim contract
    uses, so they can compute the "random" result in advance and only enter when
    they win. `blockhash` of the current or a future block returns 0, and only
    the last 256 blocks are even available. A contract that *branches control
    flow* on a block hash is therefore making a security decision an attacker can
    predict or grind. This is the SWC registry's named SWC-120; the safe
    primitives are a commit-reveal scheme or an external randomness oracle (e.g.
    a VRF), never a raw chain attribute. Reading a block hash for a
    non-control-flow purpose (storing it, emitting it, returning it) is harmless;
    the bug is specifically *deciding control flow* on it.

    Detection signal — the contract **branched control flow on** a block hash:
    a path constraint references a `blockhash_<pc>` leaf. oracle's VM mints a
    fresh `blockhash_<pc>` symbol for every BLOCKHASH, and an
    `if (blockhash(n) % N == ...)` / `require(uint(blockhash(n)) ...)` guard
    compiles to a comparison feeding a JUMPI, whose taken/not-taken constraint
    carries the `blockhash_<pc>` term. A contract that merely reads a block hash
    for a non-control-flow purpose never produces such a constraint, so this keys
    on the *decision* use specifically rather than any BLOCKHASH execution.

    The detector fires once per path. The blockhash-guard constraint persists for
    the remainder of the path, so a per-path `blockhash_flagged` latch (carried
    on the MachineState across forks) reports each block-hash-dependent path
    exactly once instead of re-emitting on every subsequent instruction. A
    per-detector set of already-flagged pcs additionally dedupes the same guard
    reached via different paths.

    This is deliberately distinct from the neighbouring SWC-116
    timestamp-dependence detector. That detector was scoped to the
    time/number *proxy* surface (`block.timestamp` / `block.number`) and
    explicitly excluded BLOCKHASH as "a distinct, only weakly-manipulable
    construct." SWC-120 is that distinct construct: weak *randomness* derived from
    a chain attribute, a different named SWC entry with its own remediation
    (commit-reveal / VRF rather than "don't use time as a deadline"). Keeping the
    two detectors separate keeps each keyed to one bug class and one SWC id.

    [Worker decision: keying on a `blockhash_<pc>` symbol family appearing in the
    path constraints (control flow branched on a block hash) mirrors how
    TimestampDependenceDetector keys on the block-value symbol,
    ExtcodesizeCallerCheckDetector keys on the `extcodesize` family, and
    StrictBalanceEqualityDetector keys on the `balance` family, and reuses the
    same prefix AST-walk (`_ast_mentions_prefix`). The symbols are minted per-pc
    (`blockhash_<pc>`), so a prefix match over the `blockhash` family catches
    every block-hash read without enumerating program counters. It is sound for
    the canonical `blockhash(n)`-as-randomness pattern and does not
    false-positive on a contract that merely reads a block hash without gating on
    it, because a non-branching read never enters a JUMPI condition. Adding the
    BLOCKHASH opcode handler (previously unhandled, so paths halted at it) is a
    prerequisite — the detector cannot observe a guard on a value the VM never
    materialises. No new dependency.]
    """

    category = "blockhash_randomness"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        # Only meaningful once a block hash has been read on this path. Cheap gate
        # before the (more expensive) constraint AST walk.
        if not state.blockhash_loaded:
            return
        if state.blockhash_flagged:
            return  # this path's blockhash guard has already been reported
        if not state.constraints:
            return
        # The guard site is the first instruction whose path constraints branch
        # on a block hash (control flow gated on a predictable/grindable chain
        # attribute — the unsafe weak-randomness pattern).
        if any(_ast_mentions_prefix(c, "blockhash") for c in state.constraints):
            state.blockhash_flagged = True
            if instruction.pc not in self._flagged_pcs:
                self._flagged_pcs.add(instruction.pc)
                self.findings.append(
                    _finding(self.category, state, instruction, vm)
                )


class TransactionOrderDependenceDetector(DetectorHook):
    """Detects control flow that depends on `tx.gasprice` (SWC-114, "Transaction
    Order Dependence").

    The order in which transactions execute inside a block is **not** chosen by
    the contract — it is chosen by the block proposer / searcher, who orders
    transactions by fee (and can insert, drop, or reorder them). A contract whose
    outcome depends on transaction ordering is exposed to front-running and
    sandwich attacks: an observer watching the mempool can place their own
    transaction *ahead of* a victim's by bidding a higher `tx.gasprice` (a
    priority fee), or *behind* it, to capture value — the classic
    approve/transferFrom race, the DEX sandwich, and the "first claimer wins" gas
    auction. The single most direct on-chain signal of this exposure is a
    contract that **branches control flow on `tx.gasprice` itself**: either a
    misguided gas-price ceiling meant to deter front-running
    (`require(tx.gasprice <= maxGasPrice)` — itself trivially satisfiable and a
    smell that the author knows ordering matters), or an outcome derived from the
    gas price (`if (tx.gasprice > X) reward = ...`). `tx.gasprice` is set freely
    by the transaction sender and is the exact lever that governs ordering, so
    gating logic on it is a security decision driven by an attacker-controlled,
    ordering-determining value. This is the SWC registry's named SWC-114. The
    safe primitives are commit-reveal schemes, batch auctions, submarine sends,
    or slippage bounds — never logic that trusts gas price or transaction order.

    Detection signal — the contract **branched control flow on** the gas price:
    a path constraint references the `gasprice` leaf. oracle's VM mints a stable
    `gasprice` symbol for the GASPRICE opcode, and an `if (tx.gasprice ...)` /
    `require(tx.gasprice ...)` guard compiles to a comparison feeding a JUMPI,
    whose taken/not-taken constraint carries the `gasprice` term. A contract that
    reads `tx.gasprice` for a non-control-flow purpose (storing it, emitting it,
    returning it, refunding it) never produces such a constraint, so this keys on
    the *decision* use specifically rather than any GASPRICE execution.

    The detector fires once per path. The gasprice-guard constraint persists for
    the remainder of the path, so a per-path `gasprice_flagged` latch (carried on
    the MachineState across forks) reports each gas-price-dependent path exactly
    once instead of re-emitting on every subsequent instruction. A per-detector
    set of already-flagged pcs additionally dedupes the same guard reached via
    different paths.

    This is deliberately distinct from the neighbouring chain-attribute
    detectors. SWC-116 timestamp-dependence keys on `block.timestamp` /
    `block.number` (a proposer-chosen *time* proxy), and SWC-120 blockhash keys on
    `blockhash(n)` (a *randomness* source). SWC-114 is a different bug class — the
    *ordering* of transactions, witnessed here by a gas-price-gated branch — with
    its own remediation (commit-reveal / batch auctions rather than "don't use
    time as a deadline" or "don't use a block hash for entropy"). Keeping the
    detectors separate keeps each keyed to one bug class and one SWC id.

    [Worker decision: keying on the `gasprice` symbol appearing in the path
    constraints (control flow branched on tx.gasprice) mirrors how
    TimestampDependenceDetector keys on the block-value symbol,
    BlockhashRandomnessDetector keys on the `blockhash` family, and
    TxOriginAuthDetector keys on `origin`, and reuses the same prefix AST-walk
    (`_ast_mentions_prefix`, which also matches the epoch-prefixed `gasprice` form
    a later transaction would mint). It is sound for the canonical
    `require(tx.gasprice <= max)` / `if (tx.gasprice ...)` ordering-dependent
    patterns — the most direct, model-robust bytecode signal of SWC-114 exposure —
    and does not false-positive on a contract that merely reads the gas price
    without gating on it (a non-branching read never enters a JUMPI condition).
    Adding a dedicated `_op_gasprice` that sets the per-path `gasprice_loaded`
    latch (the opcode previously used the generic env handler) gives the detector
    a cheap gate before its AST walk, mirroring the BLOCKHASH handler; the symbol
    name is unchanged, so no other detector or report path is affected. No new
    dependency.]
    """

    category = "transaction_order_dependence"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        # Only meaningful once the gas price has been read on this path. Cheap
        # gate before the (more expensive) constraint AST walk.
        if not state.gasprice_loaded:
            return
        if state.gasprice_flagged:
            return  # this path's gas-price guard has already been reported
        if not state.constraints:
            return
        # The guard site is the first instruction whose path constraints branch
        # on the gas price (control flow gated on an attacker-set,
        # ordering-determining quantity — the unsafe transaction-order-dependence
        # pattern).
        if any(_ast_mentions_prefix(c, "gasprice") for c in state.constraints):
            state.gasprice_flagged = True
            if instruction.pc not in self._flagged_pcs:
                self._flagged_pcs.add(instruction.pc)
                self.findings.append(
                    _finding(self.category, state, instruction, vm)
                )


def _mentions_call_result(bv) -> bool:
    """True if the bitvec value is (or is derived from) a call opcode's success
    word. oracle mints that word as `callretval_<pc>` (CALL/CALLCODE) or
    `staticretval_<pc>` (STATICCALL/DELEGATECALL), optionally namespaced with a
    per-transaction epoch prefix, so a prefix match over the symbol family
    catches every call site without enumerating program counters."""
    return _ast_mentions_prefix(bv, "callretval") or _ast_mentions_prefix(
        bv, "staticretval"
    )


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
    "underflow": IntegerUnderflowDetector,
    "selfdestruct": ReachableSelfdestructDetector,
    "ether-leak": EtherLeakDetector,
    "storage-write": StorageWriteDetector,
    "reentrancy": ReentrancyDetector,
    "access-control": AccessControlEscalationDetector,
    "tx-origin": TxOriginAuthDetector,
    "delegatecall": DelegatecallUntrustedDetector,
    "unchecked-call": UncheckedCallReturnDetector,
    "dos-failed-call": DosFailedCallDetector,
    "timestamp": TimestampDependenceDetector,
    "ether-withdrawal": UnprotectedEtherWithdrawalDetector,
    "gas-limit-dos": BlockGasLimitDosDetector,
    "extcodesize-check": ExtcodesizeCallerCheckDetector,
    "strict-balance": StrictBalanceEqualityDetector,
    "blockhash-randomness": BlockhashRandomnessDetector,
    "tx-order": TransactionOrderDependenceDetector,
}
