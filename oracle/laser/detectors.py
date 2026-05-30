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
    "unprotected_selfdestruct": "high",
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
    "arbitrary_jump": "high",
    "prevrandao_randomness": "medium",
    "write_arbitrary_storage": "high",
    "signature_replay": "high",
    "signature_malleability": "medium",
    "hardcoded_gas_call": "medium",
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


class UnprotectedSelfdestructDetector(DetectorHook):
    """Detects an unprotected SELFDESTRUCT instruction (SWC-106, "Unprotected
    SELFDESTRUCT Instruction").

    `SELFDESTRUCT(target)` deletes the contract's code from chain and forwards
    its **entire balance** to `target` in a single, irreversible operation. A
    contract that reaches a `selfdestruct` from a **public** function with **no
    access-control guard** lets *any* address destroy it and sweep its funds.
    The canonical shape is a public `kill()` / `close()` / `destroy()` that calls
    `selfdestruct(msg.sender)` (or an attacker-supplied address) with no
    `require(msg.sender == owner)` / `onlyOwner` gate — the Parity multisig
    wallet-library incident that bricked ~$280M of user funds when an
    unauthenticated caller invoked the library's unprotected `kill()`. The safe
    design gates every `selfdestruct` on the caller's authorisation.

    Detection signal — a `SELFDESTRUCT` reached on a path whose accumulated
    constraints **never branch on the caller's identity**. In oracle's bitvec
    constraint model a genuine `require(msg.sender == owner)` guard compiles to a
    comparison feeding a JUMPI, so the symbolic `caller` leaf appears in a path
    constraint; a missing/ineffective guard leaves `caller` entirely
    unconstrained. So a SELFDESTRUCT on a `caller`-unconstrained path is the
    unprotected destruction.

    This is deliberately distinct from the two neighbouring SELFDESTRUCT-aware
    detectors:
      * ReachableSelfdestructDetector (`reachable_selfdestruct`) fires on **any**
        reachable SELFDESTRUCT — including one perfectly gated behind
        `require(msg.sender == owner)`. That is the "is this destructible at
        all?" question; SWC-106 is the narrower "can an *unauthorised* caller
        destroy it?" question, and a triage team wants to band and suppress the
        two independently. A correctly owner-gated `kill()` is a true
        `reachable_selfdestruct` but is **not** SWC-106, and this detector stays
        silent on it.
      * AccessControlEscalationDetector (`access_control_escalation`) also flags
        an unguarded SELFDESTRUCT, but bundles it into a broad ownership /
        privilege-escalation category alongside `owner = msg.sender` writes and
        unguarded DELEGATECALL. SWC-106 is a named registry entry with its own
        remediation ("guard the selfdestruct"), so it reports under its own
        `unprotected_selfdestruct` category / SWC-106 title for clean,
        per-bug-class triage — exactly the precedent set when SWC-105
        (unprotected ether withdrawal) was carved out as its own detector even
        though access-control already overlapped the value-forwarding-CALL sink.

    A per-detector flagged-pc set reports each unprotected SELFDESTRUCT site once
    across paths.

    [Worker decision: the discriminating signal is "SELFDESTRUCT on a
    caller-unconstrained path", reusing the `_guarded_by_caller` constraint walk
    that AccessControlEscalation, tx.origin, and SWC-105 ether-withdrawal already
    use for `caller` — no engine change, no new dependency, no new VM symbol or
    MachineState field. The two existing SELFDESTRUCT detectors are individually
    insufficient for SWC-106: `reachable_selfdestruct` flags every reachable
    destruction (it would mark a correctly owner-gated `kill()` as a finding,
    over-reporting the SWC-106 surface), and `access_control_escalation` folds
    the unguarded case into a broad escalation category that a triage team cannot
    band or suppress as SWC-106 specifically. Carving out a dedicated
    caller-guard-keyed detector mirrors the SWC-105 carve-out exactly: a named
    SWC entry deserves its own category / title even when a broader detector
    overlaps. The detector keys on the missing caller guard rather than the
    SELFDESTRUCT's target operand (which an EtherLeak-style "symbolic recipient"
    test would key on) because the SWC-106 property is the *absent access
    control*, not the recipient — a `kill()` that destructs to a hard-coded
    address is still an unprotected drain.]
    """

    category = "unprotected_selfdestruct"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "SELFDESTRUCT":
            return
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


class PrevrandaoRandomnessDetector(DetectorHook):
    """Detects control flow that depends on `block.prevrandao` /
    `block.difficulty` used as a randomness source (SWC-120, "Weak Sources of
    Randomness from Chain Attributes").

    `block.prevrandao` (the post-Merge name for the `DIFFICULTY` opcode, 0x44;
    `block.difficulty` pre-Merge) is the single most-reached-for on-chain "random"
    number after the Merge: lotteries, raffles, NFT-mint orderings, coin-flip
    games, and airdrop selectors gate a winner / payout on it. It is **not** a
    secure source of entropy. The value is supplied by the block proposer
    (the validator who assembles the block contributes the RANDAO reveal), and —
    more cheaply — any attacker calling in the *same* transaction reads the exact
    same `block.prevrandao` the victim contract uses, so they can compute the
    "random" result in advance and only enter when they win. A contract that
    *branches control flow* on `block.prevrandao` is therefore making a security
    decision an attacker can predict or grind. This is the SWC registry's named
    SWC-120; the safe primitives are a commit-reveal scheme or an external
    randomness oracle (e.g. a VRF), never a raw chain attribute. Reading
    prevrandao for a non-control-flow purpose (storing it, emitting it, returning
    it) is harmless; the bug is specifically *deciding control flow* on it.

    Detection signal — the contract **branched control flow on** prevrandao:
    a path constraint references the `prevrandao` leaf. oracle's VM mints a stable
    `prevrandao` symbol for the DIFFICULTY/PREVRANDAO opcode, and an
    `if (block.prevrandao % N == ...)` / `require(block.prevrandao ...)` guard
    compiles to a comparison feeding a JUMPI, whose taken/not-taken constraint
    carries the `prevrandao` term. A contract that merely reads prevrandao for a
    non-control-flow purpose never produces such a constraint, so this keys on the
    *decision* use specifically rather than any DIFFICULTY execution.

    The detector fires once per path. The prevrandao-guard constraint persists for
    the remainder of the path, so a per-path `prevrandao_flagged` latch (carried
    on the MachineState across forks) reports each prevrandao-dependent path
    exactly once instead of re-emitting on every subsequent instruction. A
    per-detector set of already-flagged pcs additionally dedupes the same guard
    reached via different paths.

    This is deliberately distinct from its sibling SWC-120 detector
    BlockhashRandomnessDetector, which keys on the `blockhash_<pc>` symbol family
    (the BLOCKHASH opcode, 0x40). `block.prevrandao` and `blockhash(n)` are
    different chain attributes — the former is the beacon-chain RANDAO mix exposed
    on the `DIFFICULTY` opcode, the latter the hash of a recent block — minted
    from different opcodes into different symbol families, and a contract can
    misuse one without the other. Keeping the two detectors separate keeps each
    keyed to one opcode and lets a triage team see exactly which chain attribute a
    contract gambled on. It is also distinct from the SWC-116 timestamp detector
    (`block.timestamp` / `block.number`, a *time* proxy) and the SWC-114
    transaction-order detector (`tx.gasprice`, an *ordering* lever).

    [Worker decision: keying on the stable `prevrandao` symbol appearing in the
    path constraints (control flow branched on prevrandao) mirrors how
    BlockhashRandomnessDetector keys on the `blockhash` family,
    TransactionOrderDependenceDetector keys on `gasprice`, and
    StrictBalanceEqualityDetector keys on the `balance` family, reusing the same
    prefix AST-walk (`_ast_mentions_prefix`). The VM's `_op_difficulty` was
    previously a generic env-pusher minting an unflagged "difficulty" symbol with
    no detector observing it, so prevrandao-as-randomness — a named, common,
    post-Merge bug class — was an uncovered surface even though every other weak
    chain-attribute (blockhash, timestamp, gasprice) had a dedicated detector.
    Renaming the minted symbol to `prevrandao` and setting a `prevrandao_loaded`
    latch (the same shape as `blockhash_loaded` / `gasprice_loaded`) closes that
    gap with zero engine refactor and no new dependency. The replay validator's
    DIFFICULTY env-pusher is renamed in lockstep so a concrete-input replay
    materialises the same symbol.]
    """

    category = "prevrandao_randomness"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        # Only meaningful once prevrandao has been read on this path. Cheap gate
        # before the (more expensive) constraint AST walk.
        if not state.prevrandao_loaded:
            return
        if state.prevrandao_flagged:
            return  # this path's prevrandao guard has already been reported
        if not state.constraints:
            return
        # The guard site is the first instruction whose path constraints branch
        # on prevrandao (control flow gated on a predictable/grindable chain
        # attribute — the unsafe weak-randomness pattern).
        if any(_ast_mentions_prefix(c, "prevrandao") for c in state.constraints):
            state.prevrandao_flagged = True
            if instruction.pc not in self._flagged_pcs:
                self._flagged_pcs.add(instruction.pc)
                self.findings.append(
                    _finding(self.category, state, instruction, vm)
                )


class ArbitraryJumpDetector(DetectorHook):
    """Detects a `JUMP` / `JUMPI` whose destination is derived from calldata
    (SWC-127, "Arbitrary Jump with Function Type Variable").

    The EVM's control flow is, in well-formed compiler output, entirely
    compiler-determined: every `JUMP`/`JUMPI` target is a constant the compiler
    computed, and the only legal landing sites are `JUMPDEST` opcodes. A
    `function` type variable, however, holds an internal jump destination (a code
    offset) as an ordinary 256-bit value; if that value can be influenced by
    untrusted input — overwritten via inline assembly, read from an
    attacker-writable storage slot, or, as in the canonical case, computed from a
    calldata argument — then invoking it lets the attacker **redirect execution
    to any JUMPDEST in the bytecode**. That is the SWC registry's named SWC-127,
    "Arbitrary Jump with Function Type Variable": control flow is steered by the
    attacker, bypassing access checks, re-entering privileged code paths, or
    skipping validation. It is the EVM analogue of a corrupted function pointer.

    Detection signal — the destination operand of a `JUMP` / `JUMPI` is
    **symbolic and derived from calldata** (attacker-controllable). The detector
    hook runs *before* the instruction executes, so the destination is still the
    top of the stack: `stack[-1]` for both `JUMP` (`JUMP dest`) and `JUMPI`
    (`JUMPI dest, cond`). A *concrete* destination — the overwhelmingly common
    case of ordinary compiler-generated control flow (function dispatch, loop
    back-edges, internal calls to a fixed offset) — is **not** flagged: it is not
    attacker-controllable. Only a destination that the engine cannot resolve to a
    constant *and* that is influenced by calldata is reported.

    This is significant for oracle specifically because the VM **halts** a `JUMP`
    whose destination it cannot resolve to a concrete `JUMPDEST` (see
    `_op_jump`): without this detector the most dangerous case — an
    attacker-steerable jump — is silently pruned as an unexplorable path rather
    than surfaced as a bug. The detector inspects the operand *before* that
    pruning, so the arbitrary jump is reported instead of disappearing.

    A per-detector set of already-flagged pcs dedupes the same jump site reached
    via multiple paths.

    [Worker decision: SWC-127's canonical trigger is a function-type variable
    whose code-offset value is attacker-influenced. The sound, low-false-positive,
    model-robust bytecode signal is therefore "the JUMP/JUMPI destination is
    derived from calldata" — exactly the DelegatecallUntrustedDetector's
    untrusted-target test (`_mentions_calldata` over the target operand), applied
    to the jump destination instead of the delegatecall target. Requiring the
    destination to be *calldata-derived* (not merely symbolic) avoids
    false-positives on a destination that collapses to a fresh symbol for benign
    reasons (e.g. a value loaded from oracle's all-zero initial storage) while
    still catching every attacker-controllable jump — the same reasoning the
    delegatecall detector documents. Keyed on the operand at inspect time so the
    finding is recorded before the VM prunes the unresolvable-destination path.
    No engine refactor, no new dependency.]
    """

    category = "arbitrary_jump"

    _OPS = ("JUMP", "JUMPI")

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic not in self._OPS:
            return
        # destination is the top of stack for both JUMP (dest) and JUMPI
        # (dest, cond); the hook runs before the operand is popped.
        if not state.stack:
            return
        dest = state.stack[-1]
        if _is_concrete(dest):
            return  # ordinary compiler-generated control flow — trusted target
        if not _mentions_calldata(dest, vm):
            return  # symbolic but not attacker-controllable — not SWC-127
        if instruction.pc in self._flagged_pcs:
            return
        self._flagged_pcs.add(instruction.pc)
        self.findings.append(_finding(self.category, state, instruction, vm))


class WriteArbitraryStorageDetector(DetectorHook):
    """Detects an `SSTORE` whose **storage key is derived from calldata**
    (SWC-124, "Write to Arbitrary Storage Location").

    The EVM addresses contract storage by 256-bit keys. In well-formed
    compiler output every `SSTORE` key is either a compile-time constant (a
    top-level state variable's slot, fixed at compile time) or a
    `keccak256`-derived word (a `mapping(...)` / dynamic-array element's slot,
    whose preimage is compiler-controlled). An attacker cannot steer those
    keys: they are pinned by the source. Inline-assembly `sstore(key, val)`
    with a *calldata-supplied* `key`, however — or any code path that loads a
    raw storage slot index from calldata and stores through it — lets an
    attacker write to **any** storage slot: overwriting `owner`, upgrading the
    contract to a controlled implementation, or corrupting state any other
    state variable depends on. That is the SWC registry's named SWC-124,
    "Write to Arbitrary Storage Location": the attacker steers the storage
    *key*, and a single transaction can rewrite arbitrary contract state.

    Detection signal — the SSTORE key operand is **symbolic and derived from
    calldata** (attacker-controllable). The detector hook runs *before* the
    instruction executes, so the key is the top of the stack: `stack[-1]` for
    `SSTORE key, value` (the VM's `_op_sstore` pops `[key, value]`). A
    *concrete* key — the overwhelmingly common case of ordinary compiler-
    generated storage layout (a top-level state variable's fixed slot) — is
    **not** flagged. A *symbolic-but-not-calldata-derived* key — the typical
    `mapping(...)` access whose slot is `keccak256(key . slot)`, symbolic but
    compiler-controlled — is likewise **not** flagged, exactly the
    discrimination the SWC-127 `ArbitraryJumpDetector` and the SWC-112
    `DelegatecallUntrustedDetector` apply to their target operands.

    This is deliberately distinct from `StorageWriteDetector` (category
    `arbitrary_storage_write`), which flags *any* symbolic SSTORE key
    including the routine `keccak256`-derived mapping slot. SWC-124's named
    bug is the narrower, higher-severity case of an attacker-steered key, so a
    dedicated SWC-aligned detector lets a triage team triage one bug class
    per finding — exactly the precedent set by `unprotected_selfdestruct`
    (SWC-106) sitting alongside the broader `reachable_selfdestruct`. A
    per-detector flagged-pc set reports each SSTORE site once across paths.

    [Worker decision: SWC-124's canonical trigger is an SSTORE whose key the
    attacker controls. The sound, low-false-positive, model-robust bytecode
    signal is therefore "the SSTORE key is derived from calldata" — the
    DelegatecallUntrustedDetector's untrusted-target test
    (`_mentions_calldata` over the key operand), applied to the storage write
    key. Requiring the key to be *calldata-derived* (not merely symbolic)
    avoids the false-positive a strict "symbolic key" rule would emit on
    every mapping access (whose slot is the symbolic `keccak256(...)` of a
    compiler-controlled preimage). Keyed on the operand at inspect time so
    the finding is recorded before any subsequent state mutation. No engine
    refactor, no new dependency.]
    """

    category = "write_arbitrary_storage"

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic != "SSTORE":
            return
        # SSTORE pops [key, value]; the hook runs before the pop, so the key
        # is still on top of the stack.
        if len(state.stack) < 2:
            return
        key = state.stack[-1]
        if _is_concrete(key):
            return  # ordinary state-variable slot — compiler-controlled
        if not _mentions_calldata(key, vm):
            return  # symbolic but not attacker-controllable (e.g. keccak slot)
        if instruction.pc in self._flagged_pcs:
            return
        self._flagged_pcs.add(instruction.pc)
        self.findings.append(_finding(self.category, state, instruction, vm))


# Precompile address of ECRECOVER (signature recovery), per the Yellow Paper.
_ECRECOVER_ADDR = 1

# Opcode mnemonic for CHAINID (EIP-1344, 0x46), Solidity's `block.chainid`.
_CHAINID_MNEMONIC = "CHAINID"


class SignatureReplayDetector(DetectorHook):
    """Detects cross-chain signature replay (SWC-121, "Missing Protection
    against Signature Replay Attacks").

    The classic SWC-121 bug is a contract that authenticates an action via
    `ecrecover(...)` over a payload that does **not** bind the signature to
    this deploy chain. Without a chain-identifier in the signed hash a
    well-formed signature is valid bit-for-bit on every chain the contract is
    deployed on, so an attacker can lift a signature off one chain and replay
    it on another (Ethereum mainnet → a fork chain, an L1 → an L2 mirror, or
    any post-fork wallet → its pre-fork twin — the canonical post-DAO-fork
    drain class). EIP-155 + EIP-1344 introduced `CHAINID` (opcode 0x46,
    Solidity's `block.chainid`) for exactly this remediation: include it in
    the signed payload and the signature only verifies on the chain that
    produced it.

    Detection signal — a bytecode-level conjunction:

      1. The contract REACHES (executes on at least one path) a low-level call
         opcode (`STATICCALL` is the Solidity-emitted form; `CALL` covers the
         pre-Byzantium pattern) whose target address is the **concrete value
         `0x0000...0001`** — the ECRECOVER precompile address. Solidity
         emits `ecrecover(...)` as `staticcall(gas, 1, in, insz, out, outsz)`
         with the `1` as a `PUSH1 0x01` literal, so the target is reliably a
         concrete BitVec at inspect time.

      2. AND the contract's disassembly contains **no `CHAINID` opcode
         anywhere** — so the contract cannot possibly bind the signed payload
         to its deploy chain.

    A `CHAINID` *anywhere* in the bytecode is enough to acquit the contract:
    even if a specific path does not happen to read it, the contract has the
    capacity to bind chain context (e.g. an `__INIT_DOMAIN_SEPARATOR()` that
    runs once and caches a chain-bound domain separator in storage compiles
    to a single CHAINID at deploy time and an SLOAD per call). Conversely,
    the *absence* of CHAINID is a hard impossibility result: a contract with
    zero CHAINID opcodes in its bytecode demonstrably cannot incorporate the
    chain id into any signed payload — a structural, model-robust signal. This
    keeps the false-positive rate low without modelling ECRECOVER's
    precompile semantics, the contract's hash construction, or the
    cross-call data-flow from the signed bytes into the call buffer.

    A `STATICCALL` / `CALL` to a concrete address other than 1 — the
    overwhelmingly common case of an external contract call — is not flagged,
    and a `STATICCALL` whose target is symbolic (so cannot be statically
    identified as ECRECOVER) is also not flagged. A contract that never calls
    ECRECOVER produces no finding regardless of whether it reads CHAINID.

    The detector caches the bytecode-level CHAINID presence on the `vm` once
    (it cannot change across paths) and dedupes per ECRECOVER call site
    (one finding per pc across all paths). No engine refactor, no new
    dependency. Reuses the concrete-target inspection the
    `DelegatecallUntrustedDetector` (SWC-112) applies to its delegatecall
    target, applied here to the STATICCALL/CALL target instead, with the
    direction inverted: SWC-112 flags an attacker-CONTROLLED target,
    SWC-121 flags a known-precompile target alongside an absent chain bind.

    This is deliberately distinct from the SWC-114 transaction-order
    detector (`tx.gasprice`-gated ordering) and the SWC-117 signature-
    malleability class (`s`-value bounds): SWC-121's bug is the *absent
    chain bind*, witnessed structurally in the bytecode, with its own
    remediation (include `block.chainid` in the signed payload, or use
    EIP-712 with a chain-bound domain separator).

    [Worker decision: the discriminator is a bytecode-level static signal
    rather than a path-constraint signal because the bug is a *structural*
    impossibility — the contract demonstrably cannot bind the signed payload
    to its chain — and a constraint-walk over the ecrecover output would
    require modelling the precompile's return (the recovered address) as it
    flows from memory back into a comparison, which oracle's coarse memory
    model does not track precisely. The "zero CHAINID opcodes in the
    bytecode" signal is sound on the absence side (no opcode means no chain
    bind is possible) and conservative on the presence side (a CHAINID
    opcode does not guarantee correct use, but it removes the impossibility
    proof, which is the threshold for a high-confidence SWC-121 finding).
    This mirrors the WriteArbitraryStorageDetector's concrete/symbolic
    discrimination — both ride the cheap, model-robust signal available
    without engine changes.]
    """

    category = "signature_replay"

    # STATICCALL is the Solidity-emitted form for `ecrecover(...)` since the
    # Byzantium fork; CALL is included for pre-Byzantium / hand-rolled
    # assembly. DELEGATECALL/CALLCODE cannot reach a precompile usefully in
    # the Solidity-source sense and are intentionally out of scope.
    _OPS = ("STATICCALL", "CALL")

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic not in self._OPS:
            return
        # Stack layout (top→):
        #   STATICCALL: gas, addr, argsOff, argsLen, retOff, retLen
        #   CALL:       gas, addr, value, argsOff, argsLen, retOff, retLen
        # In both cases addr = stack[-2].
        if len(state.stack) < 2:
            return
        target_val = _concrete_val(state.stack[-2])
        if target_val != _ECRECOVER_ADDR:
            return  # symbolic target or some non-precompile address
        if _has_chainid_opcode(vm):
            return  # bytecode can bind a signature to its chain
        if instruction.pc in self._flagged_pcs:
            return
        self._flagged_pcs.add(instruction.pc)
        self.findings.append(_finding(self.category, state, instruction, vm))


# half of the secp256k1 curve order — the upper bound on a non-malleable
# signature `s` value. Any contract that rejects malleable signatures must
# compare `s` against this exact 256-bit constant (EIP-2 / SEC 1 §4.1.4).
# OpenZeppelin's ECDSA library, Solady, and Solidity's own assembly all
# materialise the bound as a `PUSH32 0x7FFF...20A0` literal in the runtime
# bytecode. Its *absence* from the disassembly is a structural impossibility
# proof that no malleability bound check exists in the contract.
_SECP256K1_HALF_N = (
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
)


# The EIP-150 / `transfer` / `send` gas stipend, 2300, materialised as a
# `PUSH2 0x08FC` immediate by solc immediately before the call's setup
# arithmetic. Solidity emits the literal verbatim: `transfer` lowers to
# `call(2300, to, value, 0, 0, 0, 0)` and `send` lowers to a sibling form,
# both with the 2300 as a PUSH2 literal rather than as a runtime `GAS`
# opcode. Detecting the literal next to the call is the SWC-134 signature.
_TRANSFER_GAS_STIPEND = 0x08FC  # 2300 decimal


# How far back from a CALL site we look for the hardcoded-2300 PUSH2. solc's
# `transfer` lowering interleaves a few stack/memory ops between the literal
# and the CALL (a SUB for the value/balance check, the memory-region setup,
# the DUPs that hoist the gas literal to the top of stack at CALL time);
# 24 instructions amply covers every solc 0.4-0.8 lowering I have seen
# without straying into an unrelated earlier function. The window matters
# because the literal is NOT the immediate predecessor: it is pushed early
# and then DUPed into position. The window IS NOT permitted to also
# contain a `GAS` opcode — if `GAS` shows up the gas operand is "forward
# all remaining gas", which is the safe pattern and not SWC-134.
_HARDCODED_GAS_WINDOW = 24


class HardcodedGasCallDetector(DetectorHook):
    """Detects a message call with a hardcoded gas amount (SWC-134, "Message
    call with hardcoded gas amount").

    Solidity's `address.transfer(x)` and `address.send(x)` lower to a
    low-level `CALL` whose gas operand is the fixed 2300-gas EIP-150
    stipend — emitted by solc as a `PUSH2 0x08FC` immediate immediately
    before the call's setup arithmetic. Originally the 2300 stipend was
    sized to cover a "log + nothing else" recipient fallback; post-Istanbul
    (EIP-1884, Dec 2019) the gas cost of several common opcodes (SLOAD,
    BALANCE, EXTCODEHASH) increased, and 2300 gas is no longer guaranteed
    to be enough for *any* non-trivial recipient fallback to complete. A
    contract that uses `transfer` to pay an arbitrary recipient — a proxy,
    a multisig, an account-abstraction wallet, a Gnosis Safe — can revert
    on perfectly innocent destinations, permanently bricking the pay
    function for any address the original author did not anticipate.

    The canonical fix is `(bool ok,) = to.call{value: x}(""); require(ok)`,
    which forwards all remaining gas. This is the form documented by
    OpenZeppelin's `Address.sendValue`, by Consensys Diligence, by
    Solidity's own docs (since 0.6.0), and by the OWASP Smart Contract Top
    10. SWC-134 is the named entry in the SWC registry.

    Detection signal — a bytecode-level structural conjunction (mirrors the
    SWC-117 / SWC-121 detectors' structural-impossibility approach,
    inverted: here the bytecode CONTAINS the bug-witnessing literal rather
    than ABSENT the fix-witnessing literal):

      1. A `CALL` or `CALLCODE` instruction is REACHED on some path (the
         standard inspect-hook signal — DELEGATECALL and STATICCALL cannot
         forward value, so the `transfer`/`send` form does not apply to
         them and they are intentionally out of scope).

      2. AND in the disassembly's preceding window (the last 24
         instructions before the CALL) there is a `PUSH2 0x08FC` immediate
         — the EIP-150 2300-gas stipend literal — AND no `GAS` opcode
         appears anywhere in that same window.

    The `GAS`-absence half of the conjunction is what discriminates the
    SWC-134 pattern from the safe `address.call{value: x}("")` pattern.
    The safe form emits a `GAS` opcode immediately before the CALL
    (forwarding all remaining gas) and emits no `PUSH2 0x08FC` at all;
    the unsafe `transfer` form emits the `PUSH2 0x08FC` and emits no
    `GAS` in the window. A `PUSH2 0x08FC` that happens to appear in
    bytecode for an unrelated reason (e.g. the literal `2300` used as a
    constant elsewhere in the program) is harmless: the per-call-site
    window scopes the match to the few instructions immediately preceding
    each CALL, so an unrelated 2300 literal somewhere else in the bytecode
    does not false-positive a normal call.

    The disassembly is scanned once and cached on the `vm` instance (the
    bytecode does not change across paths), and a per-detector flagged-pc
    set reports each hardcoded-gas call site at most once across the run.
    No engine refactor, no new dependency.

    This is deliberately distinct from the neighbouring call-aware
    detectors. The EtherLeak detector (`unconstrained_ether_transfer`)
    keys on the CALL's *recipient* being attacker-controlled; the
    Unprotected Ether Withdrawal detector (SWC-105) keys on a *missing
    caller guard* in front of a value-forwarding call; the Unchecked Call
    Return detector (SWC-104) keys on the call's *return word being
    discarded*; the DoS-with-failed-call detector (SWC-113) keys on the
    call being *loop-bound*. SWC-134 is the **hardcoded gas amount**
    surface — a structural property of the *gas operand*, orthogonal to
    every other call-related check. A `transfer`-using fixture can simul-
    taneously be perfectly access-controlled, called once not in a loop,
    pay only `msg.sender`, and have its return value irrelevant (revert
    on failure) — yet still be SWC-134 vulnerable on a recipient with a
    non-trivial fallback.

    [Worker decision: the discriminator is a static disassembly window
    rather than a runtime-stack inspection of the gas operand because
    oracle's bounded symbolic execution does not reliably preserve the
    `2300` literal at the CALL site. solc's `transfer` lowering actually
    materialises the gas as `2300 * iszero(iszero(value))` so that a zero
    `value` call still completes — that arithmetic flows through MUL /
    ISZERO and z3 may or may not simplify it back to the integer 2300 at
    the inspect moment, depending on the symbolic shape of `value` on each
    path. The static window approach is independent of the symbolic shape:
    if the bytecode emits `PUSH2 0x08FC` next to a CALL with no `GAS`
    intervening, the contract is using a hardcoded 2300-gas stipend — a
    structural, model-robust signal that mirrors the proven approach
    SWC-117 / SWC-121 use for their own structural-impossibility checks.
    POST_V01.md had previously deferred SWC-131 (a sibling "restrictive
    gas" item) as "fragile (the 2300-gas literal rarely survives as a
    concrete operand in oracle's coarse model)" — the static-window read
    is exactly the model-independent reframing that lifts that deferral
    for the named SWC-134 surface.]
    """

    category = "hardcoded_gas_call"

    # Solidity emits `transfer` / `send` as a CALL (legacy `callcode` form
    # is also covered). DELEGATECALL / STATICCALL cannot forward value, so
    # the `transfer`/`send` source form does not lower to them — they are
    # intentionally out of scope.
    _OPS = ("CALL", "CALLCODE")

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic not in self._OPS:
            return
        if instruction.pc in self._flagged_pcs:
            return
        if not _call_has_hardcoded_gas(vm, instruction.pc):
            return
        self._flagged_pcs.add(instruction.pc)
        self.findings.append(_finding(self.category, state, instruction, vm))


def _call_has_hardcoded_gas(vm, call_pc: int) -> bool:
    """True if the CALL/CALLCODE at `call_pc` is preceded (within
    `_HARDCODED_GAS_WINDOW` instructions) by a `PUSH2 0x08FC` immediate
    AND no intervening `GAS` opcode — the structural signature of solc's
    `transfer`/`send` hardcoded-2300-gas-stipend lowering (SWC-134).

    Result is cached on the vm in a dict keyed by call pc. The bytecode
    does not change across paths so the per-pc decision amortises to O(1)
    across the run.
    """
    cache = getattr(vm, "_hardcoded_gas_cache", None)
    if cache is None:
        cache = {}
        vm._hardcoded_gas_cache = cache
    if call_pc in cache:
        return cache[call_pc]

    insts = vm.disasm.instructions
    # locate the call's index in the instruction list. `vm.disasm.by_pc` is
    # the pc->instruction map; we need the *index* into `insts` so we can
    # walk backwards over the preceding window. The instruction list is in
    # pc order, so a linear scan would also work but the by_pc dict makes
    # the lookup O(1) per call site.
    call_inst = vm.disasm.by_pc.get(call_pc)
    if call_inst is None:
        cache[call_pc] = False
        return False
    # find the index — instructions are ordered but pc gaps may exist after
    # PUSH-immediates, so we can't compute the index from pc directly.
    try:
        idx = insts.index(call_inst)
    except ValueError:  # defensive — should not happen
        cache[call_pc] = False
        return False

    has_stipend = False
    window_start = max(0, idx - _HARDCODED_GAS_WINDOW)
    for j in range(window_start, idx):
        inst = insts[j]
        if inst.mnemonic == "GAS":
            # the call is forwarding runtime gas — the safe pattern.
            cache[call_pc] = False
            return False
        if (
            inst.mnemonic == "PUSH2"
            and inst.operand == _TRANSFER_GAS_STIPEND
        ):
            has_stipend = True
    cache[call_pc] = has_stipend
    return has_stipend


class SignatureMalleabilityDetector(DetectorHook):
    """Detects missing signature-malleability protection (SWC-117, "Signature
    Malleability").

    An ECDSA signature over secp256k1 is a triple `(v, r, s)`. The curve is
    symmetric: for every valid `(v, r, s)` the negation `(v', r, n-s)` (with
    `v` flipped) is **also a valid signature for the same message and the
    same signer**. An attacker who has any valid signature can therefore mint
    a second, bit-different signature that ECRECOVER will accept just as
    readily — a problem for any contract that uses the signature bytes
    themselves as an identity (e.g. a `mapping(bytes32 => bool) usedSigs`
    nonce-set keyed on `keccak256(sig)`, or a deduplication check based on
    the raw `(v,r,s)` triple, or any external relayer / off-chain queue that
    treats sig bytes as a unique identifier). The canonical fix, codified by
    EIP-2 and standardised by OpenZeppelin's ECDSA library, is to constrain
    `s` to the lower half of the curve order: reject any signature whose
    `s > secp256k1n/2`. With that bound the malleated twin is uniquely
    represented and the dedup invariant holds.

    Detection signal — a bytecode-level conjunction (mirrors the SWC-121
    SignatureReplayDetector's structural impossibility approach):

      1. The contract REACHES a low-level call opcode (`STATICCALL` is the
         Solidity-emitted form since Byzantium; `CALL` covers pre-Byzantium
         / hand-rolled assembly) whose target address is the **concrete
         value `0x0000...0001`** — the ECRECOVER precompile address.
         Solidity emits `ecrecover(...)` as `staticcall(gas, 1, in, insz,
         out, outsz)` with the `1` as a `PUSH1 0x01` literal, so the target
         is reliably a concrete BitVec at inspect time.

      2. AND the contract's disassembly contains **no PUSH32 immediate
         equal to `secp256k1n/2`
         (`0x7FFF...5D576E7357A4501DDFE92F46681B20A0`)** anywhere — so the
         contract cannot possibly enforce the EIP-2 lower-`s`-half malleability
         bound.

    The constant `secp256k1n/2` is the unique mathematical bound for the
    malleability check; every well-formed implementation materialises it as
    a PUSH32 literal (or as a PUSH variant of fewer bytes that the
    disassembler still records the same integer operand for). The presence
    of the literal *anywhere* in the bytecode is enough to acquit the
    contract: even if a specific path does not happen to compare against
    it, the contract has the *capacity* to enforce the bound. The absence
    of the literal is a hard impossibility proof, sound on the absence
    side and conservative on the presence side — the same threshold the
    SWC-121 detector applies to CHAINID.

    A `STATICCALL` / `CALL` to a concrete address other than `1` — the
    overwhelmingly common case of an external contract call — is not
    flagged, and a `STATICCALL` whose target is symbolic (so cannot be
    statically identified as ECRECOVER) is also not flagged. A contract
    that never calls ECRECOVER produces no finding regardless of whether
    it materialises the bound. The check is silent on contracts that
    happen to PUSH `secp256k1n/2` for some unrelated reason, and on
    contracts that use an `s`-range check that does not key off the
    canonical EIP-2 bound — both are conservative trade-offs that
    preserve the impossibility-proof contract.

    The detector caches the bytecode-level bound presence on the `vm` once
    (the bytecode does not change across paths) and dedupes per ECRECOVER
    call site (one finding per pc across all paths). No engine refactor,
    no new dependency.

    Reuses the `SignatureReplayDetector`'s concrete-ECRECOVER-target test
    and structural-impossibility approach, applied to a different absent
    bytecode signal: SWC-121 keys on missing CHAINID (the chain-bind
    fix), SWC-117 keys on missing secp256k1n/2 (the malleability-bound
    fix). The two detectors fire on the same call-site sink (ECRECOVER)
    but for orthogonal bugs with orthogonal remediations — a contract can
    bind to the chain but still accept malleable signatures (so SWC-117
    fires but SWC-121 stays silent), and vice versa.

    [Worker decision: the discriminator is the bytecode-level absence of
    the EIP-2 bound constant rather than a path-constraint signal because
    the bug is a *structural* impossibility — the contract demonstrably
    cannot enforce the malleability bound if the canonical constant is
    not materialised anywhere in its runtime code — and a constraint-walk
    over the ecrecover output would require modelling the precompile's
    return value as it flows from memory into a subsequent comparison
    against `s`, which oracle's coarse memory model does not track
    precisely. The "zero PUSH32 0x7FFF...20A0 immediates" signal is sound
    on the absence side (no constant means no canonical bound check is
    possible) and conservative on the presence side (the constant being
    present does not guarantee correct use, but it removes the
    impossibility proof, which is the threshold for a high-confidence
    SWC-117 finding). This is the exact same impossibility-proof pattern
    that R31's SWC-121 detector pioneered — the only new machinery is a
    PUSH-immediate scan instead of an opcode-mnemonic scan, since the
    SWC-117 signal lives in PUSH data rather than in an opcode itself.]
    """

    category = "signature_malleability"

    # Same scope as the SWC-121 detector: STATICCALL is the Solidity-emitted
    # form for `ecrecover(...)` since Byzantium; CALL covers pre-Byzantium /
    # hand-rolled assembly. DELEGATECALL/CALLCODE cannot reach a precompile
    # usefully in the Solidity-source sense and are intentionally out of scope.
    _OPS = ("STATICCALL", "CALL")

    def __init__(self):
        super().__init__()
        self._flagged_pcs = set()

    def inspect(self, vm, state, instruction) -> None:
        if instruction.mnemonic not in self._OPS:
            return
        # Stack layout (top→):
        #   STATICCALL: gas, addr, argsOff, argsLen, retOff, retLen
        #   CALL:       gas, addr, value, argsOff, argsLen, retOff, retLen
        # In both cases addr = stack[-2].
        if len(state.stack) < 2:
            return
        target_val = _concrete_val(state.stack[-2])
        if target_val != _ECRECOVER_ADDR:
            return  # symbolic target or some non-precompile address
        if _has_secp256k1_half_n(vm):
            return  # bytecode can enforce the EIP-2 malleability bound
        if instruction.pc in self._flagged_pcs:
            return
        self._flagged_pcs.add(instruction.pc)
        self.findings.append(_finding(self.category, state, instruction, vm))


def _has_secp256k1_half_n(vm) -> bool:
    """True if the disassembled bytecode contains a PUSH-family immediate
    whose 256-bit value equals `secp256k1n/2` — the EIP-2 / SWC-117
    malleability bound.

    Cached on the vm instance — the bytecode does not change across paths,
    so a single linear scan amortises to O(1) across the run. A bytecode
    without this exact constant demonstrably cannot enforce the canonical
    lower-`s`-half malleability check, which is the SWC-117 impossibility
    signal.
    """
    cached = getattr(vm, "_secp_half_n_present", None)
    if cached is not None:
        return cached
    present = any(
        getattr(i, "operand", None) == _SECP256K1_HALF_N
        for i in vm.disasm.instructions
    )
    vm._secp_half_n_present = present
    return present


def _has_chainid_opcode(vm) -> bool:
    """True if the disassembled bytecode contains the CHAINID opcode anywhere.

    Cached on the vm instance — the bytecode does not change across paths,
    so a single linear scan amortises to O(1) across the run. A bytecode
    without CHAINID demonstrably cannot incorporate `block.chainid` into any
    signed payload, which is the SWC-121 impossibility signal.
    """
    cached = getattr(vm, "_chainid_present", None)
    if cached is not None:
        return cached
    present = any(
        i.mnemonic == _CHAINID_MNEMONIC for i in vm.disasm.instructions
    )
    vm._chainid_present = present
    return present


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
    "unprotected-selfdestruct": UnprotectedSelfdestructDetector,
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
    "arbitrary-jump": ArbitraryJumpDetector,
    "prevrandao-randomness": PrevrandaoRandomnessDetector,
    "write-arbitrary-storage": WriteArbitraryStorageDetector,
    "signature-replay": SignatureReplayDetector,
    "signature-malleability": SignatureMalleabilityDetector,
    "hardcoded-gas": HardcodedGasCallDetector,
}
