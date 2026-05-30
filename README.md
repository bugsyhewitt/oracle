# oracle

**mythril's symbolic-execution capability, made install-clean on modern Python.**

oracle symbolically executes EVM bytecode with the [Z3](https://github.com/Z3Prover/z3)
SMT solver to find the classes of vulnerabilities that only path exploration
can reach: reachable assertion violations, integer overflows and underflows, reachable
`SELFDESTRUCT`, unconstrained ether transfers, and arbitrary storage writes.

It is **not** another pattern-matching smart-contract scanner. oracle is
mythril's symbolic-execution engine — the part that explores paths and asks a
solver "is there an input that reaches this bug?" — repackaged so it installs
cleanly on a current Python and emits bug-bounty-ready output: for every
finding, the **EVM execution trace** to the bug and the **concrete trigger
input** Z3 produced.

oracle forks mythril's SMT-over-Z3 wrapper verbatim (with attribution — see
[`NOTICE`](NOTICE)) and ships its own clean, bounded symbolic-EVM engine and
detector framework on top of it.

---

## Requirements

- **Python 3.13** (exactly: `>=3.13,<3.14`).

### Why not Python 3.14 (yet)?

oracle's transitive dependency stack includes `coincurve`, which wraps
`libsecp256k1` via native bindings. `coincurve` has historically lagged new
CPython releases, and at the time of this v0.1 release it does not yet provide
working wheels/bindings for **Python 3.14**. Rather than ship a broken or
half-installable package, oracle **pins to Python 3.13** and declares
`requires-python = ">=3.13,<3.14"` in `pyproject.toml`.

If you try to install oracle on Python 3.14 you will get a clear, immediate
error from pip:

```
ERROR: Package 'oracle-symexec' requires a different Python: 3.14.x not in '<3.14,>=3.13'
```

Python 3.14 support is a **v0.2** item — it depends on the upstream
`coincurve` / `libsecp256k1` toolchain catching up. It is intentionally out of
scope for v0.1.

---

## Install

```bash
# create and activate a Python 3.13 virtualenv
python3.13 -m venv .venv
source .venv/bin/activate

# install oracle (editable, from a checkout)
pip install -e .
```

This installs the `oracle` command. `z3-solver` comes in automatically.
`py-solc-x` is also installed; it is only used when you analyse a `.sol`
source file and lets oracle fetch a `solc` binary on demand. **Analysing
bytecode directly needs no `solc` at all.**

---

## Usage

```
oracle --contract PATH
       --input-type {sol,bytecode}
       [--check {assertion,overflow,underflow,selfdestruct,unprotected-selfdestruct,ether-leak,storage-write,reentrancy,access-control,tx-origin,delegatecall,unchecked-call,dos-failed-call,timestamp,ether-withdrawal,gas-limit-dos,extcodesize-check,strict-balance,blockhash-randomness,tx-order,arbitrary-jump,prevrandao-randomness,write-arbitrary-storage,signature-replay,signature-malleability,all}]
       [--max-depth N]            # default 12
       [--sequence-depth N]       # default 1
       [--timeout SECONDS]        # default 30 (0 = no limit)
       [--validate]               # concretely replay each finding's trigger input
       [--format {json,h1md,sarif}]  # default json
       [--coverage PATH]          # write an LCOV instruction-coverage tracefile
       [--fail-on {none,low,medium,high}]  # default none (CI exit-code gate)
```

- `--contract` — path to a `.sol` source file **or** a `.bin` EVM bytecode blob.
- `--input-type` — `sol` to compile source, `bytecode` to analyse a blob directly.
- `--check` — which vulnerability class to look for (`all` runs every detector).
- `--max-depth` — maximum symbolic branch depth to explore (default `12`).
  Deeper bugs need a higher depth; shallow depths prune long paths.
- `--sequence-depth` — number of transactions to sequence for **stateful**
  exploration (default `1` = single-transaction analysis). See
  [Multi-transaction exploration](#multi-transaction-stateful-exploration).
- `--timeout` — per-query Z3 solver budget in **seconds** (default `30`). A
  single hard query on a constraint-dense contract can otherwise hang the run
  indefinitely. A query that exceeds the budget is **not dropped** — it is
  reported with `confidence: timeout` and no `trigger_input`, so the dense path
  surfaces for manual review instead of silently disappearing. Use `0` to
  disable the per-query limit.
- `--validate` — **concretely replay** each finding's `trigger_input` to confirm
  it is a real counterexample. oracle's symbolic engine reports the model Z3
  computed; `--validate` feeds that model back through a small, self-contained
  concrete EVM and checks whether the vulnerable opcode is actually reached. Each
  finding gains a `validation` verdict (`confirmed` — the opcode was reached;
  `unreachable` — concrete replay did **not** reach it, flagging a possible false
  positive; `skipped` — no replayable trigger, e.g. a `timeout` finding) plus a
  boolean `validated`. Findings are reported either way — this only annotates
  them. No extra dependency: the replay EVM is part of oracle. See
  [Counterexample validation](#counterexample-validation).
- `--format` — `json` (machine-readable), `h1md` (HackerOne-style markdown
  report), or `sarif` (SARIF v2.1.0 for GitHub code scanning / CI ingestion).
- `--coverage` — write an [LCOV](#instruction-coverage) instruction-coverage
  tracefile to `PATH`. This reports **how much of the contract the symbolic
  exploration actually reached**, so a `0 findings` run can be told apart from
  one that pruned most of the contract (depth cap, a halting opcode, reverts).
  A one-line summary (`coverage: 136/173 instructions (78.61%) -> PATH`) is also
  printed to stderr. Findings still go to stdout in the requested `--format`.
- `--fail-on` — make oracle a **CI build gate**. With `--fail-on {low,medium,high}`
  the process exits `1` if any finding's severity is at or above the given band
  (`low < medium < high`); otherwise it exits `0`. The default `none` never
  gates, preserving the historical "exit 0 on a successful run" behaviour.
  Findings are still written to stdout regardless. See
  [Exit codes](#exit-codes).

Every finding carries:

- `category`, `severity`
- `confidence` — `confirmed` (Z3 produced a satisfying model with a concrete
  trigger) or `timeout` (the query exceeded `--timeout`; reachability undecided).
- `trace` — the array of EVM ops leading to the vulnerable state
- `trigger_input` — the concrete symbolic transaction input Z3 found that
  triggers the bug (the function selector + decoded arguments, `callvalue`,
  `caller`). Empty `{}` for `timeout` findings.
- `validation`, `validated` — present only when `--validate` is passed; the
  concrete-replay verdict (see [Counterexample validation](#counterexample-validation)).

---

## Examples — one per check class

All examples use the deliberately-vulnerable fixtures shipped in
[`tests/fixtures/`](tests/fixtures).

### `assertion` — reachable assertion violation

```bash
oracle --contract tests/fixtures/assertion-violation.sol \
       --input-type sol --check assertion --format json
```

Finds the reachable `INVALID` (`category: "assertion_violation"`) and reports
the calldata argument (`0x42` == 66) that triggers it.

### `overflow` — integer overflow

```bash
oracle --contract tests/fixtures/integer-overflow.sol \
       --input-type sol --check overflow --format json
```

Finds the wrapping `ADD` inside an `unchecked` block
(`category: "integer_overflow"`) and the input that overflows it.

### `underflow` — integer underflow (SWC-101)

```bash
oracle --contract tests/fixtures/integer-underflow-vuln.sol \
       --input-type sol --check underflow --format json
```

Flags an unsigned **subtraction underflow** (`category: "integer_underflow"`,
severity `high`) — the underflow half of SWC-101 and the mirror of the `overflow`
check, which covers only `ADD`/`MUL`. EVM arithmetic is modular over 256 bits, so
`a - b` where `b > a` does not error — it wraps to `2**256 - (b - a)`, a near-
maximum value. A `balances[msg.sender] -= amount` that underflows silently mints
the caller an astronomical balance and drains the contract (the batchOverflow /
underflowed-accounting incident family); solc ≥ 0.8 reverts on underflow by
default, so this surfaces the `unchecked { ... }` blocks and pre-0.8 / assembly
contracts that opt out. `integer-underflow-vuln.sol`'s `withdraw(amount)` does
`balance - amount` in an `unchecked` block and is flagged, with the concrete
`amount` that triggers the wrap.

The detector records a candidate on a `SUB` whose operands involve symbolic
program data, carrying the underflow condition `b > a` as an extra constraint Z3
solves against the path: only a genuinely reachable underflow becomes a finding, so
a guarded subtraction — `integer-underflow-safe.sol`'s `safeSub(a, b)` with
`require(b <= a)`, the `SUB` still present — is proved unsatisfiable and **not**
flagged. The detector also screens out solc's ABI/memory *plumbing* subtractions
(the `calldatasize - 4` dispatcher length check and free-memory-pointer math over
oracle's coarse memory model), so it keys on a subtraction over genuine program
data rather than the compiler scaffolding every contract emits. This is distinct
from `overflow`: that detector flags the `ADD`/`MUL` wrap direction and the
`integer_overflow` category, this one the `SUB` underflow direction and the
`integer_underflow` category.

### `selfdestruct` — reachable SELFDESTRUCT

```bash
oracle --contract tests/fixtures/reachable-selfdestruct.sol \
       --input-type sol --check selfdestruct --format json
```

Finds the unguarded `SELFDESTRUCT` (`category: "reachable_selfdestruct"`) that
any caller can reach.

### `unprotected-selfdestruct` — unprotected SELFDESTRUCT (SWC-106)

```bash
oracle --contract tests/fixtures/unprotected-selfdestruct-vuln.sol \
       --input-type sol --check unprotected-selfdestruct --format json
```

Flags a `SELFDESTRUCT` reached on a path with **no access-control guard**
(`category: "unprotected_selfdestruct"`, severity `high`). A public `kill()` /
`close()` / `destroy()` that runs `selfdestruct(target)` without a
`require(msg.sender == owner)` / `onlyOwner` gate lets *any* address destroy the
contract and sweep its entire balance — the canonical SWC-106 bug, the Parity
multisig wallet-library `kill()` incident that froze ~$280M of user funds.
`unprotected-selfdestruct-vuln.sol`'s `kill(target)` self-destructs with no owner
check and is flagged.

The discriminating signal is that the `SELFDESTRUCT` is reached on a path whose
accumulated constraints **never branch on the caller's identity**: a genuine
`require(msg.sender == owner)` guard compiles to a comparison on the symbolic
`caller` leaf feeding a JUMPI, so a guarded path carries `caller` in a
constraint; an unguarded path leaves it entirely free.

This is deliberately narrower than the `selfdestruct` check, which flags **any**
reachable `SELFDESTRUCT` — including one correctly gated behind
`require(msg.sender == owner)`. `selfdestruct` answers "is this destructible at
all?"; `unprotected-selfdestruct` answers "can an *unauthorised* caller destroy
it?", and it stays silent on a properly owner-gated `kill()`
(`unprotected-selfdestruct-safe.sol` is flagged by `selfdestruct` but **not** by
`unprotected-selfdestruct`). It also reports under its own SWC-106 category /
title rather than folding into the broad `access-control` escalation category, so
a triage team can band and suppress SWC-106 independently — the same carve-out as
SWC-105 (`ether-withdrawal`) versus `access-control`.

### `ether-leak` — unconstrained ether transfer

```bash
oracle --contract <yourcontract>.sol \
       --input-type sol --check ether-leak --format json
```

Flags a `CALL` that forwards value to an attacker-controllable recipient
without guarding access (`category: "unconstrained_ether_transfer"`).

### `storage-write` — arbitrary storage write

```bash
oracle --contract <yourcontract>.sol \
       --input-type sol --check storage-write --format json
```

Flags an `SSTORE` whose slot key is attacker-controllable
(`category: "arbitrary_storage_write"`).

### `reentrancy` — check-effects-interactions violation

```bash
oracle --contract tests/fixtures/reentrancy_vuln.sol \
       --input-type sol --check reentrancy --format json
```

Flags the classic withdraw-before-update bug (`category: "reentrancy"`): a
storage slot is `SLOAD`ed, an external `CALL`/`CALLCODE`/`DELEGATECALL` hands
control to a potentially re-entrant callee, and only *after* the call is that
same slot `SSTORE`d. The correct check-effects-interactions ordering
(`SSTORE` before the call, as in `reentrancy_safe.sol`) is **not** flagged.

### `access-control` — ownership / privilege escalation

```bash
oracle --contract tests/fixtures/access-control-vuln.sol \
       --input-type sol --check access-control --format json
```

Flags privileged operations that any address can reach because the owner/admin
gate is absent or ineffective (`category: "access_control_escalation"`). Two
shapes are caught:

- a **re-callable initializer / unprotected ownership transfer** — a storage
  write inside a function that read `msg.sender` but never bound a constraint on
  it (`owner = msg.sender` with no `require`), so anyone can drive the write and
  seize ownership. `access-control-vuln.sol`'s `initialize()` is exactly this;
- a **privileged sink** (`SELFDESTRUCT` / `DELEGATECALL` / `CALLCODE`) reachable
  on a path that never constrains `caller` — i.e. no ownership check at all.

The discriminating signal is the absence of a `caller`-binding guard on the
path to the sink: a genuine `require(msg.sender == owner)` shows up as a path
constraint that references the symbolic `caller`. A contract that sets its owner
once in the constructor and gates every privileged op behind that check
(`access-control-safe.sol`) is **not** flagged.

### `tx-origin` — tx.origin authentication (SWC-115)

```bash
oracle --contract tests/fixtures/tx-origin-vuln.sol \
       --input-type sol --check tx-origin --format json
```

Flags authorization based on `tx.origin`
(`category: "tx_origin_authentication"`). `tx.origin` is the externally-owned
account that **started** the transaction, not the immediate caller, so a
`require(tx.origin == owner)` guard is bypassable by a phishing-relay attack:
the owner is tricked into calling a malicious contract, which forwards the call
into the victim — `msg.sender` is the attacker's contract, but `tx.origin` is
still the owner, so the check passes. The safe primitive is `msg.sender`.

The discriminating signal is that control flow **branched on** `tx.origin`: an
`if`/`require` on `tx.origin` compiles to a comparison feeding a `JUMPI`, so a
path constraint references the symbolic `origin` value. A contract that
authenticates via `msg.sender` — or never reads `tx.origin` at all
(`tx-origin-safe.sol`) — is **not** flagged.

### `delegatecall` — delegatecall to untrusted callee (SWC-112)

```bash
oracle --contract tests/fixtures/delegatecall-vuln.sol \
       --input-type sol --check delegatecall --format json
```

Flags a `DELEGATECALL`/`CALLCODE` whose **target address is derived from
calldata** (`category: "delegatecall_untrusted_callee"`). `delegatecall` runs
the callee's code in **this** contract's storage and balance context, so if the
target is attacker-supplied the attacker can rewrite any storage slot (including
the owner slot) and drain the contract — the canonical Parity multisig wallet
bug. `delegatecall-vuln.sol`'s `forward(address target, ...)` passes a
calldata-supplied `target` straight into `delegatecall` and is flagged.

The discriminating signal is that the call **target operand** is
attacker-controllable, not merely that a `delegatecall` exists. A `delegatecall`
to a **hard-coded / immutable library address** (`delegatecall-safe.sol`) is a
compile-time constant, not attacker-controllable, and is **not** flagged — which
keeps the detector to the specific untrusted-callee bug rather than every
upgradeable-proxy pattern. (This is distinct from `access-control`, which flags
an *unguarded* `delegatecall` regardless of where the target comes from.)

### `unchecked-call` — unchecked call return value (SWC-104)

```bash
oracle --contract tests/fixtures/unchecked-call-vuln.sol \
       --input-type sol --check unchecked-call --format json
```

Flags a low-level call whose **boolean success result is discarded**
(`category: "unchecked_call_return"`, severity `medium`). An EVM call opcode
(`CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL`) does **not** revert when the
callee reverts — it pushes a success word and execution continues. A low-level
`addr.call(...)` / `addr.send(...)` whose result is ignored lets a failed
external call pass silently; the contract proceeds as though it succeeded — the
canonical "unchecked send" bug (the King-of-the-Ether class of incident).
`unchecked-call-vuln.sol`'s `pay()` makes a `to.call{value: 1}("")` and throws
the result away, and is flagged.

The discriminating signal is that the success word reaches a `POP` **without
ever having been branched on** (it appears in no path constraint). A
`require(ok)` / `if (!ok)` guarded call routes the word through a `JUMPI`, so the
result is checked — even though Solidity also cleans up the duplicated word with
a `POP` later — and a checked call (`unchecked-call-safe.sol`) is **not**
flagged.

### `dos-failed-call` — DoS with failed call / revert in loop (SWC-113)

```bash
oracle --contract tests/fixtures/dos-failed-call-vuln.sol \
       --input-type sol --check dos-failed-call --max-depth 24 --format json
```

Flags an external call (`CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL`) made
**inside a loop** (`category: "dos_failed_call"`, severity `medium`). A "push"
payout that `transfer`s/`send`s to every recipient in a loop is a denial-of-
service surface: an EVM external call hands control to the callee, and
`transfer`/`send` (or a `require`-checked low-level call) reverts the whole
transaction when the callee fails. A single recipient that cannot accept the
call — a contract with a reverting fallback — reverts the *entire* batch, so
**no** recipient is ever paid. One malicious or broken entry permanently bricks
the function for everyone (the classic auction-refund / airdrop DoS).
`dos-failed-call-vuln.sol`'s `distribute(address[] calldata)` `transfer`s in a
loop and is flagged.

The discriminating signal is that an external call op's program counter is
reached **more than once on a single path**: oracle's bounded executor unrolls
loops by revisiting the loop body, so a recurring call pc witnesses that the call
is loop-bound. (The vulnerable loop needs `--max-depth ≳ 18` to unroll past one
iteration.) A single, isolated call — the **pull-payment** design where each
account withdraws its own balance (`dos-failed-call-safe.sol`) — reaches its
call pc at most once per transaction and is **not** flagged.

### `timestamp` — block values as a proxy for time (SWC-116)

```bash
oracle --contract tests/fixtures/timestamp-dependence-vuln.sol \
       --input-type sol --check timestamp --format json
```

Flags control flow that **branches on a block value** (`block.timestamp` or
`block.number`) used as a proxy for time or randomness (`category:
"timestamp_dependence"`, severity `medium`). Both values are set by the block
proposer (miner/validator), who has discretion over them — a few seconds of
slack on the timestamp and full control over transaction ordering. A contract
that gates a payout, picks a winner, or enforces a deadline on a block value is
letting the proposer influence the outcome: the canonical timestamp-as-
randomness gambling bug and the deadline-manipulation class.
`timestamp-dependence-vuln.sol`'s `play()` gates a payout on `block.timestamp %
2 == 0` and is flagged.

The discriminating signal is that a path constraint references the symbolic
`timestamp` / `block_number` leaf — an `if (block.timestamp ...)` /
`require(block.number ...)` guard compiles to a comparison feeding a JUMPI, whose
branch condition carries the block-value term. A **non-control-flow** read — a
view getter that merely *returns* `block.timestamp` (`timestamp-dependence-
safe.sol`), or storing it for a log — never enters a JUMPI condition and is
**not** flagged. The safe primitive is a commit-reveal scheme or an external
randomness oracle, never a raw block value. (`BLOCKHASH` is intentionally out of
scope here: past block hashes are a distinct construct; SWC-116's named surface
is the time/number proxy.)

### `ether-withdrawal` — unprotected ether withdrawal (SWC-105)

```bash
oracle --contract tests/fixtures/ether-withdrawal-vuln.sol \
       --input-type sol --check ether-withdrawal --format json
```

Flags a value-forwarding call (`CALL` / `CALLCODE`) reached on a path with **no
access-control guard** (`category: "unprotected_ether_withdrawal"`, severity
`high`). A public `withdraw()` / `sweep()` / `claim()` that forwards the
contract's ether (`transfer`/`send`/a value-bearing low-level `call`) without a
`require(msg.sender == owner)` / `onlyOwner` gate lets *any* address drain the
contract — the canonical SWC-105 "anyone can empty the contract" bug (the
Parity-wallet class and a long tail of stuck-/stolen-funds incidents).
`ether-withdrawal-vuln.sol`'s `withdraw()` sends `address(this).balance` to
`msg.sender` with no owner check and is flagged.

The discriminating signal is that the value-forwarding call is reached on a path
whose accumulated constraints **never branch on the caller's identity**: a
genuine `require(msg.sender == owner)` guard compiles to a comparison on the
symbolic `caller` leaf feeding a JUMPI, so a guarded path carries `caller` in a
constraint; an unguarded path leaves it entirely free. This is distinct from
`ether-leak`, which flags a call whose *recipient* is attacker-controlled — SWC-105
fires even when the recipient is `msg.sender`, because the bug is the **absent
access control**, not the recipient. A withdrawal gated on `msg.sender`
(`ether-withdrawal-safe.sol`), and a pull-payment that pays only the caller's own
entitled balance (`dos-failed-call-safe.sol`), are **not** flagged. A provably
zero-value call (a pure data call) is also skipped — there is no ether to steal.
`DELEGATECALL` / `STATICCALL` cannot move the contract's own balance and are out
of scope.

### `gas-limit-dos` — DoS with block gas limit / unbounded loop (SWC-128)

```bash
oracle --contract tests/fixtures/gas-limit-dos-vuln.sol \
       --input-type sol --check gas-limit-dos --max-depth 24 --format json
```

Flags a loop whose body re-reads **contract storage** every iteration while its
trip count is not bounded by a constant (`category: "block_gas_limit_dos"`,
severity `medium`). Every EVM transaction can only consume up to the block gas
limit, so a function whose gas cost grows without bound — iterating an unbounded
storage array, an unchecked caller-supplied count, or a monotonically growing
collection while doing per-iteration storage work — eventually exceeds the limit
and can **never** be executed again, permanently bricking any funds or state it
gates. This is the classic unbounded-operation DoS (SWC-128, "DoS With Block Gas
Limit"): airdrops, dividend sweeps, and "process all pending" batch functions
over a collection that can grow. `gas-limit-dos-vuln.sol`'s `processN(n)` loops
`n` times (no upper bound) and reads + writes storage every iteration, so it is
flagged.

The discriminating signal is that an `SLOAD`'s program counter is reached **more
than once on a single path**: oracle's bounded executor unrolls loops by
revisiting the loop body, so a recurring SLOAD pc witnesses a loop that re-reads
contract state every iteration — the unbounded-operation surface. This is
distinct from `dos-failed-call` (SWC-113), which keys on a recurring *CALL* pc
(one reverting callee DoSing a batch); SWC-128 needs no external call at all, and
the `gas-limit-dos-vuln.sol` fixture (which makes no call) is flagged by
`gas-limit-dos` but **not** by `dos-failed-call`. A loop bounded by a fixed
constant / range-checked argument whose body does **not** re-read storage
(`gas-limit-dos-safe.sol`'s `sumN(n)` with `require(n <= 100)` and a local-only
accumulator) never recurs an SLOAD pc and is **not** flagged, and a single,
non-loop storage read reaches its SLOAD pc at most once per path and is likewise
clean.

### `extcodesize-check` — bypassable EXTCODESIZE caller-type check

```bash
oracle --contract tests/fixtures/extcodesize-guard.sol \
       --input-type sol --check extcodesize-check --format json
```

Flags control flow that **branches on an external account's code size**
(`extcodesize(addr)`, `category: "extcodesize_caller_check"`, severity
`medium`). A widespread, flawed access-control idiom restricts a function to
externally-owned accounts by checking `require(extcodesize(msg.sender) == 0)`
("no contracts allowed"), or the inverse `require(extcodesize(addr) > 0)` to
"prove" an address is a deployed contract. Both are bypassable: during a
contract's **constructor** its code is not yet on-chain, so `extcodesize`
returns 0 and an attacker simply calls from within their constructor — the
"EOA-only" guard passes for a contract. The mirror form is defeated by
not-yet-deployed CREATE2 addresses and self-destructed contracts, so a code-size
read can never be relied on for authorization. `extcodesize-guard.sol`'s
`destroy(target)` gates a `selfdestruct` behind `require(extcodesize(sender) ==
0)` and is flagged.

The discriminating signal is that a path constraint references an
`extcodesize_<pc>` leaf — an `if (extcodesize(x) ...)` / `require(extcodesize(x)
...)` guard compiles to a comparison feeding a JUMPI, whose condition carries
the code-size term. A contract that authenticates via `msg.sender` and never
reads a code size (`extcodesize-check-safe.sol`'s owner-gated `destroy()`)
produces no such constraint and is **not** flagged. The safe primitives are
explicit allow/deny lists, signature checks, or simply not distinguishing EOAs
from contracts at all.

### `strict-balance` — unexpected ether balance (SWC-132)

```bash
oracle --contract tests/fixtures/strict-balance-vuln.sol \
       --input-type sol --check strict-balance --format json
```

Flags control flow that **branches on an account balance**
(`address(this).balance` / `address(x).balance`, `category:
"strict_balance_equality"`, severity `medium`). A contract's ether balance is
not controlled solely by its own logic: any account can force ether in via
`selfdestruct(this)` or by pre-funding a CREATE2 address before deployment —
neither path runs the receive/fallback code. A contract that treats its raw
balance as a trustworthy invariant — the canonical `require(address(this).balance
== expected)` game / state-machine gate — is making an attacker-falsifiable
assumption (SWC-132, "Unexpected Ether Balance"): a few forced wei breaks the
invariant, bricking or skewing the contract. `strict-balance-vuln.sol`'s
`claim()` gates a payout behind `require(address(this).balance == target)` and
is flagged.

The discriminating signal is that a path constraint references a `balance`
(BALANCE) or `selfbalance` (SELFBALANCE) leaf — an `if (... .balance ...)` /
`require(... .balance ...)` guard compiles to a comparison feeding a JUMPI,
whose condition carries the balance term. A contract that merely *reads* a
balance for a non-control-flow purpose — forwarding it as a call value, the way
`ether-withdrawal-vuln.sol` does — never branches on it and is **not** flagged;
nor is a contract that gates on an internally-tracked deposit accumulator
(`strict-balance-safe.sol`'s `tracked`-gated `claim()`), which force-feeding
cannot influence. The safe design tracks deposits in a dedicated storage
variable and never compares against the raw `address(this).balance`.

### `blockhash-randomness` — weak randomness from chain attributes (SWC-120)

```bash
oracle --contract tests/fixtures/blockhash-randomness-vuln.sol \
       --input-type sol --check blockhash-randomness --max-depth 40 --format json
```

Flags control flow that **branches on a block hash** (`blockhash(n)`, `category:
"blockhash_randomness"`, severity `medium`). A block hash is a cheap, tempting
on-chain "random" source — lotteries, raffles, NFT-mint orderings, and games
reach for it to pick a winner or gate a payout — but it is **not** secure
entropy. The block proposer can influence which block is produced, and, more
cheaply, an attacker calling in the *same* transaction reads the exact same
`blockhash(n)` the contract uses, so they can compute the "random" outcome in
advance and only enter when they win (SWC-120, "Weak Sources of Randomness from
Chain Attributes"). `blockhash-randomness-vuln.sol`'s `play()` gates a payout on
`uint256(blockhash(blockNo)) % 2 == 0` and is flagged.

The discriminating signal is that a path constraint references a `blockhash_<pc>`
leaf — an `if (uint(blockhash(n)) ...)` guard compiles to a comparison feeding a
JUMPI, whose condition carries the block-hash term. A contract that merely
*reads* a block hash for a non-control-flow purpose — a view getter that
*returns* it, the way `blockhash-randomness-safe.sol`'s `hashOf()` does — never
branches on it and is **not** flagged. This is distinct from `timestamp`
(SWC-116, the time/number *proxy* surface): SWC-120 is the weak-*randomness*
construct, with its own remediation — a commit-reveal scheme or an external
randomness oracle (VRF), never a raw chain attribute. (This rotation also adds
the `BLOCKHASH` opcode handler the engine previously lacked, so paths through a
`blockhash(n)` call no longer halt at the opcode.)

### `tx-order` — transaction order dependence (SWC-114)

```bash
oracle --contract tests/fixtures/tx-order-vuln.sol \
       --input-type sol --check tx-order --max-depth 40 --format json
```

Flags control flow that **branches on `tx.gasprice`** (`category:
"transaction_order_dependence"`, severity `medium`). The order in which
transactions execute inside a block is chosen by the block proposer / searcher
(by fee), not by the contract, so a contract whose outcome depends on ordering is
exposed to front-running and sandwich attacks. The most direct on-chain signal of
that exposure is a contract that gates logic on `tx.gasprice` itself — a misguided
gas-price ceiling meant to deter front-running (`require(tx.gasprice <= max)`,
itself trivially satisfiable) or a gas-price-derived outcome. `tx.gasprice` is set
freely by the sender and is the exact lever that governs ordering, so gating on it
is a security decision driven by an attacker-controlled, ordering-determining value
(SWC-114, "Transaction Order Dependence"). `tx-order-vuln.sol`'s `claim()` gates a
reward on `tx.gasprice <= maxGasPrice` and is flagged.

The discriminating signal is that a path constraint references the `gasprice` leaf
— an `if (tx.gasprice ...)` guard compiles to a comparison feeding a JUMPI, whose
condition carries the gas-price term. A contract that merely *reads* the gas price
for a non-control-flow purpose — a view getter that *returns* it, the way
`tx-order-safe.sol`'s `currentGasPrice()` does — never branches on it and is
**not** flagged. This is distinct from `timestamp` (SWC-116, a proposer-chosen
*time* proxy) and `blockhash-randomness` (SWC-120, a *randomness* source):
SWC-114 is the *ordering* bug class, with its own remediation — commit-reveal
schemes, batch auctions, submarine sends, or slippage bounds, never logic that
trusts gas price or transaction order. (This rotation also adds a dedicated
`GASPRICE` opcode handler that records the read for the detector; the symbol name
is unchanged.)

### `arbitrary-jump` — arbitrary jump with function type variable (SWC-127)

```bash
oracle --contract tests/fixtures/arbitrary-jump-vuln.sol \
       --input-type sol --check arbitrary-jump --max-depth 40 --format json
```

Flags a `JUMP` / `JUMPI` whose **destination operand is derived from calldata**
(`category: "arbitrary_jump"`, severity `high`). In well-formed compiler output
every jump destination is a constant the compiler computed, and the only legal
landing sites are `JUMPDEST` opcodes. A `function` type variable, however, holds
an internal jump destination (a code offset) as an ordinary 256-bit value; if
that value is influenced by untrusted input — read from a calldata argument,
overwritten via inline assembly, or loaded from an attacker-writable slot — then
invoking it lets an attacker redirect execution to *any* `JUMPDEST` in the
bytecode, bypassing access checks or re-entering privileged code (SWC-127,
"Arbitrary Jump with Function Type Variable" — the EVM analogue of a corrupted
function pointer). `arbitrary-jump-vuln.sol`'s `run()` overwrites a function
pointer with a calldata-supplied value and invokes it, so the `JUMP` it lowers to
takes an attacker-controllable target, and is flagged.

The discriminating signal is that the jump destination is **symbolic and
calldata-derived** — the same untrusted-target test the `delegatecall` detector
(SWC-112) applies to its call target, here applied to the jump destination. A
*concrete* destination (ordinary compiler-generated control flow — function
dispatch, loop back-edges, internal calls to a fixed offset) is **not** flagged:
`arbitrary-jump-safe.sol`'s `sum()` emits many `JUMP`/`JUMPI` opcodes for its loop
and branches, all to fixed labels, and is clean — proving the detector keys on the
calldata-derived target, not the opcode. This is especially valuable for oracle
because the engine otherwise **halts** a jump whose destination it cannot resolve
to a concrete `JUMPDEST`, so without this detector the most dangerous case — an
attacker-steerable jump — would be silently pruned rather than surfaced; the
detector inspects the operand before that pruning.

### `prevrandao-randomness` — weak randomness from `block.prevrandao` (SWC-120)

```bash
oracle --contract tests/fixtures/prevrandao-randomness-vuln.sol \
       --input-type sol --check prevrandao-randomness --max-depth 40 --format json
```

Flags control flow that **branches on `block.prevrandao`** (the post-Merge name
for the `DIFFICULTY` opcode, 0x44; `block.difficulty` pre-Merge — `category:
"prevrandao_randomness"`, severity `medium`). `block.prevrandao` is the single
most-reached-for on-chain "random" number after the Merge: lotteries, raffles,
NFT-mint orderings, coin-flip games, and airdrop selectors gate a winner /
payout on it. It is **not** secure entropy — the block proposer contributes the
RANDAO reveal that produces the value, and an attacker calling in the *same*
transaction reads the same `block.prevrandao` the victim contract uses, so
they can compute the "random" outcome in advance and only enter when they win
(SWC-120, "Weak Sources of Randomness from Chain Attributes").
`prevrandao-randomness-vuln.sol`'s `play()` gates a payout on
`uint256(block.prevrandao) % 2 == 0` and is flagged.

The discriminating signal is that a path constraint references the stable
`prevrandao` leaf — an `if (block.prevrandao % N == ...)` guard compiles to a
comparison feeding a JUMPI, whose branch condition carries the prevrandao term.
A contract that merely *reads* prevrandao — `prevrandao-randomness-safe.sol`'s
`currentRandao()` returns it and `record()` stores it without branching — never
enters a JUMPI condition on it and is clean, proving the detector keys on the
value deciding control flow, not on the opcode. Deliberately distinct from
`blockhash-randomness` (also SWC-120, but the BLOCKHASH opcode and a
`blockhash_<pc>` symbol family — a different chain attribute with the same
remediation), `timestamp` (SWC-116, a *time* proxy), and `tx-order` (SWC-114, an
*ordering* lever): a triage team can band by which chain attribute a contract
gambled on. Safe primitives are a commit-reveal scheme or an external
randomness oracle (a VRF), never a raw chain attribute.

### `write-arbitrary-storage` — write to arbitrary storage location (SWC-124)

```bash
oracle --contract tests/fixtures/write-arbitrary-storage-vuln.sol \
       --input-type sol --check write-arbitrary-storage --max-depth 40 --format json
```

Flags an `SSTORE` whose **storage key is derived from calldata**
(`category: "write_arbitrary_storage"`, severity `high`). The EVM addresses
contract storage by 256-bit keys. In well-formed compiler output every `SSTORE`
key is either a compile-time constant (a top-level state variable's slot, fixed
by the compiler) or a `keccak256`-derived word (a `mapping(...)` / dynamic-array
element's slot, whose preimage is compiler-controlled). An attacker cannot steer
those keys. Inline-assembly `sstore(key, val)` with a calldata-supplied `key` —
or any path that loads a raw storage slot index from calldata and stores through
it — lets an attacker write to **any** storage slot: overwriting `owner`,
upgrading the contract to a controlled implementation, or corrupting state any
other state variable depends on (SWC-124, "Write to Arbitrary Storage
Location"). `write-arbitrary-storage-vuln.sol`'s `set(uint256 key, uint256 val)`
takes both the storage key and value from calldata and SSTOREs through them,
and is flagged.

The discriminating signal is that the SSTORE key is **symbolic and
calldata-derived** — the same untrusted-target test the `delegatecall` detector
(SWC-112) applies to its call target and the `arbitrary-jump` detector
(SWC-127) applies to its jump destination, here applied to the storage write
key. A *concrete* key (the overwhelmingly common case of an ordinary
state-variable's fixed slot) is **not** flagged, and a symbolic-but-not-
calldata-derived key (the typical `mapping(...)` access, whose slot is
`keccak256(key . slot)` — symbolic but compiler-controlled) is **not** flagged
either: `write-arbitrary-storage-safe.sol` SSTOREs to a constant slot
(`setValue`) and to mapping slots (`deposit` / `withdraw`'s
`balances[msg.sender]`), and is clean — proving the detector keys on a
calldata-derived key, not on the SSTORE opcode or on symbolic-ness alone.

Deliberately distinct from `storage-write` (`arbitrary_storage_write`, which
flags *any* symbolic SSTORE key including the routine keccak-derived mapping
slot): SWC-124's named bug is the narrower, higher-severity *attacker-steered*
case, so a dedicated SWC-aligned detector lets a triage team band one bug class
per finding — the precedent set by `unprotected-selfdestruct` (SWC-106) sitting
alongside the broader `selfdestruct` (`reachable_selfdestruct`) detector. Safe
designs never accept a storage *key* from untrusted input; if dynamic storage
addressing is genuinely needed, gate it behind a strict caller-bound access
check (`onlyOwner`) and a fixed allow-list of slot indices.

### `signature-replay` — cross-chain signature replay (SWC-121)

```bash
oracle --contract tests/fixtures/signature-replay-vuln.sol \
       --input-type sol --check signature-replay --max-depth 64 --format json
```

Flags a contract that uses `ecrecover(...)` to authenticate an action over a
payload that does **not** include `block.chainid` (`category:
"signature_replay"`, severity `high`). Without a chain-identifier in the
signed hash a well-formed signature is valid bit-for-bit on every chain the
contract is deployed on, so an attacker lifts a signature off one chain and
replays it on another (Ethereum mainnet → a fork chain, L1 → L2 mirror, or
any post-fork wallet → its pre-fork twin — the canonical post-DAO-fork drain
class, SWC-121, "Missing Protection against Signature Replay Attacks"). EIP-
155 + EIP-1344 introduced `CHAINID` (opcode `0x46`, Solidity's
`block.chainid`) for exactly this remediation: include it in the signed
payload and the signature only verifies on the chain that produced it.

The discriminating signal is a **bytecode-level conjunction**: the contract
reaches a `STATICCALL` (or `CALL`) whose concrete target address is `1` (the
ECRECOVER precompile) **and** the contract's disassembly contains no
`CHAINID` opcode anywhere. The absence of `CHAINID` is a hard impossibility
proof: a contract with zero `CHAINID` opcodes in its bytecode demonstrably
cannot incorporate the chain id into any signed payload. A `CHAINID`
*anywhere* in the bytecode is enough to acquit (even if a specific path does
not happen to read it, the contract has the *capacity* to bind chain
context, e.g. a cached domain separator computed once at deploy time).
`signature-replay-vuln.sol`'s `claim(...)` recovers a signer over
`keccak256(abi.encodePacked(recipient, amount, nonce))` and is flagged.
`signature-replay-safe.sol`'s `claim(...)` includes `block.chainid` in the
hash and is clean — proving the detector keys on the **absence** of
`CHAINID` alongside the `ecrecover`, not on the `ecrecover` call alone (the
STATICCALL to address `1` is still in the safe bytecode).

A `STATICCALL` / `CALL` to a concrete address other than `1` (the
overwhelmingly common case of an external contract call), and a
`STATICCALL` / `CALL` whose target is symbolic, are not flagged. A contract
that never calls `ECRECOVER` produces no finding regardless of whether it
reads `CHAINID`. Safe designs use EIP-712 with a chain-bound domain
separator, or otherwise bind `block.chainid` into the signed payload.

### `signature-malleability` — ECDSA signature malleability (SWC-117)

```bash
oracle --contract tests/fixtures/signature-malleability-vuln.sol \
       --input-type sol --check signature-malleability --max-depth 64 --format json
```

Flags a contract that authenticates via `ecrecover(...)` without enforcing
the EIP-2 `s <= secp256k1n / 2` malleability bound (`category:
"signature_malleability"`, severity `medium`). The EVM's `ecrecover`
precompile does **not** reject the high-`s` half of the secp256k1 curve, so
for every valid signature `(r, s, v)` there is a second, equally valid
signature `(r, n - s, v ^ 1)` that recovers the *same* signer over the
*same* message but is a different byte pattern. A contract that uses the
raw signature bytes as a uniqueness key — the canonical
`usedSignatures[keccak256(r, s, v)] = true` anti-replay pattern, and a long
tail of "nonce by signature" bugs — sees the malleable twin as a new
signature and lets the action through twice (SWC-117, "Signature
Malleability"). The safe primitive is OpenZeppelin's `ECDSA.recover`, which
emits the EIP-2 reference guard
`require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)`.
`signature-malleability-vuln.sol`'s `claim(...)` recovers a signer and keys
uniqueness off the sig bytes with no `s`-bound check, and is flagged.

The discriminating signal is a **bytecode-level conjunction** (the same
shape the SWC-121 `signature-replay` detector uses for CHAINID-absence,
applied to a different structural literal): the contract (1) reaches a
`STATICCALL` (or `CALL`) whose concrete target address is `1` (the
ECRECOVER precompile) **and** (2) the contract's disassembly contains **no
`PUSH32` of the secp256k1n / 2 constant
(`0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`)
anywhere**. The absence of that PUSH32 is a hard impossibility proof: a
contract that nowhere materialises the n / 2 literal demonstrably cannot
enforce `s <= n / 2` against an attacker-supplied `s`. A `PUSH32` of the
constant *anywhere* in the bytecode is enough to acquit (the contract has
the *capacity* to bind the bound, even if a specific path does not
exercise it). `signature-malleability-safe.sol`'s `claim(...)` enforces the
EIP-2 guard before the recover and is clean — proving the detector keys on
the **absence** of the n / 2 PUSH32 alongside the `ecrecover`, not on the
`ecrecover` call alone (the STATICCALL to address `1` is still in the safe
bytecode).

A `STATICCALL` / `CALL` to a concrete address other than `1` (the
overwhelmingly common case of an external contract call), and a
`STATICCALL` / `CALL` whose target is symbolic, are not flagged. A
contract that never calls `ECRECOVER` produces no finding regardless of
whether it pushes the n / 2 literal.

Deliberately distinct from `signature-replay` (SWC-121, the *absent chain
bind*): SWC-117 and SWC-121 are independently keyed bug classes, and the
same contract can be vulnerable to one, the other, both, or neither — a
triage team gets two distinct findings rather than a single conflated
"signature problem" alert. This mirrors the SWC-105 / SWC-106 carve-out
precedent (an unprotected ether withdrawal and an unprotected
SELFDESTRUCT each get their own SWC-aligned category even when the broader
access-control detector overlaps).

### bytecode input (no solc)

```bash
oracle --contract tests/fixtures/bytecode-selfdestruct.bin \
       --input-type bytecode --check selfdestruct --format h1md
```

### controlling depth

```bash
# a deep bug pruned at shallow depth ...
oracle --contract tests/fixtures/deep-assertion.sol \
       --input-type sol --check assertion --max-depth 4    # 0 findings
# ... found at the default depth
oracle --contract tests/fixtures/deep-assertion.sol \
       --input-type sol --check assertion --max-depth 12   # 1 finding
```

---

## Opcode coverage

oracle's symbolic-EVM engine implements the opcodes its detectors need to keep
a path **alive** all the way to a vulnerable sink. Unhandled opcodes stop a
path conservatively (sound-by-omission), so missing handlers manifest as
*missed* findings rather than crashes.

Beyond the stack/memory/storage/control-flow core, oracle models the full set
of EVM arithmetic and bit ops with **exact two's-complement semantics** —
including the signed and modular operations that earlier symbolic engines
often skip:

| Opcode | Handler | Notes |
|---|---|---|
| `SAR` | arithmetic right shift | sign bit replicated into the vacated high bits |
| `SDIV` / `SMOD` | signed division / modulo | div/mod by zero → `0` (EVM spec); `SMOD` follows the sign of the dividend |
| `ADDMOD` / `MULMOD` | `(a±b) % N` / `(a·b) % N` | computed in a wider intermediate so the `% N` is overflow-exact; `N == 0` → `0` |
| `SIGNEXTEND` | sign-extend byte `b` | the opcode solc emits for `int8`/`int16`/`int32` casts |
| `BYTE` | big-endian byte select | byte index `≥ 32` → `0` |

This matters for real Solidity: any contract that uses `int*` arithmetic emits
`SIGNEXTEND` / `SDIV` / `SMOD` / `SAR`, and a guard built on signed comparison
sits in front of the interesting code. With these handlers oracle explores
*through* the signed-arithmetic guard instead of halting at it — see
[`tests/fixtures/signed-arith-guard.sol`](tests/fixtures/signed-arith-guard.sol),
which gates a reachable `SELFDESTRUCT` behind exactly that pattern.

The block-attribute and transaction-context opcodes are likewise modelled so a
path survives through a guard built on them: `TIMESTAMP` / `NUMBER` feed the
`timestamp` detector (SWC-116), `BLOCKHASH` (`0x40`) feeds the
`blockhash-randomness` detector (SWC-120), and `GASPRICE` (`0x3A`) feeds the
`tx-order` detector (SWC-114). Each mints a fresh symbol the detectors recognise
in a branch constraint, so a contract that branches on `blockhash(n)` or
`tx.gasprice` no longer halts the path at the opcode.

---

## Multi-transaction (stateful) exploration

oracle v0.1 models a **single** transaction starting from fresh, all-zero
storage. Some vulnerabilities are only reachable *after* an earlier transaction
has mutated persistent storage — a guard like `require(initialized)` where the
flag is set by a separate `init()` call, an access-control escalation that needs
`init()` then `admin()`, or a price-manipulation path that needs a setup deposit
before the trigger. A single transaction from zero storage can never satisfy
those guards, so the bug stays invisible.

`--sequence-depth N` chains up to **N** symbolic transactions. Each later
transaction **resumes from a terminal storage state** of the previous one, with
a fresh, independent set of symbolic inputs (`calldata`, `caller`, `callvalue`,
…), and the path constraints of every transaction in the sequence are composed
before Z3 decides reachability. Transactions after the first use a `txN_`-prefixed
symbol namespace so they are never conflated with earlier ones.

```bash
# guarded SELFDESTRUCT: arm() must run before blow() can self-destruct.
# single transaction from fresh storage -> nothing found:
oracle --contract tests/fixtures/stateful-selfdestruct.sol \
       --input-type sol --check selfdestruct --sequence-depth 1   # 0 findings

# two-transaction sequence (arm() then blow()) -> the bug is reachable:
oracle --contract tests/fixtures/stateful-selfdestruct.sol \
       --input-type sol --check selfdestruct --sequence-depth 2   # 1 finding
```

Notes and bounds:

- **Combinatorial cost.** Each transaction re-explores from every terminal
  world of the prior one. The fan-out of carried-forward worlds is capped
  (`MAX_SEQUENCE_FANOUT`) so a deep sequence stays bounded; raise `--max-depth`
  if a per-transaction path is being pruned before it completes.
- **`--sequence-depth 1` is exactly the v0.1 behaviour** — same trigger-input
  symbol names, same findings. The flag is purely additive.
- The reported `trigger_input` reflects the **final (triggering) transaction**
  in the sequence; the trace shows the ops of that transaction.

---

## Counterexample validation

A symbolic engine reports the model the solver computed: "these inputs make the
vulnerable opcode reachable." That is a *claim* about EVM semantics. `--validate`
checks the claim by **replaying the trigger concretely**.

```bash
oracle --contract Vault.sol --input-type sol --check all --validate --format json
```

For each finding, oracle feeds the finding's `trigger_input` into a small,
self-contained concrete EVM interpreter (shipped as part of oracle — **no extra
dependency**, no `py-evm`), executes the bytecode deterministically, and records
whether the finding's vulnerable `pc` is actually reached. Each finding gains:

- `validated` — boolean: was the vulnerable opcode reached on the concrete path?
- `validation` — a verdict string:
  - `confirmed` — the opcode **was** reached: a replayable counterexample. This
    is the strongest evidence oracle can offer short of an on-chain transaction.
  - `unreachable` — the concrete replay **did not** reach the opcode. Treat the
    finding as a **possible false positive** worth manual review (the symbolic
    path may have relied on an abstraction the concrete EVM doesn't follow, e.g.
    `SHA3`/`CALL` return values).
  - `skipped` — there is no replayable trigger (e.g. a `timeout` finding with an
    empty `trigger_input`), so no verdict can be produced.

Validation is **purely additive**: it never adds, drops, or reorders findings —
it only annotates them. Without `--validate`, no `validation`/`validated` keys
appear, preserving the historical output shape.

The concrete interpreter implements the same arithmetic, comparison,
bit-manipulation, memory, storage, and control-flow semantics as oracle's
symbolic engine, so the two agree. Opcodes the symbolic engine reasons about
abstractly (`SHA3`, external calls, `CREATE`) halt the concrete replay cleanly;
such a finding simply stays unvalidated rather than crashing the validator.
Replay is bounded by an instruction-step cap so adversarially shaped calldata
can never hang the run.

---

## Testing

```bash
# default run — fast, hermetic, Z3 NEVER invoked (the solver boundary is mocked)
pytest

# slow run — exercises the REAL Z3 solver against the small fixtures
pytest -m slow
```

The single point of contact with Z3 is `oracle.analysis.solve_finding`. Default
tests patch that boundary so they never touch the solver; the real-Z3 tests are
decorated `@pytest.mark.slow` and are excluded from the default run.

---

## Output formats

- **`json`** — `{ tool, contract, finding_count, findings: [...] }`. Each
  finding has `category`, `severity`, `pc`, `op`, `trace`, `trigger_input`.
- **`h1md`** — a HackerOne-style markdown report. It opens with a `## Summary`
  block — a severity banding line (`**Severity:** 2 High, 1 Medium`, highest
  band first, zero bands omitted) and a jump table (`# / Severity / Finding /
  Opcode / pc`) so a triage reader gets the executive view before the detail —
  followed by one section per finding with the trigger input and the execution
  trace.
- **`sarif`** — a [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) document,
  the OASIS static-analysis interchange format that GitHub Advanced Security
  code scanning, Azure DevOps, and most security dashboards ingest directly.
  Each oracle detector category becomes a SARIF *rule* (`ruleId` = the category,
  so alerts can be triaged/suppressed by bug class); each finding becomes a
  *result* whose `level` is `error` for reachable High/Medium bugs and whose
  `properties.security-severity` (`8.0` / `5.0` / `2.0`) drives GitHub's alert
  banding. The vulnerable opcode's program counter is exposed as the result
  location's `startLine` (`pc + 1`), and `pc`, `opcode`, `depth`,
  `trigger_input`, and `confidence` ride along in `properties` (plus
  `validation`/`validated` when `--validate` is used). This lets an
  oracle run drop straight into a CI `github/codeql-action/upload-sarif` step
  with no glue code:

  ```bash
  oracle --contract Vault.sol --input-type sol --check all --format sarif > oracle.sarif
  # then in a GitHub Actions workflow:
  #   - uses: github/codeql-action/upload-sarif@v3
  #     with: { sarif_file: oracle.sarif }
  ```

  Every result also carries a `partialFingerprints` entry
  (`oracleFindingHash/v1`) so a SARIF consumer can track an alert **across
  runs**. GitHub code scanning uses this fingerprint to decide whether a result
  in a new run is the *same* logical finding as one it has already seen — so a
  bug you have already triaged is not re-opened as "new", and a dismissed alert
  stays dismissed, even when an unrelated edit elsewhere in the contract shifts
  every program counter. The fingerprint is deliberately **position-
  independent**: it hashes the finding's bug class plus the *opcode path* that
  reaches it (the control-flow signature), not the raw `pc`. It changes only
  when the reaching path genuinely changes — i.e. when it really is a different
  finding — which is exactly the behaviour a CI baseline wants.

---

## Instruction coverage

A symbolic engine is only as trustworthy as the fraction of the contract it
actually explored. A `0 findings` result is reassuring **only** if oracle
reached the code that could contain the bug — and oracle's exploration is
deliberately bounded: it stops a path conservatively at the `--max-depth` cap,
at any opcode it does not model, and at every `REVERT`. A run that pruned most
of the contract and a run that exhaustively cleared it both print "0 findings",
and you need to be able to tell them apart.

`--coverage PATH` writes an **[LCOV](https://github.com/linux-test-project/lcov)
tracefile** — the line-coverage interchange format `genhtml`, Codecov,
Coveralls, and GitHub coverage actions all ingest, and the same format
Halmos v0.3.0 emits. oracle works on EVM bytecode, so each **instruction** is
one coverage "line": the program counter maps to a 1-based line (`pc + 1`,
matching the SARIF location convention), a reached instruction has hit count
`1`, an unreached one `0`. A one-line summary also goes to stderr.

```bash
oracle --contract Vault.sol --input-type sol --check all \
       --coverage oracle.info
# stderr: coverage: 136/173 instructions (78.61%) -> oracle.info

# turn the tracefile into a browsable HTML report ...
genhtml oracle.info -o coverage-html
# ... or upload it in CI alongside the SARIF findings.
```

Coverage honours `--max-depth` and `--sequence-depth`: raising either can only
reach the same or more instructions. Coverage is a pure property of the
exploration (no solver involved), so it is computed independently of and in
addition to the normal findings output, which still goes to stdout in the
requested `--format`.

---

## Exit codes

oracle is built to be scripted, so its exit codes are stable and a build can
gate on them:

| Code | Meaning |
|---|---|
| `0` | Analysis completed. Either no findings, or findings below the `--fail-on` band (or `--fail-on none`, the default). |
| `1` | Analysis completed **and** at least one finding met the `--fail-on` severity threshold. |
| `2` | Usage / IO error — bad arguments, missing contract file, or an unwritable `--coverage` path. |
| `3` | Analysis crashed (an unexpected error inside the engine). |

By default (`--fail-on none`) a successful run always exits `0`, even with
findings — the historical behaviour. Add `--fail-on {low,medium,high}` to make
oracle fail the build when a finding's severity is at or above the chosen band
(`low < medium < high`). Because a gated failure (`1`) is distinct from a tool
error (`2`/`3`), a pipeline can fail the build on findings without masking a
broken invocation:

```bash
# fail the job only when a High-severity bug is reachable;
# still upload the SARIF + coverage artifacts either way.
oracle --contract Vault.sol --input-type sol --check all \
       --format sarif --fail-on high > oracle.sarif
# stderr (on a hit): fail-on: 2 finding(s) at or above severity 'high' -> exit 1
```

---

## Attribution

oracle forks the SMT-over-Z3 wrapper from
[mythril](https://github.com/Consensys/mythril) (ConsenSys Diligence, MIT). See
[`NOTICE`](NOTICE) for the exact scope of the fork and the rationale.

---

## Ethical use

oracle is for **authorized** security testing and bug-bounty research only.
Analyse contracts you own or are explicitly permitted to assess. Using oracle
to find weaknesses in systems you do not have permission to test may be
illegal. You are responsible for how you use it.

---

## Out of scope for v0.1

Python 3.14 support, a custom solver beyond Z3, multi-chain support, live
mainnet contract analysis, custom detector authoring, concolic execution,
DeFi-specific patterns, and any GUI are explicitly **not** part of v0.1.
