# oracle

**mythril's symbolic-execution capability, made install-clean on modern Python.**

oracle symbolically executes EVM bytecode with the [Z3](https://github.com/Z3Prover/z3)
SMT solver to find the classes of vulnerabilities that only path exploration
can reach: reachable assertion violations, integer overflows, reachable
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
       [--check {assertion,overflow,selfdestruct,ether-leak,storage-write,reentrancy,access-control,all}]
       [--max-depth N]            # default 12
       [--sequence-depth N]       # default 1
       [--timeout SECONDS]        # default 30 (0 = no limit)
       [--format {json,h1md}]     # default json
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
- `--format` — `json` (machine-readable) or `h1md` (HackerOne-style markdown report).

Every finding carries:

- `category`, `severity`
- `confidence` — `confirmed` (Z3 produced a satisfying model with a concrete
  trigger) or `timeout` (the query exceeded `--timeout`; reachability undecided).
- `trace` — the array of EVM ops leading to the vulnerable state
- `trigger_input` — the concrete symbolic transaction input Z3 found that
  triggers the bug (the function selector + decoded arguments, `callvalue`,
  `caller`). Empty `{}` for `timeout` findings.

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

### `selfdestruct` — reachable SELFDESTRUCT

```bash
oracle --contract tests/fixtures/reachable-selfdestruct.sol \
       --input-type sol --check selfdestruct --format json
```

Finds the unguarded `SELFDESTRUCT` (`category: "reachable_selfdestruct"`) that
any caller can reach.

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
