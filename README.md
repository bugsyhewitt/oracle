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
       [--check {assertion,overflow,selfdestruct,ether-leak,storage-write,reentrancy,access-control,tx-origin,delegatecall,unchecked-call,dos-failed-call,all}]
       [--max-depth N]            # default 12
       [--sequence-depth N]       # default 1
       [--timeout SECONDS]        # default 30 (0 = no limit)
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
- **`sarif`** — a [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) document,
  the OASIS static-analysis interchange format that GitHub Advanced Security
  code scanning, Azure DevOps, and most security dashboards ingest directly.
  Each oracle detector category becomes a SARIF *rule* (`ruleId` = the category,
  so alerts can be triaged/suppressed by bug class); each finding becomes a
  *result* whose `level` is `error` for reachable High/Medium bugs and whose
  `properties.security-severity` (`8.0` / `5.0` / `2.0`) drives GitHub's alert
  banding. The vulnerable opcode's program counter is exposed as the result
  location's `startLine` (`pc + 1`), and `pc`, `opcode`, `depth`,
  `trigger_input`, and `confidence` ride along in `properties`. This lets an
  oracle run drop straight into a CI `github/codeql-action/upload-sarif` step
  with no glue code:

  ```bash
  oracle --contract Vault.sol --input-type sol --check all --format sarif > oracle.sarif
  # then in a GitHub Actions workflow:
  #   - uses: github/codeql-action/upload-sarif@v3
  #     with: { sarif_file: oracle.sarif }
  ```

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
