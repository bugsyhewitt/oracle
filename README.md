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
       [--check {assertion,overflow,selfdestruct,ether-leak,storage-write,all}]
       [--max-depth N]            # default 12
       [--format {json,h1md}]     # default json
```

- `--contract` — path to a `.sol` source file **or** a `.bin` EVM bytecode blob.
- `--input-type` — `sol` to compile source, `bytecode` to analyse a blob directly.
- `--check` — which vulnerability class to look for (`all` runs every detector).
- `--max-depth` — maximum symbolic branch depth to explore (default `12`).
  Deeper bugs need a higher depth; shallow depths prune long paths.
- `--format` — `json` (machine-readable) or `h1md` (HackerOne-style markdown report).

Every finding carries:

- `category`, `severity`
- `trace` — the array of EVM ops leading to the vulnerable state
- `trigger_input` — the concrete symbolic transaction input Z3 found that
  triggers the bug (the function selector + decoded arguments, `callvalue`,
  `caller`).

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
- **`h1md`** — a HackerOne-style markdown report, one section per finding, with
  the trigger input and the execution trace.

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
