# oracle — Post-v0.1 Improvement Roadmap

Rotation 1 research lap. Based on: (1) deep codebase audit of the v0.1 engine,
(2) current EVM symbolic-execution landscape survey (May 2026), (3) gap analysis
against the best-in-class tools (Halmos v0.3.0, hevm, mythril, Manticore).

Items are ranked by **value/effort** ratio. "Value" = bug-finding uplift for
real-world Solidity contracts. "Effort" = estimated implementation complexity
inside oracle's clean, bounded architecture.

---

## TIER 1 — High value, contained effort (ship next)

### 1. Opcode coverage: RETURNDATASIZE / RETURNDATACOPY / EXTCODESIZE / EXTCODEHASH ✅ IMPLEMENTED (Phase 2, Rotation 2)

**Status:** Shipped. All five missing opcodes (`0x3B EXTCODESIZE`, `0x3C
EXTCODECOPY`, `0x3D RETURNDATASIZE`, `0x3E RETURNDATACOPY`, `0x3F EXTCODEHASH`)
were added to `opcodes.py` with conservative-sound `_op_*` handlers in `vm.py`
(fresh symbolic words for the size/hash ops; no-op memory writes for the copy
ops). The previously-missing arithmetic/bit handlers were also implemented with
**correct EVM semantics** (not symbolic approximations): `SAR`, `SDIV`, `SMOD`,
`ADDMOD` (256-bit-safe via 512-bit Concat intermediate), `MULMOD`,
`SIGNEXTEND`, `BYTE`, `CALLDATACOPY`, `CODECOPY`, and `CODESIZE` (now the
concrete bytecode length). New SMT helpers `AShr`, `SDiv`, `SMod`, `SignExt`.
Two new fixtures (`returndata-after-call.sol`, `extcodesize-guard.sol`) prove
the reachable SELFDESTRUCT downstream of an external call / extcodesize guard is
now discoverable — both returned zero findings under v0.1, one finding now.
Tests: `tests/test_opcodes_arithmetic.py` (24 concrete-value unit tests),
`tests/test_opcodes_extcode.py` (8 stack-effect tests),
`tests/test_post_call_paths.py` (integration + real-Z3 slow tests).

**Why it matters:** These four opcodes are absent from oracle's VM (`vm.py` halts
the path conservatively on any unhandled instruction). Solidity ≥0.5.0 emits
`RETURNDATACOPY` / `RETURNDATASIZE` on every external call because the ABI
decoder uses them. Any contract that calls out and then checks the return data
will stop exploration at that point, producing no findings on post-call paths —
including the most interesting paths for the `ether-leak` and `storage-write`
detectors.

**Missing from opcodes.py:** `0x3B EXTCODESIZE`, `0x3C EXTCODECOPY`,
`0x3D RETURNDATASIZE`, `0x3E RETURNDATACOPY`, `0x3F EXTCODEHASH`.

**Implementation approach (conservative-sound):**
- `RETURNDATASIZE` → push a fresh symbolic `returndatasize` bitvec. No state
  effect.
- `RETURNDATACOPY` → pop (destOffset, offset, size), no memory modelling needed
  beyond what `MSTORE` already skips. Continue path rather than halt.
- `EXTCODESIZE` → pop address, push a fresh symbolic `extcodesize_N` bitvec.
- `EXTCODECOPY` → pop four args, no-op (halting is worse than skipping).
- `EXTCODEHASH` → pop address, push a fresh symbolic `extcodehash_N` bitvec.
- Add all five to `opcodes.py`, add corresponding `_op_*` handlers in `vm.py`.
- Fix: also add `BYTE`, `SAR`, `SDIV`, `SMOD`, `ADDMOD`, `MULMOD`,
  `SIGNEXTEND`, `CALLDATACOPY`, `CODECOPY`, `CODESIZE` — all in the opcode
  table already but missing `_op_*` handlers, so they cause path termination.

**Tests to add:** two new `.sol` fixtures — one that calls out and then stores
the return-data length in storage (tests `RETURNDATASIZE` survives), one that
uses `extcodesize` in an access-control guard (tests that oracle still finds
the bypass).

**Estimated effort:** Medium. ~200 lines of new `_op_*` handlers + fixtures.

---

### 2. Reentrancy detector

**Why it matters:** Reentrancy is the canonical EVM bug class. oracle v0.1 has
five detectors but none cover reentrancy. Every audit report, every bug bounty
programme, and every symbolic-execution benchmark suite asks for it. The 2025
SliSE paper achieves 90%+ recall using program-slicing + symbolic verification —
the approach maps cleanly onto oracle's existing architecture.

**Detection logic:** Flag a `CALL`/`DELEGATECALL`/`CALLCODE` that:
1. Forwards ether (`value > 0` or symbolic value), **and**
2. Is followed (in the same path) by an `SSTORE` to any slot that was already
   `SLOAD`ed **before** the CALL.

This catches the standard "check-effects-interactions" violation. The path
constraint is: "CALL executes before SSTORE, and the SSTORE slot was read
before the CALL." Z3 decides reachability.

**Implementation sketch:**
- New `ReentrancyDetector(DetectorHook)` in `detectors.py`.
- Track `sload_slots` (set of slot bitvecs seen) per path in MachineState or
  the detector's own state.
- On CALL with non-zero value: snapshot `sload_slots`.
- On SSTORE after a tracked CALL: if the slot overlaps with the pre-CALL
  snapshot → record finding.
- Add `"reentrancy"` → `ReentrancyDetector` to `DETECTOR_REGISTRY`.
- Add CLI choice `--check reentrancy`.

**Tests to add:** `tests/fixtures/reentrancy.sol` (classic withdraw pattern),
`tests/fixtures/reentrancy-guarded.sol` (ReentrancyGuard should produce 0
findings).

**Estimated effort:** Medium-High. The MachineState clone in `vm.py` must also
clone the detector's per-path slot tracking.

---

### 3. SAR / SDIV / SMOD / ADDMOD / MULMOD / SIGNEXTEND — arithmetic completeness

**Why it matters:** These six opcodes are in the opcode table but have no
`_op_*` handler. The VM's `_step` dispatches to `state.halted = True` for them.
`SAR` (arithmetic right shift) appears in every Solidity integer that involves
signed arithmetic. `SIGNEXTEND` is used in `int8`/`int16`/`int32` casts. Any
contract using signed integers will have paths cut at these operations.

**Implementation:**
- `SAR`: use Z3's signed `>>` (arithmetic shift right). `a >> shift` in Z3 bv
  arithmetic is already signed-shift — oracle's SMT wrapper has `simplify` but
  needs a helper `AShr(value, shift)`.
- `SDIV`, `SMOD`: signed division/modulo; Z3 BitVec already supports `/` and
  `%` as signed when using signed operators.
- `ADDMOD`, `MULMOD`: `(a + b) % N` and `(a * b) % N` with 256-bit wrap.
  Model conservatively as a fresh symbolic when N is symbolic.
- `SIGNEXTEND`: `b = SIGNEXTEND(b, x)` — sign-extend x to b+1 bytes.
  Expressible in Z3 with `z3.SignExt`.
- `BYTE`: `(value >> (248 - i*8)) & 0xFF` — extract byte i from value.

All are pure-stack arithmetic, no control-flow effect. Medium-low effort.

**Estimated effort:** Low-Medium. ~60 lines.

---

## TIER 2 — High value, higher effort (next quarter)

### 4. Multi-transaction / stateful path exploration

**Why it matters:** Halmos v0.3.0's most-requested feature was stateful invariant
testing — sequencing multiple symbolic transactions and asserting invariants
across the resulting state. oracle v0.1 models a single transaction. Real
reentrancy, access-control escalation (e.g. "call `init()` then `admin()`"), and
price manipulation bugs require at least two transactions.

**Implementation approach:**
- After `vm.run()` completes one transaction, record all reachable
  `WorldState` snapshots (one per non-reverted path end).
- Re-run `vm.run()` from each snapshot as a new starting state, with a fresh
  set of symbolic inputs (new `calldata`, `callvalue`, `caller`).
- Compose path constraints: `path1.constraints + path2.constraints`.
- Limit by `max_seq_depth` (default: 2 transactions). Combinatorial blowup is
  real but bounded.
- New CLI flag: `--sequence-depth N` (default 1 = v0.1 behaviour).

**Key challenge:** `WorldState` storage arrays need proper Z3-level composition
across sequence steps. The existing `fork_world()` copy-on-write pattern extends
naturally.

**Estimated effort:** High. Requires VM refactor to support initial `WorldState`
injection and constraint chaining.

---

### 5. Access-control escalation detector

**Why it matters:** "Anyone can call `owner()`-restricted function" is the
second-most-common smart-contract vulnerability class after reentrancy.
oracle v0.1 has no access control detector. The v0.1 EtherLeakDetector already
detects the `CALL`-to-attacker pattern; access control escalation is the
complementary gate-bypass pattern.

**Detection logic:**
- Track patterns like: `CALLER == PUSH <concrete>` → `JUMPI` (access guard).
- Flag paths where the guard is satisfiably bypassable: the path constraint
  `caller == owner_address` is *not* required along the finding path.
- In practice: if a JUMPI's condition is `caller == someConstant` and the
  constraint is **not** in the path leading to a sensitive op (SSTORE/CALL),
  that's an unchecked access.

**Estimated effort:** High. Requires taint analysis on CALLER through the
constraint set, which is non-trivial with the current bitvec constraint model.

---

### 6. Keccak-over-symbolic-data modelling

**Why it matters:** oracle v0.1 models `SHA3` (KECCAK256) as an uninterpreted
fresh symbol. This is sound (never produces false negatives) but imprecise:
Z3 cannot reason about relationships between keccak outputs. Solidity mapping
slot computation is `keccak256(key ++ slot)` — oracle cannot currently follow
mapping reads/writes with symbolic keys through storage, so storage-layout-
dependent bugs are unreachable.

**Implementation approach:** Adopt the Halmos/hevm "uninterpreted function with
injectivity axiom" approach: model `sha3` as an uninterpreted Z3 `Function`
with the axiom `sha3(x) == sha3(y) → x == y`. This lets Z3 reason about
collisions-are-impossible while still exploring all paths.

**Estimated effort:** High. Requires changes to SMT wrapper (`oracle.laser.smt`)
and the SHA3 handler.

---

## TIER 3 — Medium value, exploratory

### 7. Concrete-input replay / counterexample validator

**Why it matters:** oracle produces trigger inputs but does not validate them
against a real EVM. False positives undermine confidence. A replay step would:
(1) execute the trigger calldata against the contract bytecode in a concrete
micro-EVM, (2) confirm the vulnerable opcode is reached, (3) mark validated
findings with `"confirmed": true`.

**Implementation:** use `py-evm` (Trinity's core) or a 200-line concrete EVM
interpreter. Findings not confirmed are still reported but flagged
`"confidence": "symbolic_only"`.

**Estimated effort:** Medium. py-evm is a clean dependency; plumbing the output
back into oracle's report format is straightforward.

---

### 8. h1md report: severity-banded summary block ✅ IMPLEMENTED (Phase 2, Rotation 9)

**Status:** Shipped. `format_h1md` now emits a `## Summary` block immediately
after the `**Findings:**` count and before the first per-finding section
(non-empty reports only). The block has two parts: (1) a severity banding line
(`**Severity:** 2 High, 1 Medium`) that lists only non-zero bands, highest
severity first — any non-standard severity value is title-cased and appended;
and (2) a jump table (`| # | Severity | Finding | Opcode | pc |`) with one row
per finding linking the triage reader straight to the relevant detail section.
Pure formatting over the already-computed findings — zero logic risk, no change
to the JSON format. Tests: four new cases in `tests/test_report.py` cover the
banding string and order, the table rows, summary-before-findings ordering,
omission of zero bands for a single-severity report, and the empty-report case
(no summary block).

**Why it matters:** When submitting to bug bounty platforms, triage teams need
a one-page executive summary above the per-finding sections. The current h1md
format jumps straight into findings with no summary table. A severity-banded
summary ("2 High, 1 Medium") at the top maps directly to HackerOne's submission
template.

**Implementation:** 5-10 lines in `report.py`. Pure formatting, zero logic risk.

**Estimated effort:** Very low. Half an hour.

---

### 9. `--timeout` flag and Z3 per-finding timeout ✅ IMPLEMENTED (Phase 2, Rotation 8)

**Status:** Shipped. Added a `--timeout SECONDS` CLI flag (default `30`, `0`
disables) plumbed through `analyze(..., timeout=)` into `solve_finding`, which
now calls `Solver.set_timeout(seconds * 1000)`. A `z3.unknown` result (timeout
or otherwise undecided) is no longer silently dropped: the candidate is kept and
flagged `confidence: "timeout"` with an empty `trigger_input`, so dense paths
surface for manual review. Satisfiable findings carry `confidence: "confirmed"`;
the h1md report renders a confidence banner (with a "re-run with a larger
`--timeout`" hint for timeouts). CLI validates `--timeout >= 0`. Tests:
`tests/test_timeout.py` (14 default + 1 slow real-Z3) cover CLI parsing,
the sat/unsat/unknown → confirmed/dropped/timeout mapping via a fake solver,
timeout-ms conversion, the `analyze` end-to-end thread, and report rendering.

**Why it matters:** `solve_finding` has no timeout. A single hard Z3 query can
hang oracle indefinitely on a path-constraint-dense contract. mythril sets a
per-query timeout of 25 seconds; hevm defaults to 300s overall. oracle should
expose a `--timeout` flag (default: 30s per query, or global wall-clock limit).

**Implementation:** Z3's `Solver` supports `.set("timeout", ms)`. Queries that
hit timeout produce `"confidence": "timeout"` findings (same as `unknown`).

**Estimated effort:** Low. 10 lines in `analysis.py`, one CLI flag.

---

### 10. Python 3.14 support

**Why it matters:** Already listed as a v0.2 item in the README. Blocked on
`coincurve` / `libsecp256k1` wheels for 3.14. Track upstream; lift the
`requires-python` cap when `coincurve` ships 3.14 wheels.

**Action:** Monitor `coincurve` release notes. No code change needed in oracle
until the blocker clears.

**Estimated effort:** Near-zero (dependency wait), then 5-minute pyproject.toml
change.

---

## Implementation Priority Order (recommended)

| Rank | Item | Rationale |
|------|------|-----------|
| 1 | SAR / SDIV / arithmetic completeness (#3) | Low effort, immediate path-coverage uplift; unblocks everything else |
| 2 | Missing opcode handlers (#1) | Medium effort, unblocks post-call reentrancy + ether-leak paths |
| 3 | Reentrancy detector (#2) | Most-requested bug class; architecture already supports it |
| 4 | `--timeout` flag (#9) ✅ | Safety net before v0.2 goes to wider users |
| 5 | h1md summary block (#8) ✅ | Zero-risk polish |
| 6 | Multi-transaction exploration (#4) | Game-changer for access-control bugs; save for a dedicated lap |
| 7 | Access-control detector (#5) | Depends on multi-tx for full value |
| 8 | Keccak modelling (#6) | Research-heavy; high reward if correct |
| 9 | Counterexample validator (#7) | Quality-of-life after core detectors are solid |
| 10 | Python 3.14 (#10) | Blocked on upstream |

---

## Landscape notes (May 2026)

- **Halmos v0.3.0** (a16z, Oct 2025): 32× EVM loop speedup, stateful invariant
  testing, Yices as default solver, LCOV coverage output. Closest competitor for
  oracle's niche. Key differentiator oracle should maintain: zero-config
  bytecode-direct input (Halmos requires a Foundry project).
- **hevm**: multi-solver (Z3 + Bitwuzla), fast, Haskell-based. Not a Python
  tool. oracle's Python ecosystem advantage holds.
- **mythril**: still Z3-only, path explosion unsolved. oracle's bounded depth
  design is already better-behaved.
- **FlawCheck** (Wiley 2025): new academic tool, 5 vuln types on 13K contracts.
  Shows demand for exactly oracle's niche — a clean, scriptable symbolic engine.
- **SliSE**: program-slicing + symbolic verification achieves 90%+ reentrancy
  recall. Item #2 above is inspired by its "warning → verify" pipeline.

Sources consulted:
- https://a16zcrypto.com/posts/article/halmos-v0-3-0-release-highlights/
- https://dl.acm.org/doi/10.1007/978-3-031-65627-9_22 (hevm CAV 2024)
- https://onlinelibrary.wiley.com/doi/10.1002/spy2.477 (FlawCheck 2025)
- https://dl.acm.org/doi/10.1145/3643734 (SliSE reentrancy)
- https://hackmd.io/@SaferMaker/EVM-Sym-Exec (EVM symex survey)
- https://github.com/ConsenSysDiligence/mythril
- https://github.com/a16z/halmos
