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

### 7. Concrete-input replay / counterexample validator ✅ IMPLEMENTED (Phase 2, Rotation 21)

**Status:** Shipped. Added a `--validate` flag and a self-contained concrete EVM
interpreter (`oracle/laser/replay.py`) that re-executes each finding's
`trigger_input` against the bytecode and confirms whether the vulnerable `pc` is
actually reachable on the concrete path. Per the spec's lighter alternative, the
replay engine is a ~200-line concrete interpreter rather than a `py-evm`
dependency — oracle's "install-clean on modern Python" guarantee makes a
heavyweight EVM the wrong trade. Each finding gains `validated` (bool) and
`validation` (`confirmed` = opcode reached / `unreachable` = candidate false
positive / `skipped` = no replayable trigger, e.g. a `timeout` finding). The
verdict surfaces in the h1md report (a `**Validation:**` line, with a
false-positive hint for `unreachable`) and in SARIF `properties`. Validation is
purely additive: it never adds, drops, or reorders findings, and absent
`--validate` no `validation`/`validated` keys appear (historical shape
preserved). The interpreter mirrors the symbolic engine's arithmetic /
comparison / bitwise / memory / storage / control-flow semantics so the two
engines agree; abstractly-modelled opcodes (`SHA3`, external calls, `CREATE`)
halt the replay cleanly rather than crashing, and a step cap bounds adversarial
calldata. CALLDATASIZE is inferred from the calldata words the model supplies so
ABI-decoder length gates pass. Tests: `tests/test_replay_validator.py` (22 cases:
input coercion, control flow, signed/unsigned arithmetic agreement, step cap,
unmodelled-opcode halt, finding enrichment), plus `analyze(validate=True)`
integration and CLI/report-rendering cases, plus two real-Z3 slow tests proving
genuine assertion/overflow/selfdestruct findings replay as `confirmed`.

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

### 11. SARIF v2.1.0 output format ✅ IMPLEMENTED (Phase 2, Rotation 10)

**Status:** Shipped. Added a `--format sarif` option (alongside `json` / `h1md`)
backed by a new `format_sarif` in `report.py`. The formatter emits a SARIF
v2.1.0 document: one `reportingDescriptor` (rule) per distinct detector category
(deduplicated, `id` = category, with `defaultConfiguration.level` and a
`properties.security-severity` of `8.0`/`5.0`/`2.0`), and one `result` per
finding (`level` `error` for High/Medium, `warning` otherwise; a physical
location whose `startLine` is `pc + 1`; and `pc`/`opcode`/`depth`/
`trigger_input`/`confidence` carried in `result.properties`). Pure formatting
over the already-computed findings — no analysis logic, no new dependency, the
JSON finding format is unchanged. Also filled the two missing `_TITLE` entries
(`reentrancy`, `access_control_escalation`) so rule short-descriptions and the
h1md headings render proper titles instead of the raw category string. Tests:
ten new SARIF cases in `tests/test_report.py` (top-level shape, one-result-
per-finding, rule dedup, severity→level mapping, security-severity property,
location/pc line, result properties, confidence surfacing, empty run, newer-
detector titles, dispatch) plus a CLI `--format sarif` choice test.

**Why it matters:** SARIF is the OASIS standard consumed by GitHub Advanced
Security code scanning, Azure DevOps, and most security dashboards. Emitting it
lets an oracle run drop straight into a CI `upload-sarif` step with zero glue
code — directly serving oracle's "clean, scriptable symbolic engine" niche
(the landscape notes flag scriptability as oracle's key differentiator). This
was selected as the Rotation 10 item because the two remaining numbered roadmap
items are both blocked: #7 (counterexample validator) requires `py-evm`, and #10
(Python 3.14) is blocked on upstream `coincurve` wheels.

**Estimated effort:** Low. Pure formatting in `report.py`, one CLI flag value.

---

### 12. LCOV instruction-coverage output (`--coverage`) ✅ IMPLEMENTED (Phase 2, Rotation 11)

**Status:** Shipped. Added a `--coverage PATH` CLI flag that writes an LCOV
tracefile reporting which EVM instructions the symbolic exploration reached.
The VM now records `visited_pcs` (every pc an instruction was executed at,
across all paths) in `_step`; a new `analysis.compute_coverage` re-runs the
*same* bounded exploration `analyze` uses — same detectors registered, same
`--max-depth`/`--sequence-depth` honoured — and diffs the visited pcs against
the full disassembly to produce `{total_instructions, covered_instructions,
coverage_pct, covered_pcs, uncovered_pcs}`. A new `report.format_coverage_lcov`
renders that as an LCOV tracefile (`TN`/`SF`/`DA:<pc+1>,<hits>`/`LF`/`LH`/
`end_of_record`), with each instruction mapped to a 1-based line via `pc + 1`
(consistent with the SARIF location mapping). The CLI writes the file and prints
a one-line summary (`coverage: 136/173 instructions (78.61%) -> PATH`) to
stderr; findings still go to stdout in the requested `--format`. No Z3 is
involved — coverage is a pure property of exploration, so it works under the
mocked-solver default test run. No new dependency. Tests: five `compute_coverage`
cases in `tests/test_analysis.py` (shape, totals-match-disassembly, sorted/real
pcs, deeper-depth-covers-more monotonicity, unknown-check raises), five LCOV
formatter cases in `tests/test_report.py` (header/footer, DA pc→line+hits
mapping, LF/LH counts, empty contract, all-covered), and five CLI cases in
`tests/test_cli.py` (flag default/parse, help listing, end-to-end file write +
stderr summary, bad-path exit 2).

**Why it matters:** oracle's exploration is bounded (depth cap, halting opcodes,
reverts), so a "0 findings" run is only trustworthy if you know oracle actually
reached the relevant code. Coverage tells a "0 findings" run apart from an
under-explored one and tells the user when to raise `--max-depth`. LCOV is the
format Halmos v0.3.0 emits and that `genhtml`/Codecov/Coveralls/GitHub coverage
actions ingest directly — serving oracle's "clean, scriptable symbolic engine"
niche the same way the Rotation 10 SARIF item did. Selected for Rotation 11
because the two remaining *numbered* roadmap items are both blocked: #7
(counterexample validator) needs `py-evm`, #10 (Python 3.14) needs upstream
`coincurve` wheels — so this self-contained scriptability gap is the
highest-value unblocked work.

**Estimated effort:** Low-Medium. Visited-pc set in the VM + a pure-formatting
LCOV emitter + one CLI flag.

---

### 13. `--fail-on SEVERITY` CI exit-code gate ✅ IMPLEMENTED (Phase 2, Rotation 12)

**Status:** Shipped. Added a `--fail-on {none,low,medium,high}` CLI flag
(default `none`). After a successful analysis the CLI now returns exit code `1`
when any finding's severity is at or above the requested band (`low < medium <
high`); `none` never gates, preserving oracle's historical "exit 0 on a
successful run" behaviour. The gate decision is a pure, Z3-free helper
(`cli._gate_triggered`) ranking severities and ignoring unrecognised bands
(treated as the weakest, so a non-standard severity never fails a build). Exit
codes are now a documented contract: `0` clean/below-threshold, `1` gated
finding, `2` usage/IO error, `3` analysis crash — so a pipeline can fail on
findings without masking a broken invocation. A one-line `fail-on: N finding(s)
at or above severity 'band' -> exit 1` notice goes to stderr; findings still
print to stdout in the requested `--format`. The JSON/finding format is
unchanged. Tests: 13 new cases in `tests/test_cli.py` (flag default/parse,
reject unknown band, help listing, six `_gate_triggered` unit cases covering
none/empty/at-or-above/below-threshold/highest-finding/unknown-severity, and
three end-to-end `main()` cases: gate-on-medium -> 1, gate-on-high-above-findings
-> 0, default -> 0 with findings). README gains an "Exit codes" table and a
`--fail-on` flag description.

**Why it matters:** Rotations 10 (SARIF) and 11 (LCOV) made oracle's output CI-
ingestible, but a CI step can only *act* on results if the tool's exit code
reflects them — every comparable scanner exposes this (mythril `--exitcode`,
semgrep, trivy). Without it, an oracle run in CI uploads its SARIF/coverage but
always reports success, so a reachable High-severity bug never fails the build.
`--fail-on` closes that loop and completes the scriptability story those two
rotations began. Selected for Rotation 12 because the two remaining *numbered*
roadmap items are still blocked: #7 (counterexample validator) needs `py-evm`,
#10 (Python 3.14) needs upstream `coincurve` 3.14 wheels — so this self-
contained CI-integration gap is the highest-value unblocked work.

**Estimated effort:** Low. One CLI flag, a small pure gate helper, one return
path, and docs.

---

### 14. `tx.origin` authentication detector (SWC-115) ✅ IMPLEMENTED (Phase 2, Rotation 13)

**Status:** Shipped. Added `TxOriginAuthDetector` (category
`tx_origin_authentication`, severity `high`, CLI token `tx-origin`) — oracle's
eighth detector and the first new *bug class* since the access-control detector
(Rotation 5). It flags authorization based on `tx.origin`, a classic
high-severity EVM bug: `tx.origin` is the EOA that *started* the transaction,
not the immediate caller, so a `require(tx.origin == owner)` guard is bypassable
by a phishing-relay attack (`msg.sender` is the relay contract, `tx.origin` is
still the owner). The discriminating signal mirrors the access-control
detector's `caller`-in-constraints test: the contract *branched control flow on*
`tx.origin`, so a path constraint references the symbolic `origin` leaf (an
`if`/`require` on tx.origin compiles to a comparison feeding a JUMPI). To make
that recognisable, `ORIGIN` now pushes a *stable, named* `origin` symbol (like
`caller`) instead of a fresh anonymous one per execution, and the VM tracks
`origin_loaded`. A per-path `tx_origin_flagged` latch (carried on MachineState
across forks) reports each guarded path exactly once rather than re-emitting on
every subsequent instruction (the origin constraint persists down the path); a
per-detector flagged-pc set additionally dedupes a guard reached via multiple
paths. A contract that authenticates via `msg.sender` — or never reads
`tx.origin` — produces no such constraint and is not flagged. The report `_TITLE`
map gains `tx.origin Authentication (SWC-115)` so h1md headings and SARIF rule
descriptions render properly. Tests: `tests/test_tx_origin.py` (14 default + 2
slow real-Z3) cover registry/CLI registration, severity, fixture opcode
presence, vulnerable-flagged / safe-clean at both the detector and end-to-end
layers, the per-path over-report guard, the msg.sender false-positive guard,
participation in an `all`-checks run, and h1md rendering. Two new fixtures:
`tx-origin-vuln.sol` (`require(tx.origin == owner)`) and `tx-origin-safe.sol`
(`require(msg.sender == owner)`, never reads tx.origin).

**Why it matters:** `tx.origin` authentication is a named entry in the SWC
registry (SWC-115) and on every audit checklist; it was a visible gap in
oracle's detector set (seven detectors, none covering it). It maps cleanly onto
oracle's existing `_ast_mentions` constraint-walk architecture — the same
machinery the access-control detector already uses — so it adds a high-value bug
class with no engine refactor and no new dependency. Selected for Rotation 13
because numbered roadmap items 1-13 are all shipped or blocked: #7
(counterexample validator) needs `py-evm` and #10 (Python 3.14) needs upstream
`coincurve` 3.14 wheels, so a new self-contained detector is the highest-value
unblocked work.

**Estimated effort:** Low-Medium. One detector class, a stable ORIGIN symbol +
`origin_loaded`/`tx_origin_flagged` state fields, a report title, two fixtures.

---

### 15. `delegatecall`-to-untrusted-callee detector (SWC-112) ✅ IMPLEMENTED (Phase 2, Rotation 14)

**Status:** Shipped. Added `DelegatecallUntrustedDetector` (category
`delegatecall_untrusted_callee`, severity `high`, CLI token `delegatecall`) —
oracle's ninth detector and the second new *bug class* of Phase 2 (after the
Rotation 13 tx.origin detector). It flags a `DELEGATECALL`/`CALLCODE` whose
**target address operand is derived from calldata** (attacker-controllable),
which is SWC-112, "Delegatecall to Untrusted Callee" — the canonical Parity
multisig wallet bug. `delegatecall` runs the callee's code in *this* contract's
storage and balance context, so an attacker who supplies a malicious target can
rewrite any storage slot (including the owner slot) and drain the contract. The
discriminating signal mirrors the EtherLeak detector's recipient test, applied
to the delegatecall target (`stack[-2]`): the target is checked with a new
`_mentions_calldata` walk (a prefix-matching variant of `_ast_mentions` that
recognises the `calldata`/`calldata_<offset>`/`calldata_dyn` symbol family). A
**concrete** target — a hard-coded / immutable library address — is *not*
flagged: it is not attacker-controllable. This keeps the detector to the
specific untrusted-callee bug rather than the legitimate upgradeable-proxy
pattern (an owner-gated implementation slot is a fresh storage symbol, not a
calldata leaf), and distinguishes it from the access-control detector (which
flags an *unguarded* delegatecall regardless of target origin). The report
`_TITLE` map gains `Delegatecall to Untrusted Callee (SWC-112)` so h1md headings
and SARIF rule descriptions render properly. Tests: `tests/test_delegatecall.py`
(14 default + 2 slow real-Z3) cover registry/CLI registration, severity, fixture
opcode presence, vulnerable-flagged / safe-clean at both the detector and
end-to-end layers, the no-delegatecall false-positive guard, participation in an
`all`-checks run, and h1md + SARIF rendering. Two new fixtures:
`delegatecall-vuln.sol` (`forward(address target, ...)` delegatecalls into a
calldata-supplied target) and `delegatecall-safe.sol` (delegatecalls a hard-coded
constant library address — DELEGATECALL still present, so the test proves the
detector keys on the untrusted target, not the opcode).

**Why it matters:** `delegatecall` to an untrusted callee is a named SWC entry
(SWC-112), on every audit checklist, and the root cause of the second Parity
multisig freeze ($150M+). oracle modelled DELEGATECALL only as an access-control
*sink* (Rotation 5), which misses the distinct, very-high-severity case where
the target *itself* is attacker-supplied — even a perfectly access-controlled
`delegatecall(userLib, ...)` is exploitable. It maps cleanly onto oracle's
existing detector architecture (the same concrete/symbolic + AST-walk machinery
the EtherLeak and access-control detectors use), so it adds a high-value bug
class with no engine refactor and no new dependency. Selected for Rotation 14
because the numbered roadmap items 1-14 are all shipped or blocked (#7
counterexample validator needs `py-evm`, #10 Python 3.14 needs upstream
`coincurve` 3.14 wheels), so a new self-contained detector — the same play that
shipped Rotation 13 — is the highest-value unblocked work. This is the assessed
"#15+" gap the roster called for.

**Estimated effort:** Low-Medium. One detector class, a `_mentions_calldata`
prefix walk, a report title, two fixtures.

---

### 16. Unchecked call return value detector (SWC-104) ✅ IMPLEMENTED (Phase 2, Rotation 15)

**Status:** Shipped. Added `UncheckedCallReturnDetector` (category
`unchecked_call_return`, severity `medium`, CLI token `unchecked-call`) —
oracle's tenth detector and the third new *bug class* of Phase 2 (after the
Rotation 13 tx.origin and Rotation 14 delegatecall detectors). It flags a
low-level call (`CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL`) whose **boolean
success word is discarded without ever being branched on** — SWC-104,
"Unchecked Call Return Value" (the King-of-the-Ether class of incident). An EVM
call opcode does not revert when the callee reverts; it pushes a success word
(1/0) and execution continues, so a low-level `addr.call(...)` / `addr.send(...)`
whose result is ignored lets a failed external call pass silently while the
contract proceeds as though it succeeded. oracle's VM already mints that word as
a uniquely-named symbol per call site (`callretval_<pc>` for CALL/CALLCODE,
`staticretval_<pc>` for STATICCALL/DELEGATECALL), so the detector keys on a `POP`
that is about to discard a value from that symbol family **and** where the same
family appears in no accumulated path constraint. The "no path constraint" gate
is what distinguishes unchecked from checked: a `require(ok)` / `if (!ok)`
guarded call routes the word through ISZERO/JUMPI (so `callretval` lands in a
path constraint), even though Solidity also POPs the duplicated original during
stack cleanup — a bare-POP-of-the-success-word test alone false-positives on
correctly checked calls. Reuses the same `_ast_mentions_prefix` AST-walk
machinery the delegatecall detector uses for the calldata family, with a new
`_mentions_call_result` helper and a per-detector flagged-pc dedupe set. No
engine change, no new dependency. The report `_TITLE` map gains `Unchecked Call
Return Value (SWC-104)` so h1md headings and SARIF rule descriptions render
properly; medium severity is already handled by the SARIF level / security-
severity maps. Tests: `tests/test_unchecked_call.py` (14 default + 2 slow real-
Z3) cover registry/CLI registration, severity, fixture opcode presence,
vulnerable-flagged / safe-clean at both the detector and end-to-end layers, the
no-call false-positive guard, participation in an `all`-checks run, and h1md +
SARIF rendering. Two new fixtures: `unchecked-call-vuln.sol` (`pay()` discards a
`to.call{value: 1}("")` result) and `unchecked-call-safe.sol` (same call, but
`require(ok, ...)` — CALL still present, so the test proves the detector keys on
the unbranched, discarded word, not the opcode).

**Why it matters:** Unchecked low-level call return values are a named SWC entry
(SWC-104), on every audit checklist, and the root cause of the King-of-the-Ether
Throne incident and a long tail of stuck-funds bugs. It was a visible gap in
oracle's detector set (nine detectors, none covering it) and maps cleanly onto
oracle's existing detector architecture — the same concrete/symbolic + AST-walk
machinery the EtherLeak, access-control, tx.origin, and delegatecall detectors
use — so it adds a high-value bug class with no engine refactor and no new
dependency. Selected for Rotation 15 because the numbered roadmap items 1-15 are
all shipped or blocked (#7 counterexample validator needs `py-evm`, #10 Python
3.14 needs upstream `coincurve` 3.14 wheels), so a new self-contained detector —
the same play that shipped Rotations 13 and 14 — is the highest-value unblocked
work. This is the assessed "#16+" gap the roster called for.

**Estimated effort:** Low-Medium. One detector class, a `_mentions_call_result`
prefix walk over the existing call-result symbols, a report title, two fixtures.

---

### 17. DoS with failed call / revert-in-loop detector (SWC-113) ✅ IMPLEMENTED (Phase 2, Rotation 16)

**Status:** Shipped. Added `DosFailedCallDetector` (category `dos_failed_call`,
severity `medium`, CLI token `dos-failed-call`) — oracle's eleventh detector and
the fourth new *bug class* of Phase 2 (after the Rotation 13 tx.origin, Rotation
14 delegatecall, and Rotation 15 unchecked-call detectors). It flags an external
call (`CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL`) made **inside a loop** —
SWC-113, "DoS with Failed Call" (the revert-in-loop class). A "push" payout that
`transfer`s/`send`s to every recipient in a loop is a denial-of-service surface:
an EVM external call hands control to the callee, and `transfer`/`send` (or a
`require`-checked low-level call) reverts the whole transaction when the callee
fails, so a single recipient that cannot accept the call reverts the entire
batch and **no** recipient is ever paid — one malicious or broken entry
permanently bricks the function for everyone (the classic auction-refund /
airdrop DoS). The discriminating signal reuses what oracle's executor already
produces: it unrolls loops by revisiting the loop body's instructions onto the
per-path `state.trace`, so an external-call op whose pc is **already present in
the trace at inspect time** (the hook runs before the instruction executes, so
the current pc is not yet recorded) witnesses that the call has been reached
before on this path — it is loop-bound. A single, isolated call (a forwarding
call, or a pull-payment `withdraw()`) reaches its call pc at most once per path
and is not flagged. A per-detector flagged-pc set reports each loop-bound call
site once across paths. This is independent of the unchecked-return (SWC-104) and
ether-leak detectors, which key on the call's *return value* and *recipient*
respectively, not on the call being loop-bound — and independent of the
reentrancy/access-control detectors, which key on storage ordering and caller
guards. No engine change, no new dependency. The report `_TITLE` map gains `DoS
with Failed Call (SWC-113)` so h1md headings and SARIF rule descriptions render
properly; medium severity is already handled by the SARIF level / security-
severity maps. Tests: `tests/test_dos_failed_call.py` (17 default + 2 slow real-
Z3) cover registry/CLI registration, severity, fixture opcode + loop presence,
vulnerable-flagged / safe-clean at both the detector and end-to-end layers, the
per-call-site dedupe, a depth-too-shallow-to-unroll case (pins the signal on the
loop *recurrence*, not the call), the single-call and no-call false-positive
guards, participation in an `all`-checks run, and h1md + SARIF rendering. Two new
fixtures: `dos-failed-call-vuln.sol` (`distribute(address[] calldata)` `transfer`s
in a loop — a calldata-supplied recipient list, so the loop-entered path is
satisfiable rather than collapsed by oracle's all-zero initial storage) and
`dos-failed-call-safe.sol` (a pull-payment `withdraw()` makes a single isolated
`call` — CALL still present, so the test proves the detector keys on the call
being loop-bound, not the opcode).

**Why it matters:** DoS with a failed call in a loop is a named SWC entry
(SWC-113), on every audit checklist, and the root cause of a long tail of
stuck-funds / unwithdrawable-auction incidents. It was a visible gap in oracle's
detector set (ten detectors, none covering a loop-structure / availability bug —
every prior detector keys on a single instruction's operands or the path
constraints, never on the *control-flow shape*). It maps cleanly onto oracle's
existing architecture: the bounded executor already unrolls loops onto the trace,
so the loop-bound signal is a sound, model-robust property the engine produces
for free, with no engine refactor and no new dependency. Selected for Rotation 16
because the numbered roadmap items 1-16 are all shipped or blocked (#7
counterexample validator needs `py-evm`, #10 Python 3.14 needs upstream
`coincurve` 3.14 wheels), so a new self-contained detector — the same play that
shipped Rotations 13-15 — is the highest-value unblocked work. SWC-105
(unprotected SELFDESTRUCT) and SWC-106 (unprotected ether withdrawal) were
considered and rejected as already covered by the existing reachable-selfdestruct
+ access-control and ether-leak detectors; SWC-107 (reentrancy) already shipped
in Rotation (#2). SWC-113 is the highest-value *uncovered* candidate. This is the
assessed "#17+" gap the roster called for.

**Estimated effort:** Low-Medium. One detector class keying on a recurring call
pc in the per-path trace, a report title, two fixtures.

---

### 18. Timestamp-dependence detector (SWC-116) ✅ IMPLEMENTED (Phase 2, Rotation 17)

**Status:** Shipped. Added `TimestampDependenceDetector` (category
`timestamp_dependence`, severity `medium`, CLI token `timestamp`) — oracle's
twelfth detector and the fifth new *bug class* of Phase 2 (after the Rotation 13
tx.origin, Rotation 14 delegatecall, Rotation 15 unchecked-call, and Rotation 16
DoS-with-failed-call detectors). It flags control flow that **branches on a block
value** (`block.timestamp` / `block.number`) used as a proxy for time or
randomness — SWC-116, "Block values as a proxy for time." Both values are set by
the block proposer (miner/validator), who has discretion over them: a few seconds
of slack on the timestamp and full control over transaction ordering. A contract
that gates a payout, picks a "random" winner, or enforces a deadline on a block
value is letting the proposer influence the outcome — the canonical
timestamp-as-randomness gambling bug and the deadline-manipulation class.

The discriminating signal reuses the exact architecture of the tx.origin detector
(Rotation 13): the contract **branched control flow on** a block value, so a path
constraint references the symbolic `timestamp` / `block_number` leaf — the shape
an `if (block.timestamp ...)` / `require(block.number ...)` guard compiles to (a
comparison feeding a JUMPI, whose taken/not-taken constraint carries the
block-value term). The VM's TIMESTAMP and NUMBER handlers now set a per-path
`blockval_loaded` latch (mirroring `caller_loaded` / `origin_loaded`) so the
detector cheaply gates before its `_ast_mentions` walk, and `block.number` got a
dedicated `_op_number` handler (replacing the generic-env lambda) so it sets the
latch and keeps the stable `block_number` symbol name. A per-path
`timestamp_flagged` latch (carried on the MachineState across forks, copied in
`clone()`) reports each block-value-dependent path exactly once, and a
per-detector flagged-pc set dedupes the same guard reached via different paths —
the same once-per-path discipline the tx.origin detector uses. No new dependency.

A **non-control-flow** read is deliberately *not* flagged: a view getter that
merely *returns* `block.timestamp` never enters a JUMPI condition, so its symbol
appears in no path constraint. `BLOCKHASH` is intentionally out of scope —
past block hashes are a distinct, only weakly-manipulable construct; SWC-116's
named surface is the time/number proxy, and folding BLOCKHASH in would broaden the
detector past one bug class. The report `_TITLE` map gains `Block values as a
proxy for time (SWC-116)` so h1md headings and SARIF rule descriptions render
properly; medium severity is already handled by the SARIF level / security-
severity maps. Tests: `tests/test_timestamp_dependence.py` (20 default + 2 slow
real-Z3) cover registry/CLI registration, severity, the `_BLOCKVAL_NAMES`
coverage of both block values, the VM `blockval_loaded` latch on TIMESTAMP and
NUMBER, latch survival across `clone()`, fixture opcode + branch presence,
vulnerable-flagged / safe-clean at both the detector and end-to-end layers, the
per-guard-site dedupe, the no-block-value and caller-guard false-positive guards,
participation in an `all`-checks run, and h1md + SARIF rendering. Two new
fixtures: `timestamp-dependence-vuln.sol` (`play(uint256)` gates a payout on
`block.timestamp % 2 == 0` — a calldata-supplied amount keeps the gated path
satisfiable rather than collapsed by oracle's all-zero initial storage) and
`timestamp-dependence-safe.sol` (a `now_()` view getter returns `block.timestamp`
and `deposit()` branches on a calldata argument — TIMESTAMP still present, so the
test proves the detector keys on the value *deciding control flow*, not the
opcode).

**Why it matters:** Block-value dependence is a named SWC entry (SWC-116), on
every audit checklist, and the root cause of a long tail of on-chain-lottery /
gambling exploits and deadline-manipulation bugs. It was a visible gap in
oracle's detector set (eleven detectors, none covering a miner/validator-
influence bug). It maps cleanly onto oracle's existing architecture — the same
`_ast_mentions` constraint-walk and per-path-latch machinery the tx.origin and
access-control detectors use, plus the block-value symbols the VM already mints —
so it adds a high-value bug class with no engine refactor and no new dependency.
Selected for Rotation 17 because the numbered roadmap items 1-17 are all shipped
or blocked (#7 counterexample validator needs `py-evm`, #10 Python 3.14 needs
upstream `coincurve` 3.14 wheels), so a new self-contained detector — the same
play that shipped Rotations 13-16 — is the highest-value unblocked work. SWC-131
(restrictive gas / hardcoded 2300-gas `transfer`/`send`) was considered and
rejected: Solidity lowers `transfer`/`send` to a CALL whose gas operand is
computed arithmetically (`2300 * !iszero(value)`), so the literal 2300 rarely
survives as a clean concrete operand in oracle's coarse model — a fragile signal.
SWC-101 (integer overflow) is already covered for ADD/MUL by
`IntegerOverflowDetector`; SWC-107 (reentrancy) already shipped in Rotation #2.
SWC-116 is the highest-value *uncovered* candidate. This is the assessed "#18+"
gap the roster called for.

**Estimated effort:** Low-Medium. One detector class keying on a block-value
symbol in the path constraints, a VM `blockval_loaded` latch + `_op_number`
handler, a report title, two fixtures.

---

### 19. Unprotected-ether-withdrawal detector (SWC-105) ✅ IMPLEMENTED (Phase 2, Rotation 18)

**Status:** Shipped. Added `UnprotectedEtherWithdrawalDetector` (category
`unprotected_ether_withdrawal`, severity `high`, CLI token `ether-withdrawal`) —
oracle's thirteenth detector and the sixth new *bug class* of Phase 2 (after the
Rotation 13 tx.origin, Rotation 14 delegatecall, Rotation 15 unchecked-call,
Rotation 16 DoS-with-failed-call, and Rotation 17 timestamp-dependence
detectors). It flags a value-forwarding call (`CALL` / `CALLCODE`) reached on a
path with **no access-control guard** — SWC-105, "Unprotected Ether Withdrawal."
A public `withdraw()` / `sweep()` / `claim()` that forwards the contract's ether
(`transfer`/`send`/a value-bearing low-level `call`) without a
`require(msg.sender == owner)` / `onlyOwner` gate lets *any* address drain the
contract — the Parity-wallet `initWallet`+`withdraw` class and a long tail of
"anyone can empty the contract" stuck-/stolen-funds incidents.

The discriminating signal reuses the `_guarded_by_caller` constraint walk that
the access-control detector (Rotation, #5) already uses for `caller`: the
value-forwarding call is reached on a path whose accumulated constraints **never
branch on the caller's identity**. A genuine `require(msg.sender == owner)` guard
compiles to a comparison on the symbolic `caller` leaf feeding a JUMPI, so a
guarded path carries `caller` in a constraint; an unguarded path leaves it
entirely free. Only `CALL` / `CALLCODE` are inspected — they alone can forward
the contract's own ether; `DELEGATECALL` / `STATICCALL` cannot move the balance
and are out of scope. A *provably concrete-zero* `value` operand (a pure data
call) is skipped — there is no ether to steal — but a value derived from a
storage balance that collapses to oracle's all-zero initial storage is **not**
treated as proof of a zero-value call (the same model-robust reading the
reentrancy and DoS detectors use). A per-detector flagged-pc set reports each
unprotected call site once across paths. No engine change, no new dependency.

This is deliberately distinct from the two neighbouring detectors. EtherLeak
(`unconstrained_ether_transfer`) fires on a call whose *recipient* is
attacker-controlled (a symbolic `to`); SWC-105 fires even when the recipient is
`msg.sender` — the bug is the **absent access control**, not the recipient, so a
`withdraw()` that pays the caller an unentitled share has a perfectly ordinary
`to == caller` recipient yet is still an unprotected drain. AccessControlEscalation
keys on the privileged sinks SELFDESTRUCT / DELEGATECALL and the
`owner = msg.sender` SSTORE; SWC-105 keys on an ordinary value-forwarding CALL, a
different sink class. The report `_TITLE` map gains `Unprotected Ether Withdrawal
(SWC-105)` so h1md headings and SARIF rule descriptions render properly; high
severity is already handled by the SARIF level / security-severity maps. Tests:
`tests/test_ether_withdrawal.py` (18 default + 2 slow real-Z3) cover
registry/CLI registration, severity, the `_VALUE_CALL_OPS` scope, fixture opcode
+ branch presence, vulnerable-flagged / safe-clean at both the detector and
end-to-end layers, the per-call-site dedupe, and three false-positive guards (a
contract that never forwards ether, a pull-payment paying only the caller's own
balance, and a caller-guarded withdrawal), participation in an `all`-checks run,
and h1md + SARIF rendering. Two new fixtures: `ether-withdrawal-vuln.sol`
(`withdraw()` sends `address(this).balance` to `msg.sender` with no owner check —
the recipient is an ordinary `msg.sender`, so the test proves the detector keys
on the missing caller guard, not an attacker-controlled recipient) and
`ether-withdrawal-safe.sol` (`withdraw()` forwards the balance only after
`require(msg.sender == owner)` — CALL still present, so the test proves the
detector keys on the *missing caller guard*, not the value-forwarding opcode).

**Why it matters:** Unprotected ether withdrawal is a named SWC entry (SWC-105),
on every audit checklist, and the root cause of some of the largest fund-loss
incidents in EVM history (the Parity multisig freeze/drain class). It maps cleanly
onto oracle's existing architecture — the same `_guarded_by_caller` constraint
walk the access-control and tx.origin detectors use, applied to a value-forwarding
call sink — so it adds a high-severity bug class with no engine refactor and no
new dependency. Selected for Rotation 18 because the numbered roadmap items 1-18
are all shipped or blocked (#7 counterexample validator needs `py-evm`, #10 Python
3.14 needs upstream `coincurve` 3.14 wheels), so a new self-contained detector —
the same play that shipped Rotations 13-17 — is the highest-value unblocked work.
SWC-128 (DoS by block gas limit — loops over unbounded arrays) was considered and
deferred: it overlaps the existing loop-recurrence machinery of the SWC-113
DoS-with-failed-call detector and the highest-value, lowest-overlap availability
case is already covered. SWC-111 (deprecated functions — `suicide`/`sha3`/`throw`)
was rejected as a poor fit for a bytecode/symbolic tool: those source-level
deprecations compile to the *same* opcodes (SELFDESTRUCT / KECCAK256 / INVALID)
modern code emits, so bytecode cannot distinguish them — a source-AST linter's
job, not a symbolic executor's. SWC-119 (shadowing state variables) is a pure
source-level naming concept with no bytecode signal at all. SWC-105 is the
highest-value *uncovered* candidate that fits oracle's symbolic-execution model.
This is the assessed "#19+" gap the roster called for.

**Estimated effort:** Low. One detector class keying on a value-forwarding call
on a caller-unconstrained path (reusing `_guarded_by_caller`), a report title, two
fixtures. No engine or VM change.

---

### 20. Block-gas-limit DoS detector (SWC-128) ✅ IMPLEMENTED (Phase 2, Rotation 19)

**Status:** Shipped. Added `BlockGasLimitDosDetector` (category
`block_gas_limit_dos`, severity `medium`, CLI token `gas-limit-dos`) — oracle's
fourteenth detector and the seventh new *bug class* of Phase 2 (after the
Rotation 13 tx.origin, Rotation 14 delegatecall, Rotation 15 unchecked-call,
Rotation 16 DoS-with-failed-call, Rotation 17 timestamp-dependence, and Rotation
18 unprotected-ether-withdrawal detectors). It flags a loop whose body re-reads
**contract storage** every iteration while its trip count is not bounded by a
constant — SWC-128, "DoS With Block Gas Limit." Every EVM transaction can only
consume up to the block gas limit, so a function whose gas cost grows without
bound (iterating an unbounded storage array, an unchecked caller-supplied count,
or a monotonically growing collection while doing per-iteration storage work)
eventually exceeds the limit and can never be executed again, permanently
bricking any funds or state it gates — the classic airdrop / dividend-sweep /
"process all pending" unbounded-operation DoS.

The discriminating signal reuses the exact architecture of the SWC-113
DoS-with-failed-call detector (Rotation 16), applied to a different opcode: an
`SLOAD` whose program counter the engine has already executed earlier on the
same path. oracle's bounded executor unrolls loops by revisiting the loop body
and appending each executed `(pc, op)` to `state.trace`, so a recurring SLOAD pc
witnesses a loop that re-reads contract state every iteration — the
unbounded-operation surface. The hook runs *before* the instruction executes, so
a current pc already present on the trace means this storage read sits inside a
loop body that has iterated. A per-detector flagged-pc set reports each
loop-bound storage-read site once across paths. No engine change, no new
dependency — the trace machinery the SWC-113 detector already relies on produces
the signal for free.

This is deliberately kept distinct from the two neighbouring loop / availability
detectors. `dos_failed_call` (SWC-113) keys on a recurring *CALL* pc — one
reverting callee in a loop DoSing a batch; SWC-128 needs no external call at all,
and the vulnerable fixture (which makes no call) is flagged by `gas-limit-dos`
but **not** by `dos-failed-call` (a dedicated test pins this separation). A loop
bounded by a fixed constant / range-checked argument whose body does not re-read
storage never recurs an SLOAD pc, and a single non-loop storage read reaches its
pc once per path — both are clean. The report `_TITLE` map gains `DoS With Block
Gas Limit (SWC-128)` so h1md headings and SARIF rule descriptions render; medium
severity is already handled by the SARIF level / security-severity maps. Tests:
`tests/test_gas_limit_dos.py` (18 default + 2 slow real-Z3) cover registry/CLI
registration, severity, fixture opcode + loop presence, vulnerable-flagged /
safe-clean at both the detector and end-to-end layers, the per-storage-read-site
dedupe, a depth-too-shallow-to-unroll case (pins the signal on the loop
*recurrence*, not the storage read), two false-positive guards (a single non-loop
storage read and a contract whose paths do not re-read storage in a loop), the
explicit distinct-from-SWC-113 separation, participation in an `all`-checks run,
and h1md + SARIF rendering. Two new fixtures: `gas-limit-dos-vuln.sol`
(`processN(uint256 n)` loops `n` times — an unbounded calldata count — and reads
+ writes storage `total`/`step` each iteration, so the SLOAD pc recurs and, since
the trip count is a calldata argument, the loop-entered path stays satisfiable
rather than collapsed by oracle's all-zero initial storage) and
`gas-limit-dos-safe.sol` (`sumN(n)` with `require(n <= 100)` loops over a
constant-ceiling count with a local-only accumulator — the loop / JUMPI back-edge
is still present, so the test proves the detector keys on the loop *re-reading
storage*, not on the loop opcode).

**Why it matters:** Block-gas-limit DoS is a named SWC entry (SWC-128), on every
audit checklist, and the root cause of a long tail of permanently-stuck-funds and
unprocessable-queue incidents (the unbounded-array / unbounded-loop class). It
was a visible gap in oracle's detector set — the only prior availability detector
(SWC-113) keys on a loop-bound *call*, leaving the more common callless
unbounded-operation surface uncovered. It maps cleanly onto oracle's existing
architecture — the same trace-recurrence machinery the SWC-113 detector uses,
applied to SLOAD instead of CALL — so it adds a distinct bug class with no engine
refactor and no new dependency. Selected for Rotation 19 because the numbered
roadmap items 1-19 are all shipped or blocked (#7 counterexample validator needs
`py-evm`, #10 Python 3.14 needs upstream `coincurve` 3.14 wheels), so a new
self-contained detector — the same play that shipped Rotations 13-18 — is the
highest-value unblocked work. SWC-128 was previously deferred in Rotation 18 as
overlapping the SWC-113 loop machinery; on closer assessment the overlap is the
*machinery* (the trace-recurrence walk), not the *bug class* — the two detectors
key on different opcodes (CALL vs SLOAD) and the vulnerable fixture here makes no
call at all, so SWC-128 covers a surface SWC-113 cannot reach. SWC-106
(unprotected SELFDESTRUCT) is already covered by the access-control detector's
unguarded-SELFDESTRUCT sink and the reachable-selfdestruct detector; SWC-131
(restrictive gas) was rejected earlier as fragile (the 2300-gas literal rarely
survives as a concrete operand in oracle's coarse model); SWC-111 (deprecated
functions) and SWC-119 (state-variable shadowing) are source-AST-linter concerns
with no distinguishing bytecode signal. SWC-128 is the highest-value *uncovered*
candidate that fits oracle's symbolic-execution model. This is the assessed
"#20+" gap the roster called for.

**Estimated effort:** Low. One detector class keying on a recurring SLOAD pc in
the per-path trace (reusing the SWC-113 trace-recurrence pattern), a report title,
two fixtures. No engine or VM change.

---

### 21. Strict-balance-equality detector (SWC-132) ✅ IMPLEMENTED (Phase 2, Rotation 23)

**Status:** Shipped. Added `StrictBalanceEqualityDetector` (category
`strict_balance_equality`, severity `medium`, CLI token `strict-balance`) —
oracle's sixteenth detector and the ninth new *bug class* of Phase 2 (after the
Rotation 13 tx.origin, 14 delegatecall, 15 unchecked-call, 16 DoS-with-failed-call,
17 timestamp-dependence, 18 unprotected-ether-withdrawal, 19 block-gas-limit-DoS,
and 22 bypassable-EXTCODESIZE detectors). It flags control flow that **branches
on an account balance** — SWC-132, "Unexpected Ether Balance." A contract's ether
balance is not controlled solely by its own logic: any account can force ether in
via `selfdestruct(this)` or by pre-funding a CREATE2 address before deployment,
neither of which runs the receive/fallback code. A contract that treats its raw
`address(this).balance` as a trustworthy invariant — the canonical
`require(address(this).balance == expected)` game / state-machine gate — is making
an attacker-falsifiable assumption: a few forced wei break the invariant and brick
or skew the contract.

The discriminating signal mirrors the SWC-116 timestamp-dependence and
bypassable-EXTCODESIZE detectors: a path constraint references a `balance` (BALANCE,
`address(x).balance`) or `selfbalance` (SELFBALANCE, the gas-cheap
`address(this).balance`) leaf. An `if (... .balance ...)` / `require(... .balance
...)` guard compiles to a comparison feeding a JUMPI, whose taken/not-taken
constraint carries the balance term. Both symbol names share the substring
`balance`, so a single `_ast_mentions_prefix(c, "balance")` walk catches both
forms without enumerating the two names. The detector fires once per path via a
per-path `balance_flagged` latch carried on the MachineState across forks (new
state field, cloned in `MachineState.clone`), plus a per-detector flagged-pc set
that dedupes the same guard reached on different paths — the exact pattern the
EXTCODESIZE and timestamp detectors use. No engine or VM change: the VM already
mints the `balance` / `selfbalance` symbols (`_op_balance` / `_op_selfbalance`).

This is deliberately distinct from the ether-leak / unprotected-withdrawal
detectors, which key on a value-forwarding CALL's *recipient* and on a *missing
caller guard* respectively; here the bug is the **balance-as-trusted-invariant
assumption itself**, independent of any ether movement. A contract that merely
*reads* its balance to forward it as a call value never branches on it — the
`ether-withdrawal-vuln.sol` / `ether-withdrawal-safe.sol` fixtures read
SELFBALANCE only to forward it, and a dedicated false-positive test pins that
neither is flagged by `strict-balance`. The report `_TITLE` map gains `Unexpected
Ether Balance (SWC-132)` so h1md headings and SARIF rule descriptions render;
medium severity is already handled by the SARIF level / security-severity maps.
Tests: `tests/test_strict_balance.py` (14 default + 2 slow real-Z3) cover
registry/CLI registration, severity, fixture opcode presence (vuln reads
SELFBALANCE; safe reads no balance), vulnerable-flagged / safe-clean at both the
detector and end-to-end layers, the per-path latch dedupe, the
balance-forwarding false-positive guard, participation in an `all`-checks run, and
h1md + SARIF rendering. Two new fixtures: `strict-balance-vuln.sol` (`claim()`
gates a payout behind `require(address(this).balance == target)`) and
`strict-balance-safe.sol` (`claim()` gates on an internally-tracked `tracked`
deposit accumulator and authenticates via `msg.sender`, never branching on the
raw balance — force-feeding cannot influence `tracked`).

**Why it matters:** Unexpected ether balance is a named SWC entry (SWC-132), on
every audit checklist, and the root cause of a long tail of force-feeding /
balance-invariant bugs (the classic "this contract assumes nobody can change its
balance except through its own functions" gambling and accounting incidents). It
was a visible gap in oracle's detector set — no prior detector keyed on a
balance-dependent branch; the neighbouring ether detectors key on call recipients
and caller guards, not on the balance-as-invariant assumption. It maps cleanly
onto oracle's existing architecture — the same constraint-AST-walk + per-path-latch
machinery the timestamp (SWC-116) and EXTCODESIZE detectors use, applied to the
already-minted balance symbols — so it adds a distinct bug class with no engine
refactor and no new dependency. Selected for Rotation 23 because the roster called
for assessing SWC-132 ("unexpected ether balance or delegatecall injection"):
delegatecall injection (SWC-112) was already shipped in Rotation 14
(`DelegatecallUntrustedDetector`), so the uncovered half of the assessed gap —
SWC-132's balance-branch surface — is the highest-value unblocked work, the same
self-contained-detector play that shipped Rotations 13-22. This is the assessed
"#21+" gap the roster called for.

**Estimated effort:** Low. One detector class keying on a balance symbol in the
path constraints (reusing the timestamp / EXTCODESIZE constraint-walk + per-path
latch pattern), one new MachineState field, a report title, two fixtures. No engine
or VM change.

---

### 22. Blockhash weak-randomness detector (SWC-120) ✅ IMPLEMENTED (Phase 2, Rotation 24)

**Status:** Shipped. Added `BlockhashRandomnessDetector` (category
`blockhash_randomness`, severity `medium`, CLI token `blockhash-randomness`) plus
the previously-missing `BLOCKHASH` (`0x40`) opcode handler. Flags control flow
that branches on a block hash used as a randomness source — the lottery / raffle
/ NFT-mint gambling bug (SWC-120, "Weak Sources of Randomness from Chain
Attributes"). The discriminating signal is a path constraint referencing a
`blockhash_<pc>` leaf, reusing the per-path-latch + prefix-AST-walk pattern. Two
fixtures (`blockhash-randomness-vuln.sol`, `blockhash-randomness-safe.sol`) and
`tests/test_blockhash_randomness.py`. Deliberately distinct from the SWC-116
timestamp detector, which scoped itself to the time/number proxy and excluded
BLOCKHASH as a separate construct. Adding the BLOCKHASH handler was a prerequisite
(paths previously halted at the unhandled opcode).

---

### 23. Transaction-order-dependence detector (SWC-114) ✅ IMPLEMENTED (Phase 2, Rotation 25)

**Status:** Shipped. Added `TransactionOrderDependenceDetector` (category
`transaction_order_dependence`, severity `medium`, CLI token `tx-order`) —
oracle's eighteenth detector and the eleventh new *bug class* of Phase 2 (after
the Rotation 13 tx.origin, 14 delegatecall, 15 unchecked-call, 16
DoS-with-failed-call, 17 timestamp-dependence, 18 unprotected-ether-withdrawal,
19 block-gas-limit-DoS, 22 bypassable-EXTCODESIZE, 23 strict-balance-equality,
and 24 blockhash-randomness detectors). It flags control flow that **branches on
`tx.gasprice`** — SWC-114, "Transaction Order Dependence." The order in which
transactions land in a block is chosen by the proposer / searcher by fee, not by
the contract, so a contract whose outcome depends on ordering is exposed to
front-running and sandwich attacks. The single most direct on-chain signal of that
exposure is a contract that gates logic on `tx.gasprice` itself — a misguided
gas-price ceiling meant to deter front-running (`require(tx.gasprice <= max)`,
itself trivially satisfiable) or a gas-price-derived outcome. `tx.gasprice` is set
freely by the sender and is the exact lever that governs ordering.

The discriminating signal mirrors the SWC-116 timestamp, SWC-120 blockhash, and
SWC-132 strict-balance detectors: a path constraint references the `gasprice`
leaf. An `if (tx.gasprice ...)` / `require(tx.gasprice ...)` guard compiles to a
comparison feeding a JUMPI, whose taken/not-taken constraint carries the gas-price
term. The detector fires once per path via a per-path `gasprice_flagged` latch
carried on the MachineState across forks (new state field, cloned in
`MachineState.clone`), plus a per-detector flagged-pc set that dedupes the same
guard reached on different paths — the exact pattern the timestamp / blockhash
detectors use. The reused prefix-AST-walk (`_ast_mentions_prefix`) also matches the
epoch-prefixed `gasprice` symbol a later transaction would mint. A dedicated
`_op_gasprice` handler that sets the per-path `gasprice_loaded` latch replaces the
generic env handler the opcode previously used, giving the detector a cheap gate
before the AST walk; the symbol name (`gasprice`) is unchanged, so no other
detector or report path is affected.

This is deliberately distinct from the neighbouring chain-attribute detectors:
SWC-116 timestamp keys on a proposer-chosen *time* proxy, SWC-120 blockhash on a
*randomness* source; SWC-114 is the *ordering* bug class, witnessed by a
gas-price-gated branch, with its own remediation (commit-reveal / batch auctions /
slippage bounds rather than "don't use time as a deadline" or "don't use a block
hash for entropy"). The report `_TITLE` map gains `Transaction Order Dependence
(SWC-114)`; medium severity is already handled by the SARIF level /
security-severity maps. Tests: `tests/test_tx_order_dependence.py` (21 default + 2
slow real-Z3) cover registry/CLI registration, severity, the VM `gasprice_loaded`
latch + clone survival, fixture opcode presence, vulnerable-flagged / safe-clean at
both the detector and end-to-end layers, the per-pc dedupe, three false-positive
guards (no-gasprice contract, timestamp guard, blockhash guard), the cross-detector
separation (timestamp / blockhash detectors do not claim a gas-price guard),
participation in an `all`-checks run, and h1md + SARIF rendering. Two new fixtures:
`tx-order-vuln.sol` (`claim(maxGasPrice, amount)` gates a reward behind
`require(tx.gasprice <= maxGasPrice)`) and `tx-order-safe.sol`
(`currentGasPrice()` is a read-through view getter that *returns* `tx.gasprice`
and `deposit()` branches on a calldata argument — the GASPRICE opcode is present
but no branch is gated on it, proving the detector keys on the value deciding
control flow, not the opcode).

**Why it matters:** Transaction order dependence is a named SWC entry (SWC-114),
on every audit checklist, and the root cause of the entire MEV / front-running /
sandwich-attack class — the approve/transferFrom race, the DEX sandwich, the
"first claimer wins" gas auction. It was a visible gap in oracle's detector set —
no prior detector keyed on a gas-price-dependent branch; the neighbouring
chain-attribute detectors key on time, randomness, code size, and balance, not on
the ordering surface. It maps cleanly onto oracle's existing architecture — the
same constraint-AST-walk + per-path-latch machinery the timestamp (SWC-116),
blockhash (SWC-120), EXTCODESIZE, and strict-balance (SWC-132) detectors use,
applied to the already-minted gas-price symbol — so it adds a distinct bug class
with no engine refactor and no new dependency. Selected for Rotation 25 because the
roster called for assessing SWC-114 (transaction order dependence) or SWC-123
(requirement violation): SWC-114 is the higher-value, lower-false-positive fit for
oracle's symbolic model — the gas-price-gated branch is a clean, model-robust
bytecode signal, whereas SWC-123 (a `require()` whose argument is
attacker-controllable / always-true) is a source-level / fuzzing concern that
maps poorly onto a sound bytecode detector and would be false-positive-prone over
oracle's coarse storage model. This is the same self-contained-detector play that
shipped Rotations 13-24. This is the assessed "#22+" gap the roster called for.

**Verification of prior state (per roster instruction):** confirmed before
implementing that neither SWC-114 nor SWC-123 was present — a repo-wide grep for
`SWC-114`, `SWC-123`, `transaction order`, `requirement violation`, and `tx-order`
returned only prose mentions of "transaction ordering" inside the SWC-116 timestamp
docstring/fixture, no detector. SWC-120 (blockhash) was confirmed already shipped in
Rotation 24 (`BlockhashRandomnessDetector`), so the assessed candidate pair was
genuinely open and SWC-114 was implemented.

**Estimated effort:** Low. One detector class keying on a gas-price symbol in the
path constraints (reusing the timestamp / blockhash constraint-walk + per-path
latch pattern), one dedicated `_op_gasprice` handler, two new MachineState fields,
a report title, two fixtures. No engine refactor, no new dependency.

---

### 24. Unprotected-SELFDESTRUCT detector (SWC-106) ✅ IMPLEMENTED (Phase 2, Rotation 27)

**Status:** Shipped. Added `UnprotectedSelfdestructDetector` (category
`unprotected_selfdestruct`, severity `high`, CLI token `unprotected-selfdestruct`).
It flags a `SELFDESTRUCT` reached on a path whose accumulated constraints **never
branch on the caller's identity** — SWC-106, "Unprotected SELFDESTRUCT
Instruction." A public `kill()` / `close()` / `destroy()` that runs
`selfdestruct(target)` with no `require(msg.sender == owner)` / `onlyOwner` gate
lets *any* address destroy the contract and forward its entire balance to an
arbitrary recipient — the Parity multisig wallet-library `kill()` incident that
froze ~$280M of user funds, and a long tail of "anyone can destroy the contract"
bugs. The discriminating signal is the **absent caller guard**: a genuine
`require(msg.sender == owner)` compiles to a comparison on the symbolic `caller`
leaf feeding a JUMPI, so a guarded path carries `caller` in a path constraint and
an unguarded path leaves it entirely free, reusing the `_guarded_by_caller`
constraint walk the access-control, tx.origin, and SWC-105 ether-withdrawal
detectors already share. A per-detector flagged-pc set reports each unprotected
SELFDESTRUCT site once across paths.

This is deliberately distinct from the two neighbouring SELFDESTRUCT-aware
detectors. The `selfdestruct` detector (`reachable_selfdestruct`) fires on **any**
reachable SELFDESTRUCT — including one correctly gated behind
`require(msg.sender == owner)` — answering "is it destructible at all?"; SWC-106
is the narrower "can an *unauthorised* caller destroy it?" question and stays
silent on a properly owner-gated `kill()`. The `access-control`
(`access_control_escalation`) detector also flags the unguarded case but folds it
into a broad ownership/privilege-escalation category alongside `owner = msg.sender`
writes and unguarded DELEGATECALL; SWC-106 reports under its own
`unprotected_selfdestruct` category / SWC-106 title so a triage team can band and
suppress it independently. The report `_TITLE` map gains `Unprotected SELFDESTRUCT
(SWC-106)` so h1md headings and SARIF rule descriptions render properly; high
severity is already handled by the SARIF level / security-severity maps. Tests:
`tests/test_unprotected_selfdestruct.py` (16 default + 2 slow real-Z3) cover
registry/CLI registration, severity, fixture opcode + branch presence,
vulnerable-flagged / safe-clean at both the detector and end-to-end layers, the
per-site dedupe, the defining distinction from the broad `reachable_selfdestruct`
detector on the *safe* fixture (the broad detector flags it; SWC-106 does not), a
false-positive guard on a contract that never self-destructs, participation in an
`all`-checks run, and h1md + SARIF rendering. Two new fixtures:
`unprotected-selfdestruct-vuln.sol` (`kill(target)` self-destructs with no owner
check — flagged) and `unprotected-selfdestruct-safe.sol` (`kill(target)`
self-destructs only after `require(msg.sender == owner)` — SELFDESTRUCT still
present, so the test proves the detector keys on the *missing caller guard*, not
the opcode).

**Why it matters:** Unprotected SELFDESTRUCT is a named SWC entry (SWC-106), on
every audit checklist, and the root cause of one of the largest fund-loss
incidents in EVM history (the Parity multisig wallet-library freeze). It maps
cleanly onto oracle's existing architecture — the same `_guarded_by_caller`
constraint walk the access-control, tx.origin, and SWC-105 detectors use, applied
to the SELFDESTRUCT sink — so it adds a high-severity named bug class with no
engine refactor and no new dependency. Selected for Rotation 27 because the roster
called for assessing SWC-107 (reentrancy variants) or SWC-106 (unprotected
self-destruct) as the next detector after SWC-101 integer-underflow shipped (and
noted SWC-105 already shipped in R18, SWC-123 assessed infeasible on the coarse
memory model). SWC-106 is the higher-feasibility fit: it reuses the proven
caller-guard constraint walk verbatim with zero engine change, exactly mirroring
the SWC-105 carve-out (a named SWC entry deserves its own category/title even when
a broader detector overlaps), whereas a new SWC-107 reentrancy *variant* (e.g.
cross-function or cross-transaction reentrancy beyond the existing single-function
CEI detector) would require cross-function / cross-transaction state modelling that
is heavier and more false-positive-prone over oracle's coarse memory model. This
is the same self-contained-detector play that shipped Rotations 13-25.

**Verification of prior state (per roster instruction):** confirmed before
implementing that no dedicated SWC-106 detector existed. A repo-wide grep for
`SWC-106`, `unprotected self-destruct`, and `unprotected-selfdestruct` returned
only (a) a stale 2-line note in the Rotation 16 (#17) assessment that had
*considered and rejected* SWC-106 as "already covered by reachable-selfdestruct +
access-control" — the identical overlap reasoning that was later overridden when
SWC-105 was carved out as its own detector in Rotation 18 — and (b) the
access-control detector's unguarded-SELFDESTRUCT sink (a broad escalation
category, not a dedicated SWC-106 category). Neither the `reachable_selfdestruct`
detector (fires on *any* reachable SELFDESTRUCT, including guarded ones) nor the
`access_control_escalation` detector (broad category) reports SWC-106 as its own
triageable bug class, so the gap was genuinely open. SWC-105 was confirmed already
shipped (`UnprotectedEtherWithdrawalDetector`), so the carve-out precedent it set
directly justified this one.

**Estimated effort:** Low. One detector class keying on an unguarded SELFDESTRUCT
(reusing the `_guarded_by_caller` constraint walk), a report title, two fixtures.
No engine refactor, no new dependency.

---

### 25. Arbitrary-jump detector (SWC-127) ✅ IMPLEMENTED (Phase 2, Rotation 28)

**Status:** Shipped. Added `ArbitraryJumpDetector` (category `arbitrary_jump`,
severity `high`, CLI token `arbitrary-jump`) — the next new *bug class* of Phase
2. It flags a `JUMP` / `JUMPI` whose **destination operand is derived from
calldata** (attacker-controllable) — SWC-127, "Arbitrary Jump with Function Type
Variable." In well-formed compiler output every jump destination is a constant
the compiler computed and the only legal landing sites are `JUMPDEST` opcodes; a
`function` type variable, however, holds an internal jump destination (a code
offset) as an ordinary 256-bit value, and if that value is influenced by
untrusted input — read from a calldata argument, overwritten via inline assembly,
or loaded from an attacker-writable slot — invoking it lets an attacker redirect
execution to *any* JUMPDEST in the bytecode, bypassing access checks or
re-entering privileged code (the EVM analogue of a corrupted function pointer).

The discriminating signal is the DelegatecallUntrustedDetector's untrusted-target
test (`_mentions_calldata` over the operand), applied to the jump destination
instead of the delegatecall target. The detector hook runs *before* the
instruction executes, so the destination is the top of stack (`stack[-1]` for
both `JUMP dest` and `JUMPI dest, cond`); a *concrete* destination — the
overwhelmingly common case of ordinary compiler-generated control flow (function
dispatch, loop back-edges, internal calls to a fixed offset) — is **not** flagged,
and a symbolic-but-not-calldata destination is likewise not flagged (avoiding
false-positives on a destination that collapses to a fresh symbol from oracle's
all-zero initial storage). A per-detector flagged-pc set reports each jump site
once across paths. No engine refactor, no new dependency.

This is especially valuable for oracle because `_op_jump` **halts** a JUMP whose
destination it cannot resolve to a concrete `JUMPDEST`: without this detector the
most dangerous case — an attacker-steerable jump — is silently pruned as an
unexplorable path rather than surfaced. The detector inspects the operand before
that pruning, so the arbitrary jump is reported instead of disappearing. It is
deliberately distinct from the delegatecall detector (SWC-112), which keys on a
*delegatecall target*, not a jump destination — a dedicated cross-detector test
pins that SWC-112 stays silent on the arbitrary-jump fixture (which makes no
delegatecall). The report `_TITLE` map gains `Arbitrary Jump with Function Type
Variable (SWC-127)`; high severity is already handled by the SARIF level /
security-severity maps. Tests: `tests/test_arbitrary_jump.py` (16 default + 2 slow
real-Z3) cover registry/CLI registration, severity, fixture opcode presence,
vulnerable-flagged / safe-clean at both the detector and end-to-end layers, the
per-pc dedupe, two false-positive guards (a contract whose jumps are all
compiler-determined, and the cross-detector separation from SWC-112),
participation in an `all`-checks run, and h1md + SARIF rendering. Two new
fixtures: `arbitrary-jump-vuln.sol` (`run(uint256 ptr)` overwrites a function
pointer with a calldata-derived value via inline assembly and invokes it — the
JUMP it lowers to takes a calldata-supplied target) and `arbitrary-jump-safe.sol`
(`sum(uint256 n)` loops and branches — the compiler emits many JUMP/JUMPI opcodes,
all to fixed labels, so the test proves the detector keys on the calldata-derived
target, not the opcode).

**Why it matters:** Arbitrary jump with a function type variable is a named SWC
entry (SWC-127), on every audit checklist, and the EVM's corrupted-function-
pointer class — a control-flow-hijack bug that bypasses every other guard in the
contract. It was a visible gap in oracle's detector set (no prior detector keyed
on a jump-target operand; the neighbouring delegatecall detector keys on a call
target). It maps cleanly onto oracle's existing architecture — the same
calldata-derived-operand AST-walk machinery (`_mentions_calldata`) the delegatecall
detector uses, applied to the JUMP/JUMPI destination — so it adds a high-severity
named bug class with no engine refactor and no new dependency.

**Verification of prior state (per roster instruction):** the roster called for
assessing SWC-110 (assert-violation) or SWC-125 (incorrect-inheritance-order) and
verifying which (if either) was already shipped. SWC-110 (assert-violation) is
**already shipped** — `AssertionViolationDetector` (category `assertion_violation`,
CLI token `assertion`) flags reachable INVALID (0xFE), the opcode solc emits for a
failing `assert()`; a repo grep confirmed the detector, its registry entry, its
fixture (`assertion-violation.sol`), and its report title all predate this
rotation. SWC-125 (incorrect inheritance order) is a *source-level* C3-linearization
concept (`is A, B` ordering) with **no distinguishing bytecode signal** — the
linearized override resolution is fully baked into the compiled dispatch and call
targets, so a bytecode/symbolic tool cannot recover the source inheritance order;
it is the same poor fit as SWC-111 (deprecated functions) and SWC-119 (state-
variable shadowing) that earlier rotations rejected as source-AST-linter concerns.
Both assessed options being shipped-or-infeasible, per the roster's "pick the next
best unshipped gap" instruction, SWC-127 was selected: a high-severity named SWC
entry with a clean, model-robust bytecode signal (a calldata-derived jump target)
that reuses the proven `_mentions_calldata` machinery with zero engine change —
the same self-contained-detector play that shipped Rotations 13-27.

**Estimated effort:** Low. One detector class keying on a calldata-derived
JUMP/JUMPI destination (reusing the delegatecall detector's `_mentions_calldata`
operand test), a report title, two fixtures. No engine refactor, no new
dependency.

---

### 27. Cross-chain-signature-replay detector (SWC-121) ✅ IMPLEMENTED (Phase 2, Rotation 31)

**Status:** Shipped. Added `SignatureReplayDetector` (category
`signature_replay`, severity `high`, CLI token `signature-replay`) — the next
new *bug class* of Phase 2. It flags a contract that authenticates via
`ecrecover(...)` over a payload that does **not** include `block.chainid` —
SWC-121, "Missing Protection against Signature Replay Attacks" (the
cross-chain replay half of SWC-121; the same-chain nonce-reuse half is already
covered by the application-level `usedNonces` pattern the fixtures
demonstrate). Without a chain-identifier in the signed hash a well-formed
signature is valid bit-for-bit on every chain the contract is deployed on, so
an attacker lifts a signature off one chain and replays it on another
(Ethereum mainnet → a fork chain, an L1 → an L2 mirror, or any post-fork
wallet → its pre-fork twin — the canonical post-DAO-fork drain class).
EIP-155 + EIP-1344 introduced `CHAINID` (opcode `0x46`, Solidity's
`block.chainid`) for exactly this remediation.

The discriminating signal is a **bytecode-level conjunction**: the contract
(1) reaches a `STATICCALL` (Solidity-emitted form since Byzantium) or `CALL`
whose **concrete target address is `1`** — the ECRECOVER precompile address
— and (2) the contract's disassembly contains **no `CHAINID` opcode anywhere**
at all. The absence of `CHAINID` is a hard impossibility proof: a contract
with zero `CHAINID` opcodes in its bytecode demonstrably cannot incorporate
the chain id into any signed payload, a structural model-robust signal. A
`CHAINID` *anywhere* in the bytecode is enough to acquit the contract: even
if a specific path does not happen to read it, the contract has the *capacity*
to bind chain context (e.g. a cached EIP-712 domain separator computed once
at deploy time compiles to a single `CHAINID` followed by an `SLOAD` per
call). This keeps the false-positive rate low without modelling ECRECOVER's
precompile semantics, the contract's hash construction, or the cross-call
data-flow from the signed bytes into the call buffer — none of which oracle's
coarse memory model tracks precisely.

Reuses the `DelegatecallUntrustedDetector`'s concrete-target inspection
applied to the STATICCALL/CALL target, with the direction inverted: SWC-112
flags an attacker-CONTROLLED target, SWC-121 flags a known-precompile target
alongside an absent chain bind. The CHAINID-presence scan is cached on the
`vm` once (the bytecode does not change across paths) and per-pc dedupes
report each ECRECOVER call site exactly once across paths. A `STATICCALL` /
`CALL` to a concrete address other than `1` (the overwhelmingly common
case), and a `STATICCALL` / `CALL` whose target is symbolic (so cannot be
statically identified as ECRECOVER), are not flagged; a contract that never
calls ECRECOVER produces no finding regardless of whether it reads
`CHAINID`. Deliberately distinct from SWC-114 transaction-order
(`tx.gasprice`-gated ordering) and the SWC-117 signature-malleability class
(`s`-value bounds): SWC-121's bug is the *absent chain bind*, witnessed
structurally in the bytecode, with its own remediation (include
`block.chainid` in the signed payload, or use EIP-712 with a chain-bound
domain separator). No engine refactor, no new dependency.

The report `_TITLE` map gains `Missing Chain Bind for Signature (SWC-121)`
so h1md headings and SARIF rule descriptions render properly; high severity
is already handled by the SARIF level / security-severity maps. Tests:
`tests/test_signature_replay.py` (21 default + 2 slow real-Z3) cover
registry/CLI registration, severity, the `_has_chainid_opcode` helper +
caching, fixture opcode presence (vuln has STATICCALL no CHAINID; safe has
both), vulnerable-flagged / safe-clean at both the detector and end-to-end
layers, the per-pc dedupe, three false-positive guards (external call to a
non-precompile target, delegatecall, a contract that makes no external call
at all), two cross-detector separation tests (SWC-112 delegatecall and
SWC-114 tx-order do not claim the SWC-121 fixture), participation in an
`all`-checks run, and h1md + SARIF rendering. Two new fixtures:
`signature-replay-vuln.sol` (`claim(...)` recovers a signer over a hash
that omits `block.chainid` — flagged) and `signature-replay-safe.sol`
(`claim(...)` recovers a signer over a hash that includes `block.chainid`
— the STATICCALL to address `1` is still present, so the test proves the
detector keys on the absence of CHAINID alongside the ecrecover, not on the
ecrecover call alone).

**Why it matters:** Cross-chain signature replay is a named SWC entry
(SWC-121), on every audit checklist, and the root cause of a long tail of
post-fork wallet drains, L1↔L2 mirror exploits, and multi-chain dapp
incidents — every place a signature produced for one chain remains valid on
another. It was a visible gap in oracle's detector set (no prior detector
keyed on signature handling or on the ECRECOVER precompile sink). Prior
rotations had explicitly deferred SWC-121 and SWC-122 as "considered but
require ECRECOVER / precompile modelling that oracle does not currently
implement" (see the Rotation 30 SWC-124 verification, lines 1316-1319). On
re-assessment for Rotation 31 the cross-chain-replay surface of SWC-121
admits a sound bytecode-level signal — the structural CHAINID-absence
impossibility proof — that does NOT require modelling ECRECOVER's
precompile semantics at all: only that ECRECOVER is *called* (a concrete
target-address check) and that the bytecode has no `CHAINID` opcode to bind
the signed payload to its chain. That signal sits entirely within the
existing detector framework, with zero engine refactor and no new
dependency — exactly the same self-contained-detector play that shipped
Rotations 13-30.

**Verification of prior state (per roster instruction):** the roster called
for assessing SWC-121 (signature replay) or SWC-122 (improper signature
verification) and verifying which (if either) was already shipped. A repo-
wide grep for `SWC-121`, `SWC-122`, `ecrecover`, `ECRECOVER`, `signature
replay`, and `chain id` confirmed: no detector for either SWC; no ECRECOVER
opcode/precompile handler; CHAINID (opcode `0x46`) is handled by the VM
(`_op_chainid`); the only prior mentions of SWC-121/SWC-122 are the
explicit deferrals in the Rotation 30 SWC-124 verification note. The
roster's POST_V01.md staleness clause specifically called this out:
"POST_V01.md may be stale. Pick the best unimplemented gap and implement
it. Document any pivot in your PR description." Both assessed options
remained open; **SWC-121 was selected over SWC-122** because the
cross-chain replay surface admits a clean *structural* bytecode signal (the
CHAINID-absence impossibility proof) that needs no ECRECOVER semantics
modelling, whereas SWC-122 ("improper verification" — failing to check the
ecrecover return value against a known signer / against the
recovered-address-equals-zero failure mode) genuinely requires modelling the
precompile's *output* (the recovered address in memory after the
STATICCALL) and tracking its flow into a subsequent comparison, which
oracle's coarse memory model does not precisely track. SWC-121 is the
higher-feasibility, lower-false-positive fit. This is the assessed "#22+"
gap the roster called for.

**Estimated effort:** Low. One detector class keying on a concrete
ECRECOVER call site without any CHAINID in the bytecode (reusing the
concrete-target inspection from the delegatecall detector and a one-line
disassembly scan cached on the vm), one CHAINID-presence helper, a report
title, two fixtures. No engine refactor, no new dependency.

---

### 26. Write-arbitrary-storage detector (SWC-124) ✅ IMPLEMENTED (Phase 2, Rotation 30)

**Status:** Shipped. Added `WriteArbitraryStorageDetector` (category
`write_arbitrary_storage`, severity `high`, CLI token `write-arbitrary-storage`) —
oracle's twentieth detector and the next new *bug class* of Phase 2. It flags an
`SSTORE` whose **storage key is derived from calldata** (attacker-controllable) —
SWC-124, "Write to Arbitrary Storage Location." The EVM addresses contract
storage by 256-bit keys; in well-formed compiler output every `SSTORE` key is
either a compile-time constant (a top-level state variable's slot, fixed by the
compiler) or a `keccak256`-derived word (a `mapping(...)` / dynamic-array
element's slot, whose preimage is compiler-controlled). An attacker cannot steer
those keys. Inline-assembly `sstore(key, val)` with a calldata-supplied `key` —
or any path that loads a raw storage slot index from calldata and stores
through it — lets an attacker write to **any** storage slot: overwriting
`owner`, upgrading the contract to a controlled implementation, or corrupting
state any other state variable depends on. A single transaction can rewrite
arbitrary contract state.

The discriminating signal reuses the exact architecture of the SWC-127
arbitrary-jump detector (Rotation 28) and the SWC-112 delegatecall detector
(Rotation 14), applied to a different operand: the top-of-stack key at SSTORE
inspect time. The detector hook runs *before* the instruction executes, so the
key is `stack[-1]` for `SSTORE key, value` (the VM's `_op_sstore` pops
`[key, value]`). A *concrete* key — the overwhelmingly common case of an
ordinary state-variable's fixed slot — is **not** flagged, and a
symbolic-but-not-calldata-derived key — the typical `mapping(...)` access whose
slot is `keccak256(key . slot)`, symbolic but compiler-controlled — is likewise
**not** flagged. A per-detector flagged-pc set reports each SSTORE site once
across paths. No engine refactor, no new dependency.

This is deliberately kept distinct from `StorageWriteDetector` (category
`arbitrary_storage_write`), which flags *any* symbolic SSTORE key including the
routine keccak-derived mapping slot. SWC-124's named bug is the narrower,
higher-severity *attacker-steered* case, so a dedicated SWC-aligned detector
lets a triage team band one bug class per finding — exactly the precedent set by
`unprotected_selfdestruct` (SWC-106) sitting alongside the broader
`reachable_selfdestruct` detector. A dedicated cross-detector test pins that the
two detectors carve different signal bands: on the safe fixture the broad
`storage-write` fires on the keccak-derived mapping slot but SWC-124 stays
silent; on the vuln fixture both fire (the key is symbolic AND calldata-derived).
The report `_TITLE` map gains `Write to Arbitrary Storage Location (SWC-124)`;
high severity is already handled by the SARIF level / security-severity maps.
Tests: `tests/test_write_arbitrary_storage.py` (17 default + 2 slow real-Z3)
cover registry/CLI registration, severity, fixture opcode presence,
vulnerable-flagged / safe-clean at both the detector and end-to-end layers, the
per-pc dedupe, two false-positive guards (the `access-control-vuln` fixture
whose `owner = msg.sender` SSTORE writes to a constant slot, and the
`arbitrary-jump-vuln` fixture which makes no SSTORE through a calldata-derived
key), the explicit distinct-from-`storage-write` separation, participation in an
`all`-checks run, and h1md + SARIF rendering. Two new fixtures:
`write-arbitrary-storage-vuln.sol` (`set(uint256 key, uint256 val)` uses inline
assembly to `sstore(key, val)` — the SSTORE key is loaded directly from
calldata) and `write-arbitrary-storage-safe.sol` (`setValue` writes to a
constant slot, `deposit`/`withdraw` write to mapping slots whose keys are
`keccak256(msg.sender . slot)` — symbolic but not calldata-derived; multiple
SSTORE opcodes are still present, so the test proves the detector keys on the
calldata-derived key, not on the opcode).

**Why it matters:** Write to Arbitrary Storage Location is a named SWC entry
(SWC-124), on every audit checklist, and the canonical "single-transaction
takeover" class — corrupt slot 0 to seize ownership, corrupt an implementation
pointer to upgrade to a malicious contract, corrupt a token-balance slot to
mint at will. It was a visible gap in oracle's detector set: the existing
`storage-write` detector flagged the broader "any symbolic SSTORE key" surface
(which catches benign mapping accesses) but did not isolate the
attacker-steered-key signal that maps to the named SWC entry. It maps cleanly
onto oracle's existing architecture — the same calldata-derived-operand AST-walk
machinery (`_mentions_calldata`) the delegatecall and arbitrary-jump detectors
use, applied to the SSTORE key — so it adds a high-severity named bug class
with no engine refactor and no new dependency.

**Verification of prior state (per roster instruction):** the roster called for
assessing SWC-119 (shadowing-state-variables) or SWC-131 (outdated-solc-version)
and verifying which (if either) was already shipped. Both are infeasible for
oracle's bytecode/symbolic model and were explicitly rejected by earlier
rotations: SWC-119 (Rotation 18 verification, line 773 of this file) is "a pure
source-level naming concept with no bytecode signal at all" — state-variable
shadowing is resolved by Solidity's compiler into ordinary SLOAD/SSTOREs to
compiler-determined slots, leaving no bytecode trace of the original
parent/child name collision. SWC-131 (Rotation 19 verification, line 859) was
"rejected earlier as fragile (the 2300-gas literal rarely survives as a
concrete operand in oracle's coarse model)" and remains so: the compiler's
2300-gas guard for `transfer`/`send` becomes a stack-derived constant that
oracle's symbolic execution does not reliably preserve as a literal, so a
pattern match on "2300" is unsound. Both assessed options being infeasible,
per the roster's "pick the next best unshipped gap" instruction, SWC-124 was
selected: a high-severity named SWC entry with a clean, model-robust bytecode
signal (a calldata-derived SSTORE key) that reuses the proven
`_mentions_calldata` machinery with zero engine change — the same
self-contained-detector play that shipped Rotations 13-28. SWC-117 (signature
malleability) and SWC-121 (signature replay) were also considered but require
ECRECOVER / precompile modelling that oracle does not currently implement;
SWC-108 (state variable default visibility), SWC-109 (uninitialized storage
pointer), SWC-118 (incorrect constructor name), SWC-122 (improper signature
verification), SWC-125 (incorrect inheritance order — explicitly rejected in
Rotation 28's verification), SWC-126 (insufficient gas griefing), SWC-129
(typographical error), SWC-130 (right-to-left override), SWC-133 (abi.encodePacked
hash collision), SWC-135 (code with no effects), and SWC-136 (unencrypted
private data) are all source-AST-linter concerns with no bytecode signal —
the same poor fit as SWC-111 and SWC-119 that earlier rotations rejected.
SWC-124 is the highest-value *uncovered* candidate that fits oracle's
symbolic-execution model. This is the assessed "#21+" gap the roster called for.

**Estimated effort:** Low. One detector class keying on a calldata-derived
SSTORE key (reusing the arbitrary-jump / delegatecall detectors'
`_mentions_calldata` operand test), a report title, two fixtures. No engine
refactor, no new dependency.

---

### 28. Hardcoded-gas message-call detector (SWC-134) ✅ IMPLEMENTED (Phase 2, Rotation 33)

**Status:** Shipped. Added `HardcodedGasCallDetector` (category
`hardcoded_gas_call`, severity `medium`, CLI token `hardcoded-gas`) — the next
new *bug class* of Phase 2. It flags a `CALL` / `CALLCODE` whose gas operand
is the fixed 2300-gas EIP-150 stipend Solidity emits for `address.transfer(x)`
and `address.send(x)` — SWC-134, "Message call with hardcoded gas amount."
Originally the 2300 stipend was sized to cover a "log + nothing else"
recipient fallback; post-Istanbul (EIP-1884, Dec 2019) the gas cost of several
common opcodes (SLOAD, BALANCE, EXTCODEHASH) increased and 2300 gas is no
longer guaranteed to be enough for any non-trivial recipient fallback. A
contract that uses `transfer` to pay an arbitrary recipient — a proxy, a
multisig, an account-abstraction wallet, a Gnosis Safe — can revert on
perfectly innocent destinations, permanently bricking the pay function for
any address the original author did not anticipate. The canonical fix is
`(bool ok,) = to.call{value: x}(""); require(ok)` (OpenZeppelin's
`Address.sendValue`, Solidity's own docs since 0.6.0), which forwards all
remaining gas.

The discriminating signal is a bytecode-level structural conjunction
(mirrors the SWC-117 / SWC-121 detectors' structural approach, inverted —
the bytecode CONTAINS the bug-witnessing literal rather than ABSENT the
fix-witnessing literal): a `CALL` / `CALLCODE` is reached on some path, AND
the preceding 24-instruction window in the disassembly contains a
`PUSH2 0x08FC` (the 2300-gas literal) AND no `GAS` opcode. The `GAS`-absence
half discriminates the SWC-134 pattern from the safe `call{value: x}("")`
lowering, which emits a `GAS` opcode immediately before the CALL (forwarding
all remaining gas) and emits no `PUSH2 0x08FC` at all. The window is scoped
to the few instructions immediately preceding each CALL so an unrelated 2300
literal elsewhere in the bytecode does not false-positive a normal call. The
per-call-site decision is cached on the `vm` (the bytecode does not change
across paths) and a per-detector flagged-pc set reports each hardcoded-gas
call site once across paths. No engine refactor, no new dependency.

DELEGATECALL / STATICCALL are intentionally out of scope: they cannot
forward value, so the `transfer` / `send` source form does not lower to
them. This is deliberately distinct from the neighbouring call-aware
detectors: EtherLeak (attacker-controlled *recipient*), SWC-105 unprotected-
ether-withdrawal (*missing caller guard*), SWC-104 unchecked-call (*discarded
return word*), SWC-113 dos-failed-call (*loop-bound call*). SWC-134 is the
**hardcoded gas amount** surface — a structural property of the gas operand,
orthogonal to every other call-related check. A `transfer`-using fixture can
simultaneously be perfectly access-controlled, called once not in a loop,
pay only `msg.sender`, and have its return word irrelevant (revert on
failure) — yet still be SWC-134 vulnerable on a recipient with a non-trivial
fallback.

The report `_TITLE` map gains `Message call with hardcoded gas amount
(SWC-134)` so h1md headings and SARIF rule descriptions render; medium
severity is already handled by the SARIF level / security-severity maps.
Tests: `tests/test_hardcoded_gas_call.py` (24 default + 2 slow real-Z3)
cover the constant pin (`_TRANSFER_GAS_STIPEND == 0x08FC == 2300`),
window-size bounds, registry/CLI registration, severity, report-title
mapping, fixture opcode + literal presence (vuln has PUSH2 0x08FC + CALL,
no GAS; safe has CALL + GAS, no PUSH2 0x08FC), the `_call_has_hardcoded_gas`
helper + per-call-pc caching on the vm + defensive unknown-pc handling,
vulnerable-flagged / safe-clean at both the detector and end-to-end
layers, the per-call-site dedupe, three false-positive guards (an ordinary
`call{value:}` fixture, a delegatecall fixture, a no-call fixture), two
cross-detector separation tests (the SWC-104 unchecked-call and reentrancy
fixtures do not trip SWC-134), participation in an `all`-checks run, and
h1md + SARIF rendering. Two new fixtures: `hardcoded-gas-vuln.sol` (`pay()`
uses `to.transfer(msg.value)`) and `hardcoded-gas-safe.sol` (`pay()` uses
`to.call{value: msg.value}("")` with `require(ok)` — CALL still present, so
the test proves the detector keys on the literal-2300 gas signature next to
the call, not on the CALL opcode itself).

**Why it matters:** Message call with a hardcoded gas amount is a named
SWC entry (SWC-134), on every audit checklist, and the root cause of a
long tail of post-Istanbul brick-the-payout incidents (the `transfer`-to-
a-Gnosis-Safe / `transfer`-to-a-proxy class). It was a visible gap in
oracle's detector set — twenty-five detectors, none covering the gas-operand
surface — and the most-cited example of an "availability bug a bytecode
tool should catch but no current oracle detector does." It maps cleanly
onto oracle's existing architecture — the same static-disassembly-conjunction
machinery the SWC-117 (signature-malleability) and SWC-121 (signature-
replay) detectors use, applied to a different pair of bytecode signals
(presence of a literal next to a CALL + absence of GAS in that window) —
so it adds a named bug class with no engine refactor and no new dependency.

**Verification of prior state (per roster instruction):** the roster called
for assessing one of SWC-134 (hardcoded gas), SWC-126 (insufficient gas
griefing), or SWC-128 (block gas-limit DoS). SWC-128 is **already shipped**
— `BlockGasLimitDosDetector` shipped in Rotation 19 — a repo grep
confirmed the detector, registry entry, fixtures, and report title all
predate this rotation. SWC-126 (insufficient gas griefing) has no clean
bytecode signal in oracle's coarse memory model — it requires modelling
the relationship between the caller's forwarded gas fraction and the
sub-call's recipient-controllable revert, a data-flow that oracle's
bounded-symbolic engine does not track precisely; earlier rotations
rejected sibling source-AST-linter concerns (SWC-111, SWC-119, SWC-125,
SWC-126, SWC-129, SWC-130, SWC-133, SWC-135, SWC-136) on the same basis.
SWC-134 was selected because (a) it admits a clean, model-robust static
signal — the bytecode literal `PUSH2 0x08FC` is the exact discriminator
solc emits for `transfer`/`send` and is preserved verbatim across every
solc 0.4-0.8 version inspected — and (b) the static-disassembly-conjunction
approach is independent of the symbolic shape of the gas operand at the
CALL site, which is exactly the model-fragility concern that previously
deferred SWC-131 (the sibling "restrictive gas" item). The same
self-contained-detector play that shipped Rotations 13-30. This is the
assessed "#23+" gap the roster called for.

**Estimated effort:** Low. One detector class keying on a static-disassembly
conjunction at each CALL site (a back-window scan for `PUSH2 0x08FC` + no
`GAS`), a per-vm cache, a report title, two fixtures. No engine refactor,
no new dependency.

---

### 29. Insufficient-gas-griefing detector (SWC-126) ✅ IMPLEMENTED (Phase 2, Rotation 34)

**Status:** Shipped. Added `InsufficientGasGriefingDetector` (category
`insufficient_gas_griefing`, severity `medium`, CLI token
`insufficient-gas-griefing`) — the next new *bug class* of Phase 2. It
flags a `CALL` / `CALLCODE` / `STATICCALL` / `DELEGATECALL` whose gas
operand on top of stack is symbolic and derived from calldata — the
canonical SWC-126 relayer / forwarder / meta-tx griefing surface, where
the caller controls the gas fraction forwarded to the inner call. A
malicious relayer can pick a `gasAmt` small enough to OOG the inner call
while the outer transaction succeeds (the signed message is recorded as
consumed / the nonce burns / the queue position advances, but the
intended inner action never executes) — that is the SWC-126 "insufficient
gas griefing" bug class. The safe pattern forwards all remaining gas (no
`{gas: ...}` modifier — Solidity emits the runtime `GAS` opcode, which
lowers to a fresh `gas_<pc>` symbol with no calldata in its AST) or
requires a minimum bound on the gas argument derived from the signed
payload.

The discriminating signal is the **symbolic origin** of the gas operand:
a `_mentions_calldata` test on `stack[-1]` at the inspect hook. This is
the same low-false-positive discriminator proven by `delegatecall`
(SWC-112, calldata-derived target), `write-arbitrary-storage` (SWC-124,
calldata-derived storage key), and `arbitrary-jump` (SWC-127,
calldata-derived jump destination) — applied here to the gas word rather
than to the target / key / destination. A concrete gas operand (the
SWC-134 hardcoded-stipend surface, or any other compile-time constant)
is not flagged: the gas amount is fixed by the contract author, not the
caller, so it is not the SWC-126 griefing surface. A per-detector
flagged-pc set reports each caller-gas call site at most once across
paths. No engine refactor, no new dependency.

The detector covers all four call-family ops — `CALL`, `CALLCODE`,
`STATICCALL`, `DELEGATECALL` — because the SWC-126 griefing surface
applies wherever the inner call can OOG without reverting the outer
transaction (all four signal an inner failure as a 0 retval, not a
revert). This is deliberately distinct from every other call-aware
detector: SWC-134 (`hardcoded_gas_call`) keys on a `PUSH2 0x08FC` literal
— the opposite end of the gas-operand spectrum (author-hardcoded, not
caller-supplied); SWC-112 keys on a calldata-derived **target** rather
than gas; SWC-104 / SWC-113 / SWC-105 key on the return word / loop
boundedness / missing caller guard respectively. SWC-126 is the
**caller-supplied gas amount** surface — orthogonal to all of them.

The report `_TITLE` map gains `Insufficient Gas Griefing (SWC-126)` so
h1md headings and SARIF rule descriptions render; medium severity is
already handled by the SARIF level / security-severity maps. Tests:
`tests/test_insufficient_gas_griefing.py` (25 default + 2 slow real-Z3)
cover registry / CLI registration, severity, report-title mapping,
fixture opcode + structure presence (vuln emits CALL with no GAS opcode
preceding; safe emits CALL with GAS opcode preceding), the symbolic
provenance probe (gas operand mentions calldata on vuln, does not on
safe), detector-level vulnerable-flagged / safe-clean, per-call-site
dedupe, end-to-end vuln / safe parity, seven false-positive guards
(SWC-134 hardcoded-gas-vuln / hardcoded-gas-safe / SWC-105
ether-withdrawal / reentrancy / SWC-104 unchecked-call / SWC-112
delegatecall / no-call assertion-violation), two cross-detector
separation tests (the SWC-126 fixture does not trip SWC-134 or
SWC-113), participation in an `all`-checks run, and h1md + SARIF
rendering. Two new fixtures: `insufficient-gas-griefing-vuln.sol`
(`relay()` does `to.call{gas: gasAmt}(data)` with a calldata `gasAmt`)
and `insufficient-gas-griefing-safe.sol` (`relay()` does
`to.call(data)`, forwarding all remaining gas — CALL still present, so
the test proves the detector keys on the gas operand's symbolic
provenance, not on the CALL opcode itself).

**Why it matters:** Insufficient gas griefing is a named SWC entry
(SWC-126), on every audit checklist of any contract that accepts
caller-relayed transactions (meta-transactions, ERC-2771 forwarders,
gasless-UX wrappers, multi-call routers, GSN relayers, EIP-712 signed
message executors). It was a visible gap in oracle's detector set —
twenty-six detectors covering twenty-five SWC classes, none keying on
the caller-supplied-gas surface — and the most-cited remaining gas-bug
gap after SWC-134 (the author-hardcoded variant) shipped in Rotation
33. It maps cleanly onto oracle's existing architecture — the same
`_mentions_calldata` symbolic-provenance machinery the SWC-112 /
SWC-124 / SWC-127 detectors use, applied to the gas operand — so it
adds a named bug class with no engine refactor and no new dependency.

**Verification of prior state (per roster instruction):** the roster
called for assessing SWC-126 (insufficient gas griefing) or, if
already shipped, SWC-128 (block-gas-limit DoS). A repo grep confirmed
the state: SWC-128 already shipped (`BlockGasLimitDosDetector`,
Rotation 19) — registry entry, fixtures, and report title all
predate this rotation. SWC-126 had been deferred in Rotation 33's
verification on the grounds that it "requires modelling the
relationship between the caller's forwarded gas fraction and the
sub-call's recipient-controllable revert" — but that framing assumed
the returndata-bomb / 63-64-rule variant of SWC-126, where the
*recipient* exhausts the forwarded gas. The relayer variant — where
the *caller* underprovisions the gas — has a clean, model-robust
symbolic signal that requires no such modelling: the gas operand
either traces to calldata or it does not, and oracle's existing
symbolic engine answers that question directly with the exact
`_mentions_calldata` test already proven across three other shipped
detectors. The relayer variant is the SWC registry's primary
worked example for SWC-126 (the canonical meta-transaction griefing
attack), so the named SWC entry is fully covered by the
relayer-keyed detector. The returndata-bomb variant remains deferred
on its original grounds (no clean symbolic signal in oracle's
bounded model) and is appropriately out of scope here. This is the
assessed "#24+" gap the roster called for.

**Estimated effort:** Low. One detector class keying on a symbolic
provenance test (`_mentions_calldata`) on `stack[-1]` at each
call-family site, a per-detector flagged-pc set, a report title, two
fixtures. No engine refactor, no new dependency.

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
