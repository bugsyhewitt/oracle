# Regenerating the fixture bytecode

The `.bin` files in this directory are **pre-compiled EVM runtime bytecode**
for the `.sol` fixtures. They are committed so that oracle's test suite and the
bytecode-input demos run without any `solc` installed (v0.1 criterion 6).

You only need to regenerate them if you change a `.sol` fixture.

## Fixtures

| source | contract | sidecar `.bin` |
|---|---|---|
| `assertion-violation.sol` | `AssertionViolation` | `assertion-violation.bin` |
| `integer-overflow.sol` | `IntegerOverflow` | `integer-overflow.bin` |
| `integer-underflow-vuln.sol` | `IntegerUnderflowVuln` | `integer-underflow-vuln.bin` |
| `integer-underflow-safe.sol` | `IntegerUnderflowSafe` | `integer-underflow-safe.bin` |
| `reachable-selfdestruct.sol` | `ReachableSelfdestruct` | `reachable-selfdestruct.bin` |
| `deep-assertion.sol` | `DeepAssertion` | `deep-assertion.bin` |
| `returndata-after-call.sol` | `ReturnDataAfterCall` | `returndata-after-call.bin` |
| `extcodesize-guard.sol` | `ExtCodeSizeGuard` | `extcodesize-guard.bin` |
| `unchecked-call-vuln.sol` | `UncheckedCallVuln` | `unchecked-call-vuln.bin` |
| `unchecked-call-safe.sol` | `UncheckedCallSafe` | `unchecked-call-safe.bin` |
| `ether-withdrawal-vuln.sol` | `EtherWithdrawalVuln` | `ether-withdrawal-vuln.bin` |
| `ether-withdrawal-safe.sol` | `EtherWithdrawalSafe` | `ether-withdrawal-safe.bin` |
| `strict-balance-vuln.sol` | `StrictBalanceVuln` | `strict-balance-vuln.bin` |
| `strict-balance-safe.sol` | `StrictBalanceSafe` | `strict-balance-safe.bin` |
| `blockhash-randomness-vuln.sol` | `BlockhashRandomnessVuln` | `blockhash-randomness-vuln.bin` |
| `blockhash-randomness-safe.sol` | `BlockhashRandomnessSafe` | `blockhash-randomness-safe.bin` |

`bytecode-selfdestruct.bin` is a **standalone bytecode-only fixture** (a copy of
the selfdestruct runtime bytecode) used to prove bytecode-input mode works with
no `.sol` source present.

## How to regenerate

The fixtures were compiled with **solc 0.8.21**. Use a throwaway virtualenv so
the project's pinned runtime deps are untouched:

```bash
python3 -m venv /tmp/oracle-fixtures
/tmp/oracle-fixtures/bin/pip install py-solc-x
/tmp/oracle-fixtures/bin/python tests/fixtures/_generate_fixtures.py
```

`_generate_fixtures.py` installs solc 0.8.21 on demand (via `py-solc-x`),
compiles each source with `--bin-runtime`, and writes the `0x`-prefixed hex to
the matching sidecar. It also refreshes `bytecode-selfdestruct.bin`.

## Why runtime bytecode (not creation bytecode)?

oracle analyses the **deployed** contract, so the fixtures store the
`bin-runtime` output (the code that lives on-chain after construction), not the
constructor/creation bytecode.
