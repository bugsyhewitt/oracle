# Changelog

All notable changes to oracle will be documented in this file.

## [1.0.0] - 2026-06-19

### Added
- Cross-function reentrancy detector (SWC-107 variant) — #35
- Insufficient-gas-griefing detector (SWC-126) — #34
- Hardcoded-gas message-call detector (SWC-134) — #33
- SignatureMalleabilityDetector for SWC-117 signature malleability — #31
- SignatureReplayDetector for SWC-121 cross-chain signature replay — #30
- SELFDESTRUCT-via-untrusted-delegatecall detector (SWC-112+SWC-106) — #37
- Cancun/Dencun/London EVM opcode coverage (TLOAD/TSTORE/MCOPY/BASEFEE/BLOBHASH/BLOBBASEFEE/CREATE2) — #36
- SARIF output format (alongside existing `json` and `h1md`)
- `--fail-on {none,low,medium,high}` severity gate (exit code 1 on threshold)
- `--version` argparse action (prints `oracle 1.0.0`)
- Wheel-ship-gate contract tests (`tests/test_wheel_ship_gate.py`, 6 `@pytest.mark.ship_gate` tests)

### Notes
- This is the v1.0 RELEASE. Future changes should be additive and tracked in CHANGELOG.md.
- Wheel distribution name: `oracle-symexec` (PyPI-normalized to `oracle_symexec` in filenames).
- Import package: `oracle` (not `oracle_symexec` — the dist-name/import-name mismatch is intentional and pinned by the ship-gate tests).
