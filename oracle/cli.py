"""oracle command-line interface.

Symbolic execution of EVM bytecode, made install-clean on modern Python.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from oracle import __version__
from oracle.laser.detectors import DETECTOR_REGISTRY

# derived from the detector registry so a newly-registered detector is exposed
# on the CLI automatically (no second source of truth to keep in sync).
CHECK_CHOICES = list(DETECTOR_REGISTRY.keys()) + ["all"]
INPUT_CHOICES = ["sol", "bytecode"]
FORMAT_CHOICES = ["json", "h1md", "sarif"]

# --fail-on severity gate. Ordered weakest-to-strongest; a finding "meets" a
# threshold when its severity is at or above the requested band. "none" (the
# default) never gates, preserving oracle's historical "exit 0 on a successful
# run" behaviour. Exit code 1 is reserved for "analysis succeeded AND a finding
# met the --fail-on threshold" so CI can distinguish a gated failure (1) from a
# tool/usage error (2) or an analysis crash (3).
FAIL_ON_CHOICES = ["none", "low", "medium", "high"]
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
GATE_EXIT_CODE = 1


def _gate_triggered(findings: List[dict], fail_on: str) -> bool:
    """True if any finding's severity meets or exceeds the --fail-on threshold.

    `fail_on == "none"` never triggers. Unknown / unranked severities are
    treated as the weakest band (rank 0) so a non-standard severity only gates
    when `--fail-on` itself is the weakest meaningful band would still not catch
    it — i.e. it is conservative and never fails a build on an unrecognised band.
    """
    if fail_on == "none":
        return False
    threshold = _SEVERITY_RANK.get(fail_on, 0)
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if _SEVERITY_RANK.get(sev, 0) >= threshold:
            return True
    return False

ETHICAL_USE = (
    "oracle is for authorized security testing and bug-bounty research only. "
    "Analyse contracts you own or are explicitly permitted to assess."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oracle",
        description=(
            "oracle — mythril's symbolic-execution capability, install-clean on "
            "modern Python. Detects path-dependent EVM vulnerabilities via Z3."
        ),
        epilog=ETHICAL_USE,
    )
    parser.add_argument(
        "--contract",
        required=True,
        metavar="PATH",
        help="path to a .sol source file or a .bin EVM bytecode blob",
    )
    parser.add_argument(
        "--input-type",
        choices=INPUT_CHOICES,
        required=True,
        help="whether --contract is Solidity source (sol) or EVM bytecode (bytecode)",
    )
    parser.add_argument(
        "--check",
        choices=CHECK_CHOICES,
        default="all",
        help="vulnerability class to check for (default: all)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=12,
        help="maximum symbolic path/branch depth to explore (default: 12)",
    )
    parser.add_argument(
        "--sequence-depth",
        type=int,
        default=1,
        metavar="N",
        help=(
            "number of transactions to sequence for stateful exploration "
            "(default: 1 = single-transaction analysis). N>1 chains symbolic "
            "transactions, resuming each from the previous one's storage to "
            "find bugs that need setup+trigger across separate calls."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help=(
            "per-query Z3 solver timeout in seconds (default: 30). A query that "
            "exceeds this is reported with confidence=timeout instead of hanging "
            "the run. Use 0 to disable the per-query limit."
        ),
    )
    parser.add_argument(
        "--format",
        choices=FORMAT_CHOICES,
        default="json",
        help=(
            "output format: json, HackerOne-style markdown (h1md), or SARIF "
            "v2.1.0 for GitHub code scanning / CI ingestion (default: json)"
        ),
    )
    parser.add_argument(
        "--coverage",
        default=None,
        metavar="PATH",
        help=(
            "write an LCOV instruction-coverage tracefile to PATH (each EVM "
            "instruction is one coverage line). Reports how much of the "
            "contract the symbolic exploration reached vs. pruned, so a "
            "'0 findings' run can be distinguished from an under-explored one. "
            "A one-line coverage summary is also printed to stderr."
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="none",
        metavar="SEVERITY",
        help=(
            "exit with code 1 if any finding's severity is at or above this "
            "band (low < medium < high), so a CI step can gate a build on "
            "oracle's results. Default 'none' always exits 0 on a successful "
            "run. Exit 2 is a usage/IO error and 3 an analysis crash, so a "
            "pipeline can tell a gated failure apart from a tool error."
        ),
    )
    parser.add_argument(
        "--contract-name",
        default=None,
        help="name of the contract to compile when a .sol defines several",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"oracle {__version__}",
    )
    return parser


def _resolve_bytecode(args) -> bytes:
    from oracle.compiler import load_runtime_bytecode
    from oracle.laser.disassembler import parse_bytecode

    if args.input_type == "sol":
        return load_runtime_bytecode(args.contract, args.contract_name)
    with open(args.contract, "r") as fh:
        return parse_bytecode(fh.read())


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check == "all":
        checks = ["all"]
    else:
        checks = [args.check]

    try:
        bytecode = _resolve_bytecode(args)
    except FileNotFoundError:
        sys.stderr.write(f"error: contract file not found: {args.contract}\n")
        return 2
    except Exception as exc:  # surface compile / parse failures cleanly
        sys.stderr.write(f"error: could not load contract: {exc}\n")
        return 2

    from oracle.analysis import analyze, compute_coverage
    from oracle.report import format_coverage_lcov, format_report

    if args.sequence_depth < 1:
        sys.stderr.write("error: --sequence-depth must be >= 1\n")
        return 2

    if args.timeout < 0:
        sys.stderr.write("error: --timeout must be >= 0\n")
        return 2

    try:
        findings = analyze(
            bytecode,
            checks,
            max_depth=args.max_depth,
            sequence_depth=args.sequence_depth,
            timeout=args.timeout,
        )
    except Exception as exc:
        sys.stderr.write(f"error: analysis failed: {exc}\n")
        return 3

    if args.coverage:
        try:
            coverage = compute_coverage(
                bytecode,
                checks,
                max_depth=args.max_depth,
                sequence_depth=args.sequence_depth,
            )
        except Exception as exc:
            sys.stderr.write(f"error: coverage computation failed: {exc}\n")
            return 3
        try:
            with open(args.coverage, "w") as fh:
                fh.write(format_coverage_lcov(coverage, args.contract))
        except OSError as exc:
            sys.stderr.write(f"error: could not write coverage file: {exc}\n")
            return 2
        sys.stderr.write(
            "coverage: {covered}/{total} instructions "
            "({pct}%) -> {path}\n".format(
                covered=coverage["covered_instructions"],
                total=coverage["total_instructions"],
                pct=coverage["coverage_pct"],
                path=args.coverage,
            )
        )

    output = format_report(findings, args.contract, args.format)
    sys.stdout.write(output)
    if not output.endswith("\n"):
        sys.stdout.write("\n")

    if _gate_triggered(findings, args.fail_on):
        sys.stderr.write(
            "fail-on: {n} finding(s) at or above severity '{band}' -> "
            "exit {code}\n".format(
                n=len(findings), band=args.fail_on, code=GATE_EXIT_CODE
            )
        )
        return GATE_EXIT_CODE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
