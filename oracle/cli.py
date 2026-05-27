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
FORMAT_CHOICES = ["json", "h1md"]

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
        "--format",
        choices=FORMAT_CHOICES,
        default="json",
        help="output format: json or HackerOne-style markdown (default: json)",
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

    from oracle.analysis import analyze
    from oracle.report import format_report

    try:
        findings = analyze(bytecode, checks, max_depth=args.max_depth)
    except Exception as exc:
        sys.stderr.write(f"error: analysis failed: {exc}\n")
        return 3

    output = format_report(findings, args.contract, args.format)
    sys.stdout.write(output)
    if not output.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
