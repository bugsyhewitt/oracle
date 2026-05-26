"""Regenerate the precompiled .bin sidecar fixtures from the .sol sources.

This is a BUILD-TIME utility, not part of oracle's runtime or test path. It
requires solc (via py-solc-x). See REGENERATE.md for usage. The resulting
.bin files are committed so the test suite and bytecode-input demos never need
solc installed.
"""

import os
import sys

import solcx

HERE = os.path.dirname(os.path.abspath(__file__))
SOLC_VERSION = "0.8.21"

# source filename -> contract name to extract
CONTRACTS = {
    "assertion-violation.sol": "AssertionViolation",
    "integer-overflow.sol": "IntegerOverflow",
    "reachable-selfdestruct.sol": "ReachableSelfdestruct",
    "deep-assertion.sol": "DeepAssertion",
}


def main() -> int:
    solcx.install_solc(SOLC_VERSION)
    solcx.set_solc_version(SOLC_VERSION)
    for src, contract in CONTRACTS.items():
        path = os.path.join(HERE, src)
        with open(path) as fh:
            source = fh.read()
        compiled = solcx.compile_source(source, output_values=["bin-runtime"])
        key = next(k for k in compiled if k.endswith(":" + contract))
        runtime = compiled[key]["bin-runtime"]
        out = os.path.splitext(path)[0] + ".bin"
        with open(out, "w") as fh:
            fh.write("0x" + runtime + "\n")
        print(f"wrote {out} ({len(runtime)//2} bytes)")

    # also write a standalone bytecode-only fixture (criterion 6): reuse the
    # selfdestruct runtime bytecode as a .bin blob with no .sol sidecar.
    sd_bin = os.path.join(HERE, "reachable-selfdestruct.bin")
    with open(sd_bin) as fh:
        blob = fh.read().strip()
    standalone = os.path.join(HERE, "bytecode-selfdestruct.bin")
    with open(standalone, "w") as fh:
        fh.write(blob + "\n")
    print(f"wrote {standalone} (bytecode-only fixture)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
