"""Solidity source loading for oracle.

oracle accepts either EVM bytecode directly or Solidity source. Compiling
Solidity requires `solc`. To keep the test suite hermetic (criterion 6: no
runtime solc dependency for tests) every `.sol` fixture ships a sidecar
`<name>.bin` containing its pre-compiled runtime bytecode.

`load_runtime_bytecode` resolves source -> runtime bytecode with this
precedence:

1. If a sidecar `<source>.bin` exists next to the `.sol`, use it. This is the
   path the test suite and the shipped fixtures rely on — zero solc needed.
2. Otherwise compile with `py-solc-x` (which fetches a solc binary on demand).

[Worker decision: sidecar .bin files are the install-clean path. solc is only
invoked when a user analyses their own .sol that has no precompiled sidecar,
keeping oracle usable for real targets while keeping CI/tests solc-free.]
"""

from __future__ import annotations

import os
from typing import Optional


def load_runtime_bytecode(source_path: str, contract_name: Optional[str] = None) -> bytes:
    sidecar = _sidecar_path(source_path)
    if os.path.exists(sidecar):
        return _read_bin(sidecar)
    return _compile_with_solcx(source_path, contract_name)


def _sidecar_path(source_path: str) -> str:
    base, _ = os.path.splitext(source_path)
    return base + ".bin"


def _read_bin(path: str) -> bytes:
    with open(path, "r") as fh:
        text = fh.read()
    text = "".join(text.split())
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    return bytes.fromhex(text)


def _compile_with_solcx(source_path: str, contract_name: Optional[str]) -> bytes:
    try:
        import solcx
    except ImportError as exc:  # pragma: no cover - exercised only without solcx
        raise RuntimeError(
            "Compiling .sol requires py-solc-x. Either `pip install py-solc-x` "
            f"or ship a precompiled sidecar at {_sidecar_path(source_path)}."
        ) from exc

    with open(source_path, "r") as fh:
        source = fh.read()

    _ensure_solc(solcx)
    compiled = solcx.compile_source(source, output_values=["bin-runtime"])
    # compiled keys look like "<stdin>:ContractName"
    items = list(compiled.items())
    if contract_name:
        for key, val in items:
            if key.endswith(":" + contract_name):
                return bytes.fromhex(val["bin-runtime"])
        raise RuntimeError(f"contract {contract_name} not found in {source_path}")
    # default: last contract defined (typically the top-level one)
    _, val = items[-1]
    return bytes.fromhex(val["bin-runtime"])


def _ensure_solc(solcx) -> None:  # pragma: no cover - network/binary fetch
    try:
        solcx.get_solc_version()
    except Exception:
        solcx.install_solc()
        solcx.set_solc_version(solcx.get_installed_solc_versions()[-1])
