"""Solidity source loading for oracle.

oracle accepts either EVM bytecode directly or Solidity source. Compiling
Solidity requires `solc`. To keep the test suite hermetic (criterion 6: no
runtime solc dependency for tests) every `.sol` fixture ships a sidecar
`<name>.bin` containing its pre-compiled runtime bytecode.

The source -> runtime bytecode resolution (sidecar precedence, then compile
with py-solc-x) now lives in the shared `evm-toolkit` library so it is shared
verbatim with omen. This module is a thin, oracle-named re-export so existing
imports (`from oracle.compiler import load_runtime_bytecode`) keep working.

[Worker decision: the sidecar `.bin` precedence — use a precompiled sidecar
when present, otherwise invoke solc — is exactly evm_toolkit's
`load_runtime_bytecode` behavior, so oracle delegates rather than duplicating.]
"""

from __future__ import annotations

from typing import Optional

from evm_toolkit import load_runtime_bytecode as _load_runtime_bytecode


def load_runtime_bytecode(source_path: str, contract_name: Optional[str] = None) -> bytes:
    """Resolve a Solidity source path to runtime bytecode.

    Delegates to evm_toolkit, which prefers a precompiled `<source>.bin`
    sidecar (keeping tests solc-free) and otherwise compiles with py-solc-x.
    """
    return _load_runtime_bytecode(source_path, contract_name)
