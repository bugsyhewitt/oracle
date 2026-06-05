"""EVM opcode table for oracle's symbolic execution engine.

[Worker decision: oracle ships its own clean symbolic-EVM engine rather than
forking mythril's laser/ethereum/ verbatim. mythril's EVM engine couples
tightly to mythril.support, mythril.disassembler, and mythril.analysis (see
NOTICE), which would have required forking most of the mythril package and
would not install cleanly on a pinned modern Python. oracle's engine is
purpose-built for the v0.1 detector set, uses the forked mythril SMT wrapper
(oracle.laser.smt) directly, and is bounded to the opcodes the supported
checks require. The opcode mnemonics and semantics follow the canonical EVM
specification.]
"""

# (mnemonic, number_of_immediate_bytes)
OPCODES = {
    0x00: ("STOP", 0),
    0x01: ("ADD", 0),
    0x02: ("MUL", 0),
    0x03: ("SUB", 0),
    0x04: ("DIV", 0),
    0x05: ("SDIV", 0),
    0x06: ("MOD", 0),
    0x07: ("SMOD", 0),
    0x08: ("ADDMOD", 0),
    0x09: ("MULMOD", 0),
    0x0A: ("EXP", 0),
    0x0B: ("SIGNEXTEND", 0),
    0x10: ("LT", 0),
    0x11: ("GT", 0),
    0x12: ("SLT", 0),
    0x13: ("SGT", 0),
    0x14: ("EQ", 0),
    0x15: ("ISZERO", 0),
    0x16: ("AND", 0),
    0x17: ("OR", 0),
    0x18: ("XOR", 0),
    0x19: ("NOT", 0),
    0x1A: ("BYTE", 0),
    0x1B: ("SHL", 0),
    0x1C: ("SHR", 0),
    0x1D: ("SAR", 0),
    0x20: ("SHA3", 0),
    0x30: ("ADDRESS", 0),
    0x31: ("BALANCE", 0),
    0x32: ("ORIGIN", 0),
    0x33: ("CALLER", 0),
    0x34: ("CALLVALUE", 0),
    0x35: ("CALLDATALOAD", 0),
    0x36: ("CALLDATASIZE", 0),
    0x37: ("CALLDATACOPY", 0),
    0x38: ("CODESIZE", 0),
    0x39: ("CODECOPY", 0),
    0x3A: ("GASPRICE", 0),
    0x3B: ("EXTCODESIZE", 0),
    0x3C: ("EXTCODECOPY", 0),
    0x3D: ("RETURNDATASIZE", 0),
    0x3E: ("RETURNDATACOPY", 0),
    0x3F: ("EXTCODEHASH", 0),
    0x40: ("BLOCKHASH", 0),
    0x41: ("COINBASE", 0),
    0x42: ("TIMESTAMP", 0),
    0x43: ("NUMBER", 0),
    0x44: ("DIFFICULTY", 0),
    0x45: ("GASLIMIT", 0),
    0x46: ("CHAINID", 0),
    0x47: ("SELFBALANCE", 0),
    0x48: ("BASEFEE", 0),      # EIP-3198 (London): current block base fee
    0x49: ("BLOBHASH", 0),     # EIP-4844 (Dencun): versioned hash of blob at index
    0x4A: ("BLOBBASEFEE", 0),  # EIP-7516 (Dencun): current block blob base fee
    0x50: ("POP", 0),
    0x51: ("MLOAD", 0),
    0x52: ("MSTORE", 0),
    0x53: ("MSTORE8", 0),
    0x54: ("SLOAD", 0),
    0x55: ("SSTORE", 0),
    0x56: ("JUMP", 0),
    0x57: ("JUMPI", 0),
    0x58: ("PC", 0),
    0x59: ("MSIZE", 0),
    0x5A: ("GAS", 0),
    0x5B: ("JUMPDEST", 0),
    0x5C: ("TLOAD", 0),        # EIP-1153 (Cancun): transient storage load
    0x5D: ("TSTORE", 0),       # EIP-1153 (Cancun): transient storage store
    0x5E: ("MCOPY", 0),        # EIP-5656 (Cancun): memory copy
    0x5F: ("PUSH0", 0),
    0xF0: ("CREATE", 0),
    0xF1: ("CALL", 0),
    0xF5: ("CREATE2", 0),      # EIP-1014 (Constantinople): create at deterministic address
    0xF2: ("CALLCODE", 0),
    0xF3: ("RETURN", 0),
    0xF4: ("DELEGATECALL", 0),
    0xFA: ("STATICCALL", 0),
    0xFD: ("REVERT", 0),
    0xFE: ("INVALID", 0),
    0xFF: ("SELFDESTRUCT", 0),
}

# PUSH1..PUSH32 (0x60..0x7f)
for _i in range(1, 33):
    OPCODES[0x60 + _i - 1] = (f"PUSH{_i}", _i)
# DUP1..DUP16 (0x80..0x8f)
for _i in range(1, 17):
    OPCODES[0x80 + _i - 1] = (f"DUP{_i}", 0)
# SWAP1..SWAP16 (0x90..0x9f)
for _i in range(1, 17):
    OPCODES[0x90 + _i - 1] = (f"SWAP{_i}", 0)
# LOG0..LOG4 (0xa0..0xa4)
for _i in range(0, 5):
    OPCODES[0xA0 + _i] = (f"LOG{_i}", 0)


def mnemonic(byte: int) -> str:
    entry = OPCODES.get(byte)
    if entry is None:
        return f"UNKNOWN_0x{byte:02x}"
    return entry[0]
