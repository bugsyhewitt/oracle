"""Tests for the EVM disassembler (Z3-free)."""

from oracle.laser.disassembler import Disassembly, parse_bytecode


def test_parse_bytecode_accepts_hex_prefix():
    assert parse_bytecode("0x6001") == b"\x60\x01"


def test_parse_bytecode_accepts_bare_hex():
    assert parse_bytecode("6001") == b"\x60\x01"


def test_parse_bytecode_strips_whitespace():
    assert parse_bytecode("60 01\n") == b"\x60\x01"


def test_disassemble_push_operands():
    # PUSH1 0x80 PUSH1 0x40 MSTORE
    d = Disassembly(bytes.fromhex("6080604052"))
    assert d.by_pc[0].mnemonic == "PUSH1"
    assert d.by_pc[0].operand == 0x80
    assert d.by_pc[2].mnemonic == "PUSH1"
    assert d.by_pc[2].operand == 0x40
    assert d.by_pc[4].mnemonic == "MSTORE"


def test_disassemble_records_jumpdests():
    # JUMPDEST STOP
    d = Disassembly(bytes.fromhex("5b00"))
    assert 0 in d.jumpdests


def test_push32_consumes_32_immediate_bytes():
    code = b"\x7f" + b"\x11" * 32 + b"\x00"  # PUSH32 ... STOP
    d = Disassembly(code)
    assert d.by_pc[0].mnemonic == "PUSH32"
    assert d.by_pc[33].mnemonic == "STOP"


def test_returndata_and_extcode_opcodes_are_in_table():
    # EXTCODESIZE EXTCODECOPY RETURNDATASIZE RETURNDATACOPY EXTCODEHASH
    d = Disassembly(bytes.fromhex("3b3c3d3e3f"))
    assert d.by_pc[0].mnemonic == "EXTCODESIZE"
    assert d.by_pc[1].mnemonic == "EXTCODECOPY"
    assert d.by_pc[2].mnemonic == "RETURNDATASIZE"
    assert d.by_pc[3].mnemonic == "RETURNDATACOPY"
    assert d.by_pc[4].mnemonic == "EXTCODEHASH"
