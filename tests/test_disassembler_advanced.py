"""Advanced disassembler tests (Z3-free).

Exercises Disassembly edge cases: empty bytecode, unknown opcodes,
all PUSH variants, JUMPDEST detection, by_pc completeness, and
instruction list ordering.  Supplements the lighter test_disassembler.py.
"""

from __future__ import annotations

import pytest

from oracle.laser.disassembler import Disassembly, parse_bytecode


# ------------------------------------------------------------------ #
# parse_bytecode edge cases
# ------------------------------------------------------------------ #

def test_parse_bytecode_accepts_bytes_passthrough():
    b = b"\x60\x01"
    assert parse_bytecode(b) == b


def test_parse_bytecode_empty_string_raises():
    from evm_toolkit.bytecode import BytecodeError
    with pytest.raises(BytecodeError):
        parse_bytecode("")


def test_parse_bytecode_empty_bytes_gives_empty_bytes():
    assert parse_bytecode(b"") == b""


def test_parse_bytecode_uppercase_hex_accepted():
    assert parse_bytecode("0x600F") == b"\x60\x0f"


# ------------------------------------------------------------------ #
# Disassembly of empty bytecode
# ------------------------------------------------------------------ #

def test_empty_bytecode_no_instructions():
    d = Disassembly(b"")
    assert d.instructions == []


def test_empty_bytecode_by_pc_empty():
    d = Disassembly(b"")
    assert d.by_pc == {}


def test_empty_bytecode_no_jumpdests():
    d = Disassembly(b"")
    assert d.jumpdests == set()


# ------------------------------------------------------------------ #
# Unknown opcodes
# ------------------------------------------------------------------ #

def test_unknown_opcode_produces_instruction():
    # 0xEF is not a standard EVM opcode
    d = Disassembly(bytes([0xEF]))
    assert len(d.instructions) == 1
    assert "UNKNOWN" in d.instructions[0].mnemonic


def test_unknown_opcode_has_no_operand():
    d = Disassembly(bytes([0xEF]))
    assert d.instructions[0].operand is None


def test_unknown_opcode_advances_pc_by_one():
    # 0xEF (unknown) STOP
    d = Disassembly(bytes([0xEF, 0x00]))
    pcs = [i.pc for i in d.instructions]
    assert pcs == [0, 1]


# ------------------------------------------------------------------ #
# PUSH opcode variants
# ------------------------------------------------------------------ #

def test_push1_advances_pc_by_2():
    # PUSH1 0x42 STOP
    d = Disassembly(bytes([0x60, 0x42, 0x00]))
    pcs = [i.pc for i in d.instructions]
    assert pcs == [0, 2]


def test_push2_advances_pc_by_3():
    # PUSH2 0x0102 STOP
    d = Disassembly(bytes([0x61, 0x01, 0x02, 0x00]))
    pcs = [i.pc for i in d.instructions]
    assert pcs == [0, 3]


def test_push1_operand_value():
    # PUSH1 0x7f
    d = Disassembly(bytes([0x60, 0x7F]))
    assert d.by_pc[0].operand == 0x7F


def test_push2_operand_combines_two_bytes():
    # PUSH2 0xBEEF
    d = Disassembly(bytes([0x61, 0xBE, 0xEF]))
    assert d.by_pc[0].operand == 0xBEEF


def test_push3_reads_three_immediate_bytes():
    # PUSH3 0x010203
    d = Disassembly(bytes([0x62, 0x01, 0x02, 0x03]))
    assert d.by_pc[0].mnemonic == "PUSH3"
    assert d.by_pc[0].operand == 0x010203


# ------------------------------------------------------------------ #
# JUMPDEST detection
# ------------------------------------------------------------------ #

def test_multiple_jumpdests_recorded():
    # JUMPDEST STOP JUMPDEST STOP
    d = Disassembly(bytes([0x5B, 0x00, 0x5B, 0x00]))
    assert d.jumpdests == {0, 2}


def test_no_jumpdest_in_push_operand():
    # PUSH1 0x5B (0x5B is JUMPDEST opcode value but it's an operand here)
    d = Disassembly(bytes([0x60, 0x5B, 0x00]))
    # only pc=2 (STOP) follows; JUMPDEST opcode 0x5B is consumed as operand
    assert 1 not in d.jumpdests


# ------------------------------------------------------------------ #
# by_pc completeness and ordering
# ------------------------------------------------------------------ #

def test_by_pc_covers_all_instructions():
    # PUSH1 0x01 PUSH1 0x02 ADD STOP
    d = Disassembly(bytes([0x60, 0x01, 0x60, 0x02, 0x01, 0x00]))
    for inst in d.instructions:
        assert inst.pc in d.by_pc
        assert d.by_pc[inst.pc] is inst


def test_instructions_list_is_sorted_by_pc():
    # PUSH1 0x01 PUSH1 0x02 ADD STOP
    d = Disassembly(bytes([0x60, 0x01, 0x60, 0x02, 0x01, 0x00]))
    pcs = [i.pc for i in d.instructions]
    assert pcs == sorted(pcs)


def test_instruction_opcode_byte_matches_input():
    # STOP INVALID SELFDESTRUCT
    d = Disassembly(bytes([0x00, 0xFE, 0xFF]))
    assert d.by_pc[0].opcode == 0x00
    assert d.by_pc[1].opcode == 0xFE
    assert d.by_pc[2].opcode == 0xFF


def test_non_push_ops_have_no_operand():
    # STOP ADD MUL SUB
    d = Disassembly(bytes([0x00, 0x01, 0x02, 0x03]))
    for inst in d.instructions:
        assert inst.operand is None


# ------------------------------------------------------------------ #
# Longer bytecode integration
# ------------------------------------------------------------------ #

def test_typical_free_function_preamble_parses_cleanly():
    # PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH1 0x0e JUMPI PUSH1 0x00 DUP1 REVERT JUMPDEST POP
    code = bytes.fromhex("6080604052348015600e57600080fd5b50")
    d = Disassembly(code)
    # just check it completes and has sane structure
    assert d.instructions
    assert all(i.pc in d.by_pc for i in d.instructions)
    pcs = [i.pc for i in d.instructions]
    assert pcs == sorted(pcs)
