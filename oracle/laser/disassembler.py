"""EVM bytecode disassembler for oracle.

Turns a runtime bytecode blob into a list of `Instruction` records keyed by
program counter, and pre-computes the set of valid JUMPDEST addresses.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from oracle.laser.opcodes import OPCODES


@dataclass
class Instruction:
    pc: int
    opcode: int
    mnemonic: str
    operand: Optional[int]  # immediate value for PUSH ops, else None


class Disassembly:
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.instructions: List[Instruction] = []
        self.by_pc: Dict[int, Instruction] = {}
        self.jumpdests: Set[int] = set()
        self._disassemble()

    def _disassemble(self) -> None:
        pc = 0
        code = self.bytecode
        n = len(code)
        while pc < n:
            byte = code[pc]
            entry = OPCODES.get(byte)
            if entry is None:
                mnem, imm_len = f"UNKNOWN_0x{byte:02x}", 0
            else:
                mnem, imm_len = entry
            operand: Optional[int] = None
            if imm_len > 0:
                raw = code[pc + 1 : pc + 1 + imm_len]
                operand = int.from_bytes(raw.ljust(imm_len, b"\x00"), "big")
            inst = Instruction(pc=pc, opcode=byte, mnemonic=mnem, operand=operand)
            self.instructions.append(inst)
            self.by_pc[pc] = inst
            if mnem == "JUMPDEST":
                self.jumpdests.add(pc)
            pc += 1 + imm_len


def parse_bytecode(hex_or_bytes) -> bytes:
    """Accept a 0x-prefixed hex string, a bare hex string, or raw bytes."""
    if isinstance(hex_or_bytes, bytes):
        return hex_or_bytes
    s = hex_or_bytes.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    # Strip whitespace/newlines that may appear in fixture files
    s = "".join(s.split())
    return bytes.fromhex(s)
