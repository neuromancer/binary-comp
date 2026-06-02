"""Capstone-backed instruction decoding helpers."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

from .pe import PEImage

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
except ImportError:  # pragma: no cover - exercised by users without optional extra
    Cs = None
    CS_ARCH_X86 = CS_MODE_32 = X86_OP_IMM = X86_OP_MEM = X86_OP_REG = None


@dataclass(frozen=True)
class Operand:
    kind: str
    text: str
    reg: str = ""
    imm: int = 0
    base: str = ""
    index: str = ""
    scale: int = 0
    disp: int = 0
    size: int = 0


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    operands: tuple[Operand, ...]
    raw: str
    size: int = 0


def require_capstone() -> None:
    if Cs is None:
        raise RuntimeError("capstone is required. Install with: python3 -m pip install binary-comp[capstone]")


def signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def unsigned32(value: int) -> int:
    return value & 0xFFFFFFFF


def normalize_mnemonic(mnemonic: str) -> str:
    aliases = {
        "je": "jz",
        "jne": "jnz",
        "jb": "jc",
        "jnae": "jc",
        "jae": "jnc",
        "jnb": "jnc",
        "jg": "jnle",
        "jnle": "jnle",
        "jge": "jnl",
        "jnl": "jnl",
        "jl": "jnge",
        "jnge": "jnge",
        "jle": "jng",
        "jng": "jng",
    }
    return aliases.get(mnemonic.lower(), mnemonic.lower())


def is_branch_or_call(mnemonic: str) -> bool:
    return mnemonic.startswith("j") or mnemonic in {"call", "loop", "loope", "loopne", "jecxz"}


def next_boundary(starts: Iterable[int], start: int) -> int | None:
    for candidate in starts:
        if candidate > start:
            return candidate
    return None


def function_bytes(image: PEImage, start: int, starts: Iterable[int], max_bytes: int) -> tuple[bytes | None, int | None]:
    section_end = image.section_end_for_va(start)
    if section_end is None:
        return None, None
    end = next_boundary(starts, start)
    if end is None or end > section_end:
        end = section_end
    if end <= start:
        return None, None
    size = min(end - start, max_bytes)
    return image.read(start, size), start + size


def make_operand(insn, op) -> Operand:
    if op.type == X86_OP_REG:
        reg = insn.reg_name(op.reg)
        return Operand("reg", reg, reg=reg, size=op.size)
    if op.type == X86_OP_IMM:
        imm = signed32(op.imm)
        return Operand("imm", str(imm), imm=imm, size=op.size)
    if op.type == X86_OP_MEM:
        base = insn.reg_name(op.mem.base) if op.mem.base else ""
        index = insn.reg_name(op.mem.index) if op.mem.index else ""
        return Operand(
            "mem",
            "",
            base=base,
            index=index,
            scale=op.mem.scale,
            disp=signed32(op.mem.disp),
            size=op.size,
        )
    return Operand("other", "")


def disassemble_x86(
    image: PEImage,
    start: int,
    starts: Iterable[int],
    max_bytes: int,
    padding_mnemonics: frozenset[str],
    trim_msvc_seh: bool = True,
    remove_jump_tables: bool = True,
) -> list[Instruction]:
    require_capstone()
    data, end = function_bytes(image, start, starts, max_bytes)
    if not data or end is None:
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    instructions: list[Instruction] = []
    for insn in md.disasm(data, start):
        mnemonic = normalize_mnemonic(insn.mnemonic)
        if mnemonic in padding_mnemonics:
            continue
        operands = tuple(make_operand(insn, op) for op in insn.operands)
        instructions.append(Instruction(
            address=insn.address,
            mnemonic=mnemonic,
            op_str=insn.op_str,
            operands=operands,
            raw=f"{insn.mnemonic} {insn.op_str}".strip(),
            size=insn.size,
        ))

    if remove_jump_tables:
        data_ranges = switch_jump_table_ranges(image, instructions, start, end)
        if data_ranges:
            instructions = [
                instr for instr in instructions
                if not address_in_ranges(instr.address, data_ranges)
            ]

    if trim_msvc_seh:
        instructions = trim_seh_cleanup_funclets(instructions)
    while instructions and instructions[-1].mnemonic in padding_mnemonics:
        instructions.pop()
    return instructions


def address_in_ranges(address: int, ranges: Iterable[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def switch_jump_table_ranges(
    image: PEImage,
    instrs: list[Instruction],
    func_start: int,
    func_end: int,
) -> tuple[tuple[int, int], ...]:
    """Find MSVC switch tables embedded in a function body."""
    ranges: list[tuple[int, int]] = []
    for instr in instrs:
        if instr.mnemonic != "jmp" or len(instr.operands) != 1:
            continue

        operand = instr.operands[0]
        if operand.kind != "mem":
            continue
        if operand.base or not operand.index or operand.scale != 4:
            continue

        table_start = unsigned32(operand.disp)
        if not (func_start <= table_start < func_end):
            continue

        table_end = switch_jump_table_end(image, table_start, func_start, func_end)
        if table_end is not None:
            ranges.append((table_start, table_end))

    ranges.extend(switch_byte_map_ranges(instrs, func_start, func_end))
    return merge_ranges(ranges)


def switch_jump_table_end(image: PEImage, table_start: int, func_start: int, func_end: int) -> int | None:
    cursor = table_start
    entries = 0
    while cursor + 4 <= func_end:
        raw = image.read(cursor, 4)
        if raw is None or len(raw) != 4:
            break
        target = struct.unpack("<I", raw)[0]
        if not (func_start <= target < func_end):
            break
        entries += 1
        cursor += 4

    if entries == 0:
        return None
    return cursor


def full_register_name(reg: str) -> str:
    aliases = {
        "al": "eax", "ah": "eax", "ax": "eax",
        "bl": "ebx", "bh": "ebx", "bx": "ebx",
        "cl": "ecx", "ch": "ecx", "cx": "ecx",
        "dl": "edx", "dh": "edx", "dx": "edx",
    }
    return aliases.get(reg, reg)


def switch_map_source_register(operand: Operand) -> str | None:
    if operand.kind != "mem":
        return None
    if operand.index and operand.scale not in (0, 1):
        return None
    if operand.base and operand.index:
        return None
    return full_register_name(operand.base or operand.index)


def previous_cmp_upper_bound(instrs: list[Instruction], idx: int, reg: str) -> int | None:
    for j in range(idx - 1, max(-1, idx - 8), -1):
        instr = instrs[j]
        if instr.mnemonic != "cmp" or len(instr.operands) < 2:
            continue
        left, right = instr.operands[0], instr.operands[1]
        if left.kind != "reg" or full_register_name(left.reg) != reg:
            continue
        if right.kind != "imm" or right.imm < 0:
            continue
        return right.imm
    return None


def following_indirect_jump_uses(instrs: list[Instruction], idx: int, reg: str) -> bool:
    for j in range(idx + 1, min(len(instrs), idx + 5)):
        instr = instrs[j]
        if instr.mnemonic != "jmp" or len(instr.operands) != 1:
            continue
        operand = instr.operands[0]
        if operand.kind == "mem" and operand.index == reg and operand.scale == 4:
            return True
    return False


def switch_byte_map_ranges(
    instrs: list[Instruction],
    func_start: int,
    func_end: int,
) -> tuple[tuple[int, int], ...]:
    """Find MSVC byte dispatch maps used before indirect switch jump tables."""
    ranges: list[tuple[int, int]] = []
    for idx, instr in enumerate(instrs):
        if instr.mnemonic not in {"mov", "movzx"} or len(instr.operands) < 2:
            continue

        dst, src = instr.operands[0], instr.operands[1]
        if dst.kind != "reg" or src.kind != "mem" or src.size != 1:
            continue

        table_start = unsigned32(src.disp)
        if not (func_start <= table_start < func_end):
            continue

        source_reg = switch_map_source_register(src)
        if source_reg is None:
            continue

        jump_reg = full_register_name(dst.reg)
        if not following_indirect_jump_uses(instrs, idx, jump_reg):
            continue

        upper_bound = previous_cmp_upper_bound(instrs, idx, source_reg)
        if upper_bound is None:
            continue

        table_end = table_start + upper_bound + 1
        if table_start < table_end <= func_end:
            ranges.append((table_start, table_end))

    return tuple(ranges)


def merge_ranges(ranges: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
            continue
        merged[-1][1] = max(merged[-1][1], end)
    return tuple((start, end) for start, end in merged)


def has_msvc_seh_frame(instrs: list[Instruction]) -> bool:
    """MSVC places EH cleanup funclets after the main body RET."""
    scan = instrs[:12]
    saw_fs_read = any(instr.mnemonic == "mov" and "fs:" in instr.op_str.lower() for instr in scan)
    saw_sentinel = any(
        instr.mnemonic == "push"
        and instr.operands
        and instr.operands[0].kind == "imm"
        and instr.operands[0].imm == -1
        for instr in scan
    )
    saw_fs_write = any(instr.mnemonic == "mov" and "fs:" in instr.op_str.lower() for instr in instrs[:24])
    return saw_fs_read and saw_sentinel and saw_fs_write


def trim_seh_cleanup_funclets(instrs: list[Instruction]) -> list[Instruction]:
    if not has_msvc_seh_frame(instrs):
        return instrs
    for idx, instr in enumerate(instrs):
        if instr.mnemonic == "ret":
            return instrs[:idx + 1]
    return instrs
