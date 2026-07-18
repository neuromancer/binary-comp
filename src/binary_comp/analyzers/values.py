"""Capstone-backed operand value verification."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from importlib import resources

from binary_comp.config import ConfigError, ProjectTarget, parse_int
from binary_comp.core.align import lcs_align
from binary_comp.core.disasm import (
    Instruction,
    Operand,
    disassemble_x86,
    full_register_name,
    has_msvc_seh_frame,
    is_branch_or_call,
    unsigned32,
)
from binary_comp.core.ghidra import function_starts_from_export_dir
from binary_comp.core.mapfile import function_starts_from_map
from binary_comp.core.pe import PEImage
from binary_comp.core.symbols import canonical_function_name
from binary_comp.source.functions import FunctionGroup, load_source_groups, map_source_groups


@dataclass(frozen=True)
class CheckResult:
    original_addr: int
    rebuilt_addr: int
    similarity: float
    original_count: int
    rebuilt_count: int
    warnings: tuple


@dataclass(frozen=True)
class VerifierPolicy:
    max_disassembly_bytes: int
    max_member_displacement: int
    nearby_window: int
    small_immediate_min: int
    small_immediate_max: int
    value_mnemonics: frozenset[str]
    padding_mnemonics: frozenset[str]
    stack_registers: frozenset[str]
    diagnostic_functions: frozenset[str]
    allowed_one_char_strings: frozenset[str]
    rejected_string_substrings: tuple[str, ...]


@dataclass(frozen=True)
class CompareContext:
    enabled_kinds: frozenset[str]
    policy: VerifierPolicy
    include_stack_locals: bool
    compiled_diagnostic_targets: frozenset[int]
    original_diagnostic_targets: frozenset[int]
    compiled_call_targets: dict[int, str] = field(default_factory=dict)
    original_call_targets: dict[int, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ValuesOptions:
    file_filter: str | None = None
    min_similarity: float = 0.0
    build: bool = True
    enabled_kinds: frozenset[str] = frozenset({"strings", "immediates", "offsets"})
    boundary_report: bool = False
    include_stack_locals: bool = False


@dataclass(frozen=True)
class ValuesSummary:
    functions_checked: int
    with_value_mismatches: int
    total_mismatches: int
    skipped_no_bytes: int
    skipped_below_threshold: int
    unmapped_source_groups: int
    boundary_inventory: dict[str, int]
    reports: tuple[tuple[FunctionGroup, CheckResult], ...]


def default_policy_path() -> str:
    return str(resources.files("binary_comp.data").joinpath("default_values_policy.json"))


def required_config(config: dict, key: str, label: str):
    if not isinstance(config, dict):
        raise ConfigError(f"{label} must be a JSON object")
    if key not in config:
        raise ConfigError(f"missing required value-check config field: {label}.{key}")
    return config[key]


def string_list_config(config: dict, key: str, label: str) -> list[str]:
    value = required_config(config, key, label)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{label}.{key} must be a list of strings")
    return value


def load_policy(path: str | None = None) -> VerifierPolicy:
    if not path:
        path = default_policy_path()
    if not os.path.exists(path):
        raise ConfigError(f"value-check policy file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)
    if not isinstance(config, dict):
        raise ConfigError(f"value-check policy root must be an object: {path}")

    literal_config = required_config(config, "literal_strings", "policy")
    return VerifierPolicy(
        max_disassembly_bytes=parse_int(
            required_config(config, "max_disassembly_bytes", "policy"),
            "policy.max_disassembly_bytes",
        ),
        max_member_displacement=parse_int(
            required_config(config, "max_member_displacement", "policy"),
            "policy.max_member_displacement",
        ),
        nearby_window=parse_int(required_config(config, "nearby_window", "policy"), "policy.nearby_window"),
        small_immediate_min=parse_int(
            required_config(config, "small_immediate_min", "policy"),
            "policy.small_immediate_min",
        ),
        small_immediate_max=parse_int(
            required_config(config, "small_immediate_max", "policy"),
            "policy.small_immediate_max",
        ),
        value_mnemonics=frozenset(m.lower() for m in string_list_config(config, "value_mnemonics", "policy")),
        padding_mnemonics=frozenset(m.lower() for m in string_list_config(config, "padding_mnemonics", "policy")),
        stack_registers=frozenset(r.lower() for r in string_list_config(config, "stack_registers", "policy")),
        diagnostic_functions=frozenset(string_list_config(config, "diagnostic_functions", "policy")),
        allowed_one_char_strings=frozenset(
            string_list_config(literal_config, "allowed_one_char", "policy.literal_strings")
        ),
        rejected_string_substrings=tuple(
            string_list_config(literal_config, "reject_substrings", "policy.literal_strings")
        ),
    )


def normalize_string(value: str) -> str:
    value = value.replace("\\\\", "\\")
    value = value.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
    return value


def normalize_string_for_compare(value: str | None) -> str | None:
    if value is None:
        return None
    value = normalize_string(value)
    value = value.strip().strip('"').strip("\\").strip('"')
    return value


def looks_like_literal_string(value: str, policy: VerifierPolicy) -> bool:
    """Reject common false positives from decoding pointers as text."""
    for rejected in policy.rejected_string_substrings:
        if rejected in value:
            return False
    if len(value) == 1:
        return value in policy.allowed_one_char_strings
    if len(value) <= 3:
        if "%" in value:
            return True
        if value.isalpha() and (value.islower() or value.isupper()):
            return True
        return False
    return any(ch.isalpha() for ch in value)


def build_diagnostic_targets(function_groups: list[FunctionGroup], policy: VerifierPolicy) -> tuple[frozenset[int], frozenset[int]]:
    original_targets: set[int] = set()
    rebuilt_targets: set[int] = set()
    for group in function_groups:
        if canonical_function_name(group.name) not in policy.diagnostic_functions:
            continue
        original_targets.update(group.original_addrs)
        rebuilt_targets.add(group.rebuilt_addr)
    return frozenset(original_targets), frozenset(rebuilt_targets)


def build_call_target_names(function_groups: list[FunctionGroup]) -> tuple[dict[int, str], dict[int, str]]:
    original_targets: dict[int, str] = {}
    rebuilt_targets: dict[int, str] = {}
    for group in function_groups:
        name = canonical_function_name(group.name)
        for address in group.original_addrs:
            original_targets[address] = name
        rebuilt_targets[group.rebuilt_addr] = name
    return original_targets, rebuilt_targets


def load_original_boundary_starts(code_dir: str | None, function_groups: list[FunctionGroup]) -> list[int]:
    starts = set(function_starts_from_export_dir(code_dir))
    for group in function_groups:
        starts.update(group.original_addrs)
    return sorted(starts)


def disassemble(image: PEImage, start: int, starts: list[int], policy: VerifierPolicy) -> list[Instruction]:
    boundaries = set(starts)
    for _ in range(8):
        instructions = disassemble_x86(
            image,
            start,
            sorted(boundaries),
            max_bytes=policy.max_disassembly_bytes,
            padding_mnemonics=policy.padding_mnemonics,
        )
        fragment = contiguous_tail_fragment_start(instructions, boundaries)
        if fragment is None:
            return instructions
        boundaries.remove(fragment)
    return instructions


def contiguous_tail_fragment_start(
    instructions: list[Instruction],
    boundaries: set[int],
) -> int | None:
    """Find a Ghidra-split continuation immediately following a function.

    Some optimized class predicates branch into a contiguous shared tail that
    Ghidra exported as a second function.  Treat that target as part of the
    caller when the current fragment both reaches it directly and ends exactly
    at the boundary.  This does not merge an ordinary adjacent function merely
    because it follows in address order.
    """
    if not instructions:
        return None
    end = max(instr.address + instr.size for instr in instructions)
    if end not in boundaries:
        return None
    for instr in instructions:
        if (
            is_branch_or_call(instr.mnemonic)
            and instr.mnemonic != "call"
            and instr.operands
            and instr.operands[0].kind == "imm"
            and unsigned32(instr.operands[0].imm) == end
        ):
            return end
    return None


def operand_signature(operand: Operand) -> tuple:
    if operand.kind == "reg":
        return ("reg", operand.reg)
    if operand.kind == "mem":
        return ("mem", operand.base, operand.index, operand.scale)
    return (operand.kind,)


def comparable_lhs(
    left: Operand,
    right: Operand,
    policy: VerifierPolicy,
    include_stack_locals: bool = False,
) -> bool:
    if left.kind != right.kind:
        return False
    if left.kind == "reg":
        return left.reg == right.reg
    if left.kind != "mem":
        return False
    if left.base != right.base or left.index != right.index or left.scale != right.scale:
        return False
    if left.base in policy.stack_registers and not include_stack_locals:
        return False
    if not left.base:
        return False
    return True


def comparable_operands(compiled: Instruction, original: Instruction) -> bool:
    if len(compiled.operands) != len(original.operands):
        return False
    for c_op, o_op in zip(compiled.operands, original.operands):
        if c_op.kind == "imm" or o_op.kind == "imm":
            if c_op.kind != o_op.kind:
                return False
            continue
        if operand_signature(c_op) != operand_signature(o_op):
            return False
    return True


def immediate_operands(instr: Instruction) -> list[tuple[int, Operand]]:
    return [(idx, op) for idx, op in enumerate(instr.operands) if op.kind == "imm"]


def memory_operands(instr: Instruction) -> list[tuple[int, Operand]]:
    return [(idx, op) for idx, op in enumerate(instr.operands) if op.kind == "mem"]


def immediate_string(image: PEImage, operand: Operand, policy: VerifierPolicy) -> str | None:
    return image.c_string_at(unsigned32(operand.imm), predicate=lambda value: looks_like_literal_string(value, policy))


def small_numeric_immediate(operand: Operand, policy: VerifierPolicy) -> bool:
    value = operand.imm
    return policy.small_immediate_min <= value < policy.small_immediate_max


def has_pointer_immediate(instr: Instruction) -> bool:
    return any(unsigned32(operand.imm) >= 0x400000 for _, operand in immediate_operands(instr))


def member_displacement(value: int, policy: VerifierPolicy) -> bool:
    return -policy.max_member_displacement < value < policy.max_member_displacement


def lhs_is_stack_memory(instr: Instruction, policy: VerifierPolicy) -> bool:
    if not instr.operands:
        return False
    operand = instr.operands[0]
    return operand.kind == "mem" and operand.base in policy.stack_registers


def is_msvc_eh_state_slot(operand: Operand) -> bool:
    return operand.kind == "mem" and operand.base == "ebp" and not operand.index and operand.disp == -4


def writes_msvc_eh_state(instr: Instruction) -> bool:
    if not instr.operands:
        return False
    return is_msvc_eh_state_slot(instr.operands[0])


def compare_targets_msvc_eh_state(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled: Instruction,
    original: Instruction,
    context: CompareContext,
) -> bool:
    if not context.include_stack_locals:
        return False
    if not (writes_msvc_eh_state(compiled) or writes_msvc_eh_state(original)):
        return False
    return has_msvc_seh_frame(compiled_instrs) or has_msvc_seh_frame(original_instrs)


def has_stack_memory_operand(instr: Instruction, policy: VerifierPolicy) -> bool:
    return any(op.kind == "mem" and op.base in policy.stack_registers for op in instr.operands)


def should_compare_values(compiled: Instruction, original: Instruction, context: CompareContext) -> bool:
    if compiled.mnemonic in context.policy.value_mnemonics:
        return True
    return (
        context.include_stack_locals
        and compiled.mnemonic == "lea"
        and (
            has_stack_memory_operand(compiled, context.policy)
            or has_stack_memory_operand(original, context.policy)
        )
    )


def nearby_immediate_values(instrs: list[Instruction], idx: int, policy: VerifierPolicy) -> set[int]:
    values: set[int] = set()
    start = max(0, idx - policy.nearby_window)
    end = min(len(instrs), idx + policy.nearby_window + 1)
    for j in range(start, end):
        for _, operand in immediate_operands(instrs[j]):
            if small_numeric_immediate(operand, policy):
                values.add(operand.imm)
    return values


def nearby_strings(instrs: list[Instruction], image: PEImage, idx: int, policy: VerifierPolicy) -> set[str | None]:
    values: set[str | None] = set()
    start = max(0, idx - policy.nearby_window)
    end = min(len(instrs), idx + policy.nearby_window + 1)
    for j in range(start, end):
        for _, operand in immediate_operands(instrs[j]):
            string = immediate_string(image, operand, policy)
            if string is not None:
                values.add(normalize_string_for_compare(string))
    return values


def nearby_calls_target(instrs: list[Instruction], idx: int, targets: frozenset[int], window: int = 8) -> bool:
    if not targets:
        return False
    end = min(len(instrs), idx + window + 1)
    for j in range(idx + 1, end):
        instr = instrs[j]
        if instr.mnemonic != "call":
            continue
        for _, operand in immediate_operands(instr):
            if unsigned32(operand.imm) in targets:
                return True
    return False


def nearby_memory_displacements(
    instrs: list[Instruction],
    idx: int,
    policy: VerifierPolicy,
    mnemonic: str | None = None,
) -> set[int]:
    values: set[int] = set()
    start = max(0, idx - policy.nearby_window)
    end = min(len(instrs), idx + policy.nearby_window + 1)
    aliases: dict[str, Operand] = {}
    for j in range(start, end):
        instr = instrs[j]
        if mnemonic is None or instr.mnemonic == mnemonic:
            for _, operand in memory_operands(instr):
                if member_displacement(operand.disp, policy):
                    values.add(operand.disp)
                alias = aliases.get(operand.base)
                if alias is not None and not operand.index:
                    effective_disp = alias.disp + operand.disp
                    if member_displacement(effective_disp, policy):
                        values.add(effective_disp)

        update_register_aliases(aliases, instr, policy)

    return values


def writes_register(instr: Instruction, reg: str) -> bool:
    if not instr.operands:
        return False
    operand = instr.operands[0]
    return operand.kind == "reg" and operand.reg == reg


def stack_slot_key(operand: Operand, policy: VerifierPolicy) -> tuple[str, int] | None:
    if operand.kind != "mem" or operand.base not in policy.stack_registers or operand.index:
        return None
    return (operand.base, operand.disp)


def stack_slot_alias(operand: Operand, policy: VerifierPolicy) -> Operand | None:
    key = stack_slot_key(operand, policy)
    if key is None:
        return None
    return Operand("mem", "", base=f"stack:{key[0]}:{key[1]}", scale=1)


def update_register_aliases(
    aliases: dict[str, Operand],
    instr: Instruction,
    policy: VerifierPolicy,
    stack_aliases: dict[tuple[str, int], Operand] | None = None,
) -> None:
    if instr.mnemonic == "call":
        for reg in ("eax", "ecx", "edx"):
            aliases.pop(reg, None)
        return

    if instr.mnemonic == "mov" and len(instr.operands) >= 2:
        dst = instr.operands[0]
        src = instr.operands[1]
        if dst.kind == "reg" and src.kind == "mem":
            key = stack_slot_key(src, policy)
            if key is not None:
                if stack_aliases is not None and key in stack_aliases:
                    aliases[dst.reg] = stack_aliases[key]
                else:
                    alias = stack_slot_alias(src, policy)
                    if alias is not None:
                        aliases[dst.reg] = alias
                return
        if dst.kind == "mem" and src.kind == "reg":
            key = stack_slot_key(dst, policy)
            if stack_aliases is not None and key is not None:
                alias = aliases.get(src.reg)
                if alias is None:
                    stack_aliases.pop(key, None)
                else:
                    stack_aliases[key] = alias
                return

    if instr.mnemonic == "lea" and len(instr.operands) >= 2:
        dst = instr.operands[0]
        src = instr.operands[1]
        if dst.kind == "reg" and src.kind == "mem":
            if src.base and src.base not in policy.stack_registers and member_displacement(src.disp, policy):
                aliases[dst.reg] = src
            else:
                aliases.pop(dst.reg, None)
        return

    if instr.mnemonic in {"add", "sub"} and len(instr.operands) >= 2:
        dst = instr.operands[0]
        src = instr.operands[1]
        if dst.kind == "reg" and src.kind == "imm" and member_displacement(src.imm, policy):
            current = aliases.get(dst.reg, Operand("mem", "", base=dst.reg, scale=1))
            delta = src.imm if instr.mnemonic == "add" else -src.imm
            aliases[dst.reg] = Operand(
                "mem",
                "",
                base=current.base,
                index=current.index,
                scale=current.scale,
                disp=current.disp + delta,
            )
            return

    register_write_mnemonics = {
        "mov", "xor", "or", "and", "imul",
        "shl", "shr", "sar", "inc", "dec",
    }
    if instr.mnemonic in register_write_mnemonics and instr.operands and instr.operands[0].kind == "reg":
        aliases.pop(instr.operands[0].reg, None)


def recent_pointer_alias(
    instrs: list[Instruction],
    idx: int,
    reg: str,
    policy: VerifierPolicy,
    max_window: int = 8,
) -> Operand | None:
    start = max(0, idx - max_window)
    for j in range(idx - 1, start - 1, -1):
        instr = instrs[j]
        if instr.mnemonic == "call" or is_branch_or_call(instr.mnemonic):
            return None
        if not writes_register(instr, reg):
            continue
        if instr.mnemonic == "lea" and len(instr.operands) >= 2:
            src = instr.operands[1]
            if src.kind != "mem" or not src.base or src.base in policy.stack_registers:
                return None
            if not member_displacement(src.disp, policy):
                return None
            return src
        if instr.mnemonic in {"add", "sub"} and len(instr.operands) >= 2:
            src = instr.operands[1]
            if src.kind != "imm" or not member_displacement(src.imm, policy):
                return None
            delta = src.imm if instr.mnemonic == "add" else -src.imm
            return Operand("mem", "", base=reg, scale=1, disp=delta)
        return None
    return None


def register_alias_at(instrs: list[Instruction], idx: int, reg: str, policy: VerifierPolicy) -> Operand | None:
    aliases: dict[str, Operand] = {}
    stack_aliases: dict[tuple[str, int], Operand] = {}
    for j in range(0, idx):
        update_register_aliases(aliases, instrs[j], policy, stack_aliases)
    return aliases.get(reg)


def append_unique_alias(aliases: list[Operand], alias: Operand | None) -> None:
    if alias is None:
        return
    key = (alias.kind, alias.base, alias.index, alias.scale, alias.disp)
    if key in {(item.kind, item.base, item.index, item.scale, item.disp) for item in aliases}:
        return
    aliases.append(alias)


def pointer_aliases_at(instrs: list[Instruction], idx: int, reg: str, policy: VerifierPolicy) -> list[Operand]:
    aliases: list[Operand] = []
    append_unique_alias(aliases, recent_pointer_alias(instrs, idx, reg, policy))
    append_unique_alias(aliases, register_alias_at(instrs, idx, reg, policy))
    return aliases


def equivalent_alias_displacement(
    c_alias: Operand | None,
    o_alias: Operand | None,
    c_disp: int,
    o_disp: int,
) -> bool:
    if c_alias is None and o_alias is None:
        return False
    if c_alias is not None and o_alias is not None:
        if c_alias.base != o_alias.base or c_alias.index != o_alias.index or c_alias.scale != o_alias.scale:
            return False
        return c_alias.disp + c_disp == o_alias.disp + o_disp
    if c_alias is not None:
        return c_alias.disp + c_disp == o_disp
    return c_disp == o_alias.disp + o_disp


def same_effective_lea_displacement(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    c_op: Operand,
    o_op: Operand,
    policy: VerifierPolicy,
) -> bool:
    c_aliases = pointer_aliases_at(compiled_instrs, ci, c_op.base, policy)
    o_aliases = pointer_aliases_at(original_instrs, oi, o_op.base, policy)
    if not c_aliases and not o_aliases:
        return False

    for c_alias in c_aliases or [None]:
        for o_alias in o_aliases or [None]:
            if equivalent_alias_displacement(c_alias, o_alias, c_op.disp, o_op.disp):
                return True
    return False


def affine_add(
    left: tuple[dict[str, int], int],
    right: tuple[dict[str, int], int],
    scale: int = 1,
) -> tuple[dict[str, int], int]:
    coefficients = dict(left[0])
    for name, coefficient in right[0].items():
        coefficients[name] = coefficients.get(name, 0) + coefficient * scale
        if coefficients[name] == 0:
            del coefficients[name]
    return coefficients, left[1] + right[1] * scale


def affine_registers_at(
    instrs: list[Instruction],
    idx: int,
) -> dict[str, tuple[dict[str, int], int]]:
    registers = {
        name: ({name: 1}, 0)
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    stack_values: dict[
        tuple[tuple[tuple[str, int], ...], int],
        tuple[dict[str, int], int],
    ] = {}

    def stack_address(operand: Operand):
        address = affine_memory_address(operand, registers)
        if address is None:
            return None
        coefficients, _constant = address
        if coefficients != (("esp", 1),):
            return None
        return address

    for instr in instrs[:idx]:
        operands = instr.operands
        if instr.mnemonic == "call":
            for name in ("eax", "ecx", "edx"):
                registers[name] = ({name: 1}, 0)
            continue
        if instr.mnemonic == "push":
            registers["esp"] = (
                dict(registers["esp"][0]),
                registers["esp"][1] - 4,
            )
            continue
        if instr.mnemonic == "pop":
            if operands and operands[0].kind == "reg":
                dst = full_register_name(operands[0].reg)
                registers[dst] = ({dst: 1}, 0)
            registers["esp"] = (
                dict(registers["esp"][0]),
                registers["esp"][1] + 4,
            )
            continue
        if instr.mnemonic == "leave":
            registers["esp"] = (
                dict(registers["ebp"][0]),
                registers["ebp"][1] + 4,
            )
            registers["ebp"] = ({"ebp": 1}, 0)
            continue
        if not operands:
            continue

        if instr.mnemonic == "mov" and len(operands) >= 2 and operands[0].kind == "mem":
            destination = stack_address(operands[0])
            if destination is not None:
                src = operands[1]
                if src.kind == "reg":
                    value = registers.get(full_register_name(src.reg))
                    if value is not None:
                        stack_values[destination] = (dict(value[0]), value[1])
                    else:
                        stack_values.pop(destination, None)
                elif src.kind == "imm":
                    stack_values[destination] = ({}, src.imm)
                else:
                    stack_values.pop(destination, None)
            continue

        if operands[0].kind != "reg":
            continue

        dst = full_register_name(operands[0].reg)
        if dst not in registers:
            continue
        if instr.mnemonic == "mov" and len(operands) >= 2:
            source = operands[1]
            if source.kind == "reg":
                src = full_register_name(source.reg)
                if src not in registers:
                    registers[dst] = ({dst: 1}, 0)
                    continue
                registers[dst] = (dict(registers[src][0]), registers[src][1])
                continue
            if source.kind == "imm":
                registers[dst] = ({}, source.imm)
                continue
            if source.kind == "mem":
                source_address = stack_address(source)
                if source_address is None:
                    registers[dst] = ({dst: 1}, 0)
                    continue
                stored = stack_values.get(source_address)
                if stored is not None:
                    registers[dst] = (dict(stored[0]), stored[1])
                    continue
                token = f"stack-value:{source_address!r}"
                registers[dst] = ({token: 1}, 0)
                continue
        if instr.mnemonic == "lea" and len(operands) >= 2 and operands[1].kind == "mem":
            src = operands[1]
            value: tuple[dict[str, int], int] = ({}, src.disp)
            if src.base:
                base = full_register_name(src.base)
                if base not in registers:
                    registers[dst] = ({dst: 1}, 0)
                    continue
                value = affine_add(value, registers[base])
            if src.index:
                index = full_register_name(src.index)
                if index not in registers:
                    registers[dst] = ({dst: 1}, 0)
                    continue
                value = affine_add(
                    value,
                    registers[index],
                    src.scale,
                )
            registers[dst] = value
            continue
        if instr.mnemonic in {"add", "sub"} and len(operands) >= 2 and operands[1].kind == "imm":
            delta = operands[1].imm if instr.mnemonic == "add" else -operands[1].imm
            registers[dst] = (dict(registers[dst][0]), registers[dst][1] + delta)
            continue
        if instr.mnemonic in {"add", "sub"} and len(operands) >= 2 and operands[1].kind == "reg":
            src = full_register_name(operands[1].reg)
            if src not in registers:
                registers[dst] = ({dst: 1}, 0)
                continue
            scale = 1 if instr.mnemonic == "add" else -1
            registers[dst] = affine_add(registers[dst], registers[src], scale)
            continue
        if instr.mnemonic in {"inc", "dec"}:
            delta = 1 if instr.mnemonic == "inc" else -1
            registers[dst] = (dict(registers[dst][0]), registers[dst][1] + delta)
            continue
        if (
            instr.mnemonic == "shl"
            and len(operands) >= 2
            and operands[1].kind == "imm"
            and 0 <= operands[1].imm < 8
        ):
            scale = 1 << operands[1].imm
            registers[dst] = (
                {name: coefficient * scale for name, coefficient in registers[dst][0].items()},
                registers[dst][1] * scale,
            )
            continue
        if (
            instr.mnemonic == "xor"
            and len(operands) >= 2
            and operands[1].kind == "reg"
            and full_register_name(operands[1].reg) == dst
        ):
            registers[dst] = ({}, 0)
            continue

        registers[dst] = ({dst: 1}, 0)
    return registers


def affine_memory_address(
    operand: Operand,
    registers: dict[str, tuple[dict[str, int], int]],
) -> tuple[tuple[tuple[str, int], ...], int] | None:
    if operand.kind != "mem" or not operand.base:
        return None
    base = full_register_name(operand.base)
    if base not in registers:
        return None
    value: tuple[dict[str, int], int] = ({}, operand.disp)
    value = affine_add(value, registers[base])
    if operand.index:
        index = full_register_name(operand.index)
        if index not in registers:
            return None
        value = affine_add(
            value,
            registers[index],
            operand.scale,
        )
    return tuple(sorted(value[0].items())), value[1]


def same_affine_memory_address(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    c_op: Operand,
    o_op: Operand,
) -> bool:
    compiled_registers = affine_registers_at(compiled_instrs, ci)
    original_registers = affine_registers_at(original_instrs, oi)
    compiled_address = affine_memory_address(c_op, compiled_registers)
    original_address = affine_memory_address(o_op, original_registers)
    return compiled_address is not None and compiled_address == original_address


def same_effective_register_immediate(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    c_imm: int,
    o_imm: int,
    policy: VerifierPolicy,
) -> bool:
    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic not in {"add", "sub"} or original.mnemonic != compiled.mnemonic:
        return False
    if len(compiled.operands) < 2 or len(original.operands) < 2:
        return False
    c_dst = compiled.operands[0]
    o_dst = original.operands[0]
    if c_dst.kind != "reg" or o_dst.kind != "reg" or c_dst.reg != o_dst.reg:
        return False

    c_aliases = pointer_aliases_at(compiled_instrs, ci, c_dst.reg, policy)
    o_aliases = pointer_aliases_at(original_instrs, oi, o_dst.reg, policy)
    if not c_aliases and not o_aliases:
        return False

    c_delta = c_imm if compiled.mnemonic == "add" else -c_imm
    o_delta = o_imm if original.mnemonic == "add" else -o_imm
    for c_alias in c_aliases or [None]:
        for o_alias in o_aliases or [None]:
            if equivalent_alias_displacement(c_alias, o_alias, c_delta, o_delta):
                return True
    return False


def shifted_memory_base_match_count(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    delta: int,
    policy: VerifierPolicy,
    include_stack_locals: bool = False,
) -> int:
    if delta == 0:
        return 0

    count = 0
    for rel in range(-policy.nearby_window, policy.nearby_window + 1):
        c_idx = ci + rel
        o_idx = oi + rel
        if c_idx < 0 or o_idx < 0 or c_idx >= len(compiled_instrs) or o_idx >= len(original_instrs):
            continue

        compiled = compiled_instrs[c_idx]
        original = original_instrs[o_idx]
        if compiled.mnemonic != original.mnemonic:
            continue
        if operand_idx >= len(compiled.operands) or operand_idx >= len(original.operands):
            continue

        c_op = compiled.operands[operand_idx]
        o_op = original.operands[operand_idx]
        if c_op.kind != "mem" or o_op.kind != "mem":
            continue
        if not comparable_lhs(c_op, o_op, policy, include_stack_locals):
            continue
        if not member_displacement(c_op.disp, policy) or not member_displacement(o_op.disp, policy):
            continue
        if c_op.disp - o_op.disp != delta:
            continue

        count += 1

    return count


def equivalent_shifted_memory_base(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    c_op: Operand,
    o_op: Operand,
    policy: VerifierPolicy,
    include_stack_locals: bool = False,
) -> bool:
    delta = c_op.disp - o_op.disp
    return shifted_memory_base_match_count(
        compiled_instrs,
        original_instrs,
        ci,
        oi,
        operand_idx,
        delta,
        policy,
        include_stack_locals,
    ) >= 3


def register_has_literal_pointer_origin(
    instrs: list[Instruction],
    idx: int,
    register: str,
) -> bool:
    """Return whether a register currently derives from a pointer literal.

    MSVC sometimes chooses a different element of a global array as its loop
    base, then compensates every indexed access by the same displacement.  The
    original Arthur binary also spills that base to a stack slot while the
    reconstruction keeps it in a register, so follow those simple spills.
    """
    origins: dict[str, bool] = {}
    stack_origins: dict[tuple[str, int], bool] = {}

    for instr in instrs[:idx]:
        operands = instr.operands
        if instr.mnemonic == "call":
            for name in ("eax", "ecx", "edx"):
                origins.pop(name, None)
            continue
        if not operands:
            continue

        dst = operands[0]
        if instr.mnemonic == "mov" and len(operands) >= 2:
            src = operands[1]
            if dst.kind == "reg":
                dst_reg = full_register_name(dst.reg)
                if src.kind == "imm":
                    origins[dst_reg] = unsigned32(src.imm) >= 0x400000
                elif src.kind == "reg":
                    origins[dst_reg] = origins.get(full_register_name(src.reg), False)
                elif src.kind == "mem" and not src.index and src.base in {"esp", "ebp"}:
                    origins[dst_reg] = stack_origins.get((src.base, src.disp), False)
                else:
                    origins.pop(dst_reg, None)
                continue
            if dst.kind == "mem" and not dst.index and dst.base in {"esp", "ebp"}:
                key = (dst.base, dst.disp)
                if src.kind == "imm":
                    stack_origins[key] = unsigned32(src.imm) >= 0x400000
                elif src.kind == "reg":
                    stack_origins[key] = origins.get(full_register_name(src.reg), False)
                else:
                    stack_origins.pop(key, None)
                continue

        if dst.kind == "reg":
            dst_reg = full_register_name(dst.reg)
            if instr.mnemonic not in {"add", "sub", "inc", "dec"}:
                origins.pop(dst_reg, None)

    return origins.get(full_register_name(register), False)


def shifted_memory_sequence_match_count(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    delta: int,
    policy: VerifierPolicy,
) -> int:
    def displacements(instrs: list[Instruction], center: int) -> list[int]:
        result: list[int] = []
        start = max(0, center - policy.nearby_window)
        end = min(len(instrs), center + policy.nearby_window + 1)
        source = instrs[center]
        source_op = source.operands[operand_idx]
        for instr in instrs[start:end]:
            if instr.mnemonic != source.mnemonic or operand_idx >= len(instr.operands):
                continue
            operand = instr.operands[operand_idx]
            if operand.kind != "mem":
                continue
            if (
                operand.base != source_op.base
                or operand.index != source_op.index
                or operand.scale != source_op.scale
                or not member_displacement(operand.disp, policy)
            ):
                continue
            result.append(operand.disp)
        return result

    compiled_values = [value - delta for value in displacements(compiled_instrs, ci)]
    original_values = displacements(original_instrs, oi)
    return len(lcs_align(compiled_values, original_values))


def equivalent_shifted_literal_pointer_base(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    c_op: Operand,
    o_op: Operand,
    policy: VerifierPolicy,
) -> bool:
    if not c_op.base or not o_op.base:
        return False
    if not register_has_literal_pointer_origin(compiled_instrs, ci, c_op.base):
        return False
    if not register_has_literal_pointer_origin(original_instrs, oi, o_op.base):
        return False
    delta = c_op.disp - o_op.disp
    return shifted_memory_sequence_match_count(
        compiled_instrs,
        original_instrs,
        ci,
        oi,
        operand_idx,
        delta,
        policy,
    ) >= 2


def next_mnemonic(instrs: list[Instruction], idx: int) -> str | None:
    if idx + 1 >= len(instrs):
        return None
    return instrs[idx + 1].mnemonic


def next_instruction(instrs: list[Instruction], idx: int) -> Instruction | None:
    if idx + 1 >= len(instrs):
        return None
    return instrs[idx + 1]


def following_flag_branch_mnemonic(
    instrs: list[Instruction],
    idx: int,
    max_steps: int = 5,
) -> str | None:
    """Find the branch consuming flags while allowing flag-neutral scheduling."""
    flag_neutral = {"mov", "lea", "push", "pop", "nop", "xchg"}
    for instr in instrs[idx + 1:idx + 1 + max_steps]:
        if is_conditional_branch_mnemonic(instr.mnemonic):
            return instr.mnemonic
        if instr.mnemonic not in flag_neutral:
            return None
    return None


def is_conditional_branch_mnemonic(mnemonic: str) -> bool:
    return mnemonic.startswith("j") and mnemonic != "jmp"


def complemented_branch_mnemonic(mnemonic: str) -> str | None:
    complements = {
        "jz": "jnz",
        "jnz": "jz",
        "jc": "jnc",
        "jnc": "jc",
        "ja": "jbe",
        "jbe": "ja",
        "jnle": "jng",
        "jng": "jnle",
        "jnl": "jnge",
        "jnge": "jnl",
        "jo": "jno",
        "jno": "jo",
        "js": "jns",
        "jns": "js",
        "jp": "jnp",
        "jnp": "jp",
    }
    return complements.get(mnemonic)


def branch_successor_mnemonics(
    instrs: list[Instruction],
    branch_idx: int,
    taken: bool,
    max_instructions: int = 24,
) -> list[str]:
    if branch_idx < 0 or branch_idx >= len(instrs):
        return []
    branch = instrs[branch_idx]
    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    if taken:
        if not branch.operands or branch.operands[0].kind != "imm":
            return []
        pos = by_addr.get(unsigned32(branch.operands[0].imm))
    else:
        pos = branch_idx + 1

    result: list[str] = []
    seen: set[int] = set()
    while pos is not None and 0 <= pos < len(instrs) and len(result) < max_instructions:
        if pos in seen:
            break
        seen.add(pos)
        instr = instrs[pos]
        if instr.mnemonic == "jmp" and instr.operands and instr.operands[0].kind == "imm":
            pos = by_addr.get(unsigned32(instr.operands[0].imm))
            continue

        result.append(instr.mnemonic)
        if instr.mnemonic == "ret" or is_conditional_branch_mnemonic(instr.mnemonic):
            break
        pos += 1
    return result


def branch_successor_effects(
    instrs: list[Instruction],
    branch_idx: int,
    taken: bool,
    policy: VerifierPolicy,
    max_instructions: int = 24,
) -> list[tuple]:
    """Describe stable side effects along one branch edge.

    Register allocation and loop-tail scheduling make mnemonic sequences a
    weak signal for an inverted layout.  Member stores and calls survive those
    changes and identify which edge performs the work.
    """
    if branch_idx < 0 or branch_idx >= len(instrs):
        return []
    branch = instrs[branch_idx]
    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    if taken:
        if not branch.operands or branch.operands[0].kind != "imm":
            return []
        pos = by_addr.get(unsigned32(branch.operands[0].imm))
    else:
        pos = branch_idx + 1

    result: list[tuple] = []
    seen: set[int] = set()
    steps = 0
    while pos is not None and 0 <= pos < len(instrs) and steps < max_instructions:
        if pos in seen:
            break
        seen.add(pos)
        steps += 1
        instr = instrs[pos]
        if instr.mnemonic == "jmp" and instr.operands and instr.operands[0].kind == "imm":
            pos = by_addr.get(unsigned32(instr.operands[0].imm))
            continue
        if instr.mnemonic == "call":
            signature = call_signature(instr)
            if signature is not None:
                result.append(("call", signature))
        elif instr.operands and instr.operands[0].kind == "mem":
            destination = instr.operands[0]
            if member_displacement(destination.disp, policy):
                result.append(("write", destination.disp, destination.size))
        if instr.mnemonic == "ret" or is_conditional_branch_mnemonic(instr.mnemonic):
            break
        pos += 1
    return result


def mnemonic_sequence_similarity(left: list[str], right: list[str]) -> float:
    if not left or not right:
        return 0.0
    return len(lcs_align(left, right)) / max(len(left), len(right))


def equivalent_reordered_branch_layout(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_branch_idx: int,
    original_branch_idx: int,
    policy: VerifierPolicy,
) -> bool:
    compiled = compiled_instrs[compiled_branch_idx]
    original = original_instrs[original_branch_idx]
    c_taken = branch_successor_mnemonics(compiled_instrs, compiled_branch_idx, True)
    c_fallthrough = branch_successor_mnemonics(compiled_instrs, compiled_branch_idx, False)
    o_taken = branch_successor_mnemonics(original_instrs, original_branch_idx, True)
    o_fallthrough = branch_successor_mnemonics(original_instrs, original_branch_idx, False)

    cross_scores = (
        mnemonic_sequence_similarity(c_taken, o_fallthrough),
        mnemonic_sequence_similarity(c_fallthrough, o_taken),
    )
    same_scores = (
        mnemonic_sequence_similarity(c_taken, o_taken),
        mnemonic_sequence_similarity(c_fallthrough, o_fallthrough),
    )
    required_margin = (
        0.35 if complemented_branch_mnemonic(compiled.mnemonic) == original.mnemonic else 0.15
    )
    if (
        max(cross_scores) >= 0.85
        and sum(cross_scores) >= sum(same_scores) + required_margin
    ):
        return True

    if complemented_branch_mnemonic(compiled.mnemonic) != original.mnemonic:
        return False
    c_taken_effects = branch_successor_effects(compiled_instrs, compiled_branch_idx, True, policy)
    c_fallthrough_effects = branch_successor_effects(compiled_instrs, compiled_branch_idx, False, policy)
    o_taken_effects = branch_successor_effects(original_instrs, original_branch_idx, True, policy)
    o_fallthrough_effects = branch_successor_effects(original_instrs, original_branch_idx, False, policy)
    cross_effect_match = (
        bool(c_taken_effects)
        and c_taken_effects == o_fallthrough_effects
    ) or (
        bool(c_fallthrough_effects)
        and c_fallthrough_effects == o_taken_effects
    )
    same_effect_match = (
        bool(c_taken_effects)
        and c_taken_effects == o_taken_effects
    ) or (
        bool(c_fallthrough_effects)
        and c_fallthrough_effects == o_fallthrough_effects
    )
    return cross_effect_match and not same_effect_match


def immediate_window_similarity(
    left: list[Instruction],
    left_idx: int,
    right: list[Instruction],
    right_idx: int,
    radius: int = 8,
) -> tuple[float, float]:
    left_before = [instr.mnemonic for instr in left[max(0, left_idx - radius):left_idx]]
    right_before = [instr.mnemonic for instr in right[max(0, right_idx - radius):right_idx]]
    left_after = [instr.mnemonic for instr in left[left_idx + 1:left_idx + 1 + radius]]
    right_after = [instr.mnemonic for instr in right[right_idx + 1:right_idx + 1 + radius]]
    return (
        mnemonic_sequence_similarity(left_before, right_before),
        mnemonic_sequence_similarity(left_after, right_after),
    )


def has_structurally_relocated_immediate(
    source_instrs: list[Instruction],
    source_idx: int,
    target_instrs: list[Instruction],
    operand_idx: int,
    wanted_value: int,
) -> bool:
    source = source_instrs[source_idx]
    for target_idx, target in enumerate(target_instrs):
        if target.mnemonic != source.mnemonic or not comparable_operands(source, target):
            continue
        target_immediates = dict(immediate_operands(target))
        if operand_idx not in target_immediates or target_immediates[operand_idx].imm != wanted_value:
            continue
        before_score, after_score = immediate_window_similarity(
            source_instrs, source_idx, target_instrs, target_idx
        )
        if max(before_score, after_score) >= 0.8 and before_score + after_score >= 1.25:
            return True
    return False


def equivalent_structurally_reordered_immediates(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    compiled_value: int,
    original_value: int,
) -> bool:
    bidirectional = has_structurally_relocated_immediate(
        compiled_instrs, ci, original_instrs, operand_idx, compiled_value
    ) and has_structurally_relocated_immediate(
        original_instrs, oi, compiled_instrs, operand_idx, original_value
    )
    if bidirectional:
        return True

    def has_much_better_exact_match(
        source_instrs: list[Instruction],
        source_idx: int,
        paired_instrs: list[Instruction],
        paired_idx: int,
        wanted_value: int,
    ) -> bool:
        source = source_instrs[source_idx]
        current_scores = immediate_window_similarity(
            source_instrs, source_idx, paired_instrs, paired_idx
        )
        for candidate_idx, candidate in enumerate(paired_instrs):
            if candidate.mnemonic != source.mnemonic or not comparable_operands(source, candidate):
                continue
            candidate_immediates = dict(immediate_operands(candidate))
            if (
                operand_idx not in candidate_immediates
                or candidate_immediates[operand_idx].imm != wanted_value
            ):
                continue
            candidate_scores = immediate_window_similarity(
                source_instrs, source_idx, paired_instrs, candidate_idx
            )
            if (
                max(candidate_scores) >= 0.75
                and candidate_scores[0] >= current_scores[0]
                and candidate_scores[1] >= current_scores[1]
                and sum(candidate_scores) >= sum(current_scores) + 0.25
            ):
                return True
        return False

    return has_much_better_exact_match(
        compiled_instrs,
        ci,
        original_instrs,
        oi,
        compiled_value,
    ) or has_much_better_exact_match(
        original_instrs,
        oi,
        compiled_instrs,
        ci,
        original_value,
    )


def has_structurally_relocated_displacement(
    source_instrs: list[Instruction],
    source_idx: int,
    target_instrs: list[Instruction],
    operand_idx: int,
    wanted_displacement: int,
) -> bool:
    source = source_instrs[source_idx]
    for target_idx, target in enumerate(target_instrs):
        if target.mnemonic != source.mnemonic or not comparable_operands(source, target):
            continue
        target_memory = dict(memory_operands(target))
        if operand_idx not in target_memory or target_memory[operand_idx].disp != wanted_displacement:
            continue
        before_score, after_score = immediate_window_similarity(
            source_instrs, source_idx, target_instrs, target_idx
        )
        if max(before_score, after_score) >= 0.8 and before_score + after_score >= 1.25:
            return True
    return False


def equivalent_structurally_reordered_displacements(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    compiled_displacement: int,
    original_displacement: int,
) -> bool:
    bidirectional = has_structurally_relocated_displacement(
        compiled_instrs,
        ci,
        original_instrs,
        operand_idx,
        compiled_displacement,
    ) and has_structurally_relocated_displacement(
        original_instrs,
        oi,
        compiled_instrs,
        operand_idx,
        original_displacement,
    )
    if bidirectional:
        return True

    def has_much_better_exact_match(
        source_instrs: list[Instruction],
        source_idx: int,
        paired_instrs: list[Instruction],
        paired_idx: int,
        wanted_displacement: int,
    ) -> bool:
        source = source_instrs[source_idx]
        current_scores = immediate_window_similarity(
            source_instrs, source_idx, paired_instrs, paired_idx
        )
        for candidate_idx, candidate in enumerate(paired_instrs):
            if candidate.mnemonic != source.mnemonic or not comparable_operands(source, candidate):
                continue
            candidate_memory = dict(memory_operands(candidate))
            if (
                operand_idx not in candidate_memory
                or candidate_memory[operand_idx].disp != wanted_displacement
            ):
                continue
            candidate_scores = immediate_window_similarity(
                source_instrs, source_idx, paired_instrs, candidate_idx
            )
            if (
                max(candidate_scores) >= 0.75
                and candidate_scores[0] >= current_scores[0]
                and candidate_scores[1] >= current_scores[1]
                and sum(candidate_scores) >= sum(current_scores) + 0.25
            ):
                return True
        return False

    return has_much_better_exact_match(
        compiled_instrs,
        ci,
        original_instrs,
        oi,
        compiled_displacement,
    ) or has_much_better_exact_match(
        original_instrs,
        oi,
        compiled_instrs,
        ci,
        original_displacement,
    )


def has_structurally_relocated_effective_address(
    source_instrs: list[Instruction],
    source_idx: int,
    target_instrs: list[Instruction],
    operand_idx: int,
    wanted_address: tuple[tuple[tuple[str, int], ...], int],
) -> bool:
    source = source_instrs[source_idx]
    for target_idx, target in enumerate(target_instrs):
        if target.mnemonic != source.mnemonic or not comparable_operands(source, target):
            continue
        target_memory = dict(memory_operands(target))
        if operand_idx not in target_memory:
            continue
        target_address = affine_memory_address(
            target_memory[operand_idx], affine_registers_at(target_instrs, target_idx)
        )
        if target_address != wanted_address:
            continue
        return True
    return False


def equivalent_structurally_reordered_effective_addresses(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    operand_idx: int,
    c_op: Operand,
    o_op: Operand,
) -> bool:
    compiled_address = affine_memory_address(
        c_op, affine_registers_at(compiled_instrs, ci)
    )
    original_address = affine_memory_address(
        o_op, affine_registers_at(original_instrs, oi)
    )
    if compiled_address is None or original_address is None:
        return False
    return has_structurally_relocated_effective_address(
        compiled_instrs, ci, original_instrs, operand_idx, compiled_address
    ) and has_structurally_relocated_effective_address(
        original_instrs, oi, compiled_instrs, operand_idx, original_address
    )


def equivalent_integer_threshold(
    c_imm: int,
    o_imm: int,
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    c_next = following_flag_branch_mnemonic(compiled_instrs, ci)
    o_next = following_flag_branch_mnemonic(original_instrs, oi)
    if c_next is None or o_next is None:
        return False

    if (c_next, o_next) in (("jnl", "jnle"), ("jnc", "ja")):
        return c_imm == o_imm + 1
    if (c_next, o_next) in (("jnle", "jnl"), ("ja", "jnc")):
        return o_imm == c_imm + 1
    if (c_next, o_next) in (("jnge", "jng"), ("jc", "jbe")):
        return c_imm == o_imm + 1
    if (c_next, o_next) in (("jng", "jnge"), ("jbe", "jc")):
        return o_imm == c_imm + 1
    return False


def sign_step_outputs(instrs: list[Instruction], idx: int) -> tuple[int, int] | None:
    """Evaluate MSVC's branchless ``delta < 0 ? -1 : 1`` idiom.

    VC6 emits this either as ``setl; dec; and 2; dec`` or as the complementary
    ``setge; dec; and -2; inc`` sequence.  The mask literals differ even though
    both forms produce the same step for non-negative and negative deltas.
    """
    if idx < 3 or idx + 1 >= len(instrs):
        return None
    current = instrs[idx]
    if current.mnemonic != "and" or len(current.operands) < 2:
        return None
    destination, mask_operand = current.operands[0], current.operands[1]
    if destination.kind != "reg" or mask_operand.kind != "imm":
        return None
    register = full_register_name(destination.reg)

    def writes_full_register(instr: Instruction) -> bool:
        return bool(
            instr.operands
            and instr.operands[0].kind == "reg"
            and full_register_name(instr.operands[0].reg) == register
        )

    previous_writes = [
        instr for instr in reversed(instrs[max(0, idx - 8):idx])
        if writes_full_register(instr)
    ]
    following_writes = [
        instr for instr in instrs[idx + 1:min(len(instrs), idx + 9)]
        if writes_full_register(instr)
    ]
    if len(previous_writes) < 2 or not following_writes:
        return None
    decrement = previous_writes[0]
    set_condition = previous_writes[1]
    adjustment = following_writes[0]
    set_index = instrs.index(set_condition, max(0, idx - 8), idx)
    test = instrs[set_index - 1] if set_index > 0 else None
    if (
        decrement.mnemonic != "dec"
        or not decrement.operands
        or decrement.operands[0].kind != "reg"
        or full_register_name(decrement.operands[0].reg) != register
        or set_condition.mnemonic not in {"setl", "setnge", "setge", "setnl"}
        or not set_condition.operands
        or set_condition.operands[0].kind != "reg"
        or full_register_name(set_condition.operands[0].reg) != register
        or test is None
        or test.mnemonic != "test"
        or adjustment.mnemonic not in {"inc", "dec"}
        or not adjustment.operands
        or adjustment.operands[0].kind != "reg"
        or full_register_name(adjustment.operands[0].reg) != register
    ):
        return None

    outputs = []
    mask = mask_operand.imm & 0xFFFFFFFF
    for negative in (False, True):
        if set_condition.mnemonic in {"setl", "setnge"}:
            value = int(negative)
        else:
            value = int(not negative)
        value = ((value - 1) & mask) & 0xFFFFFFFF
        value = (value + (1 if adjustment.mnemonic == "inc" else -1)) & 0xFFFFFFFF
        if value & 0x80000000:
            value -= 0x100000000
        outputs.append(value)
    return tuple(outputs)


def equivalent_sign_step_masks(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    compiled_outputs = sign_step_outputs(compiled_instrs, ci)
    original_outputs = sign_step_outputs(original_instrs, oi)
    return compiled_outputs is not None and compiled_outputs == original_outputs


def x87_status_test_mask(instrs: list[Instruction], idx: int) -> int | None:
    """Return the x87 condition-code mask consumed by a status-word test."""
    if idx < 2 or idx >= len(instrs):
        return None
    instr = instrs[idx]
    if instr.mnemonic != "test" or len(instr.operands) < 2:
        return None
    status, mask = instr.operands[0], instr.operands[1]
    if status.kind != "reg" or status.reg != "ah" or mask.kind != "imm":
        return None
    previous = instrs[idx - 1]
    if (
        previous.mnemonic != "fnstsw"
        or not previous.operands
        or previous.operands[0].kind != "reg"
        or previous.operands[0].reg != "ax"
    ):
        return None
    if not any(
        candidate.mnemonic.startswith("fcom")
        or candidate.mnemonic.startswith("fucom")
        for candidate in instrs[max(0, idx - 4):idx - 1]
    ):
        return None
    return mask.imm


def equivalent_reordered_x87_status_masks(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    """Recognize strict/inclusive x87 tests paired across reordered regions.

    A mnemonic LCS cannot distinguish repeated geometric tests after VC6 lays
    their blocks out in a different order.  Only reconcile a mismatched pair
    when both complete functions contain the same multiset of x87 status masks
    and each disputed mask occurs elsewhere.  A real one-off ``<``/``<=``
    change therefore remains visible.
    """
    compiled_mask = x87_status_test_mask(compiled_instrs, ci)
    original_mask = x87_status_test_mask(original_instrs, oi)
    if compiled_mask is None or original_mask is None or compiled_mask == original_mask:
        return False

    compiled_masks = [
        mask
        for idx in range(len(compiled_instrs))
        if (mask := x87_status_test_mask(compiled_instrs, idx)) is not None
    ]
    original_masks = [
        mask
        for idx in range(len(original_instrs))
        if (mask := x87_status_test_mask(original_instrs, idx)) is not None
    ]
    if sorted(compiled_masks) != sorted(original_masks):
        return False
    return (
        compiled_masks.count(compiled_mask) > 1
        and compiled_masks.count(original_mask) > 1
    )


def same_cmp_immediate_values(compiled: Instruction, original: Instruction) -> bool:
    c_imms = dict(immediate_operands(compiled))
    o_imms = dict(immediate_operands(original))
    if not c_imms or set(c_imms) != set(o_imms):
        return False
    return all(c_imms[idx].imm == o_imms[idx].imm for idx in c_imms)


def report_cmp_branch_condition_mismatch(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    context: CompareContext,
) -> tuple | None:
    if "immediates" not in context.enabled_kinds:
        return None

    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic != "cmp" or original.mnemonic != "cmp":
        return None
    if not same_cmp_immediate_values(compiled, original):
        return None

    c_next = next_instruction(compiled_instrs, ci)
    o_next = next_instruction(original_instrs, oi)
    if c_next is None or o_next is None:
        return None
    if not (is_conditional_branch_mnemonic(c_next.mnemonic) and is_conditional_branch_mnemonic(o_next.mnemonic)):
        return None
    if c_next.mnemonic == o_next.mnemonic:
        return None
    if equivalent_reordered_branch_layout(
        compiled_instrs, original_instrs, ci + 1, oi + 1, context.policy
    ):
        return None
    return ("branch", c_next.mnemonic, o_next.mnemonic, c_next, o_next)


def starts_boolean_mask_after_cmp(instrs: list[Instruction], idx: int) -> bool:
    if idx + 2 >= len(instrs):
        return False

    mov_instr = instrs[idx + 1]
    adc_instr = instrs[idx + 2]
    if mov_instr.mnemonic != "mov" or adc_instr.mnemonic != "adc":
        return False
    if len(mov_instr.operands) < 2 or len(adc_instr.operands) < 2:
        return False

    mov_dst = mov_instr.operands[0]
    mov_src = mov_instr.operands[1]
    adc_dst = adc_instr.operands[0]
    adc_src = adc_instr.operands[1]
    return (
        mov_dst.kind == "reg"
        and mov_src.kind == "imm"
        and mov_src.imm == 0
        and adc_dst.kind == "reg"
        and adc_dst.reg == mov_dst.reg
        and adc_src.kind == "imm"
        and adc_src.imm == -1
    )


def equivalent_boolean_zero_test(
    c_imm: int,
    o_imm: int,
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    if {c_imm, o_imm} != {0, 1}:
        return False
    return starts_boolean_mask_after_cmp(compiled_instrs, ci) or starts_boolean_mask_after_cmp(original_instrs, oi)


def masked_register_only_stored_as_word(
    instrs: list[Instruction],
    idx: int,
    register: str,
    max_steps: int = 12,
) -> bool:
    full_register = full_register_name(register)
    for instr in instrs[idx + 1:idx + 1 + max_steps]:
        if instr.mnemonic == "call":
            return False
        for operand_idx, operand in enumerate(instr.operands):
            if operand.kind == "mem" and (
                full_register_name(operand.base) == full_register
                or full_register_name(operand.index) == full_register
            ):
                return False
            if operand.kind != "reg" or full_register_name(operand.reg) != full_register:
                continue
            if (
                instr.mnemonic == "mov"
                and operand_idx > 0
                and operand.size <= 2
                and instr.operands[0].kind == "mem"
                and instr.operands[0].size <= 2
            ):
                return True
            if operand_idx == 0 and instr.mnemonic in {"and", "or", "xor", "add", "sub"}:
                continue
            if operand.size > 2:
                return False
        if instr.mnemonic == "ret":
            return False
    return False


def equivalent_low_word_mask(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    compiled_value: int,
    original_value: int,
) -> bool:
    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic != "and" or original.mnemonic != "and":
        return False
    if (compiled_value & 0xFFFF) != (original_value & 0xFFFF):
        return False
    if not compiled.operands or not original.operands:
        return False
    c_dst = compiled.operands[0]
    o_dst = original.operands[0]
    if c_dst.kind != "reg" or o_dst.kind != "reg":
        return False
    if full_register_name(c_dst.reg) != full_register_name(o_dst.reg):
        return False
    return masked_register_only_stored_as_word(
        compiled_instrs, ci, c_dst.reg
    ) and masked_register_only_stored_as_word(
        original_instrs, oi, o_dst.reg
    )


def is_stack_adjustment(instr: Instruction) -> bool:
    if instr.mnemonic not in {"add", "sub"} or len(instr.operands) < 2:
        return False
    return instr.operands[0].kind == "reg" and instr.operands[0].reg == "esp"


def is_stack_probe_size_load(instrs: list[Instruction], idx: int) -> bool:
    if idx < 0 or idx >= len(instrs):
        return False
    instr = instrs[idx]
    if instr.mnemonic != "mov" or len(instr.operands) < 2:
        return False
    dst, src = instr.operands[0], instr.operands[1]
    return (
        idx <= 6
        and dst.kind == "reg"
        and full_register_name(dst.reg) == "eax"
        and src.kind == "imm"
        and any(
            candidate.mnemonic == "call"
            for candidate in instrs[idx + 1:min(len(instrs), idx + 4)]
        )
        and (
            instrs[idx + 1].mnemonic == "call"
            or has_msvc_seh_frame(instrs)
        )
    )


def direct_jump_target(instr: Instruction) -> int | None:
    if instr.mnemonic != "jmp" or len(instr.operands) != 1:
        return None
    operand = instr.operands[0]
    if operand.kind != "imm":
        return None
    return unsigned32(operand.imm)


def call_signature(instr: Instruction, direct_targets: dict[int, str] | None = None) -> tuple | None:
    if instr.mnemonic != "call" or len(instr.operands) != 1:
        return None
    operand = instr.operands[0]
    if operand.kind == "mem":
        return ("mem", operand.index, operand.scale, operand.disp)
    if operand.kind == "imm":
        if direct_targets:
            target_name = direct_targets.get(unsigned32(operand.imm))
            if target_name is not None:
                return ("direct", target_name)
        return ("direct",)
    return None


def following_call_signature(
    instrs: list[Instruction],
    idx: int,
    max_steps: int = 48,
    direct_targets: dict[int, str] | None = None,
) -> tuple | None:
    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    seen: set[int] = set()
    pos = idx + 1
    steps = 0
    while 0 <= pos < len(instrs) and steps < max_steps:
        if pos in seen:
            return None
        seen.add(pos)
        steps += 1

        instr = instrs[pos]
        signature = call_signature(instr, direct_targets)
        if signature is not None:
            return signature
        if instr.mnemonic == "ret":
            return None
        if instr.mnemonic == "jmp":
            target = direct_jump_target(instr)
            if target is None or target not in by_addr:
                return None
            pos = by_addr[target]
            continue
        if is_branch_or_call(instr.mnemonic):
            return None
        pos += 1
    return None


def following_call_context(
    instrs: list[Instruction],
    idx: int,
    max_steps: int = 48,
    direct_targets: dict[int, str] | None = None,
) -> tuple[tuple, int] | None:
    """Return the destination and argument position for a pushed value.

    Optimized switch bodies are frequently emitted in a different order even
    when their calls and arguments are identical.  The plain mnemonic LCS can
    consequently align a PUSH from one case with a PUSH from another.  Track
    the call reached by the push, including simple tail merges, and count the
    later pushes so values can be reconciled at the same argument position.
    """
    if idx < 0 or idx >= len(instrs) or instrs[idx].mnemonic != "push":
        return None

    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    seen: set[int] = set()
    pos = idx + 1
    steps = 0
    later_pushes = 0
    while 0 <= pos < len(instrs) and steps < max_steps:
        if pos in seen:
            return None
        seen.add(pos)
        steps += 1

        instr = instrs[pos]
        signature = call_signature(instr, direct_targets)
        if signature is not None:
            return signature, later_pushes
        if instr.mnemonic == "push":
            later_pushes += 1
        if instr.mnemonic == "ret":
            return None
        if instr.mnemonic == "jmp":
            target = direct_jump_target(instr)
            if target is None or target not in by_addr:
                return None
            pos = by_addr[target]
            continue
        if is_branch_or_call(instr.mnemonic):
            return None
        pos += 1
    return None


def loaded_value_call_context(
    instrs: list[Instruction],
    idx: int,
    direct_targets: dict[int, str] | None = None,
    max_steps: int = 5,
) -> tuple[tuple, int] | None:
    """Resolve a register load to the call argument that consumes it."""
    if idx < 0 or idx >= len(instrs):
        return None
    instr = instrs[idx]
    if instr.mnemonic != "mov" or len(instr.operands) < 2:
        return None
    destination = instr.operands[0]
    if destination.kind != "reg":
        return None
    register = full_register_name(destination.reg)

    for pos in range(idx + 1, min(len(instrs), idx + 1 + max_steps)):
        candidate = instrs[pos]
        if candidate.mnemonic == "push" and candidate.operands:
            pushed = candidate.operands[0]
            if pushed.kind == "reg" and full_register_name(pushed.reg) == register:
                return following_call_context(
                    instrs, pos, direct_targets=direct_targets
                )
        if candidate.mnemonic == "ret" or is_branch_or_call(candidate.mnemonic):
            return None
        if (
            candidate.operands
            and candidate.operands[0].kind == "reg"
            and full_register_name(candidate.operands[0].reg) == register
        ):
            return None
    return None


def block_literal_anchors(
    instrs: list[Instruction],
    image: PEImage,
    idx: int,
    policy: VerifierPolicy,
) -> frozenset[str]:
    """Literal strings in the straight-line region containing ``idx``.

    A nearby unique dialogue line is a stable semantic anchor for the small
    animation values surrounding it.  Calls remain inside the region, while
    control-flow boundaries prevent unrelated switch cases from lending each
    other anchors.
    """
    branch_targets = {
        unsigned32(instr.operands[0].imm)
        for instr in instrs
        if is_branch_or_call(instr.mnemonic)
        and instr.mnemonic != "call"
        and instr.operands
        and instr.operands[0].kind == "imm"
    }

    lo = idx
    steps = 0
    while lo > 0 and steps < 64:
        previous = instrs[lo - 1]
        if previous.mnemonic == "ret" or (
            is_branch_or_call(previous.mnemonic) and previous.mnemonic != "call"
        ):
            break
        if instrs[lo].address in branch_targets:
            break
        lo -= 1
        steps += 1

    hi = idx + 1
    steps = 0
    while hi < len(instrs) and steps < 64:
        if instrs[hi].address in branch_targets:
            break
        previous = instrs[hi - 1]
        if previous.mnemonic == "ret" or (
            is_branch_or_call(previous.mnemonic) and previous.mnemonic != "call"
        ):
            break
        hi += 1
        steps += 1

    anchors: set[str] = set()
    for instr in instrs[lo:hi]:
        for _, operand in immediate_operands(instr):
            value = immediate_string(image, operand, policy)
            if value is not None:
                anchors.add(normalize_string_for_compare(value).lower())
    return frozenset(anchors)


def pushed_operand_fingerprint(
    operand: Operand,
    image: PEImage,
    policy: VerifierPolicy,
) -> tuple:
    if operand.kind == "imm":
        value = immediate_string(image, operand, policy)
        if value is not None:
            return ("string", normalize_string_for_compare(value).lower())
        return ("imm", operand.imm)
    return (operand.kind,)


def push_argument_fingerprint(
    instrs: list[Instruction],
    image: PEImage,
    idx: int,
    policy: VerifierPolicy,
) -> tuple:
    """Describe the other pushed operands belonging to the same call."""
    if idx < 0 or idx >= len(instrs) or instrs[idx].mnemonic != "push":
        return ()

    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    branch_targets = {
        unsigned32(instr.operands[0].imm)
        for instr in instrs
        if is_branch_or_call(instr.mnemonic)
        and instr.mnemonic != "call"
        and instr.operands
        and instr.operands[0].kind == "imm"
    }

    lo = idx
    while lo > 0:
        previous = instrs[lo - 1]
        if previous.mnemonic in {"call", "ret"} or (
            is_branch_or_call(previous.mnemonic) and previous.mnemonic != "call"
        ):
            break
        if instrs[lo].address in branch_targets:
            break
        lo -= 1

    path = list(range(lo, idx + 1))
    seen = set(path)
    pos = idx + 1
    steps = 0
    while 0 <= pos < len(instrs) and steps < 48:
        if pos in seen:
            return ()
        seen.add(pos)
        steps += 1
        instr = instrs[pos]
        if instr.mnemonic == "call":
            break
        if instr.mnemonic == "ret":
            return ()
        if instr.mnemonic == "jmp":
            target = direct_jump_target(instr)
            if target is None or target not in by_addr:
                return ()
            pos = by_addr[target]
            continue
        if is_branch_or_call(instr.mnemonic):
            return ()
        path.append(pos)
        pos += 1
    else:
        return ()

    pushes = [pos for pos in path if instrs[pos].mnemonic == "push"]
    if idx not in pushes:
        return ()
    current_ordinal = len(pushes) - pushes.index(idx) - 1
    result: list[tuple] = []
    for push_index, push_pos in enumerate(pushes):
        ordinal = len(pushes) - push_index - 1
        if ordinal == current_ordinal:
            continue
        push = instrs[push_pos]
        if not push.operands:
            continue
        result.append((
            ordinal,
            pushed_operand_fingerprint(push.operands[0], image, policy),
        ))
    return tuple(result)


def push_has_contextual_value(
    instrs: list[Instruction],
    image: PEImage,
    wanted_value: int | str,
    wanted_context: tuple[tuple, int],
    wanted_anchors: frozenset[str],
    wanted_fingerprint: tuple,
    context: CompareContext,
    direct_targets: dict[int, str],
) -> bool:
    for idx, instr in enumerate(instrs):
        if instr.mnemonic != "push" or not instr.operands:
            continue
        operand = instr.operands[0]
        if operand.kind != "imm":
            continue

        if isinstance(wanted_value, str):
            candidate = immediate_string(image, operand, context.policy)
            if candidate is None or normalize_string_for_compare(candidate) != wanted_value:
                continue
        else:
            if operand.imm != wanted_value:
                continue
            if immediate_string(image, operand, context.policy) is not None:
                continue

        candidate_context = following_call_context(
            instrs, idx, direct_targets=direct_targets
        )
        if candidate_context != wanted_context:
            continue
        candidate_anchors = block_literal_anchors(
            instrs, image, idx, context.policy
        )
        candidate_fingerprint = push_argument_fingerprint(
            instrs, image, idx, context.policy
        )
        if wanted_anchors & candidate_anchors:
            return True
        if wanted_fingerprint and candidate_fingerprint == wanted_fingerprint:
            return True
    return False


def contextual_push_value_counts(
    instrs: list[Instruction],
    image: PEImage,
    wanted_context: tuple[tuple, int],
    wanted_values: frozenset[int | str],
    context: CompareContext,
    direct_targets: dict[int, str],
) -> dict[int | str, int]:
    counts = {value: 0 for value in wanted_values}
    for idx, instr in enumerate(instrs):
        if instr.mnemonic != "push" or not instr.operands:
            continue
        operand = instr.operands[0]
        if operand.kind != "imm":
            continue
        candidate_context = following_call_context(
            instrs, idx, direct_targets=direct_targets
        )
        if candidate_context != wanted_context:
            continue
        string = immediate_string(image, operand, context.policy)
        if string is None:
            value: int | str = operand.imm
        else:
            value = normalize_string_for_compare(string)
        if value in counts:
            counts[value] += 1
    return counts


def equivalent_reordered_push_values(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    ci: int,
    oi: int,
    compiled_value: int | str,
    original_value: int | str,
    context: CompareContext,
) -> bool:
    """Recognize values paired with the wrong reordered switch case.

    Reconciliation is deliberately bidirectional and requires the same call,
    argument position, and a shared literal anchor on both sides.  A genuinely
    changed argument next to the same dialogue therefore remains reportable;
    only values that can each be placed in their matching semantic region are
    ignored.
    """
    compiled_call = following_call_context(
        compiled_instrs, ci, direct_targets=context.compiled_call_targets
    )
    original_call = following_call_context(
        original_instrs, oi, direct_targets=context.original_call_targets
    )
    if compiled_call is None or original_call is None or compiled_call != original_call:
        return False

    compiled_anchors = block_literal_anchors(
        compiled_instrs, compiled_image, ci, context.policy
    )
    original_anchors = block_literal_anchors(
        original_instrs, original_image, oi, context.policy
    )
    compiled_fingerprint = push_argument_fingerprint(
        compiled_instrs, compiled_image, ci, context.policy
    )
    original_fingerprint = push_argument_fingerprint(
        original_instrs, original_image, oi, context.policy
    )
    compiled_relocated = push_has_contextual_value(
        original_instrs,
        original_image,
        compiled_value,
        compiled_call,
        compiled_anchors,
        compiled_fingerprint,
        context,
        context.original_call_targets,
    )
    original_relocated = push_has_contextual_value(
        compiled_instrs,
        compiled_image,
        original_value,
        original_call,
        original_anchors,
        original_fingerprint,
        context,
        context.compiled_call_targets,
    )
    if compiled_relocated and original_relocated:
        return True

    # One compiler may split the other side of the LCS pair into an unlabelled
    # tail-merge block.  The anchored value alone still proves the current pair
    # is wrong; retain the warning when both sides have competing anchors so a
    # genuinely changed argument is not hidden.
    if compiled_anchors and not original_anchors and compiled_relocated:
        return True
    if original_anchors and not compiled_anchors and original_relocated:
        return True

    # Large switch functions can share dialogue tails without leaving a
    # literal in each individual basic block.  In that case compare the value
    # multiplicities for the same call and argument position.  Values that are
    # fully accounted for on both sides are merely paired with the wrong case
    # by the mnemonic LCS; an added, removed, or changed argument still has an
    # unmatched count and remains reportable.
    wanted_values = frozenset((compiled_value, original_value))
    compiled_counts = contextual_push_value_counts(
        compiled_instrs,
        compiled_image,
        compiled_call,
        wanted_values,
        context,
        context.compiled_call_targets,
    )
    original_counts = contextual_push_value_counts(
        original_instrs,
        original_image,
        original_call,
        wanted_values,
        context,
        context.original_call_targets,
    )
    return (
        compiled_counts[compiled_value] <= original_counts[compiled_value]
        and original_counts[original_value] <= compiled_counts[original_value]
    )


def different_following_call(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    context: CompareContext,
) -> bool:
    c_context = following_call_context(
        compiled_instrs, ci, direct_targets=context.compiled_call_targets
    )
    o_context = following_call_context(
        original_instrs, oi, direct_targets=context.original_call_targets
    )
    return (
        c_context is not None
        and o_context is not None
        and c_context != o_context
    )


def different_loaded_value_call_context(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    context: CompareContext,
) -> bool:
    compiled_call = loaded_value_call_context(
        compiled_instrs, ci, context.compiled_call_targets
    )
    original_call = loaded_value_call_context(
        original_instrs, oi, context.original_call_targets
    )
    return (
        compiled_call is not None
        and original_call is not None
        and compiled_call != original_call
    )


def stack_argument_origin_at(
    instrs: list[Instruction],
    idx: int,
    register: str,
) -> int | None:
    """Resolve a forwarded register to an entry-stack argument.

    Follow control flow so an early-return epilogue cannot corrupt the stack
    delta or overwrite a register on a path that never reaches the push being
    checked.  An origin is returned only when every reachable state agrees.
    """
    if idx < 0 or idx >= len(instrs):
        return None
    if idx > 512:
        return None

    target_register = full_register_name(register)
    by_addr = {instr.address: pos for pos, instr in enumerate(instrs)}
    # position, ESP delta from function entry, EBP frame delta, origins
    initial = (0, 0, None, ())
    worklist = [initial]
    seen: set[tuple] = set()
    target_origins: set[int | None] = set()

    while worklist and len(seen) < 2000:
        pos, stack_delta, frame_delta, packed_origins = worklist.pop()
        state_key = (pos, stack_delta, frame_delta, packed_origins)
        if state_key in seen or pos < 0 or pos >= len(instrs):
            continue
        seen.add(state_key)
        origins = dict(packed_origins)
        if pos == idx:
            target_origins.add(origins.get(target_register))
            continue

        instr = instrs[pos]
        operands = instr.operands
        next_stack = stack_delta
        next_frame = frame_delta
        next_origins = dict(origins)

        if instr.mnemonic == "call":
            for volatile in ("eax", "ecx", "edx"):
                next_origins.pop(volatile, None)
        elif instr.mnemonic == "mov" and len(operands) >= 2:
            dst, src = operands[0], operands[1]
            if dst.kind == "reg":
                dst_reg = full_register_name(dst.reg)
                src_reg = full_register_name(src.reg) if src.kind == "reg" else None
                if dst_reg == "ebp" and src_reg == "esp":
                    next_frame = stack_delta
                    next_origins.pop(dst_reg, None)
                elif dst_reg == "esp" and src_reg == "ebp":
                    if frame_delta is None:
                        continue
                    next_stack = frame_delta
                    next_origins.pop(dst_reg, None)
                else:
                    origin = None
                    if src.kind == "reg":
                        origin = origins.get(src_reg)
                    elif src.kind == "mem" and not src.index:
                        base = full_register_name(src.base)
                        if base == "esp":
                            origin = stack_delta + src.disp
                        elif base == "ebp" and frame_delta is not None:
                            origin = frame_delta + src.disp
                    if origin is not None and origin >= 4:
                        next_origins[dst_reg] = origin
                    else:
                        next_origins.pop(dst_reg, None)
        elif operands and operands[0].kind == "reg":
            written = full_register_name(operands[0].reg)
            if instr.mnemonic in {
                "pop", "lea", "add", "sub", "xor", "or", "and", "imul",
                "shl", "shr", "sar", "inc", "dec", "movzx", "movsx",
            }:
                next_origins.pop(written, None)

        if instr.mnemonic == "push":
            next_stack -= 4
        elif instr.mnemonic == "pop":
            next_stack += 4
        elif instr.mnemonic in {"add", "sub"} and len(operands) >= 2:
            dst, src = operands[0], operands[1]
            if (
                dst.kind == "reg"
                and full_register_name(dst.reg) == "esp"
                and src.kind == "imm"
            ):
                next_stack += src.imm if instr.mnemonic == "add" else -src.imm
        elif instr.mnemonic == "leave":
            if frame_delta is None:
                continue
            next_stack = frame_delta + 4
            next_frame = None
            next_origins.pop("ebp", None)
        elif instr.mnemonic in {"enter", "pushal", "popal"}:
            continue

        packed_next_origins = tuple(sorted(next_origins.items()))
        fallthrough = pos + 1
        successors: list[int] = []
        if instr.mnemonic == "ret":
            successors = []
        elif instr.mnemonic == "jmp":
            if operands and operands[0].kind == "imm":
                target = by_addr.get(unsigned32(operands[0].imm))
                if target is not None:
                    successors.append(target)
        elif is_conditional_branch_mnemonic(instr.mnemonic):
            if fallthrough < len(instrs):
                successors.append(fallthrough)
            if operands and operands[0].kind == "imm":
                target = by_addr.get(unsigned32(operands[0].imm))
                if target is not None:
                    successors.append(target)
        elif fallthrough < len(instrs):
            successors.append(fallthrough)

        for successor in successors:
            worklist.append((
                successor,
                next_stack,
                next_frame,
                packed_next_origins,
            ))

    if len(target_origins) != 1:
        return None
    origin = next(iter(target_origins))
    return origin if origin is not None and 4 <= origin <= 0x100 else None


def report_stack_argument_origin_mismatch(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
    context: CompareContext,
) -> tuple | None:
    if "offsets" not in context.enabled_kinds:
        return None

    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    if compiled.mnemonic != "push" or original.mnemonic != "push":
        return None
    if len(compiled.operands) != 1 or len(original.operands) != 1:
        return None

    c_op = compiled.operands[0]
    o_op = original.operands[0]
    if c_op.kind != "reg" or o_op.kind != "reg":
        return None
    if full_register_name(c_op.reg) == full_register_name(o_op.reg):
        return None

    c_call = following_call_context(
        compiled_instrs, ci, direct_targets=context.compiled_call_targets
    )
    o_call = following_call_context(
        original_instrs, oi, direct_targets=context.original_call_targets
    )
    if c_call is None or o_call is None or c_call != o_call:
        return None

    c_origin = stack_argument_origin_at(compiled_instrs, ci, c_op.reg)
    o_origin = stack_argument_origin_at(original_instrs, oi, o_op.reg)
    if c_origin is None or o_origin is None or c_origin == o_origin:
        return None
    return ("arg", c_origin, o_origin, compiled, original)


def report_string_mismatch(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    ci: int,
    oi: int,
    c_str: str | None,
    o_str: str | None,
    context: CompareContext,
):
    if c_str is None or o_str is None:
        return None
    c_norm = normalize_string_for_compare(c_str)
    o_norm = normalize_string_for_compare(o_str)
    if c_norm == o_norm:
        return None
    if c_norm is not None and o_norm is not None:
        compiled_strings = {
            normalize_string_for_compare(value)
            for idx in range(len(compiled_instrs))
            for _, operand in immediate_operands(compiled_instrs[idx])
            if (value := immediate_string(compiled_image, operand, context.policy)) is not None
        }
        original_strings = {
            normalize_string_for_compare(value)
            for idx in range(len(original_instrs))
            for _, operand in immediate_operands(original_instrs[idx])
            if (value := immediate_string(original_image, operand, context.policy)) is not None
        }
        if o_norm in compiled_strings and c_norm in original_strings:
            return None
        if (
            o_norm in nearby_strings(compiled_instrs, compiled_image, ci, context.policy)
            and c_norm in nearby_strings(original_instrs, original_image, oi, context.policy)
        ):
            return None
        if equivalent_reordered_push_values(
            compiled_instrs,
            original_instrs,
            compiled_image,
            original_image,
            ci,
            oi,
            c_norm,
            o_norm,
            context,
        ):
            return None
    if (
        nearby_calls_target(compiled_instrs, ci, context.compiled_diagnostic_targets)
        and nearby_calls_target(original_instrs, oi, context.original_diagnostic_targets)
    ):
        return None
    return ("string", c_str, o_str, compiled_instrs[ci], original_instrs[oi])


def compare_instruction_pair(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    ci: int,
    oi: int,
    context: CompareContext,
) -> list[tuple]:
    compiled = compiled_instrs[ci]
    original = original_instrs[oi]
    warnings: list[tuple] = []

    if compiled.mnemonic != original.mnemonic:
        return warnings
    if is_branch_or_call(compiled.mnemonic):
        return warnings
    if not should_compare_values(compiled, original, context):
        return warnings
    argument_warning = report_stack_argument_origin_mismatch(
        compiled_instrs, original_instrs, ci, oi, context
    )
    if argument_warning is not None:
        warnings.append(argument_warning)
    if not comparable_operands(compiled, original):
        return warnings
    if compiled.mnemonic == "push" and different_following_call(
        compiled_instrs, original_instrs, ci, oi, context
    ):
        return warnings
    if compare_targets_msvc_eh_state(compiled_instrs, original_instrs, compiled, original, context):
        return warnings
    branch_warning = report_cmp_branch_condition_mismatch(compiled_instrs, original_instrs, ci, oi, context)
    if branch_warning is not None:
        warnings.append(branch_warning)

    c_imms = dict(immediate_operands(compiled))
    o_imms = dict(immediate_operands(original))
    for idx in sorted(set(c_imms) & set(o_imms)):
        c_op = c_imms[idx]
        o_op = o_imms[idx]
        if c_op.imm == o_op.imm:
            continue
        c_str = immediate_string(compiled_image, c_op, context.policy)
        o_str = immediate_string(original_image, o_op, context.policy)
        if c_str is not None or o_str is not None:
            if "strings" not in context.enabled_kinds:
                continue
            if (
                not context.include_stack_locals
                and compiled.mnemonic != "push"
                and lhs_is_stack_memory(compiled, context.policy)
            ):
                continue
            warning = report_string_mismatch(
                compiled_instrs, original_instrs,
                compiled_image, original_image,
                ci, oi, c_str, o_str, context,
            )
            if warning is not None:
                warnings.append(warning)
            continue

        if "immediates" not in context.enabled_kinds:
            continue
        if (
            not context.include_stack_locals
            and compiled.mnemonic != "push"
            and lhs_is_stack_memory(compiled, context.policy)
        ):
            continue
        if is_stack_adjustment(compiled) and is_stack_adjustment(original):
            continue
        if (
            not context.include_stack_locals
            and is_stack_probe_size_load(compiled_instrs, ci)
            and is_stack_probe_size_load(original_instrs, oi)
        ):
            continue
        if not small_numeric_immediate(c_op, context.policy) or not small_numeric_immediate(o_op, context.policy):
            continue
        if compiled.mnemonic == "cmp" and equivalent_integer_threshold(
            c_op.imm, o_op.imm, compiled_instrs, original_instrs, ci, oi
        ):
            continue
        if compiled.mnemonic == "cmp" and equivalent_boolean_zero_test(
            c_op.imm, o_op.imm, compiled_instrs, original_instrs, ci, oi
        ):
            continue
        if equivalent_low_word_mask(
            compiled_instrs,
            original_instrs,
            ci,
            oi,
            c_op.imm,
            o_op.imm,
        ):
            continue
        if equivalent_sign_step_masks(compiled_instrs, original_instrs, ci, oi):
            continue
        if equivalent_reordered_x87_status_masks(
            compiled_instrs, original_instrs, ci, oi
        ):
            continue
        if same_effective_register_immediate(
            compiled_instrs, original_instrs, ci, oi, c_op.imm, o_op.imm, context.policy
        ):
            continue
        if compiled.mnemonic == "push":
            c_anchors = block_literal_anchors(
                compiled_instrs, compiled_image, ci, context.policy
            )
            o_anchors = block_literal_anchors(
                original_instrs, original_image, oi, context.policy
            )
            if c_anchors and o_anchors and c_anchors.isdisjoint(o_anchors):
                continue
        if (
            o_op.imm in nearby_immediate_values(compiled_instrs, ci, context.policy)
            and c_op.imm in nearby_immediate_values(original_instrs, oi, context.policy)
        ):
            continue
        if compiled.mnemonic == "push" and equivalent_reordered_push_values(
            compiled_instrs,
            original_instrs,
            compiled_image,
            original_image,
            ci,
            oi,
            c_op.imm,
            o_op.imm,
            context,
        ):
            continue
        if compiled.mnemonic != "push" and equivalent_structurally_reordered_immediates(
            compiled_instrs,
            original_instrs,
            ci,
            oi,
            idx,
            c_op.imm,
            o_op.imm,
        ):
            continue
        warnings.append(("imm", c_op.imm, o_op.imm, compiled, original))

    c_mems = dict(memory_operands(compiled))
    o_mems = dict(memory_operands(original))
    if "offsets" in context.enabled_kinds:
        for idx in sorted(set(c_mems) & set(o_mems)):
            c_op = c_mems[idx]
            o_op = o_mems[idx]
            if c_op.disp == o_op.disp:
                continue
            if not member_displacement(c_op.disp, context.policy) or not member_displacement(o_op.disp, context.policy):
                continue
            if not comparable_lhs(c_op, o_op, context.policy, context.include_stack_locals):
                continue
            if different_loaded_value_call_context(
                compiled_instrs, original_instrs, ci, oi, context
            ):
                continue
            c_near = nearby_memory_displacements(compiled_instrs, ci, context.policy, compiled.mnemonic)
            o_near = nearby_memory_displacements(original_instrs, oi, context.policy, original.mnemonic)
            if o_op.disp in c_near and c_op.disp in o_near:
                continue
            if same_effective_lea_displacement(compiled_instrs, original_instrs, ci, oi, c_op, o_op, context.policy):
                continue
            if same_affine_memory_address(
                compiled_instrs, original_instrs, ci, oi, c_op, o_op
            ):
                continue
            if equivalent_structurally_reordered_effective_addresses(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                idx,
                c_op,
                o_op,
            ):
                continue
            if equivalent_shifted_literal_pointer_base(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                idx,
                c_op,
                o_op,
                context.policy,
            ):
                continue
            if equivalent_structurally_reordered_displacements(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                idx,
                c_op.disp,
                o_op.disp,
            ):
                continue
            if (c_op.disp == 0 or o_op.disp == 0) and (has_pointer_immediate(compiled) or has_pointer_immediate(original)):
                continue
            warnings.append(("offset", c_op.disp, o_op.disp, compiled, original))

    return warnings


def check_candidate(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    context: CompareContext,
) -> tuple[float, tuple]:
    c_mnemonics = [instr.mnemonic for instr in compiled_instrs]
    o_mnemonics = [instr.mnemonic for instr in original_instrs]
    if not c_mnemonics or not o_mnemonics:
        return 0.0, ()

    similarity_matches = lcs_align(c_mnemonics, o_mnemonics)
    similarity = 100.0 * len(similarity_matches) / max(len(c_mnemonics), len(o_mnemonics))
    matches = value_aware_align(
        compiled_instrs,
        original_instrs,
        compiled_image,
        original_image,
        context,
    )

    warnings: list[tuple] = []
    for ci, oi in matches:
        warnings.extend(compare_instruction_pair(
            compiled_instrs,
            original_instrs,
            compiled_image,
            original_image,
            ci,
            oi,
            context,
        ))
    return similarity, tuple(warnings)


def instruction_value_anchor(
    instr: Instruction,
    image: PEImage,
    context: CompareContext,
) -> tuple:
    """Build an exact-value token used only to disambiguate mnemonic ties."""
    values: list[tuple] = []
    for operand_index, operand in immediate_operands(instr):
        string = immediate_string(image, operand, context.policy)
        if string is not None:
            values.append(("string", operand_index, normalize_string_for_compare(string)))
        elif small_numeric_immediate(operand, context.policy):
            values.append(("imm", operand_index, operand.imm))
    for operand_index, operand in memory_operands(instr):
        if (
            member_displacement(operand.disp, context.policy)
            and (
                context.include_stack_locals
                or operand.base not in context.policy.stack_registers
            )
        ):
            values.append(("disp", operand_index, operand.disp))
    return (instr.mnemonic, *values)


def value_aware_align(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    compiled_image: PEImage,
    original_image: PEImage,
    context: CompareContext,
) -> list[tuple[int, int]]:
    """Prefer exact-value anchors, then align mnemonic-only gaps.

    Plain mnemonic LCS has many equally optimal solutions in switch-heavy
    functions.  It can consequently compare an event's argument load with its
    event-code load even when exact counterparts for both exist.  Exact tokens
    select stable anchors; mnemonic alignment inside the gaps still exposes a
    genuinely changed value instead of dropping it from comparison.
    """
    compiled_tokens = [
        instruction_value_anchor(instr, compiled_image, context)
        for instr in compiled_instrs
    ]
    original_tokens = [
        instruction_value_anchor(instr, original_image, context)
        for instr in original_instrs
    ]
    anchors = lcs_align(compiled_tokens, original_tokens)
    matches: list[tuple[int, int]] = []
    previous_c = -1
    previous_o = -1
    for anchor_c, anchor_o in [*anchors, (len(compiled_instrs), len(original_instrs))]:
        c_start = previous_c + 1
        o_start = previous_o + 1
        gap_matches = lcs_align(
            [instr.mnemonic for instr in compiled_instrs[c_start:anchor_c]],
            [instr.mnemonic for instr in original_instrs[o_start:anchor_o]],
        )
        matches.extend((c_start + ci, o_start + oi) for ci, oi in gap_matches)
        if anchor_c < len(compiled_instrs) and anchor_o < len(original_instrs):
            matches.append((anchor_c, anchor_o))
        previous_c = anchor_c
        previous_o = anchor_o
    return matches


def check_function(
    group: FunctionGroup,
    original_image: PEImage,
    rebuilt_image: PEImage,
    original_starts: list[int],
    rebuilt_starts: list[int],
    context: CompareContext,
) -> CheckResult | None:
    rebuilt_instrs = disassemble(rebuilt_image, group.rebuilt_addr, rebuilt_starts, context.policy)
    if not rebuilt_instrs:
        return None

    results: list[CheckResult] = []
    for original_addr in group.original_addrs:
        original_instrs = disassemble(original_image, original_addr, original_starts, context.policy)
        if not original_instrs:
            continue
        similarity, warnings = check_candidate(
            rebuilt_instrs,
            original_instrs,
            rebuilt_image,
            original_image,
            context,
        )
        results.append(CheckResult(
            original_addr=original_addr,
            rebuilt_addr=group.rebuilt_addr,
            similarity=similarity,
            original_count=len(original_instrs),
            rebuilt_count=len(rebuilt_instrs),
            warnings=warnings,
        ))

    if not results:
        return None
    return sorted(results, key=lambda result: (result.similarity, -len(result.warnings)), reverse=True)[0]


def format_warning(warning: tuple) -> str:
    kind, compiled_value, original_value, compiled, original = warning
    if kind == "string":
        return (
            f"    STRING compiled {compiled_value!r} vs original {original_value!r}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    if kind == "imm":
        return (
            f"    IMM {compiled_value} vs {original_value}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    if kind == "offset":
        return (
            f"    OFFSET 0x{compiled_value & 0xFFFFFFFF:X} vs 0x{original_value & 0xFFFFFFFF:X}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    if kind == "branch":
        return (
            f"    BRANCH compiled {compiled_value} vs original {original_value}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    if kind == "arg":
        return (
            f"    ARG STACK+0x{compiled_value:X} vs STACK+0x{original_value:X}: "
            f"0x{compiled.address:08X} {compiled.raw}  |  "
            f"0x{original.address:08X} {original.raw}"
        )
    return str(warning)


def warning_kind_counts(warnings: tuple) -> dict[str, int]:
    counts = {"imm": 0, "string": 0, "offset": 0, "branch": 0, "arg": 0}
    for warning in warnings:
        if not warning:
            continue
        kind = warning[0]
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def format_kind_counts(counts: dict[str, int]) -> str:
    labels = (
        ("imm", "IMM"),
        ("string", "STRING"),
        ("offset", "OFFSET"),
        ("branch", "BRANCH"),
        ("arg", "ARG"),
    )
    parts = [f"{label} {counts[kind]}" for kind, label in labels if counts.get(kind, 0)]
    return ", ".join(parts) if parts else "none"


def maybe_build(target: ProjectTarget, do_build: bool) -> int:
    if not do_build:
        return 0
    if target.build.clean:
        subprocess.run(target.build.clean.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if not target.build.build:
        return 0
    build_command = target.build.build.split()
    if target.build.jobs and target.build.jobs > 1:
        build_command.append(f"-j{target.build.jobs}")
    return subprocess.run(build_command, check=False).returncode


def check_values(target: ProjectTarget, policy: VerifierPolicy, options: ValuesOptions) -> ValuesSummary:
    build_rc = maybe_build(target, options.build)
    if build_rc != 0:
        raise RuntimeError("build failed")

    for path, label in (
        (target.original_exe, "original executable"),
        (target.rebuilt_exe, "rebuilt executable"),
        (target.map_path, "linker map"),
    ):
        if not os.path.exists(path):
            raise FileNotFoundError(f"missing {label}: {path}")

    groups_by_source = load_source_groups(target.source_dirs, target.map_skip, target.source_excludes)
    mapped_groups, missing_groups, entries_by_obj = map_source_groups(groups_by_source, target.map_path)
    original_call_targets, rebuilt_call_targets = build_call_target_names(mapped_groups)

    if options.file_filter:
        mapped_groups = [
            group for group in mapped_groups
            if options.file_filter in os.path.basename(group.source_path) or options.file_filter in group.name
        ]

    original_starts = load_original_boundary_starts(target.code_dir, mapped_groups)
    rebuilt_starts = function_starts_from_map(entries_by_obj)
    boundary_inventory = {}
    if options.boundary_report:
        boundary_inventory = {
            "source_function_groups": sum(len(groups) for groups in groups_by_source.values()),
            "mapped_groups": len(mapped_groups),
            "original_marker_candidates": sum(len(group.original_addrs) for group in mapped_groups),
            "original_boundary_starts": len(original_starts),
            "rebuilt_boundary_starts": len(rebuilt_starts),
            "missing_map_groups": len(missing_groups),
        }

    original_image = PEImage(target.original_exe)
    rebuilt_image = PEImage(target.rebuilt_exe)
    original_diag_targets, rebuilt_diag_targets = build_diagnostic_targets(mapped_groups, policy)
    context = CompareContext(
        enabled_kinds=options.enabled_kinds,
        policy=policy,
        include_stack_locals=options.include_stack_locals,
        compiled_diagnostic_targets=rebuilt_diag_targets,
        original_diagnostic_targets=original_diag_targets,
        compiled_call_targets=rebuilt_call_targets,
        original_call_targets=original_call_targets,
    )

    total = 0
    with_mismatches = 0
    total_warnings = 0
    skipped_below_threshold = 0
    skipped_no_bytes = 0
    reports: list[tuple[FunctionGroup, CheckResult]] = []

    for group in mapped_groups:
        total += 1
        result = check_function(group, original_image, rebuilt_image, original_starts, rebuilt_starts, context)
        if result is None:
            skipped_no_bytes += 1
            continue
        if not result.warnings:
            continue
        if result.similarity < options.min_similarity:
            skipped_below_threshold += 1
            continue

        with_mismatches += 1
        total_warnings += len(result.warnings)
        reports.append((group, result))

    return ValuesSummary(
        functions_checked=total,
        with_value_mismatches=with_mismatches,
        total_mismatches=total_warnings,
        skipped_no_bytes=skipped_no_bytes,
        skipped_below_threshold=skipped_below_threshold,
        unmapped_source_groups=len(missing_groups),
        boundary_inventory=boundary_inventory,
        reports=tuple(reports),
    )


def format_summary(summary: ValuesSummary, min_similarity: float = 0.0) -> str:
    lines: list[str] = []
    if summary.boundary_inventory:
        inventory = summary.boundary_inventory
        lines.extend([
            "--- Boundary Inventory ---",
            f"Source function groups: {inventory['source_function_groups']}",
            f"Mapped groups: {inventory['mapped_groups']}",
            f"Original marker candidates in mapped groups: {inventory['original_marker_candidates']}",
            f"Original boundary starts: {inventory['original_boundary_starts']}",
            f"Rebuilt boundary starts from map: {inventory['rebuilt_boundary_starts']}",
            f"Missing map groups: {inventory['missing_map_groups']}",
            "",
        ])

    for group, result in summary.reports:
        lines.append(
            f"\n{group.name} "
            f"(orig 0x{result.original_addr:X}, rebuilt 0x{result.rebuilt_addr:X}, "
            f"{result.similarity:.1f}%) - {len(result.warnings)} mismatch(es):"
        )
        for warning in result.warnings:
            lines.append(format_warning(warning))

    if lines:
        lines.append("")
    if summary.total_mismatches:
        total_counts: dict[str, int] = {}
        for _, result in summary.reports:
            for kind, count in warning_kind_counts(result.warnings).items():
                total_counts[kind] = total_counts.get(kind, 0) + count

        lines.extend([
            "--- Mismatch Breakdown ---",
            f"By kind: {format_kind_counts(total_counts)}",
            "Top functions:",
        ])
        top_reports = sorted(summary.reports, key=lambda item: len(item[1].warnings), reverse=True)[:10]
        for group, result in top_reports:
            lines.append(
                f"  {group.name}: {len(result.warnings)} "
                f"({format_kind_counts(warning_kind_counts(result.warnings))}; {result.similarity:.1f}%)"
            )
        lines.append("")

    lines.extend([
        "--- Summary ---",
        f"Functions checked: {summary.functions_checked}",
        f"With value mismatches: {summary.with_value_mismatches}",
        f"Total mismatches: {summary.total_mismatches}",
        f"Skipped (no bytes/disassembly): {summary.skipped_no_bytes}",
    ])
    if min_similarity > 0:
        lines.append(f"Skipped (similarity < {min_similarity:.1f}%): {summary.skipped_below_threshold}")
    if summary.unmapped_source_groups:
        lines.append(f"Unmapped source groups: {summary.unmapped_source_groups}")
    return "\n".join(lines)
