"""Capstone-backed operand value verification."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from importlib import resources

from binary_comp.config import ConfigError, ProjectTarget, parse_int
from binary_comp.core.align import lcs_align
from binary_comp.core.disasm import (
    Instruction,
    Operand,
    disassemble_x86,
    is_branch_or_call,
    signed32,
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


def equivalent_format_strings(left: str, right: str) -> bool:
    if "%" not in left or "%" not in right:
        return False
    return "".join(left.split()) == "".join(right.split())


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


def load_original_boundary_starts(code_dir: str | None, function_groups: list[FunctionGroup]) -> list[int]:
    starts = set(function_starts_from_export_dir(code_dir))
    for group in function_groups:
        starts.update(group.original_addrs)
    return sorted(starts)


def disassemble(image: PEImage, start: int, starts: list[int], policy: VerifierPolicy) -> list[Instruction]:
    return disassemble_x86(
        image,
        start,
        starts,
        max_bytes=policy.max_disassembly_bytes,
        padding_mnemonics=policy.padding_mnemonics,
    )


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


def update_register_aliases(aliases: dict[str, Operand], instr: Instruction, policy: VerifierPolicy) -> None:
    if instr.mnemonic == "call":
        for reg in ("eax", "ecx", "edx"):
            aliases.pop(reg, None)
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
    for j in range(0, idx):
        update_register_aliases(aliases, instrs[j], policy)
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


def next_mnemonic(instrs: list[Instruction], idx: int) -> str | None:
    if idx + 1 >= len(instrs):
        return None
    return instrs[idx + 1].mnemonic


def equivalent_integer_threshold(
    c_imm: int,
    o_imm: int,
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    c_next = next_mnemonic(compiled_instrs, ci)
    o_next = next_mnemonic(original_instrs, oi)
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


def is_stack_adjustment(instr: Instruction) -> bool:
    if instr.mnemonic not in {"add", "sub"} or len(instr.operands) < 2:
        return False
    return instr.operands[0].kind == "reg" and instr.operands[0].reg == "esp"


def direct_jump_target(instr: Instruction) -> int | None:
    if instr.mnemonic != "jmp" or len(instr.operands) != 1:
        return None
    operand = instr.operands[0]
    if operand.kind != "imm":
        return None
    return unsigned32(operand.imm)


def call_signature(instr: Instruction) -> tuple | None:
    if instr.mnemonic != "call" or len(instr.operands) != 1:
        return None
    operand = instr.operands[0]
    if operand.kind == "mem":
        return ("mem", operand.index, operand.scale, operand.disp)
    if operand.kind == "imm":
        return ("direct",)
    return None


def following_call_signature(instrs: list[Instruction], idx: int, max_steps: int = 48) -> tuple | None:
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
        signature = call_signature(instr)
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


def different_following_call(
    compiled_instrs: list[Instruction],
    original_instrs: list[Instruction],
    ci: int,
    oi: int,
) -> bool:
    c_sig = following_call_signature(compiled_instrs, ci)
    o_sig = following_call_signature(original_instrs, oi)
    return c_sig is not None and o_sig is not None and c_sig != o_sig


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
    if c_norm.lower() == o_norm.lower():
        return None
    if c_norm and o_norm and (c_norm.startswith(o_norm) or o_norm.startswith(c_norm)):
        return None
    if c_norm is not None and o_norm is not None and equivalent_format_strings(c_norm, o_norm):
        return None
    if c_norm is not None and o_norm is not None:
        if (
            o_norm in nearby_strings(compiled_instrs, compiled_image, ci, context.policy)
            and c_norm in nearby_strings(original_instrs, original_image, oi, context.policy)
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
    if not comparable_operands(compiled, original):
        return warnings
    if compiled.mnemonic == "push" and different_following_call(compiled_instrs, original_instrs, ci, oi):
        return warnings

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
        if (
            o_op.imm in nearby_immediate_values(compiled_instrs, ci, context.policy)
            and c_op.imm in nearby_immediate_values(original_instrs, oi, context.policy)
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
            c_near = nearby_memory_displacements(compiled_instrs, ci, context.policy, compiled.mnemonic)
            o_near = nearby_memory_displacements(original_instrs, oi, context.policy, original.mnemonic)
            if o_op.disp in c_near and c_op.disp in o_near:
                continue
            if same_effective_lea_displacement(compiled_instrs, original_instrs, ci, oi, c_op, o_op, context.policy):
                continue
            if equivalent_shifted_memory_base(
                compiled_instrs,
                original_instrs,
                ci,
                oi,
                idx,
                c_op,
                o_op,
                context.policy,
                context.include_stack_locals,
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

    matches = lcs_align(c_mnemonics, o_mnemonics)
    similarity = 100.0 * len(matches) / max(len(c_mnemonics), len(o_mnemonics))

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
    return str(warning)


def warning_kind_counts(warnings: tuple) -> dict[str, int]:
    counts = {"imm": 0, "string": 0, "offset": 0}
    for warning in warnings:
        if not warning:
            continue
        kind = warning[0]
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def format_kind_counts(counts: dict[str, int]) -> str:
    labels = (("imm", "IMM"), ("string", "STRING"), ("offset", "OFFSET"))
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

    groups_by_source = load_source_groups(target.source_dirs, target.map_skip)
    mapped_groups, missing_groups, entries_by_obj = map_source_groups(groups_by_source, target.map_path)

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
