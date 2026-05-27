"""Global access verification for reimplementation projects."""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from binary_comp.analyzers.calls import (
    CallsOptions,
    load_calls_policy,
    maybe_build,
    normalize_compiled,
    policy_with_same_address_aliases,
    select_functions,
)
from binary_comp.analyzers.globals import (
    GlobalDecl,
    auto_global_ranges,
    configure_globals,
    get_section,
    infer_size,
    parse_defines,
    parse_globals_source,
    symbol_for_auto_global,
)
from binary_comp.config import ConfigError, ProjectTarget
from binary_comp.core.pe import PEImage


WRITE_MNEMONICS = {
    "mov",
    "xchg",
}

REGISTER_WRITE_MNEMONICS = WRITE_MNEMONICS | {
    "movsx",
    "movzx",
}

READ_WRITE_MNEMONICS = {
    "adc",
    "add",
    "and",
    "dec",
    "inc",
    "neg",
    "not",
    "or",
    "sbb",
    "sub",
    "xor",
}


@dataclass(frozen=True)
class GlobalAccessOptions:
    filters: tuple[str, ...] = ()
    build: bool = True
    include_address_immediates: bool = False
    build_args: tuple[str, ...] = ()
    show_all: bool = False


@dataclass(frozen=True)
class GlobalAccessSummary:
    functions_selected: int
    functions_checked: int
    mismatches: tuple["GlobalAccessMismatch", ...]
    skipped_no_disasm: tuple[tuple[str, int, str], ...]
    include_address_immediates: bool
    report_all: bool
    compare_counts: bool


@dataclass(frozen=True)
class GlobalAccessMismatch:
    function_name: str
    original_addr: int
    filename: str
    missing: dict[str, int]
    extra: dict[str, int]


def split_operands(text: str) -> list[str]:
    out: list[str] = []
    start = 0
    bracket_depth = 0
    for index, ch in enumerate(text):
        if ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif ch == "," and bracket_depth == 0:
            out.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        out.append(tail)
    return out


def instruction_parts(line: str) -> tuple[str, list[str]] | None:
    line = line.split(";", 1)[0].strip()
    if not line or line.startswith(("Function:", "Address:", "$", "_$")) or line.endswith(":"):
        return None
    rep_match = re.match(r"(rep(?:n?z)?|repne|repe)\s+([A-Za-z]+)\s*(.*)$", line, flags=re.IGNORECASE)
    if rep_match:
        mnemonic = f"{rep_match.group(2).lower()}.{rep_match.group(1).lower()}"
        return mnemonic, split_operands(rep_match.group(3))
    match = re.match(r"([A-Za-z.]+)\s*(.*)$", line)
    if not match:
        return None
    mnemonic = match.group(1).lower()
    if mnemonic.startswith(("j", "ret", "call")):
        return mnemonic, split_operands(match.group(2))
    return mnemonic, split_operands(match.group(2))


def access_kind_for_operand(mnemonic: str, operand_index: int) -> str:
    if operand_index == 0 and mnemonic in WRITE_MNEMONICS:
        return "WRITE"
    if operand_index == 0 and mnemonic in READ_WRITE_MNEMONICS:
        return "WRITE"
    return "READ"


def access_kinds_for_operand(mnemonic: str, operand_index: int) -> tuple[str, ...]:
    if operand_index == 0 and mnemonic in READ_WRITE_MNEMONICS:
        return ("READ", "WRITE")
    return (access_kind_for_operand(mnemonic, operand_index),)


def configured_global_decls(config: dict[str, Any], target: ProjectTarget) -> list[GlobalDecl]:
    globals_config = get_section(config, "globals")
    configure_globals(globals_config)
    constants = parse_defines([target.globals_header, *target.define_headers])
    decls = parse_globals_source(target.globals_source)
    by_addr = sorted(decls, key=lambda decl: decl.address)
    next_by_addr: dict[int, int | None] = {}
    for index, decl in enumerate(by_addr):
        next_by_addr[id(decl)] = by_addr[index + 1].address if index + 1 < len(by_addr) else None
    for decl in decls:
        decl.size = infer_size(decl, constants, next_by_addr[id(decl)])
        if decl.size and decl.size > 0x10000:
            decl.size = None
    return decls


def data_section_ranges(target: ProjectTarget) -> list[tuple[int, int]]:
    pe = PEImage(target.original_exe)
    return [
        (section.start, section.end)
        for section in pe.sections
        if section.name.lower() in (".data", ".rdata")
    ]


def in_ranges(address: int, ranges: Sequence[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def symbol_for_address(address: int, global_ranges, data_ranges: Sequence[tuple[int, int]]) -> str | None:
    starts = [item.start for item in global_ranges]
    symbol = symbol_for_auto_global(address, starts, global_ranges)
    if not symbol.startswith("0x"):
        return symbol
    if in_ranges(address, data_ranges):
        return f"0x{address:08x}"
    return None


def access_token(kind: str, symbol: str) -> str:
    return f"{kind}:{symbol}"


def token_symbol(token: str) -> str:
    return token.split(":", 1)[1]


def is_string_constant_token(token: str) -> bool:
    return token_symbol(token).startswith("s_")


REGISTER_ALIASES = {
    "eax": "eax", "ax": "eax", "ah": "eax", "al": "eax",
    "ebx": "ebx", "bx": "ebx", "bh": "ebx", "bl": "ebx",
    "ecx": "ecx", "cx": "ecx", "ch": "ecx", "cl": "ecx",
    "edx": "edx", "dx": "edx", "dh": "edx", "dl": "edx",
    "esi": "esi", "si": "esi",
    "edi": "edi", "di": "edi",
    "ebp": "ebp", "bp": "ebp",
    "esp": "esp", "sp": "esp",
}

REGISTER_NAMES = frozenset(REGISTER_ALIASES)
CALL_CLOBBERED_REGISTERS = frozenset(("eax", "ecx", "edx"))


def discard_call_clobbered_register_bases(register_bases: dict) -> None:
    for register in CALL_CLOBBERED_REGISTERS:
        register_bases.pop(register, None)


def plain_register(operand: str) -> str | None:
    operand = operand.strip().lower()
    return REGISTER_ALIASES.get(operand)


def referenced_register(operand: str) -> str | None:
    operand = operand.strip().lower()
    if ":" in operand:
        operand = operand.rsplit(":", 1)[1]
    return plain_register(operand)


def bracket_contents(operand: str) -> list[str]:
    return re.findall(r"\[([^\]]+)\]", operand)


def parse_original_address(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 16)


def parse_numeric_literal(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    if value.upper().endswith("H"):
        return int(value[:-1], 16)
    return int(value, 10)


def memory_displacement(content: str) -> int:
    cleaned = re.sub(r"\*\s*(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+)", "", content)
    total = 0
    for match in re.finditer(r"([+-]?)\s*(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+)", cleaned):
        literal = match.group(2)
        if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{6,8}", literal, flags=re.IGNORECASE):
            continue
        value = parse_numeric_literal(literal)
        if match.group(1) == "-":
            value = -value
        total += value
    return total


def addresses_from_memory_operand(operand: str, register_bases: dict[str, int]) -> set[int]:
    addresses: set[int] = set()
    for content in bracket_contents(operand):
        direct_addresses: set[int] = set()
        for match in re.finditer(r"(?<![\w])(?:0x)?([0-9A-Fa-f]{6,8})(?![\w])", content):
            direct_addresses.add(parse_original_address(match.group(1)))
        addresses.update(direct_addresses)
        if direct_addresses:
            continue
        displacement = memory_displacement(content)
        for register, base in register_bases.items():
            if re.search(rf"\b{re.escape(register)}\b", content, re.IGNORECASE):
                addresses.add(base + displacement)
    return addresses


STRING_INSTRUCTION_RE = re.compile(r"^(?:movs|cmps|scas|lods|stos)[bwdq]?(?:\.|$)")


def is_string_instruction(mnemonic: str) -> bool:
    return STRING_INSTRUCTION_RE.match(mnemonic) is not None


def string_instruction_operands(mnemonic: str, operands: Sequence[str]) -> Sequence[str]:
    if not is_string_instruction(mnemonic):
        return ()
    if operands:
        return operands
    if mnemonic.startswith("movs") or mnemonic.startswith("cmps"):
        return ("edi", "esi")
    if mnemonic.startswith("stos") or mnemonic.startswith("scas"):
        return ("edi",)
    if mnemonic.startswith("lods"):
        return ("esi",)
    return ()


def string_instruction_kind(mnemonic: str, operand_index: int) -> str:
    if mnemonic.startswith("movs") or mnemonic.startswith("cmps"):
        return "WRITE" if mnemonic.startswith("movs") and operand_index == 0 else "READ"
    if mnemonic.startswith("stos"):
        return "WRITE"
    return "READ"


def update_original_register_bases(mnemonic: str, operands: Sequence[str], register_bases: dict[str, int]) -> None:
    if mnemonic == "call":
        discard_call_clobbered_register_bases(register_bases)
        return
    if mnemonic in ("cdq", "cwd", "idiv", "div"):
        register_bases.pop("eax", None)
        register_bases.pop("edx", None)
        return
    if not operands:
        return
    dest = plain_register(operands[0])
    if dest is None:
        return
    source_base = None
    if len(operands) >= 2:
        source = plain_register(operands[1])
        if source is not None:
            source_base = register_bases.get(source)
    if mnemonic in ("add", "sub") and len(operands) >= 2 and dest in register_bases:
        match = re.fullmatch(r"(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+)", operands[1].strip())
        if match:
            delta = parse_numeric_literal(operands[1])
            register_bases[dest] += -delta if mnemonic == "sub" else delta
            return
    lea_addresses = set()
    if mnemonic == "lea" and len(operands) >= 2:
        lea_addresses = addresses_from_memory_operand(operands[1], register_bases)
    if mnemonic not in REGISTER_WRITE_MNEMONICS and mnemonic not in READ_WRITE_MNEMONICS and mnemonic != "lea":
        return
    register_bases.pop(dest, None)
    if mnemonic == "lea" and len(operands) >= 2:
        if len(lea_addresses) == 1:
            register_bases[dest] = next(iter(lea_addresses))
        return
    if mnemonic == "mov" and len(operands) >= 2:
        if source_base is not None:
            register_bases[dest] = source_base
            return
        match = re.fullmatch(r"(?:0x)?([0-9A-Fa-f]{6,8})", operands[1].strip())
        if match:
            register_bases[dest] = parse_original_address(match.group(1))


def extract_original_global_accesses(
    disasm_path: str,
    global_ranges,
    data_ranges: Sequence[tuple[int, int]],
    include_address_immediates: bool = False,
) -> list[str]:
    accesses: list[str] = []
    try:
        with open(disasm_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return accesses

    immediate_re = re.compile(r"(?<![\w?@])0x([0-9A-Fa-f]{6,8})(?![\w?@])|(?<![\w?@])([0-9A-Fa-f]{7,8})(?![\w?@])")
    register_bases: dict[str, int] = {}
    for raw in lines:
        parsed = instruction_parts(raw.strip())
        if parsed is None:
            continue
        mnemonic, operands = parsed
        memory_addresses: set[int] = set()
        string_operands = string_instruction_operands(mnemonic, operands)
        if string_operands:
            for index, operand in enumerate(string_operands):
                register = referenced_register(operand)
                if register is None or register not in register_bases:
                    continue
                symbol = symbol_for_address(register_bases[register], global_ranges, data_ranges)
                if symbol is not None:
                    accesses.append(access_token(string_instruction_kind(mnemonic, index), symbol))
        if mnemonic != "lea":
            for index, operand in enumerate(operands):
                for address in addresses_from_memory_operand(operand, register_bases):
                    memory_addresses.add(address)
                    symbol = symbol_for_address(address, global_ranges, data_ranges)
                    if symbol is not None:
                        for kind in access_kinds_for_operand(mnemonic, index):
                            accesses.append(access_token(kind, symbol))
        elif include_address_immediates and len(operands) >= 2:
            for address in addresses_from_memory_operand(operands[1], {}):
                memory_addresses.add(address)
                symbol = symbol_for_address(address, global_ranges, data_ranges)
                if symbol is not None:
                    accesses.append(access_token("ADDR", symbol))

        if not include_address_immediates:
            update_original_register_bases(mnemonic, operands, register_bases)
            continue
        for operand in operands:
            if "[" in operand:
                continue
            for match in immediate_re.finditer(operand):
                raw_addr = match.group(1) or match.group(2)
                address = int(raw_addr, 16)
                if address in memory_addresses:
                    continue
                symbol = symbol_for_address(address, global_ranges, data_ranges)
                if symbol is not None:
                    accesses.append(access_token("ADDR", symbol))
        update_original_register_bases(mnemonic, operands, register_bases)
    return accesses


def plain_global_name(symbol: str) -> str | None:
    match = re.match(r"\?([A-Za-z_][A-Za-z0-9_]*)@@", symbol)
    if match:
        return match.group(1)
    return None


def parse_asm_offset(value: str | None) -> int:
    if not value:
        return 0
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    if value.upper().endswith("H"):
        return int(value[:-1], 16)
    return int(value, 10)


def symbol_with_offset(name: str, offset: int) -> str:
    if offset == 0:
        return name
    return f"{name}+0x{offset:x}"


def split_symbol_offset(symbol: str) -> tuple[str, int]:
    if "+0x" not in symbol:
        return symbol, 0
    name, offset = symbol.rsplit("+0x", 1)
    return name, int(offset, 16)


def add_symbol_offset(symbol: str, offset: int) -> str:
    name, current = split_symbol_offset(symbol)
    return symbol_with_offset(name, current + offset)


def canonical_compiled_symbol(symbol: str, global_ranges: Sequence | None) -> str:
    if global_ranges is None:
        return symbol
    name, offset = split_symbol_offset(symbol)
    for item in global_ranges:
        if item.name == name:
            starts = [global_item.start for global_item in global_ranges]
            return symbol_for_auto_global(item.start + offset, starts, global_ranges)
    return symbol


def extract_symbols_from_operand(operand: str, global_names: frozenset[str]) -> list[tuple[str, bool]]:
    result: list[tuple[str, bool]] = []
    is_address = "OFFSET FLAT:" in operand.upper()
    symbol_re = re.compile(
        r"\?([A-Za-z_][A-Za-z0-9_]*)@@[^\s,\]\+\[]*(?:\+(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|[0-9]+))?"
        r"|(?<![A-Za-z0-9_?@])_([A-Za-z_][A-Za-z0-9_]*)(?:\+(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|[0-9]+))?"
    )
    for match in symbol_re.finditer(operand):
        name = match.group(1) or match.group(3)
        if name in global_names:
            offset = parse_asm_offset(match.group(2) or match.group(4))
            tail = operand[match.end():].lstrip()
            if tail.startswith("["):
                contents = bracket_contents(tail)
                if contents:
                    displacement = memory_displacement(contents[0])
                    if displacement > 0:
                        offset += displacement
            result.append((symbol_with_offset(name, offset), is_address))
    return result


def symbols_from_register_memory_operand(operand: str, register_bases: dict[str, str]) -> set[str]:
    symbols: set[str] = set()
    for content in bracket_contents(operand):
        if re.search(r"\?[A-Za-z_][A-Za-z0-9_]*@@", content):
            continue
        displacement = memory_displacement(content)
        for register, symbol in register_bases.items():
            if re.search(rf"\b{re.escape(register)}\b", content, re.IGNORECASE):
                symbols.add(add_symbol_offset(symbol, displacement))
    return symbols


def update_compiled_register_bases(
    mnemonic: str,
    operands: Sequence[str],
    global_names: frozenset[str],
    register_bases: dict[str, str],
) -> None:
    if mnemonic == "call":
        discard_call_clobbered_register_bases(register_bases)
        return
    if mnemonic in ("cdq", "cwd", "idiv", "div"):
        register_bases.pop("eax", None)
        register_bases.pop("edx", None)
        return
    if not operands:
        return
    dest = plain_register(operands[0])
    if dest is None:
        return
    source_base = None
    if len(operands) >= 2:
        source = plain_register(operands[1])
        if source is not None:
            source_base = register_bases.get(source)
    if mnemonic in ("add", "sub") and len(operands) >= 2 and dest in register_bases:
        match = re.fullmatch(r"(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+)", operands[1].strip())
        if match:
            delta = parse_numeric_literal(operands[1])
            register_bases[dest] = add_symbol_offset(register_bases[dest], -delta if mnemonic == "sub" else delta)
            return
    lea_symbols = set()
    if mnemonic == "lea" and len(operands) >= 2:
        direct_symbols = extract_symbols_from_operand(operands[1], global_names)
        if direct_symbols:
            lea_symbols = {symbol for symbol, _is_address in direct_symbols}
        else:
            lea_symbols = symbols_from_register_memory_operand(operands[1], register_bases)
    if mnemonic not in REGISTER_WRITE_MNEMONICS and mnemonic not in READ_WRITE_MNEMONICS and mnemonic != "lea":
        return
    register_bases.pop(dest, None)
    if mnemonic == "mov" and len(operands) >= 2:
        if source_base is not None:
            register_bases[dest] = source_base
            return
        symbols = extract_symbols_from_operand(operands[1], global_names)
        if len(symbols) == 1 and symbols[0][1]:
            register_bases[dest] = symbols[0][0]
        return
    if mnemonic == "lea" and len(operands) >= 2:
        if len(lea_symbols) == 1:
            register_bases[dest] = next(iter(lea_symbols))


def asm_function_lines(
    asm_path: str,
    function_name: str,
    occurrence_index: int,
    signature_names: frozenset[str],
) -> list[str]:
    try:
        with open(asm_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    func_lines: list[str] = []
    current_index = -1
    in_func = False
    for line in lines:
        stripped = line.strip()
        if not in_func:
            if "PROC" not in stripped:
                continue
            matched = False
            if "; " in stripped:
                comment = stripped.split("; ", 1)[1].strip()
                if comment.endswith(", COMDAT"):
                    comment = comment[:-len(", COMDAT")].strip()
                matched = comment == function_name
            if not matched:
                symbol = stripped.split(None, 1)[0]
                matched = normalize_compiled(symbol, signature_names) == function_name
            if not matched:
                continue
            current_index += 1
            if current_index != occurrence_index:
                continue
            in_func = True
            continue

        if re.search(r"\bENDP\b", stripped):
            break
        func_lines.append(stripped)
    return func_lines


def extract_compiled_global_accesses(
    asm_path: str,
    function_name: str,
    occurrence_index: int,
    global_names: frozenset[str],
    signature_names: frozenset[str],
    include_address_immediates: bool = False,
    global_ranges: Sequence | None = None,
) -> list[str]:
    accesses: list[str] = []
    register_bases: dict[str, str] = {}
    for line in asm_function_lines(asm_path, function_name, occurrence_index, signature_names):
        parsed = instruction_parts(line)
        if parsed is None:
            continue
        mnemonic, operands = parsed
        string_operands = string_instruction_operands(mnemonic, operands)
        if string_operands:
            for index, operand in enumerate(string_operands):
                register = referenced_register(operand)
                if register is None or register not in register_bases:
                    continue
                symbol = canonical_compiled_symbol(register_bases[register], global_ranges)
                accesses.append(access_token(string_instruction_kind(mnemonic, index), symbol))
        if mnemonic != "lea":
            for index, operand in enumerate(operands):
                for symbol in symbols_from_register_memory_operand(operand, register_bases):
                    symbol = canonical_compiled_symbol(symbol, global_ranges)
                    for kind in access_kinds_for_operand(mnemonic, index):
                        accesses.append(access_token(kind, symbol))
        for index, operand in enumerate(operands):
            for symbol, is_address in extract_symbols_from_operand(operand, global_names):
                symbol = canonical_compiled_symbol(symbol, global_ranges)
                if mnemonic == "lea" and index == 1:
                    if include_address_immediates:
                        accesses.append(access_token("ADDR", symbol))
                    continue
                if is_address:
                    if include_address_immediates:
                        accesses.append(access_token("ADDR", symbol))
                    continue
                for kind in access_kinds_for_operand(mnemonic, index):
                    accesses.append(access_token(kind, symbol))
        update_compiled_register_bases(mnemonic, operands, global_names, register_bases)
    return accesses


def apply_allowances(function_name: str, missing: Counter, extra: Counter, allowances: Iterable[dict[str, Any]]) -> None:
    for allowance in allowances:
        if str(allowance.get("function", "")) != function_name:
            continue
        token = str(allowance.get("access", ""))
        if not token:
            continue
        missing_allowed = int(allowance.get("missing", 0))
        extra_allowed = int(allowance.get("extra", 0))
        if missing_allowed:
            remaining = missing.get(token, 0) - missing_allowed
            if remaining > 0:
                missing[token] = remaining
            else:
                missing.pop(token, None)
        if extra_allowed:
            remaining = extra.get(token, 0) - extra_allowed
            if remaining > 0:
                extra[token] = remaining
            else:
                extra.pop(token, None)


def load_global_access_policy(config: dict[str, Any]) -> dict[str, Any]:
    policy = config.get("global_access", {})
    if policy is None:
        return {}
    if not isinstance(policy, dict):
        raise ConfigError("global_access must be an object")
    return policy


def check_global_accesses(
    config: dict[str, Any],
    target: ProjectTarget,
    options: GlobalAccessOptions,
) -> GlobalAccessSummary:
    if not target.code_dir:
        raise ConfigError(f"targets.{target.name}.code_export_dir is required for global-access verification")
    if not target.asm_dir:
        raise ConfigError(f"targets.{target.name}.asm_dir is required for global-access verification")
    if not target.globals_source:
        raise ConfigError(f"targets.{target.name}.globals_source is required for global-access verification")

    calls_policy = policy_with_same_address_aliases(target, load_calls_policy(config))
    call_options = CallsOptions(
        filters=options.filters,
        build=options.build,
        build_args=options.build_args,
        show_all=True,
    )
    functions, skipped_no_disasm = select_functions(target, call_options, calls_policy)
    if not functions:
        raise RuntimeError("no functions selected for verification")

    maybe_build(target, call_options, calls_policy)

    decls = configured_global_decls(config, target)
    global_ranges = auto_global_ranges(decls)
    data_ranges = data_section_ranges(target)
    global_names = frozenset(decl.name for decl in decls)
    policy = load_global_access_policy(config)
    skip_tokens = frozenset(str(item) for item in policy.get("skip_tokens", []))
    include_string_constants = bool(policy.get("include_string_constants", False))
    compare_counts = bool(policy.get("compare_counts", False))
    allowances = policy.get("allowances", [])
    if not isinstance(allowances, list):
        raise ConfigError("global_access.allowances must be an array")

    checked = 0
    mismatches: list[GlobalAccessMismatch] = []
    for function in functions:
        if not os.path.exists(function.asm_path):
            continue
        original = [
            token for token in extract_original_global_accesses(
                function.disasm_path,
                global_ranges,
                data_ranges,
                include_address_immediates=options.include_address_immediates,
            )
            if token not in skip_tokens and (include_string_constants or not is_string_constant_token(token))
        ]
        compiled = [
            token for token in extract_compiled_global_accesses(
                function.asm_path,
                function.function_name,
                function.occurrence_index,
                global_names,
                calls_policy.signature_overloads,
                include_address_immediates=options.include_address_immediates,
                global_ranges=global_ranges,
            )
            if token not in skip_tokens and (include_string_constants or not is_string_constant_token(token))
        ]
        if not original and not compiled:
            continue
        checked += 1
        original_counter = Counter(original) if compare_counts else Counter(set(original))
        compiled_counter = Counter(compiled) if compare_counts else Counter(set(compiled))
        missing = original_counter - compiled_counter
        extra = compiled_counter - original_counter
        apply_allowances(function.function_name, missing, extra, allowances)
        if not missing and not extra:
            continue
        if not options.show_all:
            missing = Counter({key: value for key, value in missing.items() if not key.split(":", 1)[1].startswith("0x")})
            extra = Counter({key: value for key, value in extra.items() if not key.split(":", 1)[1].startswith("0x")})
            if not missing and not extra:
                continue
        mismatches.append(GlobalAccessMismatch(
            function_name=function.function_name,
            original_addr=function.original_addr,
            filename=os.path.basename(function.source_path),
            missing=dict(missing),
            extra=dict(extra),
        ))

    return GlobalAccessSummary(
        functions_selected=len(functions),
        functions_checked=checked,
        mismatches=tuple(sorted(mismatches, key=lambda item: item.function_name)),
        skipped_no_disasm=tuple(skipped_no_disasm),
        include_address_immediates=options.include_address_immediates,
        report_all=options.show_all,
        compare_counts=compare_counts,
    )


def format_global_access_summary(summary: GlobalAccessSummary) -> str:
    lines = [
        "",
        "=" * 70,
        "GLOBAL ACCESS VERIFICATION REPORT",
    ]
    if summary.report_all:
        lines.append("  (showing ALL mismatches including unresolved address tokens)")
    else:
        lines.append("  (showing named-global mismatches; use --all for address tokens)")
    if not summary.compare_counts:
        lines.append("  (presence mode; set global_access.compare_counts=true for exact counts)")
    if summary.include_address_immediates:
        lines.append("  (including data address immediates)")
    lines.extend([
        "=" * 70,
        f"Functions selected: {summary.functions_selected}",
        f"Functions checked: {summary.functions_checked}",
        f"Functions with global access mismatches: {len(summary.mismatches)}",
    ])
    if summary.skipped_no_disasm:
        lines.append(f"Functions skipped (no usable disassembly found): {len(summary.skipped_no_disasm)}")
    lines.append("")

    if summary.functions_checked == 0:
        lines.append("error: zero functions were actually checked. Verify assembly output and filters.")
        return "\n".join(lines)

    if not summary.mismatches:
        lines.append("All global accesses match!")
        return "\n".join(lines)

    for mismatch in summary.mismatches:
        lines.append(f"{mismatch.function_name} (0x{mismatch.original_addr:X}) [{mismatch.filename}]")
        for token, count in sorted(mismatch.missing.items()):
            lines.append(f"  MISSING: {token} x{count}")
        for token, count in sorted(mismatch.extra.items()):
            lines.append(f"  EXTRA:   {token} x{count}")
        lines.append("")
    return "\n".join(lines)
