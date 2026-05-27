"""Call target verification for reimplementation projects."""

from __future__ import annotations

import glob
import os
import re
import struct
import subprocess
from collections import Counter
from dataclasses import dataclass, replace
from typing import Any

from binary_comp.config import ConfigError, ProjectTarget, parse_int
from binary_comp.source.cpp import parse_source_function_groups


IAT_ADDRESSES: dict[int, str] = {}
IAT_ADDRESS_RANGES: list[tuple[int, int]] = []


@dataclass(frozen=True)
class CallsOptions:
    filters: tuple[str, ...] = ()
    show_all: bool = False
    build: bool = True
    include_trivial: bool = False
    strict_memory: bool = False
    build_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class CallsPolicy:
    known_crt: dict[str, dict[int, str]]
    canonical_aliases: dict[str, str]
    call_count_allowances: dict[tuple[str, str], tuple[int, int]]
    function_pointer_targets: dict[int, str]
    ordinal_imports: dict[tuple[str, int], str]
    iat_addresses: dict[int, str]
    use_pe_iat: bool
    signature_overloads: frozenset[str]
    skip_tokens: frozenset[str]
    trivial_tokens: frozenset[str]
    strict_memory_tokens: frozenset[str]
    build_args: tuple[str, ...]


@dataclass(frozen=True)
class SelectedFunction:
    source_path: str
    function_name: str
    occurrence_index: int
    original_addr: int
    disasm_path: str
    asm_path: str


@dataclass(frozen=True)
class CallMismatch:
    function_name: str
    original_addr: int
    filename: str
    missing: dict[str, int]
    extra: dict[str, int]


@dataclass(frozen=True)
class CallsSummary:
    functions_selected: int
    functions_checked: int
    mismatches: tuple[CallMismatch, ...]
    skipped_no_disasm: tuple[tuple[str, int, str], ...]
    iat_loaded: int
    report_all: bool
    strict_memory: bool
    include_trivial: bool


def parse_int_map(mapping: Any, label: str) -> dict[int, str]:
    if not mapping:
        return {}
    if not isinstance(mapping, dict):
        raise ConfigError(f"{label} must be an object")
    return {parse_int(key, f"{label} key"): str(value) for key, value in mapping.items()}


def load_calls_policy(config: dict[str, Any]) -> CallsPolicy:
    calls = config.get("calls", {})
    if calls is None:
        calls = {}
    if not isinstance(calls, dict):
        raise ConfigError("calls must be an object")

    known_crt = {}
    for mode, mapping in calls.get("known_crt", {}).items():
        known_crt[str(mode)] = parse_int_map(mapping, f"calls.known_crt.{mode}")

    allowances = {}
    for item in calls.get("call_count_allowances", []):
        allowances[(str(item["function"]), str(item["target"]))] = (
            int(item.get("missing", 0)),
            int(item.get("extra", 0)),
        )

    ordinal_imports = {}
    for item in calls.get("ordinal_imports", []):
        ordinal_imports[(str(item["dll"]).upper(), int(item["ordinal"]))] = str(item["name"])

    return CallsPolicy(
        known_crt=known_crt,
        canonical_aliases=dict(calls.get("canonical_aliases", {})),
        call_count_allowances=allowances,
        function_pointer_targets=parse_int_map(calls.get("function_pointer_globals", {}), "calls.function_pointer_globals"),
        ordinal_imports=ordinal_imports,
        iat_addresses=parse_int_map(calls.get("iat_addresses", {}), "calls.iat_addresses"),
        use_pe_iat=bool(calls.get("use_pe_iat", True)),
        signature_overloads=frozenset(str(item) for item in calls.get("signature_overloads", [])),
        skip_tokens=frozenset(str(item) for item in calls.get("skip_tokens", [])),
        trivial_tokens=frozenset(str(item) for item in calls.get("trivial_tokens", [])),
        strict_memory_tokens=frozenset(str(item) for item in calls.get("strict_memory_tokens", [])),
        build_args=tuple(str(item) for item in calls.get("build_args", [])),
    )


def canonicalize(name: str, policy: CallsPolicy, strict_memory: bool = False) -> str:
    if name.startswith("FUN_"):
        name = name.upper()
    if strict_memory and name in policy.strict_memory_tokens:
        return name
    seen = set()
    while name in policy.canonical_aliases and name not in seen:
        seen.add(name)
        name = policy.canonical_aliases[name]
        if name.startswith("FUN_"):
            name = name.upper()
        if strict_memory and name in policy.strict_memory_tokens:
            return name
    return name


def iter_source_address_names(target: ProjectTarget, policy: CallsPolicy):
    for cpp_file in iter_cpp_files(target.source_dirs, target.map_skip, target.source_excludes):
        for addrs, func_name in iter_source_functions(cpp_file, policy, include_no_assembly=True):
            for addr in addrs:
                yield addr, func_name


def build_same_address_aliases(target: ProjectTarget, policy: CallsPolicy) -> dict[str, str]:
    names_by_addr: dict[int, list[str]] = {}
    for addr, func_name in iter_source_address_names(target, policy):
        names = names_by_addr.setdefault(addr, [])
        if func_name not in names:
            names.append(func_name)

    aliases = {}
    for names in names_by_addr.values():
        if len(names) < 2:
            continue
        canonical = canonicalize(names[-1], policy)
        for name in names:
            if name != canonical:
                aliases[name] = canonical
    return aliases


def policy_with_same_address_aliases(target: ProjectTarget, policy: CallsPolicy) -> CallsPolicy:
    same_address_aliases = build_same_address_aliases(target, policy)
    if not same_address_aliases:
        return policy
    return replace(
        policy,
        canonical_aliases={**same_address_aliases, **policy.canonical_aliases},
    )


def apply_call_count_allowances(func_name: str, only_orig: Counter, only_compiled: Counter, policy: CallsPolicy) -> None:
    for (allowed_func, name), (missing_allowed, extra_allowed) in policy.call_count_allowances.items():
        if func_name != allowed_func:
            continue
        if missing_allowed:
            remaining = only_orig.get(name, 0) - missing_allowed
            if remaining > 0:
                only_orig[name] = remaining
            else:
                only_orig.pop(name, None)
        if extra_allowed:
            remaining = only_compiled.get(name, 0) - extra_allowed
            if remaining > 0:
                only_compiled[name] = remaining
            else:
                only_compiled.pop(name, None)


def iter_cpp_files(
    source_dirs: tuple[str, ...],
    map_skip: str | None = None,
    source_excludes: tuple[str, ...] = (),
):
    excluded = {
        os.path.normcase(os.path.abspath(path))
        for path in source_excludes
    }
    for source_dir in source_dirs:
        for root, _, files in os.walk(source_dir):
            if map_skip and map_skip in root:
                continue
            for filename in sorted(files):
                if filename.endswith((".cpp", ".c", ".C")):
                    path = os.path.join(root, filename)
                    if os.path.normcase(os.path.abspath(path)) in excluded:
                        continue
                    yield path


def iter_source_functions(cpp_file: str, policy: CallsPolicy, include_no_assembly: bool = False):
    for group in parse_source_function_groups(
        cpp_file,
        include_no_assembly=include_no_assembly,
        signature_names=policy.signature_overloads,
    ):
        yield [int(address, 16) for address in group.addresses], group.name


def normalize_import_name(name: str) -> str:
    name = re.sub(r"@\d+$", "", name)
    if name.startswith("_") and not name.startswith("__"):
        return name[1:]
    return name


def auto_detect_crt(code_dir: str) -> dict[int, str]:
    crt_map = {}
    for decompiled in glob.glob(os.path.join(code_dir, "FUN_*.decompiled.txt")):
        try:
            with open(decompiled, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(2000)
        except OSError:
            continue
        if "Library Function" not in content:
            continue
        match = re.match(r"FUN_([0-9a-fA-F]+)\.decompiled\.txt", os.path.basename(decompiled))
        if not match:
            continue
        addr = int(match.group(1), 16)
        header = re.match(r"Function:\s*([A-Za-z_][\w]*)", content)
        if header and not header.group(1).startswith("FUN_"):
            crt_map[addr] = normalize_import_name(header.group(1))
            continue
        lines = content.split("\n")
        for index, line in enumerate(lines):
            if "Library Function" not in line:
                continue
            for candidate in lines[index + 1:min(index + 3, len(lines))]:
                name = candidate.strip()
                if name and not name.startswith("*") and not name.startswith("/"):
                    crt_map[addr] = normalize_import_name(name)
                    break
            break
    return crt_map


def auto_detect_named_functions(code_dir: str) -> dict[int, str]:
    named_functions = dict(auto_detect_crt(code_dir))
    for disassembled in glob.glob(os.path.join(code_dir, "FUN_*.disassembled.txt")):
        match = re.match(r"FUN_([0-9a-fA-F]+)\.disassembled\.txt", os.path.basename(disassembled))
        if not match:
            continue
        addr = int(match.group(1), 16)
        try:
            with open(disassembled, "r", encoding="utf-8", errors="ignore") as f:
                header = f.readline()
        except OSError:
            continue
        name_match = re.match(r"Function:\s*(.+?)\s*$", header)
        if not name_match:
            continue
        name = name_match.group(1).strip()
        if not name or name.startswith("FUN_"):
            continue
        named_functions.setdefault(addr, name)
    return named_functions


def build_address_to_name_map(target: ProjectTarget, policy: CallsPolicy) -> dict[int, str]:
    addr_map = dict(policy.known_crt.get(target.name, {}))
    if target.code_dir:
        for addr, name in auto_detect_crt(target.code_dir).items():
            addr_map.setdefault(addr, name)

    for addr, func_name in iter_source_address_names(target, policy):
        addr_map[addr] = func_name
    return addr_map


def resolve_original_call(
    call: str | int,
    addr_map: dict[int, str],
    named_addr_map: dict[int, str],
    compiled_targets: frozenset[str],
    policy: CallsPolicy,
    strict_memory: bool = False,
) -> str:
    if not isinstance(call, int):
        return call
    if call in addr_map:
        return addr_map[call]
    candidate = named_addr_map.get(call)
    if candidate and canonicalize(candidate, policy, strict_memory=strict_memory) in compiled_targets:
        return candidate
    return f"FUN_{call:08X}"


def parse_c_string(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


def parse_pe_iat_addresses(exe_path: str, policy: CallsPolicy) -> tuple[dict[int, str], list[tuple[int, int]]]:
    if not exe_path or not os.path.exists(exe_path):
        return {}, []

    with open(exe_path, "rb") as f:
        data = f.read()

    def u16(offset: int) -> int:
        return struct.unpack_from("<H", data, offset)[0]

    def u32(offset: int) -> int:
        return struct.unpack_from("<I", data, offset)[0]

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"not a PE executable: {exe_path}")
    pe_offset = u32(0x3C)
    if pe_offset + 0x18 >= len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"invalid PE header: {exe_path}")

    file_header = pe_offset + 4
    section_count = u16(file_header + 2)
    optional_size = u16(file_header + 16)
    optional_header = file_header + 20
    if u16(optional_header) != 0x10B:
        raise ValueError(f"unsupported PE optional header: {exe_path}")

    image_base = u32(optional_header + 28)
    data_dir = optional_header + 96
    import_rva = u32(data_dir + 8)
    if import_rva == 0:
        return {}, []

    sections_offset = optional_header + optional_size
    sections = []
    for index in range(section_count):
        section_offset = sections_offset + index * 40
        if section_offset + 40 > len(data):
            break
        virtual_size = u32(section_offset + 8)
        virtual_address = u32(section_offset + 12)
        raw_size = u32(section_offset + 16)
        raw_pointer = u32(section_offset + 20)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_pointer, raw_size))

    def rva_to_offset(rva: int) -> int:
        for virtual_address, size, raw_pointer, raw_size in sections:
            if virtual_address <= rva < virtual_address + size:
                offset = raw_pointer + (rva - virtual_address)
                if offset < raw_pointer + raw_size or raw_size == 0:
                    return offset
        if rva < len(data):
            return rva
        raise ValueError(f"RVA 0x{rva:X} is outside mapped sections")

    imports = {}
    ranges = []
    descriptor = rva_to_offset(import_rva)
    while descriptor + 20 <= len(data):
        original_first_thunk = u32(descriptor)
        name_rva = u32(descriptor + 12)
        first_thunk = u32(descriptor + 16)
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break

        dll_name = parse_c_string(data, rva_to_offset(name_rva)).upper() if name_rva else ""
        thunk_rva = original_first_thunk or first_thunk
        index = 0
        while True:
            thunk = u32(rva_to_offset(thunk_rva + index * 4))
            if thunk == 0:
                break
            if thunk & 0x80000000:
                import_name = policy.ordinal_imports.get((dll_name, thunk & 0xFFFF))
                if import_name:
                    imports[image_base + first_thunk + index * 4] = import_name
            else:
                import_name_offset = rva_to_offset(thunk) + 2
                imports[image_base + first_thunk + index * 4] = normalize_import_name(
                    parse_c_string(data, import_name_offset)
                )
            index += 1

        if index:
            ranges.append((image_base + first_thunk, image_base + first_thunk + index * 4))
        descriptor += 20

    return imports, ranges


def is_iat_address(addr: int) -> bool:
    if addr in IAT_ADDRESSES:
        return True
    return any(start <= addr < end for start, end in IAT_ADDRESS_RANGES)


def parse_indirect_call(line: str, policy: CallsPolicy) -> str | None:
    match = re.match(r"(?:CALL|JMP)\s+dword\s+ptr\s*\[\s*(?:0x)?([0-9a-fA-F]+)\s*\]", line, re.IGNORECASE)
    if match:
        try:
            addr = int(match.group(1), 16)
            if is_iat_address(addr):
                return IAT_ADDRESSES.get(addr, "__import__")
            if addr in policy.function_pointer_targets:
                return policy.function_pointer_targets[addr]
            if addr >= 0x400000:
                return "__funcptr__"
        except ValueError:
            pass

    match = re.match(
        r"(?:CALL|JMP)\s+dword\s+ptr\s*\[\s*(\w+)\s*(?:\+\s*(?:0x)?([0-9a-fA-F]+))?\s*\]",
        line,
        re.IGNORECASE,
    )
    if match:
        base = match.group(1).upper()
        if base == "ESP":
            return "__indirect__"
        offset = int(match.group(2), 16) if match.group(2) else 0
        return f"indirect[0x{offset:x}]"

    match = re.match(r"(?:call|jmp)\s+DWORD\s+PTR\s*\[\s*(\w+)\s*(?:\+\s*(\d+))?\s*\]", line, re.IGNORECASE)
    if match:
        base = match.group(1).upper()
        if base == "ESP":
            return "__indirect__"
        offset = int(match.group(2)) if match.group(2) else 0
        return f"indirect[0x{offset:x}]"
    return None


def extract_calls_from_original(disasm_path: str, policy: CallsPolicy) -> list[str | int]:
    calls: list[str | int] = []
    reg_map = {}
    mov_iat_re = re.compile(
        r"MOV\s+(E[A-D]X|ESI|EDI|EBP)\s*,\s*dword\s+ptr\s*\[\s*(?:0x)?([0-9a-fA-F]+)\s*\]",
        re.IGNORECASE,
    )
    call_reg_re = re.compile(r"(CALL|JMP)\s+(E[A-D]X|ESI|EDI|EBP)\s*$", re.IGNORECASE)
    try:
        with open(disasm_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                moved = mov_iat_re.match(line)
                if moved:
                    try:
                        addr = int(moved.group(2), 16)
                        if is_iat_address(addr):
                            reg_map[moved.group(1).upper()] = IAT_ADDRESSES.get(addr, "__import__")
                        else:
                            reg_map.pop(moved.group(1).upper(), None)
                    except ValueError:
                        reg_map.pop(moved.group(1).upper(), None)
                    continue

                upper_line = line.upper()
                is_call = upper_line.startswith("CALL")
                is_jump = upper_line.startswith("JMP")
                if not is_call and not is_jump:
                    continue

                call_reg = call_reg_re.match(line)
                if call_reg:
                    reg = call_reg.group(2).upper()
                    if is_jump and reg not in reg_map:
                        continue
                    calls.append(reg_map.get(reg, "__indirect__"))
                    continue

                indirect = parse_indirect_call(line, policy)
                if indirect:
                    calls.append(indirect)
                    continue

                if is_jump:
                    continue

                match = re.match(r"CALL\s+(?:0x)?0*([0-9a-fA-F]+)\s*$", line)
                if match:
                    addr = int(match.group(1), 16)
                    calls.append("__import__" if addr < 0x1000 else addr)
                    continue

                match = re.match(r"CALL\s+LAB_0*([0-9a-fA-F]+)", line)
                if match:
                    calls.append(int(match.group(1), 16))
                    continue

                calls.append("__indirect__")
    except OSError:
        pass
    return calls


def decode_msvc_pointer_class_tokens(encoded: str) -> list[str]:
    tokens = []
    for match in re.finditer(r"PAV([^@]+)@@", encoded):
        token = match.group(1)
        if token.isdigit():
            if tokens:
                tokens.append(tokens[-1])
            continue
        tokens.append(token.replace("@", "::"))
    return tokens


def normalize_compiled(name: str, signature_names: frozenset[str] = frozenset()) -> str:
    name = name.strip()
    if name.startswith("??0") and "@@" in name:
        match = re.match(r"\?\?0(\w+)@@", name)
        if match:
            return f"{match.group(1)}::{match.group(1)}"
    if name.startswith("??1") and "@@" in name:
        match = re.match(r"\?\?1(\w+)@@", name)
        if match:
            return f"{match.group(1)}::~{match.group(1)}"
    if name.startswith("??2@"):
        return "operator_new"
    if name.startswith("??3@"):
        return "operator_delete"
    if name.startswith("?") and "@@" in name:
        match = re.match(r"\?(\w+)@(\w+)@@", name)
        if match:
            normalized = f"{match.group(2)}::{match.group(1)}"
            if normalized in signature_names:
                class_tokens = decode_msvc_pointer_class_tokens(name[match.end():])
                if len(class_tokens) > 1:
                    return f"{normalized}({','.join(f'{item}*' for item in class_tokens[1:])})"
            return normalized
        match = re.match(r"\?(\w+)@@", name)
        if match:
            return match.group(1)
    if name.startswith("_") and "::" not in name and "@" not in name:
        return name[1:]
    match = re.match(r"@([\w]+)@\d+", name)
    if match:
        return match.group(1)
    match = re.match(r"_?(\w+)@\d+$", name)
    if match:
        return match.group(1)
    if "eh vector constructor iterator" in name:
        return "__eh_vec_ctor__"
    if "eh vector destructor iterator" in name:
        return "__eh_vec_dtor__"
    return name


def extract_calls_from_compiled(
    asm_path: str,
    function_name: str,
    occurrence_index: int = 0,
    signature_names: frozenset[str] = frozenset(),
) -> list[str]:
    calls = []
    try:
        with open(asm_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return calls

    func_lines = []
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

    if not func_lines:
        return calls

    known_imports = set(IAT_ADDRESSES.values())
    compiled_reg_map = {}
    mov_imp_re = re.compile(
        r"mov\s+(eax|ebx|ecx|edx|esi|edi|ebp)\s*,\s*DWORD\s+PTR\s+__imp__([A-Za-z_][\w]*)",
        re.IGNORECASE,
    )
    for line in "\n".join(func_lines).split("\n"):
        line = line.strip()
        moved = mov_imp_re.match(line)
        if moved:
            name = normalize_import_name(moved.group(2))
            compiled_reg_map[moved.group(1).lower()] = name if name in known_imports else "__import__"
            continue
        lower_line = line.lower()
        is_call = lower_line.startswith("call")
        is_jump = lower_line.startswith("jmp")
        if not is_call and not is_jump:
            continue

        full_target = line[4 if is_call else 3:].strip()
        match = re.match(r"DWORD\s+PTR\s*\[\s*(\w+)\s*(?:\+\s*(\d+))?\s*\]", full_target, re.IGNORECASE)
        if match:
            base = match.group(1).lower()
            if base == "esp":
                calls.append("__indirect__")
                continue
            offset = int(match.group(2)) if match.group(2) else 0
            calls.append(f"indirect[0x{offset:x}]")
            continue

        if full_target in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
            if is_jump and full_target not in compiled_reg_map:
                continue
            calls.append(compiled_reg_map.get(full_target, "__indirect__"))
            continue

        if full_target.startswith("$L") or full_target.startswith("$T"):
            calls.append("__label__")
            continue

        if "__imp__" in full_target:
            match = re.search(r"__imp__([A-Za-z_][\w]*)", full_target)
            name = normalize_import_name(match.group(1)) if match else None
            calls.append(name if name and name in known_imports else "__import__")
            continue

        match = re.match(r"DWORD\s+PTR\s+(.+)", full_target, re.IGNORECASE)
        if match:
            if is_jump:
                continue
            pointer_expr = match.group(1).split(";", 1)[0].strip()
            if re.search(r"\[\s*(?:e[bs]p)\s*(?:[+\-]\s*\d+)?\s*\]", pointer_expr, re.IGNORECASE):
                calls.append("__indirect__")
                continue
            calls.append(f"DWORD PTR {pointer_expr}" if "$[" in pointer_expr else pointer_expr)
            continue

        if is_jump:
            continue

        target_symbol = full_target.split(";", 1)[0].strip()
        if target_symbol.startswith("?") or target_symbol.startswith("@"):
            normalized_symbol = normalize_compiled(target_symbol, signature_names)
            if normalized_symbol != target_symbol:
                calls.append(normalized_symbol)
                continue

        target = full_target.split(";", 1)[1].strip() if ";" in full_target else full_target
        calls.append(target)
    return calls


def matches_filter(func_name: str, cpp_file: str, filters: tuple[str, ...]) -> bool:
    if not filters:
        return True
    basename = os.path.basename(cpp_file)
    return any(item == func_name or item in func_name or item in basename for item in filters)


def has_disassembly_body(disasm_path: str) -> bool:
    body_lines = []
    try:
        with open(disasm_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("Function:", "Address:")):
                    continue
                body_lines.append(line)
    except OSError:
        return False
    if not body_lines:
        return False
    if any(line.upper().startswith("RET") for line in body_lines):
        return True
    return body_lines[-1].upper().startswith("JMP")


def find_disasm_path(code_dir: str, addr: int) -> str | None:
    addr_hex = f"{addr:X}"
    candidates = [
        f"FUN_{addr_hex}.disassembled.txt",
        f"FUN_{addr_hex.lower()}.disassembled.txt",
        f"FUN_00{addr_hex}.disassembled.txt",
        f"FUN_00{addr_hex.lower()}.disassembled.txt",
    ]
    for candidate in candidates:
        path = os.path.join(code_dir, candidate)
        if os.path.exists(path):
            return path
    return None


def select_functions(
    target: ProjectTarget,
    options: CallsOptions,
    policy: CallsPolicy,
) -> tuple[list[SelectedFunction], list[tuple[str, int, str]]]:
    if not target.code_dir:
        raise ConfigError(f"targets.{target.name}.code_export_dir is required for call verification")
    if not target.asm_dir:
        raise ConfigError(f"targets.{target.name}.asm_dir is required for call verification")

    functions = []
    skipped_no_disasm = []
    for cpp_file in sorted(iter_cpp_files(target.source_dirs, target.map_skip, target.source_excludes)):
        occurrences = {}
        for addrs, func_name in iter_source_functions(cpp_file, policy):
            if not matches_filter(func_name, cpp_file, options.filters):
                continue
            occurrence_index = occurrences.get(func_name, 0)
            occurrences[func_name] = occurrence_index + 1
            addr = addrs[-1]
            disasm_path = find_disasm_path(target.code_dir, addr)
            if disasm_path is None or not has_disassembly_body(disasm_path):
                skipped_no_disasm.append((func_name, addr, cpp_file))
                continue
            asm_path = os.path.join(target.asm_dir, os.path.splitext(os.path.basename(cpp_file))[0] + ".asm")
            functions.append(SelectedFunction(cpp_file, func_name, occurrence_index, addr, disasm_path, asm_path))
    return functions, skipped_no_disasm


def maybe_build(target: ProjectTarget, options: CallsOptions, policy: CallsPolicy) -> None:
    if not options.build:
        return
    if target.build.clean:
        subprocess.run(target.build.clean.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if not target.build.build:
        return
    build_command = target.build.build.split()
    build_command.extend(options.build_args or policy.build_args)
    if target.build.jobs and target.build.jobs > 1:
        build_command.append(f"-j{target.build.jobs}")
    result = subprocess.run(build_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        raise RuntimeError("build failed")


def check_calls(config: dict[str, Any], target: ProjectTarget, options: CallsOptions) -> CallsSummary:
    global IAT_ADDRESSES, IAT_ADDRESS_RANGES

    policy = load_calls_policy(config)
    for path, label in (
        (target.source_dirs[0] if target.source_dirs else None, "source directory"),
        (target.code_dir, "disassembly directory"),
        (target.asm_dir, "assembly output directory"),
    ):
        if not path or not os.path.isdir(path):
            raise FileNotFoundError(f"missing {label}: {path}")

    policy = policy_with_same_address_aliases(target, policy)
    functions, skipped_no_disasm = select_functions(target, options, policy)
    if not functions:
        raise RuntimeError("no functions selected for verification")

    maybe_build(target, options, policy)

    if policy.use_pe_iat:
        try:
            IAT_ADDRESSES, IAT_ADDRESS_RANGES = parse_pe_iat_addresses(target.original_exe, policy)
        except Exception:
            IAT_ADDRESSES, IAT_ADDRESS_RANGES = {}, []
    else:
        IAT_ADDRESSES, IAT_ADDRESS_RANGES = {}, []
    IAT_ADDRESSES.update(policy.iat_addresses)

    addr_map = build_address_to_name_map(target, policy)
    named_addr_map = auto_detect_named_functions(target.code_dir) if target.code_dir else {}
    total_checked = 0
    mismatches = []

    for function in functions:
        if not os.path.exists(function.asm_path):
            continue
        orig_raw = extract_calls_from_original(function.disasm_path, policy)
        compiled_raw = extract_calls_from_compiled(
            function.asm_path,
            function.function_name,
            function.occurrence_index,
            policy.signature_overloads,
        )
        if not orig_raw and not compiled_raw:
            continue
        total_checked += 1

        compiled_resolved = [
            normalize_compiled(name, policy.signature_overloads)
            if not name.startswith("indirect[") and not name.startswith("__")
            else name
            for name in compiled_raw
        ]
        compiled_targets = frozenset(
            canonicalize(name, policy, strict_memory=options.strict_memory)
            for name in compiled_resolved
        )
        orig_resolved = [
            resolve_original_call(
                call,
                addr_map,
                named_addr_map,
                compiled_targets,
                policy,
                strict_memory=options.strict_memory,
            )
            for call in orig_raw
        ]
        orig_canon = [canonicalize(name, policy, strict_memory=options.strict_memory) for name in orig_resolved]
        compiled_canon = [canonicalize(name, policy, strict_memory=options.strict_memory) for name in compiled_resolved]
        orig_filtered = [name for name in orig_canon if name not in policy.skip_tokens]
        compiled_filtered = [name for name in compiled_canon if name not in policy.skip_tokens]
        orig_filtered = ["__funcptr__" if name == "indirect[0x0]" else name for name in orig_filtered]
        compiled_filtered = ["__funcptr__" if name == "indirect[0x0]" else name for name in compiled_filtered]

        orig_counter = Counter(orig_filtered)
        compiled_counter = Counter(compiled_filtered)
        only_orig = orig_counter - compiled_counter
        only_compiled = compiled_counter - orig_counter
        apply_call_count_allowances(function.function_name, only_orig, only_compiled, policy)
        if not only_orig and not only_compiled:
            continue

        if options.include_trivial:
            real_orig = dict(only_orig)
            real_compiled = dict(only_compiled)
        else:
            real_orig = {key: value for key, value in only_orig.items() if key not in policy.trivial_tokens}
            real_compiled = {key: value for key, value in only_compiled.items() if key not in policy.trivial_tokens}
        if not real_orig and not real_compiled:
            continue

        unresolved_orig = {key: value for key, value in real_orig.items() if key.startswith("FUN_")}
        resolved_orig = {key: value for key, value in real_orig.items() if not key.startswith("FUN_")}
        if not options.show_all:
            unresolved_count = sum(unresolved_orig.values())
            extra_count = sum(real_compiled.values())
            if not resolved_orig and unresolved_count >= extra_count:
                continue

        mismatches.append(CallMismatch(
            function_name=function.function_name,
            original_addr=function.original_addr,
            filename=os.path.basename(function.source_path),
            missing=dict(real_orig),
            extra=dict(real_compiled),
        ))

    return CallsSummary(
        functions_selected=len(functions),
        functions_checked=total_checked,
        mismatches=tuple(sorted(mismatches, key=lambda item: item.function_name)),
        skipped_no_disasm=tuple(skipped_no_disasm),
        iat_loaded=len(IAT_ADDRESSES),
        report_all=options.show_all,
        strict_memory=options.strict_memory,
        include_trivial=options.include_trivial,
    )


def format_calls_summary(summary: CallsSummary) -> str:
    lines = [
        "",
        "=" * 70,
        "CALL TARGET VERIFICATION REPORT",
    ]
    if summary.report_all:
        lines.append("  (showing ALL mismatches including unresolved FUN_ entries)")
    else:
        lines.append("  (showing only resolved-name mismatches; use --all for everything)")
    if summary.strict_memory:
        lines.append("  (strict memory mode)")
    if summary.include_trivial:
        lines.append("  (including configured trivial calls)")
    if summary.iat_loaded == 0:
        lines.append("  (no IAT entries loaded; import calls compared generically)")
    lines.extend([
        "=" * 70,
        f"Functions selected: {summary.functions_selected}",
        f"Functions checked: {summary.functions_checked}",
        f"Functions with call target mismatches: {len(summary.mismatches)}",
    ])
    if summary.skipped_no_disasm:
        lines.append(f"Functions skipped (no usable disassembly found): {len(summary.skipped_no_disasm)}")
    lines.append("")

    if summary.functions_checked == 0:
        lines.append("error: zero functions were actually checked. Verify assembly output and filters.")
        return "\n".join(lines)

    if not summary.mismatches:
        lines.append("All call targets match!")
        return "\n".join(lines)

    for mismatch in summary.mismatches:
        lines.append(f"{mismatch.function_name} (0x{mismatch.original_addr:X}) [{mismatch.filename}]")
        for name, count in sorted(mismatch.missing.items()):
            tag = " (unresolved)" if name.startswith("FUN_") else ""
            lines.append(f"  MISSING: {name} x{count}{tag}")
        for name, count in sorted(mismatch.extra.items()):
            lines.append(f"  EXTRA:   {name} x{count}")
        lines.append("")
    return "\n".join(lines)
