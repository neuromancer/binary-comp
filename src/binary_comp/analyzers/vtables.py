"""Vtable verification against original PE data and reimplemented source."""

from __future__ import annotations

import glob
import os
import re
import struct
from dataclasses import dataclass
from typing import Any

from binary_comp.analyzers.rebuilt_vtables import (
    RebuiltVtableSummary,
    compare_rebuilt_vtables,
    format_rebuilt_vtable_summary,
)
from binary_comp.config import ConfigError, ProjectTarget, parse_int
from binary_comp.core.disasm import Instruction, disassemble_x86, unsigned32
from binary_comp.core.ghidra import function_starts_from_export_dir
from binary_comp.core.pe import PEImage
from binary_comp.source.cpp import (
    find_function_declarator,
    make_cpp_parser,
    node_text,
    parse_source_function_comments,
    parse_source_function_markers,
    sanitize_source,
    walk,
)


DEFAULT_MAX_FUNCTION_BYTES = 0x4000
TRIVIAL_FUNCTION_TYPES = {"stub", "ret0", "ret1", "retconst", "fieldget", "thunk"}


@dataclass(frozen=True)
class VtableOptions:
    dump: bool = False
    filter_class: str | None = None
    rdata_min: int | None = None
    rdata_max: int | None = None
    check_rebuilt: bool = True


@dataclass(frozen=True)
class VtablePolicy:
    rdata_range: tuple[int | None, int | None]
    slot_symbol_aliases: dict[tuple[str, int], set[tuple[str, str]]]
    manual_classes: tuple[dict[str, Any], ...]
    duplicate_class_drops: tuple[dict[str, Any], ...]
    class_overrides: dict[str, dict[str, Any]]
    slot_name_sets: tuple[dict[str, Any], ...]
    skip_classes: frozenset[str]
    skip_symbol_slots: frozenset[int]
    use_explicit_slot_indexes: bool
    max_function_bytes: int
    stack_registers: frozenset[str]
    object_write_displacements: frozenset[int]


@dataclass(frozen=True)
class ConstructorEvidence:
    instruction_count: int
    this_reg: str | None
    per_reg_vtables: dict[str, int]
    calls: frozenset[int]
    vtable_writes: frozenset[int]


@dataclass(frozen=True)
class VtableWriteEvidence:
    vtable_addr: int
    function_addr: int
    instruction_addr: int
    register: str
    symbols: tuple[str, ...]


@dataclass(frozen=True)
class ParentVtableCandidate:
    class_name: str
    parent: str
    vtable_addr: int
    entries_count: int
    expected_count: int
    purecall_count: int
    writes: tuple[VtableWriteEvidence, ...]


@dataclass(frozen=True)
class ClassReport:
    name: str
    vtable_addr: int
    parent: str | None
    header: str
    entries: tuple[int, ...]
    inherited: int
    overrides: int
    implemented: int
    sdtors: int
    stubs: int
    missing_real: int
    symbol_mismatch: int
    missing_real_items: tuple[tuple[int, int, str, str], ...]
    missing_stub_items: tuple[tuple[int, int, str, str, str], ...]
    symbol_mismatch_items: tuple[tuple[int, int, dict[str, Any], tuple[dict[str, Any], ...], str], ...]
    dump_lines: tuple[str, ...]


@dataclass(frozen=True)
class VtableSummary:
    binary: str
    code_range: tuple[int, int]
    rdata_range: tuple[int, int]
    vtable_addresses: tuple[int, ...]
    classes: dict[str, dict[str, Any]]
    invalid_parents: tuple[tuple[str, str], ...]
    parents_without_vtable_info: tuple[tuple[str, str], ...]
    parent_vtable_candidates: tuple[ParentVtableCandidate, ...]
    constructor_parent_warnings: tuple[dict[str, Any], ...]
    constructor_parent_stats: dict[str, int]
    implementations_count: int
    reports: tuple[ClassReport, ...]
    totals: dict[str, int]
    unmatched_vtables: tuple[int, ...]
    rebuilt: RebuiltVtableSummary | None = None

    @property
    def has_failures(self) -> bool:
        if self.rebuilt is not None and self.rebuilt.has_failures:
            return True
        return bool(self.totals["missing_real"] or self.totals["symbol_mismatch"])


def parse_optional_int(value: Any, label: str, default: int | None = None) -> int | None:
    if value in (None, ""):
        return default
    return parse_int(value, label)


def parse_int_list(value: Any, label: str, default: list[int]) -> frozenset[int]:
    if value is None:
        value = default
    if not isinstance(value, list):
        raise ConfigError(f"{label} must be a list")
    return frozenset(parse_int(item, f"{label}[]") for item in value)


def parse_string_list(value: Any, label: str, default: list[str]) -> frozenset[str]:
    if value is None:
        value = default
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{label} must be a list of strings")
    return frozenset(item for item in value)


def parse_slot_map(mapping: Any) -> dict[int, str]:
    if not mapping:
        return {}
    if not isinstance(mapping, dict):
        raise ConfigError("vtables.slot_name_sets[].slots must be an object")
    return {parse_int(key, "vtables slot key"): str(value) for key, value in mapping.items()}


def parse_range(value: Any, label: str) -> tuple[int | None, int | None]:
    if value in (None, ""):
        return None, None
    if not isinstance(value, list) or len(value) != 2:
        raise ConfigError(f"{label} must be a two-item list")
    return parse_optional_int(value[0], f"{label}[0]"), parse_optional_int(value[1], f"{label}[1]")


def load_vtable_policy(config: dict[str, Any]) -> VtablePolicy:
    vtables = config.get("vtables", {})
    if vtables is None:
        vtables = {}
    if not isinstance(vtables, dict):
        raise ConfigError("vtables must be an object")

    capstone = config.get("vtables_capstone", {})
    if capstone is None:
        capstone = {}
    if not isinstance(capstone, dict):
        raise ConfigError("vtables_capstone must be an object")

    aliases = {}
    for item in vtables.get("slot_symbol_aliases", []):
        aliases[(str(item["class"]), parse_int(item["slot"], "vtables.slot_symbol_aliases[].slot"))] = {
            tuple(alias) for alias in item.get("aliases", [])
        }

    return VtablePolicy(
        rdata_range=parse_range(vtables.get("rdata_range"), "vtables.rdata_range"),
        slot_symbol_aliases=aliases,
        manual_classes=tuple(vtables.get("manual_classes", [])),
        duplicate_class_drops=tuple(vtables.get("duplicate_class_drops", [])),
        class_overrides=dict(vtables.get("class_overrides", {})),
        slot_name_sets=tuple(
            {
                "class_or_ancestor": item["class_or_ancestor"],
                "slots": parse_slot_map(item.get("slots", {})),
            }
            for item in vtables.get("slot_name_sets", [])
        ),
        skip_classes=parse_string_list(vtables.get("skip_classes"), "vtables.skip_classes", []),
        skip_symbol_slots=parse_int_list(vtables.get("skip_symbol_slots"), "vtables.skip_symbol_slots", []),
        use_explicit_slot_indexes=bool(vtables.get("use_explicit_slot_indexes", True)),
        max_function_bytes=parse_optional_int(
            capstone.get("max_function_bytes"),
            "vtables_capstone.max_function_bytes",
            DEFAULT_MAX_FUNCTION_BYTES,
        ) or DEFAULT_MAX_FUNCTION_BYTES,
        stack_registers=frozenset(
            item.lower()
            for item in parse_string_list(
                capstone.get("stack_registers"),
                "vtables_capstone.stack_registers",
                ["esp", "ebp"],
            )
        ),
        object_write_displacements=parse_int_list(
            capstone.get("object_write_displacements"),
            "vtables_capstone.object_write_displacements",
            [0],
        ),
    )


def iter_source_files(source_dirs: tuple[str, ...], suffixes: tuple[str, ...], map_skip: str | None = None):
    for source_dir in source_dirs:
        if not os.path.isdir(source_dir):
            continue
        for root, _, files in os.walk(source_dir):
            if map_skip and map_skip in root:
                continue
            for filename in sorted(files):
                if filename.endswith(suffixes):
                    yield os.path.join(root, filename)


def strip_inline_comments(text: str) -> str:
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text)
    return text


def extract_slot_index(text: str) -> int | None:
    match = re.search(r"\[(\d+)\]", text)
    if match:
        return int(match.group(1))
    match = re.search(r"\bvtable\[(\d+)\]", text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    match = re.search(r"\+0x([0-9a-fA-F]+)", text)
    if match:
        return int(match.group(1), 16) // 4
    return None


def split_params(params: str) -> list[str]:
    parts = []
    current = []
    depth = 0
    for ch in params:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]" and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def normalize_param(param: str) -> str:
    param = strip_inline_comments(param)
    param = param.split("=")[0].strip()
    if not param or param == "void":
        return ""
    param = re.sub(r"\b(class|struct|const|volatile)\s+", "", param)
    param = re.sub(r"\s+", " ", param)
    param = re.sub(r"\s*([*&])\s*", r"\1", param)
    match = re.match(r"(.+[\s*&])([A-Za-z_]\w*)$", param)
    if match:
        param = match.group(1).strip()
    return param


def build_signature_key(method_name: str, params: str, is_const: bool = False) -> str:
    if method_name.startswith("~"):
        return "__dtor__"
    normalized = [normalize_param(part) for part in split_params(params)]
    normalized = [part for part in normalized if part]
    key = f"{method_name}({','.join(normalized)})"
    if is_const:
        key += " const"
    return key


def parse_method_declaration(decl: str, class_name: str) -> dict[str, Any] | None:
    original = decl
    decl = strip_inline_comments(decl).strip()
    if not decl:
        return None
    decl = re.sub(r"\s+", " ", decl)
    if "{" in decl:
        decl = decl.split("{", 1)[0].strip()
    if decl.endswith(";"):
        decl = decl[:-1].strip()

    match = re.match(
        r"^(?P<virtual>virtual\s+)?(?P<prefix>.*?)(?P<name>~?\w+)\s*"
        r"\((?P<params>[^()]*)\)\s*(?P<const>const\b)?(?:\s*=\s*0)?$",
        decl,
    )
    if not match:
        return None

    method_name = match.group("name")
    params = match.group("params") or ""
    is_const = bool(match.group("const"))
    return {
        "class_name": class_name,
        "method_name": method_name,
        "signature_key": build_signature_key(method_name, params, is_const),
        "is_virtual": bool(match.group("virtual")),
        "slot_index": extract_slot_index(original),
        "display_name": f"{class_name}::{method_name}",
    }


def parse_source_tree(path: str):
    with open(path, "rb") as f:
        source = f.read()
    return source, make_cpp_parser().parse(sanitize_source(source))


def line_context(source: bytes, node) -> str:
    lines = source.splitlines()
    start = node.start_point.row
    end = node.end_point.row
    return " ".join(
        lines[i].decode("utf-8", errors="ignore")
        for i in range(start, min(end + 1, len(lines)))
    )


def text_before_node_comments(source: bytes, tree, node, max_bytes: int = 1500) -> str:
    comments = []
    min_start = max(0, node.start_byte - max_bytes)
    cursor = node.start_byte
    while cursor > min_start:
        while cursor > min_start and chr(source[cursor - 1]).isspace():
            cursor -= 1
        if source[max(min_start, cursor - 2):cursor] == b"*/":
            start = source.rfind(b"/*", min_start, cursor)
            if start < 0:
                break
            comments.append(source[start:cursor].decode("utf-8", errors="ignore"))
            cursor = start
            continue
        line_start = source.rfind(b"\n", min_start, cursor) + 1
        line = source[line_start:cursor].lstrip()
        if line.startswith(b"//"):
            comments.append(line.decode("utf-8", errors="ignore"))
            cursor = line_start
            continue
        break
    comments.reverse()
    return " ".join(comments)


def text_after_node_same_line(source: bytes, node) -> str:
    line_end = source.find(b"\n", node.end_byte)
    if line_end < 0:
        line_end = len(source)
    return source[node.end_byte:line_end].decode("utf-8", errors="ignore")


def first_child_of_type(node, type_name: str):
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def class_parent_from_node(source: bytes, class_node) -> str | None:
    base_clause = first_child_of_type(class_node, "base_class_clause")
    if base_clause is None:
        return None
    for child in base_clause.children:
        if child.type in ("type_identifier", "qualified_identifier"):
            return node_text(source, child).split("::")[-1].strip()
    return None


def parameter_list_text(source: bytes, function_declarator) -> str:
    params = function_declarator.child_by_field_name("parameters")
    if params is None:
        params = first_child_of_type(function_declarator, "parameter_list")
    if params is None:
        return ""
    text = node_text(source, params).strip()
    if text.startswith("(") and text.endswith(")"):
        return text[1:-1]
    return text


def method_name_from_declarator(source: bytes, function_declarator) -> str | None:
    name_node = function_declarator.child_by_field_name("declarator")
    if name_node is None:
        return None
    name = node_text(source, name_node).strip()
    if "::" in name:
        name = name.split("::")[-1]
    return name


def parse_class_method_node(source: bytes, member_node, class_name: str, basename: str) -> dict[str, Any] | None:
    function_declarator = find_function_declarator(member_node)
    if function_declarator is None:
        return None

    method_name = method_name_from_declarator(source, function_declarator)
    if not method_name or not re.match(r"^~?[A-Za-z_]\w*$", method_name):
        return None

    member_text = node_text(source, member_node)
    context = f"{member_text} {line_context(source, member_node)}"
    params = parameter_list_text(source, function_declarator)
    is_virtual = any(child.type == "virtual" for child in member_node.children)
    is_const = bool(re.search(r"\)\s*const\b", member_text))
    return {
        "class_name": class_name,
        "method_name": method_name,
        "signature_key": build_signature_key(method_name, params, is_const),
        "is_virtual": is_virtual,
        "slot_index": extract_slot_index(context),
        "display_name": f"{class_name}::{method_name}",
        "file": basename,
        "line_number": member_node.start_point.row + 1,
    }


def iter_class_nodes(tree):
    for node in walk(tree.root_node):
        if node.type not in ("class_specifier", "struct_specifier"):
            continue
        name_node = node.child_by_field_name("name")
        body_node = node.child_by_field_name("body")
        if name_node is not None and body_node is not None:
            yield node, name_node, body_node


def parse_header_metadata(source_dirs: tuple[str, ...], map_skip: str | None):
    vtable_pat = re.compile(r"\bvtable(?:\s+address)?(?:\s+at)?[:\s]+0x([0-9a-fA-F]+)", re.IGNORECASE)
    ctor_pat = re.compile(r"Constructor(?:\s+at)?[:\s]+(?:FUN_)?0x([0-9a-fA-F]+)", re.IGNORECASE)

    hierarchy: dict[str, str] = {}
    class_header: dict[str, str] = {}
    class_methods: dict[str, list[dict[str, Any]]] = {}
    explicit_vtables: dict[str, int] = {}
    constructors: dict[str, int] = {}

    for hfile in sorted(iter_source_files(source_dirs, (".h",), map_skip)):
        basename = os.path.basename(hfile)
        source, tree = parse_source_tree(hfile)

        for class_node, name_node, body_node in iter_class_nodes(tree):
            class_name = node_text(source, name_node).strip()
            parent = class_parent_from_node(source, class_node)
            if parent:
                hierarchy[class_name] = parent
            class_header[class_name] = basename
            class_methods.setdefault(class_name, [])

            comment_context = (
                text_before_node_comments(source, tree, class_node) +
                " " +
                text_after_node_same_line(source, class_node)
            )
            for match in vtable_pat.finditer(comment_context):
                explicit_vtables[class_name] = int(match.group(1), 16)
            for match in ctor_pat.finditer(comment_context):
                constructors[class_name] = int(match.group(1), 16)

            for member_node in body_node.children:
                if member_node.type not in ("field_declaration", "declaration", "function_definition"):
                    continue
                parsed = parse_class_method_node(source, member_node, class_name, basename)
                if parsed:
                    class_methods[class_name].append(parsed)

    return hierarchy, class_header, class_methods, explicit_vtables, constructors


def find_vtable_addrs_from_headers(source_dirs: tuple[str, ...], map_skip: str | None, rdata_min: int, rdata_max: int) -> set[int]:
    pattern = re.compile(r"\bvtable(?:\s+address)?(?:\s+at)?[:\s]+0x([0-9a-fA-F]+)", re.IGNORECASE)
    addrs = set()
    for hfile in iter_source_files(source_dirs, (".h",), map_skip):
        source, tree = parse_source_tree(hfile)
        for node in walk(tree.root_node):
            if node.type != "comment":
                continue
            for match in pattern.finditer(node_text(source, node)):
                addr = int(match.group(1), 16)
                if rdata_min <= addr < rdata_max:
                    addrs.add(addr)
    return addrs


def split_symbol(name: str) -> tuple[str | None, str]:
    if "::" not in name:
        return None, name
    return name.rsplit("::", 1)


def find_source_function_symbols(source_dirs: tuple[str, ...], map_skip: str | None) -> dict[int, list[dict[str, Any]]]:
    function_symbols: dict[int, list[dict[str, Any]]] = {}

    def record_symbol(address: int, class_name: str, method_name: str, basename: str, lineno: int) -> None:
        info = {
            "class_name": class_name,
            "method_name": method_name,
            "file": basename,
            "line_number": lineno,
        }
        function_symbols.setdefault(address, [])
        if info not in function_symbols[address]:
            function_symbols[address].append(info)

    for srcfile in sorted(iter_source_files(source_dirs, (".cpp", ".h"), map_skip)):
        basename = os.path.basename(srcfile)
        source, tree = parse_source_tree(srcfile)
        class_ranges = []
        for _, name_node, body_node in iter_class_nodes(tree):
            class_ranges.append((body_node.start_byte, body_node.end_byte, node_text(source, name_node).strip()))

        for marker in parse_source_function_markers(srcfile, include_no_assembly=True):
            class_name, method_name = split_symbol(marker.name)
            if class_name is None:
                for start, end, candidate_class in class_ranges:
                    if start <= marker.function_start < end:
                        class_name = candidate_class
                        break
            if class_name is not None:
                record_symbol(int(marker.address, 16), class_name, method_name, basename, marker.line)

    return function_symbols


def find_implemented_functions(source_dirs: tuple[str, ...], map_skip: str | None) -> dict[int, list[tuple[str, int]]]:
    implementations: dict[int, list[tuple[str, int]]] = {}
    for srcfile in sorted(iter_source_files(source_dirs, (".cpp", ".h"), map_skip)):
        basename = os.path.basename(srcfile)
        for marker in parse_source_function_comments(srcfile, include_no_assembly=True):
            addr = int(marker.address, 16)
            implementations.setdefault(addr, []).append((basename, marker.line))
    return implementations


def is_rdata_address(value: int, rdata_min: int, rdata_max: int) -> bool:
    return rdata_min <= unsigned32(value) < rdata_max


def is_object_memory_operand(instr: Instruction, operand, policy: VtablePolicy) -> bool:
    if operand.kind != "mem":
        return False
    if not operand.base or operand.base in policy.stack_registers:
        return False
    if operand.index:
        return False
    return operand.disp in policy.object_write_displacements


def vtable_store(instr: Instruction, rdata_min: int, rdata_max: int, policy: VtablePolicy) -> tuple[str, int] | None:
    if instr.mnemonic != "mov" or len(instr.operands) < 2:
        return None
    left, right = instr.operands[0], instr.operands[1]
    if left.kind != "mem" or right.kind != "imm":
        return None
    imm = unsigned32(right.imm)
    if not is_rdata_address(imm, rdata_min, rdata_max):
        return None
    if not is_object_memory_operand(instr, left, policy):
        return None
    return left.base, imm


def disassemble_function(image: PEImage, starts: list[int], start: int, max_bytes: int) -> list[Instruction]:
    return disassemble_x86(
        image,
        start,
        starts,
        max_bytes=max_bytes,
        padding_mnemonics=frozenset({"nop", "int3"}),
        trim_msvc_seh=False,
        remove_jump_tables=False,
    )


def find_vtable_addrs_from_capstone(
    image: PEImage,
    starts: list[int],
    code_start: int,
    code_end: int,
    rdata_min: int,
    rdata_max: int,
    policy: VtablePolicy,
) -> set[int]:
    addrs = set()
    for start in starts:
        if not (code_start <= start < code_end):
            continue
        for instr in disassemble_function(image, starts, start, policy.max_function_bytes):
            hit = vtable_store(instr, rdata_min, rdata_max, policy)
            if hit is not None:
                _, addr = hit
                addrs.add(addr)
    return addrs


def symbol_labels_for_function(function_symbols: dict[int, list[dict[str, Any]]], addr: int) -> tuple[str, ...]:
    symbols = function_symbols.get(addr, [])
    return tuple(f"{sym['class_name']}::{sym['method_name']}" for sym in symbols if sym.get("class_name"))


def collect_vtable_writes(
    image: PEImage,
    starts: list[int],
    code_start: int,
    code_end: int,
    rdata_min: int,
    rdata_max: int,
    policy: VtablePolicy,
    function_symbols: dict[int, list[dict[str, Any]]],
) -> dict[int, tuple[VtableWriteEvidence, ...]]:
    writes: dict[int, list[VtableWriteEvidence]] = {}
    for start in starts:
        if not (code_start <= start < code_end):
            continue
        for instr in disassemble_function(image, starts, start, policy.max_function_bytes):
            hit = vtable_store(instr, rdata_min, rdata_max, policy)
            if hit is None:
                continue
            reg, addr = hit
            writes.setdefault(addr, []).append(VtableWriteEvidence(
                vtable_addr=addr,
                function_addr=start,
                instruction_addr=instr.address,
                register=reg,
                symbols=symbol_labels_for_function(function_symbols, start),
            ))
    return {addr: tuple(items) for addr, items in writes.items()}


def analyze_constructor(
    image: PEImage,
    starts: list[int],
    ctor_addr: int,
    rdata_min: int,
    rdata_max: int,
    policy: VtablePolicy,
) -> ConstructorEvidence | None:
    instrs = disassemble_function(image, starts, ctor_addr, policy.max_function_bytes)
    if not instrs:
        return None

    this_reg = None
    per_reg_vtables: dict[str, int] = {}
    calls = set()
    vtable_writes = set()

    for instr in instrs:
        operands = instr.operands
        if instr.mnemonic == "mov" and len(operands) >= 2:
            if this_reg is None and operands[0].kind == "reg" and operands[1].kind == "reg" and operands[1].reg == "ecx":
                this_reg = operands[0].reg

            hit = vtable_store(instr, rdata_min, rdata_max, policy)
            if hit is not None:
                reg, addr = hit
                per_reg_vtables[reg] = addr
                vtable_writes.add(addr)

        if instr.mnemonic == "call" and operands and operands[0].kind == "imm":
            calls.add(unsigned32(operands[0].imm))

    return ConstructorEvidence(
        instruction_count=len(instrs),
        this_reg=this_reg,
        per_reg_vtables=per_reg_vtables,
        calls=frozenset(calls),
        vtable_writes=frozenset(vtable_writes),
    )


def selected_constructor_vtable(evidence: ConstructorEvidence | None) -> int | None:
    if evidence is None:
        return None
    if evidence.this_reg:
        selected = evidence.per_reg_vtables.get(evidence.this_reg)
        if selected is not None:
            return selected
    if evidence.per_reg_vtables:
        return next(reversed(evidence.per_reg_vtables.values()))
    return None


def constructor_symbols(function_symbols: dict[int, list[dict[str, Any]]]) -> dict[int, dict[str, Any]]:
    result = {}
    for addr, infos in function_symbols.items():
        ctor_infos = [
            info for info in infos
            if info["class_name"] and (
                info["method_name"] == info["class_name"]
            )
        ]
        if ctor_infos:
            preferred = next((info for info in ctor_infos if info["method_name"] == info["class_name"]), ctor_infos[0])
            result[addr] = preferred
    return result


def class_or_descendant_of(class_name: str, ancestor: str, hierarchy: dict[str, str]) -> bool:
    current = class_name
    seen = set()
    while current and current not in seen:
        if current == ancestor:
            return True
        seen.add(current)
        current = hierarchy.get(current, "")
    return False


def write_mentions_class_or_descendant(write: VtableWriteEvidence, class_name: str, hierarchy: dict[str, str]) -> bool:
    for label in write.symbols:
        symbol_class, _, _ = label.partition("::")
        if symbol_class and class_or_descendant_of(symbol_class, class_name, hierarchy):
            return True
    return False


def find_parent_vtable_candidates(
    target: ProjectTarget,
    image: PEImage,
    starts: list[int],
    classes: dict[str, dict[str, Any]],
    parent_refs: tuple[tuple[str, str], ...],
    all_vtable_addrs: tuple[int, ...],
    code_start: int,
    code_end: int,
    rdata_min: int,
    rdata_max: int,
    policy: VtablePolicy,
) -> tuple[ParentVtableCandidate, ...]:
    if not parent_refs:
        return ()

    hierarchy, _, class_methods, _, _ = parse_header_metadata(target.source_dirs, target.map_skip)
    function_symbols = find_source_function_symbols(target.source_dirs, target.map_skip)
    writes_by_vtable = collect_vtable_writes(
        image,
        starts,
        code_start,
        code_end,
        rdata_min,
        rdata_max,
        policy,
        function_symbols,
    )
    known_addrs = {info["vtable_addr"] for info in classes.values()}
    candidate_addrs = sorted((set(all_vtable_addrs) - known_addrs) & set(writes_by_vtable))
    if not candidate_addrs:
        return ()

    expected_slots: dict[str, list[dict[str, Any] | None]] = {}
    results = []
    for class_name, parent in parent_refs:
        parent_slots = build_expected_vtable_slots(parent, classes, class_methods, expected_slots, policy)
        expected_count = len(parent_slots)
        for addr in candidate_addrs:
            writes = tuple(
                write for write in writes_by_vtable[addr]
                if write_mentions_class_or_descendant(write, class_name, hierarchy)
            )
            if not writes:
                continue

            idx = all_vtable_addrs.index(addr) if addr in all_vtable_addrs else -1
            max_addr = all_vtable_addrs[idx + 1] if idx >= 0 and idx + 1 < len(all_vtable_addrs) else addr + 0x100
            entries = read_vtable_entries(image, addr, code_start, code_end, max_addr)
            if not entries:
                continue

            purecall_count = sum(1 for entry in entries if classify_function(image, starts, entry) == "thunk")
            results.append(ParentVtableCandidate(
                class_name=class_name,
                parent=parent,
                vtable_addr=addr,
                entries_count=len(entries),
                expected_count=expected_count,
                purecall_count=purecall_count,
                writes=writes,
            ))

    return tuple(results)


def parse_class_info(
    target: ProjectTarget,
    image: PEImage,
    starts: list[int],
    rdata_min: int,
    rdata_max: int,
    policy: VtablePolicy,
) -> tuple[dict[str, dict[str, Any]], frozenset[str]]:
    classes: dict[str, dict[str, Any]] = {}
    hierarchy, class_header, _, explicit_vtables, constructors = parse_header_metadata(target.source_dirs, target.map_skip)
    known_class_names = set(class_header)
    symbols = find_source_function_symbols(target.source_dirs, target.map_skip)
    ctor_symbols = constructor_symbols(symbols)
    ctor_by_class = {
        info["class_name"]: addr
        for addr, info in ctor_symbols.items()
        if info["class_name"] not in constructors
    }

    for class_name in sorted(class_header):
        if class_name in policy.skip_classes:
            continue
        vtable_addr = explicit_vtables.get(class_name)
        if vtable_addr is not None and not is_rdata_address(vtable_addr, rdata_min, rdata_max):
            vtable_addr = None

        ctor_addr = constructors.get(class_name) or ctor_by_class.get(class_name)
        if ctor_addr:
            chosen = selected_constructor_vtable(analyze_constructor(image, starts, ctor_addr, rdata_min, rdata_max, policy))
            if chosen:
                vtable_addr = chosen

        if vtable_addr:
            classes[class_name] = {
                "vtable_addr": vtable_addr,
                "parent": hierarchy.get(class_name),
                "header": class_header.get(class_name, "(unknown)"),
                "constructor": ctor_addr,
            }

    for item in policy.manual_classes:
        name = item["name"]
        known_class_names.add(name)
        if name not in classes:
            classes[name] = {
                "vtable_addr": parse_int(item["vtable_addr"], "vtables.manual_classes[].vtable_addr"),
                "parent": item.get("parent"),
                "header": item.get("header", "(unknown)"),
                "constructor": parse_optional_int(item.get("constructor"), "vtables.manual_classes[].constructor"),
            }

    for item in policy.duplicate_class_drops:
        drop = item.get("drop")
        keep = item.get("keep")
        if drop in classes and keep in classes:
            if not item.get("when_same_vtable") or classes[drop]["vtable_addr"] == classes[keep]["vtable_addr"]:
                del classes[drop]

    for class_name, override in policy.class_overrides.items():
        if class_name in classes:
            if "vtable_addr" in override:
                classes[class_name]["vtable_addr"] = parse_int(override["vtable_addr"], f"vtables.class_overrides.{class_name}.vtable_addr")
            if "parent" in override:
                classes[class_name]["parent"] = override["parent"]
            if "header" in override:
                classes[class_name]["header"] = override["header"]

    known_class_names.update(policy.class_overrides)
    return classes, frozenset(known_class_names)


def find_constructor_parent_warnings(
    classes: dict[str, dict[str, Any]],
    image: PEImage,
    starts: list[int],
    rdata_min: int,
    rdata_max: int,
    policy: VtablePolicy,
    filter_class: str | None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    warnings = []
    stats = {
        "checked": 0,
        "missing_constructor": 0,
        "missing_parent_evidence": 0,
        "missing_disassembly": 0,
        "empty_disassembly": 0,
    }

    for class_name, info in sorted(classes.items()):
        if filter_class and class_name != filter_class:
            continue

        parent_name = info.get("parent")
        ctor_addr = info.get("constructor")
        if not parent_name:
            continue
        if not ctor_addr:
            stats["missing_constructor"] += 1
            continue

        parent_info = classes.get(parent_name)
        if not parent_info:
            continue

        parent_ctor = parent_info.get("constructor")
        parent_vtable = parent_info.get("vtable_addr")
        if not parent_ctor and not parent_vtable:
            stats["missing_parent_evidence"] += 1
            continue

        evidence = analyze_constructor(image, starts, ctor_addr, rdata_min, rdata_max, policy)
        if evidence is None:
            stats["missing_disassembly"] += 1
            continue
        if evidence.instruction_count == 0:
            stats["empty_disassembly"] += 1
            continue

        stats["checked"] += 1
        if parent_ctor and parent_ctor in evidence.calls:
            continue
        if parent_vtable and parent_vtable in evidence.vtable_writes:
            continue

        warnings.append({
            "class_name": class_name,
            "parent_name": parent_name,
            "constructor": ctor_addr,
            "parent_constructor": parent_ctor,
            "parent_vtable": parent_vtable,
        })

    return warnings, stats


def first_non_nop(instrs: list[Instruction]) -> Instruction | None:
    for instr in instrs:
        if instr.mnemonic not in {"nop", "int3"}:
            return instr
    return None


def next_non_nop(instrs: list[Instruction], idx: int) -> Instruction | None:
    for instr in instrs[idx + 1:]:
        if instr.mnemonic not in {"nop", "int3"}:
            return instr
    return None


def is_ret(instr: Instruction | None) -> bool:
    return instr is not None and instr.mnemonic == "ret"


def is_eax_zeroing(instr: Instruction | None) -> bool:
    if instr is None or instr.mnemonic != "xor" or len(instr.operands) < 2:
        return False
    left, right = instr.operands[0], instr.operands[1]
    return left.kind == "reg" and right.kind == "reg" and left.reg == right.reg and left.reg in {"eax", "ax", "al"}


def mov_return_constant(instr: Instruction | None) -> int | None:
    if instr is None or instr.mnemonic != "mov" or len(instr.operands) < 2:
        return None
    left, right = instr.operands[0], instr.operands[1]
    if left.kind != "reg" or right.kind != "imm" or left.reg not in {"eax", "ax", "al"}:
        return None
    return unsigned32(right.imm)


def is_field_getter(instr: Instruction | None) -> bool:
    if instr is None or instr.mnemonic not in {"mov", "movzx", "movsx"} or len(instr.operands) < 2:
        return False
    left, right = instr.operands[0], instr.operands[1]
    return left.kind == "reg" and right.kind == "mem" and left.reg in {"eax", "ax", "al"} and right.base == "ecx"


def classify_function(image: PEImage, starts: list[int], addr: int) -> str:
    instrs = disassemble_function(image, starts, addr, 32)
    if not instrs:
        return "unknown"
    first = first_non_nop(instrs)
    if first is None:
        return "unknown"
    first_idx = instrs.index(first)
    second = next_non_nop(instrs, first_idx)

    if first.mnemonic == "jmp" and first.operands and first.operands[0].kind == "mem":
        return "thunk"
    if is_ret(first):
        return "stub"
    if is_eax_zeroing(first) and is_ret(second):
        return "ret0"
    ret_constant = mov_return_constant(first)
    if ret_constant is not None and is_ret(second):
        return "ret1" if ret_constant == 1 else "retconst"
    if is_field_getter(first) and is_ret(second):
        return "fieldget"
    if first.mnemonic == "push" and second is not None and second.mnemonic == "call":
        return "error"
    return "real"


def read_dword(image: PEImage, va: int) -> int | None:
    data = image.read(va, 4)
    return struct.unpack("<I", data)[0] if data and len(data) == 4 else None


def read_vtable_entries(image: PEImage, vtable_addr: int, code_start: int, code_end: int, max_addr: int) -> tuple[int, ...]:
    entries = []
    addr = vtable_addr
    while addr < max_addr:
        value = read_dword(image, addr)
        if value is None or not (code_start <= value < code_end):
            break
        entries.append(value)
        addr += 4
    return tuple(entries)


def read_class_vtables(
    image: PEImage,
    classes: dict[str, dict[str, Any]],
    all_vtable_addrs: tuple[int, ...],
    code_start: int,
    code_end: int,
) -> dict[str, tuple[int, ...]]:
    vtables: dict[str, tuple[int, ...]] = {}
    for class_name, info in classes.items():
        addr = info["vtable_addr"]
        idx = all_vtable_addrs.index(addr) if addr in all_vtable_addrs else -1
        max_addr = all_vtable_addrs[idx + 1] if idx >= 0 and idx + 1 < len(all_vtable_addrs) else addr + 0x100
        vtables[class_name] = read_vtable_entries(image, addr, code_start, code_end, max_addr)
    return vtables


def build_expected_vtable_slots(
    class_name: str,
    classes: dict[str, dict[str, Any]],
    class_methods: dict[str, list[dict[str, Any]]],
    cache: dict[str, list[dict[str, Any] | None]],
    policy: VtablePolicy,
) -> list[dict[str, Any] | None]:
    if class_name in cache:
        return cache[class_name]

    parent = classes.get(class_name, {}).get("parent")
    slots = list(build_expected_vtable_slots(parent, classes, class_methods, cache, policy)) if parent else []
    slot_index = {slot["signature_key"]: idx for idx, slot in enumerate(slots) if slot is not None}

    for decl in class_methods.get(class_name, []):
        method_name = decl["method_name"]
        if method_name == class_name:
            continue
        key = decl["signature_key"]
        explicit_slot = decl.get("slot_index") if policy.use_explicit_slot_indexes else None
        if explicit_slot is not None:
            while len(slots) <= explicit_slot:
                slots.append(None)
            slots[explicit_slot] = decl
            slot_index[key] = explicit_slot
        elif key in slot_index:
            slots[slot_index[key]] = decl
        elif decl["is_virtual"]:
            slot_index[key] = len(slots)
            slots.append(decl)

    cache[class_name] = slots
    return slots


def format_symbol_list(symbols: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> str:
    if not symbols:
        return "(unresolved)"
    return ", ".join(f"{sym['class_name']}::{sym['method_name']}" for sym in symbols)


def is_trivial_function_type(ftype: str) -> bool:
    return ftype in TRIVIAL_FUNCTION_TYPES


def build_class_reports(
    target: ProjectTarget,
    image: PEImage,
    classes: dict[str, dict[str, Any]],
    all_vtable_addrs: tuple[int, ...],
    code_start: int,
    code_end: int,
    starts: list[int],
    options: VtableOptions,
    policy: VtablePolicy,
) -> tuple[tuple[ClassReport, ...], dict[str, int], tuple[int, ...]]:
    implementations = find_implemented_functions(target.source_dirs, target.map_skip)
    function_symbols = find_source_function_symbols(target.source_dirs, target.map_skip)
    _, _, class_methods, _, _ = parse_header_metadata(target.source_dirs, target.map_skip)

    expected_slots: dict[str, list[dict[str, Any] | None]] = {}
    for class_name in classes:
        build_expected_vtable_slots(class_name, classes, class_methods, expected_slots, policy)

    vtables = read_class_vtables(image, classes, all_vtable_addrs, code_start, code_end)

    func_types = {}
    for entries in vtables.values():
        for func_addr in entries:
            if func_addr not in func_types:
                func_types[func_addr] = classify_function(image, starts, func_addr)

    def get_parent_entries(class_name: str, depth: int = 0) -> tuple[int, ...]:
        if depth > 10:
            return ()
        info = classes.get(class_name)
        if not info or not info.get("parent"):
            return ()
        parent = info["parent"]
        if parent in vtables:
            return vtables[parent]
        return get_parent_entries(parent, depth + 1)

    def parent_chain_for(class_name: str) -> list[str]:
        chain = []
        cur = class_name
        while cur and cur in classes:
            chain.append(cur)
            cur = classes[cur].get("parent")
        return chain

    def slot_names_for(class_name: str) -> dict[int, str]:
        chain = parent_chain_for(class_name)
        for item in policy.slot_name_sets:
            if item["class_or_ancestor"] in chain:
                return item["slots"]
        return {}

    def matches_expected_symbol(class_name: str, slot_idx: int, expected: dict[str, Any] | None, symbols) -> bool:
        if expected is None:
            return True
        aliases = policy.slot_symbol_aliases.get((class_name, slot_idx), set())
        for sym in symbols:
            candidate = (sym["class_name"], sym["method_name"])
            if candidate == (expected["class_name"], expected["method_name"]) or candidate in aliases:
                return True
        return False

    reports = []
    totals = {
        "slots": 0,
        "inherited": 0,
        "overrides": 0,
        "implemented": 0,
        "sdtors": 0,
        "stubs": 0,
        "missing_real": 0,
        "symbol_mismatch": 0,
        "implementations_count": len(implementations),
    }

    sorted_classes = sorted(
        [class_name for class_name in vtables if not options.filter_class or class_name == options.filter_class],
        key=lambda class_name: classes[class_name]["vtable_addr"],
    )

    for class_name in sorted_classes:
        info = classes[class_name]
        entries = vtables[class_name]
        parent_entries = get_parent_entries(class_name)
        slot_names = slot_names_for(class_name)
        slot_expectations = expected_slots.get(class_name, [])

        def expected_for_slot(slot_idx: int):
            if slot_idx < len(slot_expectations):
                return slot_expectations[slot_idx]
            return None

        def slot_label(slot_idx: int) -> str:
            expected = expected_for_slot(slot_idx)
            if expected is not None:
                return expected["method_name"]
            return slot_names.get(slot_idx, "")

        def is_sdtor_slot(slot_idx: int) -> bool:
            expected = expected_for_slot(slot_idx)
            if expected is not None and expected["signature_key"] == "__dtor__":
                return True
            return slot_idx in (0, 3)

        inherited = 0
        overrides = []
        for idx, func_addr in enumerate(entries):
            if idx < len(parent_entries) and parent_entries[idx] == func_addr:
                inherited += 1
            else:
                overrides.append((idx, func_addr))

        n_impl = n_sdtor = n_stub_missing = n_real_missing = n_symbol_mismatch = 0
        missing_real = []
        missing_stubs = []
        symbol_mismatches = []
        dump_lines = []

        for slot_idx, func_addr in overrides:
            is_impl = func_addr in implementations
            ftype = func_types.get(func_addr, "unknown")
            expected = expected_for_slot(slot_idx)
            symbols = function_symbols.get(func_addr, [])
            label = slot_label(slot_idx)

            if is_impl:
                n_impl += 1
                if (
                    slot_idx not in policy.skip_symbol_slots
                    and expected is not None
                    and expected["signature_key"] != "__dtor__"
                    and not is_trivial_function_type(ftype)
                ):
                    if not matches_expected_symbol(class_name, slot_idx, expected, symbols):
                        n_symbol_mismatch += 1
                        symbol_mismatches.append((slot_idx, func_addr, expected, tuple(symbols), label))
            elif is_sdtor_slot(slot_idx):
                n_sdtor += 1
            elif is_trivial_function_type(ftype):
                n_stub_missing += 1
                tag = {
                    "stub": "RET",
                    "ret0": "return 0",
                    "ret1": "return 1",
                    "retconst": "return constant",
                    "fieldget": "simple field getter",
                    "thunk": "jump thunk",
                }.get(ftype, ftype)
                missing_stubs.append((slot_idx, func_addr, ftype, label, tag))
            else:
                n_real_missing += 1
                missing_real.append((slot_idx, func_addr, ftype, label))

        if options.dump:
            parent_str = info.get("parent") or "(root)"
            for idx, func_addr in enumerate(entries):
                is_inherited = idx < len(parent_entries) and parent_entries[idx] == func_addr
                is_impl = func_addr in implementations
                ftype = func_types.get(func_addr, "?")
                expected = expected_for_slot(idx)
                symbols = function_symbols.get(func_addr, [])
                marker = " " if is_inherited else "*"
                if is_inherited:
                    status = f"inherited ({parent_str})"
                elif is_impl:
                    matches = True
                    if (
                        idx not in policy.skip_symbol_slots
                        and expected is not None
                        and expected["signature_key"] != "__dtor__"
                        and not is_trivial_function_type(ftype)
                    ):
                        matches = matches_expected_symbol(class_name, idx, expected, symbols)
                    if matches:
                        locs = implementations[func_addr]
                        status = f"OK <- {', '.join(f'{file}:{line}' for file, line in locs)}"
                    else:
                        status = f"MISMATCH expected {expected['display_name']} got {format_symbol_list(symbols)}"
                elif is_sdtor_slot(idx):
                    status = "sdtor (compiler-generated)"
                elif is_trivial_function_type(ftype):
                    status = f"MISSING ({ftype})"
                elif ftype == "error":
                    status = "MISSING (error helper call)"
                else:
                    status = "MISSING"
                name_str = f" {slot_label(idx)}" if slot_label(idx) else ""
                dump_lines.append(f"  {marker} [{idx:2d}]{name_str:<18} 0x{func_addr:08X}  {status}")

        totals["slots"] += len(entries)
        totals["inherited"] += inherited
        totals["overrides"] += len(overrides)
        totals["implemented"] += n_impl
        totals["sdtors"] += n_sdtor
        totals["stubs"] += n_stub_missing
        totals["missing_real"] += n_real_missing
        totals["symbol_mismatch"] += n_symbol_mismatch

        reports.append(ClassReport(
            name=class_name,
            vtable_addr=info["vtable_addr"],
            parent=info.get("parent"),
            header=info.get("header", "(unknown)"),
            entries=entries,
            inherited=inherited,
            overrides=len(overrides),
            implemented=n_impl,
            sdtors=n_sdtor,
            stubs=n_stub_missing,
            missing_real=n_real_missing,
            symbol_mismatch=n_symbol_mismatch,
            missing_real_items=tuple(missing_real),
            missing_stub_items=tuple(missing_stubs),
            symbol_mismatch_items=tuple(symbol_mismatches),
            dump_lines=tuple(dump_lines),
        ))

    known_addrs = {info["vtable_addr"] for info in classes.values()}
    unmatched = tuple(sorted(set(all_vtable_addrs) - known_addrs))
    return tuple(reports), totals, unmatched


def check_vtables(config: dict[str, Any], target: ProjectTarget, options: VtableOptions) -> VtableSummary:
    policy = load_vtable_policy(config)
    if not target.code_dir:
        raise ConfigError(f"targets.{target.name}.code_export_dir is required for vtable verification")

    image = PEImage(target.original_exe)
    text = image.section_named(".text")
    if text is None:
        raise RuntimeError("original executable has no .text section")
    rdata = image.section_named(".rdata")

    configured_min, configured_max = policy.rdata_range
    rdata_min = rdata.start if rdata is not None else options.rdata_min if options.rdata_min is not None else configured_min
    rdata_max = rdata.end if rdata is not None else options.rdata_max if options.rdata_max is not None else configured_max
    if rdata_min is None or rdata_max is None:
        raise ConfigError("rdata range is required when the executable has no .rdata section")

    code_start, code_end = text.start, text.end
    starts = [addr for addr in function_starts_from_export_dir(target.code_dir) if code_start <= addr < code_end]
    if not starts:
        raise RuntimeError(f"no function boundary markers found in {target.code_dir}")

    capstone_addrs = find_vtable_addrs_from_capstone(image, starts, code_start, code_end, rdata_min, rdata_max, policy)
    header_addrs = find_vtable_addrs_from_headers(target.source_dirs, target.map_skip, rdata_min, rdata_max)
    all_vtable_addrs = tuple(sorted(capstone_addrs | header_addrs))

    classes, known_class_names = parse_class_info(target, image, starts, rdata_min, rdata_max, policy)
    invalid_parents = tuple(sorted(
        (class_name, info["parent"])
        for class_name, info in classes.items()
        if info.get("parent") and info["parent"] not in classes and info["parent"] not in known_class_names
    ))
    parents_without_vtable_info = tuple(sorted(
        (class_name, info["parent"])
        for class_name, info in classes.items()
        if info.get("parent") and info["parent"] not in classes and info["parent"] in known_class_names
    ))
    constructor_parent_warnings, constructor_parent_stats = find_constructor_parent_warnings(
        classes,
        image,
        starts,
        rdata_min,
        rdata_max,
        policy,
        options.filter_class,
    )
    parent_vtable_candidates = find_parent_vtable_candidates(
        target,
        image,
        starts,
        classes,
        parents_without_vtable_info,
        all_vtable_addrs,
        code_start,
        code_end,
        rdata_min,
        rdata_max,
        policy,
    )
    reports, totals, unmatched = build_class_reports(
        target,
        image,
        classes,
        all_vtable_addrs,
        code_start,
        code_end,
        starts,
        options,
        policy,
    )

    rebuilt = None
    if options.check_rebuilt:
        rebuilt = compare_rebuilt_vtables(
            target,
            classes,
            read_class_vtables(image, classes, all_vtable_addrs, code_start, code_end),
            find_source_function_symbols(target.source_dirs, target.map_skip),
            skip_classes=policy.skip_classes,
            filter_class=options.filter_class,
        )

    return VtableSummary(
        binary=target.original_exe,
        code_range=(code_start, code_end),
        rdata_range=(rdata_min, rdata_max),
        vtable_addresses=all_vtable_addrs,
        classes=classes,
        invalid_parents=invalid_parents,
        parents_without_vtable_info=parents_without_vtable_info,
        parent_vtable_candidates=parent_vtable_candidates,
        constructor_parent_warnings=tuple(constructor_parent_warnings),
        constructor_parent_stats=constructor_parent_stats,
        implementations_count=totals["implementations_count"],
        reports=reports,
        totals=totals,
        unmatched_vtables=unmatched,
        rebuilt=rebuilt,
    )


def format_vtable_summary(summary: VtableSummary, dump: bool = False) -> str:
    lines = [
        f"Binary:  {summary.binary}",
        f"Code:    0x{summary.code_range[0]:08X}..0x{summary.code_range[1]:08X}",
        f"Rdata:   0x{summary.rdata_range[0]:08X}..0x{summary.rdata_range[1]:08X}",
        f"Vtables: {len(summary.vtable_addresses)} unique addresses",
        f"Classes: {len(summary.classes)} with vtable info",
        f"Parents: {len(summary.invalid_parents)} invalid references",
        f"Parents without vtable info: {len(summary.parents_without_vtable_info)} references",
        (
            f"Ctor hierarchy: {summary.constructor_parent_stats['checked']} checked, "
            f"{len(summary.constructor_parent_warnings)} warnings"
        ),
    ]
    skipped_ctor_checks = sum(
        count for key, count in summary.constructor_parent_stats.items()
        if key != "checked"
    )
    if skipped_ctor_checks:
        lines.append(f"Ctor hierarchy skipped: {skipped_ctor_checks} without constructor evidence")
    lines.extend([f"Impls:   {summary.implementations_count} Function start comments", ""])

    if summary.invalid_parents:
        lines.append("Invalid parent references:")
        for class_name, parent in summary.invalid_parents:
            lines.append(f"  {class_name} -> {parent}")
        lines.append("")

    if summary.parents_without_vtable_info:
        lines.append("Parent classes without vtable info:")
        for class_name, parent in summary.parents_without_vtable_info:
            lines.append(f"  {class_name} -> {parent}")
        lines.append("")

    if summary.parent_vtable_candidates:
        lines.append("Candidate parent vtables from vptr writes:")
        for item in summary.parent_vtable_candidates:
            slot_status = (
                "slot count matches"
                if item.expected_count and item.entries_count == item.expected_count
                else f"{item.entries_count}/{item.expected_count} slots"
            )
            write_parts = []
            for write in item.writes[:3]:
                label = ", ".join(write.symbols) if write.symbols else f"0x{write.function_addr:08X}"
                write_parts.append(f"{label} @0x{write.instruction_addr:08X}")
            if len(item.writes) > 3:
                write_parts.append(f"+{len(item.writes) - 3} more")
            purecall = f", {item.purecall_count} thunk/purecall-like" if item.purecall_count else ""
            lines.append(
                f"  {item.class_name} -> {item.parent}: 0x{item.vtable_addr:08X} "
                f"({slot_status}{purecall}); writes: {'; '.join(write_parts)}"
            )
        lines.append("")

    if summary.constructor_parent_warnings:
        lines.append("Constructor hierarchy warnings:")
        for item in summary.constructor_parent_warnings:
            parent_vtable = item["parent_vtable"]
            parent_vtable_str = f"0x{parent_vtable:08X}" if parent_vtable else "(none)"
            parent_ctor = item["parent_constructor"]
            parent_ctor_str = f"0x{parent_ctor:08X}" if parent_ctor else "(none)"
            lines.append(
                f"  {item['class_name']} declares parent {item['parent_name']}, "
                f"but ctor 0x{item['constructor']:08X} neither calls parent ctor "
                f"{parent_ctor_str} nor writes parent vtable {parent_vtable_str}"
            )
        lines.append("")

    if dump:
        for report in summary.reports:
            parent_str = report.parent or "(root)"
            lines.append(f"\n{report.name} (0x{report.vtable_addr:08X}, parent={parent_str}, {report.header}):")
            lines.extend(report.dump_lines)
    else:
        lines.append("=" * 124)
        lines.append(f"{'Class':<22} {'Vtable':<14} {'Parent':<18} {'#':<4} {'Inh':<4} {'Ovr':<4} {'OK':<4} {'Stub':<5} {'Miss':<5} {'Bad':<4} Status")
        lines.append("=" * 124)
        for report in summary.reports:
            parent_str = report.parent or "(root)"
            if report.missing_real > 0:
                status = f"{report.missing_real} MISSING"
                if report.symbol_mismatch:
                    status += f" +{report.symbol_mismatch} bad slots"
                if report.stubs:
                    status += f" +{report.stubs} stubs"
            elif report.symbol_mismatch > 0:
                status = f"{report.symbol_mismatch} bad slots"
                if report.stubs:
                    status += f" +{report.stubs} stubs"
            elif report.stubs > 0:
                status = f"{report.stubs} stubs only"
            else:
                status = "OK"

            lines.append(
                f"{report.name:<22} 0x{report.vtable_addr:08X}   {parent_str:<18} "
                f"{len(report.entries):<4} {report.inherited:<4} {report.overrides:<4} "
                f"{report.implemented:<4} {report.stubs:<5} {report.missing_real:<5} "
                f"{report.symbol_mismatch:<4} {status}"
            )
            for slot_idx, func_addr, ftype, label in report.missing_real_items:
                name = f" {label}" if label else ""
                lines.append(f"    [{slot_idx:2d}]{name:<16} 0x{func_addr:08X}  [{ftype}]")
            for slot_idx, func_addr, _, label, tag in report.missing_stub_items:
                name = f" {label}" if label else ""
                lines.append(f"    [{slot_idx:2d}]{name:<16} 0x{func_addr:08X}  ({tag})")
            for slot_idx, func_addr, expected, symbols, label in report.symbol_mismatch_items:
                lines.append(
                    f"    [{slot_idx:2d}] {label:<15} 0x{func_addr:08X}  "
                    f"expected {expected['display_name']} got {format_symbol_list(symbols)}"
                )
        lines.append("=" * 124)

    lines.extend([
        "",
        f"{'Total vtable slots:':<30} {summary.totals['slots']}",
        f"{'  Inherited:':<30} {summary.totals['inherited']}",
        f"{'  Overrides:':<30} {summary.totals['overrides']}",
        f"{'    Implemented:':<30} {summary.totals['implemented']}",
        f"{'    Sdtors (compiler):':<30} {summary.totals['sdtors']}",
        f"{'    Trivial helpers/thunks:':<30} {summary.totals['stubs']}",
        f"{'    Missing (real code):':<30} {summary.totals['missing_real']}",
        f"{'    Implemented but wrong slot:':<30} {summary.totals['symbol_mismatch']}",
    ])

    if summary.unmatched_vtables:
        lines.append(f"\nVtable addresses not matched to any class ({len(summary.unmatched_vtables)}):")
        for addr in summary.unmatched_vtables:
            lines.append(f"  0x{addr:08X}")

    if summary.rebuilt is not None:
        lines.append(format_rebuilt_vtable_summary(summary.rebuilt))

    return "\n".join(lines)
