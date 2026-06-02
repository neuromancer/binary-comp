"""Generate Ghidra-style disassembly exports from a PE with Capstone."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from binary_comp.analyzers.function_compare import direct_branch_target, disassemble_function
from binary_comp.analyzers.values import load_policy
from binary_comp.config import ConfigError, ProjectTarget
from binary_comp.core.disasm import Instruction
from binary_comp.core.ghidra import function_starts_from_export_dir
from binary_comp.core.mapfile import MapEntry, function_starts_from_map, parse_msvc_map_by_obj
from binary_comp.core.pe import EXECUTABLE_FLAG, PEImage, Section
from binary_comp.core.symbols import normalize_compiled
from binary_comp.source.functions import load_source_groups


@dataclass(frozen=True)
class ExportAsmOptions:
    out_dir: str | None = None
    clean: bool = False
    original_map: str | None = None
    objects: tuple[str, ...] = ()
    include_source: bool = True
    discover: bool | None = None
    max_bytes: int | None = None
    max_functions: int = 4096
    signature_overloads: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ExportedFunction:
    address: int
    name: str
    path: str
    instruction_count: int


@dataclass(frozen=True)
class ExportAsmSummary:
    out_dir: str
    written: tuple[ExportedFunction, ...]
    skipped: tuple[tuple[int, str], ...]
    source_targets: int
    map_targets: int
    discovered_targets: int
    boundary_count: int
    cleaned: int


def output_dir(target: ProjectTarget, options: ExportAsmOptions) -> str:
    out_dir = options.out_dir or target.code_dir
    if not out_dir:
        raise ConfigError(f"targets.{target.name}.code_export_dir is required for export-asm")
    return out_dir


def source_export_targets(target: ProjectTarget, options: ExportAsmOptions) -> dict[int, str]:
    groups_by_source = load_source_groups(
        target.source_dirs,
        target.map_skip,
        target.source_excludes,
        signature_names=options.signature_overloads,
    )
    targets: dict[int, str] = {}
    for groups in groups_by_source.values():
        for group in groups:
            for address in group.addresses:
                targets.setdefault(int(address, 16), group.name)
    return targets


def normalized_object_name(value: str) -> str:
    return os.path.basename(value.replace("\\", "/")).lower()


def object_filter_matches(entry: MapEntry, filters: frozenset[str]) -> bool:
    if not filters:
        return True
    object_file = entry.object_file.replace("\\", "/").lower()
    basename = normalized_object_name(entry.object_file)
    return object_file in filters or basename in filters


def map_export_targets(
    original_map: str,
    objects: tuple[str, ...],
    signature_overloads: frozenset[str],
) -> tuple[dict[int, str], list[int]]:
    if not os.path.exists(original_map):
        raise FileNotFoundError(f"original map not found: {original_map}")
    entries_by_obj = parse_msvc_map_by_obj(original_map)
    starts = function_starts_from_map(entries_by_obj)
    filters = frozenset(item.replace("\\", "/").lower() for item in objects)
    filters |= frozenset(normalized_object_name(item) for item in objects)
    targets: dict[int, str] = {}
    for entries in entries_by_obj.values():
        for entry in entries:
            if not object_filter_matches(entry, filters):
                continue
            targets.setdefault(entry.va, normalize_compiled(entry.symbol, signature_overloads))
    return targets, starts


def export_instruction_text(raw: str) -> str:
    if not raw:
        return raw
    parts = raw.split(None, 1)
    if len(parts) == 1:
        return parts[0].upper()
    return f"{parts[0].upper()} {parts[1]}"


def render_export(name: str, address: int, instructions) -> str:
    lines = [
        f"Function: {name or f'FUN_{address:08X}'}",
        f"Address: 0x{address:08X}",
        "",
    ]
    previous = None
    for instr in instructions:
        if (
            previous is not None
            and previous.size
            and instr.address != previous.address + previous.size
        ):
            lines.extend(["", f"LAB_{instr.address:08X}:"])
        lines.append(export_instruction_text(instr.raw))
        previous = instr
    return "\n".join(lines) + "\n"


def clean_exports(out_dir: Path) -> int:
    removed = 0
    for path in out_dir.glob("FUN_*.disassembled.txt"):
        path.unlink()
        removed += 1
    return removed


def executable_code_section(image: PEImage) -> Section:
    text = image.section_named(".text")
    if text is not None and text.flags & EXECUTABLE_FLAG:
        return text
    for section in image.sections:
        if section.flags & EXECUTABLE_FLAG:
            return section
    raise RuntimeError("original executable has no executable code section")


def in_section(address: int, section: Section) -> bool:
    return section.start <= address < section.end


def has_prologue_boundary(data: bytes, index: int) -> bool:
    if index == 0:
        return True
    if data[index - 1] in (0x90, 0xCC, 0xC3):
        return True
    return index >= 3 and data[index - 3] == 0xC2


def prologue_starts(image: PEImage, section: Section) -> set[int]:
    data = image.read(section.start, min(section.size, section.rawsize))
    if not data:
        return set()

    starts: set[int] = set()
    for index in range(0, len(data) - 2):
        if data[index:index + 3] not in (b"\x55\x8b\xec", b"\x55\x89\xe5"):
            continue
        if has_prologue_boundary(data, index):
            starts.add(section.start + index)
    return starts


def direct_code_target(instr: Instruction, section: Section) -> int | None:
    target = direct_branch_target(instr)
    if target is None or not in_section(target, section):
        return None
    return target


def discover_function_starts(
    image: PEImage,
    initial_starts: set[int],
    max_bytes: int,
    padding_mnemonics: frozenset[str],
    max_functions: int,
) -> set[int]:
    section = executable_code_section(image)
    starts = {addr for addr in initial_starts if in_section(addr, section)}
    starts.add(image.entry_point)
    starts.update(prologue_starts(image, section))
    starts = {addr for addr in starts if in_section(addr, section)}

    pending = sorted(starts)
    processed: set[int] = set()
    while pending and len(starts) <= max_functions:
        start = pending.pop(0)
        if start in processed or not in_section(start, section):
            continue
        processed.add(start)

        result = disassemble_function(
            image,
            start,
            sorted(starts),
            max_bytes=max_bytes,
            padding_mnemonics=padding_mnemonics,
        )
        instruction_addresses = {instr.address for instr in result.instructions}
        for instr in result.instructions:
            target = direct_code_target(instr, section)
            if target is None:
                continue
            is_function_edge = instr.mnemonic == "call" or (
                instr.mnemonic == "jmp" and target not in instruction_addresses
            )
            if not is_function_edge or target in starts:
                continue
            starts.add(target)
            pending.append(target)

    return set(sorted(starts)[:max_functions])


def export_asm(target: ProjectTarget, options: ExportAsmOptions = ExportAsmOptions()) -> ExportAsmSummary:
    out_dir = Path(output_dir(target, options))
    out_dir.mkdir(parents=True, exist_ok=True)
    cleaned = clean_exports(out_dir) if options.clean else 0

    targets: dict[int, str] = {}
    source_count = 0
    if options.include_source:
        source_targets = source_export_targets(target, options)
        source_count = len(source_targets)
        targets.update(source_targets)

    map_count = 0
    map_starts: list[int] = []
    if options.original_map:
        map_targets, map_starts = map_export_targets(
            options.original_map,
            options.objects,
            options.signature_overloads,
        )
        map_count = len(map_targets)
        targets.update(map_targets)

    policy = load_policy(target.values_policy)
    max_bytes = options.max_bytes or policy.max_disassembly_bytes
    image = PEImage(target.original_exe)
    discovered_count = 0
    should_discover = options.discover if options.discover is not None else not targets
    if should_discover:
        discovered = discover_function_starts(
            image,
            set(targets) | set(map_starts) | set(function_starts_from_export_dir(str(out_dir))),
            max_bytes,
            policy.padding_mnemonics,
            options.max_functions,
        )
        for address in discovered:
            if address not in targets:
                discovered_count += 1
            targets.setdefault(address, f"FUN_{address:08X}")

    if not targets:
        raise RuntimeError("no functions selected for export")

    starts = sorted(set(targets) | set(map_starts) | set(function_starts_from_export_dir(str(out_dir))))

    written: list[ExportedFunction] = []
    skipped: list[tuple[int, str]] = []
    for address in sorted(targets):
        result = disassemble_function(
            image,
            address,
            starts,
            max_bytes=max_bytes,
            padding_mnemonics=policy.padding_mnemonics,
        )
        if not result.instructions:
            skipped.append((address, targets[address]))
            continue
        path = out_dir / f"FUN_{address:08X}.disassembled.txt"
        path.write_text(
            render_export(targets[address], address, result.instructions),
            encoding="utf-8",
        )
        written.append(ExportedFunction(
            address=address,
            name=targets[address],
            path=str(path),
            instruction_count=len(result.instructions),
        ))

    return ExportAsmSummary(
        out_dir=str(out_dir),
        written=tuple(written),
        skipped=tuple(skipped),
        source_targets=source_count,
        map_targets=map_count,
        discovered_targets=discovered_count,
        boundary_count=len(starts),
        cleaned=cleaned,
    )


def format_export_asm_summary(summary: ExportAsmSummary) -> str:
    lines = [
        f"Wrote {len(summary.written)} disassembly export(s) to {summary.out_dir}",
        f"Selected {summary.source_targets} source target(s), {summary.map_targets} map target(s), "
        f"{summary.discovered_targets} discovered target(s); "
        f"{summary.boundary_count} boundary marker(s).",
    ]
    if summary.cleaned:
        lines.append(f"Removed {summary.cleaned} stale FUN_*.disassembled.txt file(s).")
    if summary.skipped:
        lines.append(f"Skipped {len(summary.skipped)} function(s) with no decodable instructions:")
        for address, name in summary.skipped[:20]:
            lines.append(f"  0x{address:08X} {name}")
        if len(summary.skipped) > 20:
            lines.append(f"  ... {len(summary.skipped) - 20} more")
    return "\n".join(lines)
