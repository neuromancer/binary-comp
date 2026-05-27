"""Compare global data between original and rebuilt PE images."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from binary_comp.core.mapfile import parse_encoded_address_map
from binary_comp.core.pe import PEImage
from binary_comp.source.globals import GlobalDecl, parse_globals_source


@dataclass(frozen=True)
class DataOptions:
    section_name: str = ".data"
    verbose: bool = False


@dataclass(frozen=True)
class GlobalComparison:
    global_decl: GlobalDecl
    rebuilt_address: int | None
    original_data: bytes | None
    rebuilt_data: bytes | None
    status: str


@dataclass(frozen=True)
class DataCompareSummary:
    original_path: str
    rebuilt_path: str
    map_path: str
    globals_path: str
    symbol_count: int
    global_count: int
    matches: int
    mismatches: int
    missing_symbols: int
    comparisons: tuple[GlobalComparison, ...]


@dataclass(frozen=True)
class MissingDataCandidate:
    address: int
    value: int
    kind: str
    data: bytes


@dataclass(frozen=True)
class MissingGlobalsSummary:
    original_path: str
    globals_path: str
    section_name: str
    section_start: int
    section_end: int
    known_globals: int
    candidates: tuple[MissingDataCandidate, ...]
    min_address: int | None = None
    max_address: int | None = None
    skip_ranges: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class AddressComparison:
    address: int
    size: int
    rebuilt_address: int
    original_data: bytes | None
    rebuilt_data: bytes | None

    @property
    def matches(self) -> bool:
        return self.original_data is not None and self.original_data == self.rebuilt_data


@dataclass(frozen=True)
class RelocatedAddressRange:
    original_start: int
    original_end: int
    rebuilt_start: int


def format_bytes(data: bytes | None, max_bytes: int = 32) -> str:
    if data is None:
        return "(not found)"
    if len(data) <= max_bytes:
        return " ".join(f"{byte:02x}" for byte in data)
    prefix = " ".join(f"{byte:02x}" for byte in data[:max_bytes])
    return f"{prefix} ... ({len(data)} bytes)"


def format_value(data: bytes | None) -> str:
    if data is None or len(data) < 4:
        return "N/A"
    value = struct.unpack("<I", data[:4])[0]
    return f"0x{value:08x} ({value})"


def build_relocated_ranges(
    globals_list: list[GlobalDecl],
    address_map: dict[int, int],
) -> tuple[RelocatedAddressRange, ...]:
    ranges: list[RelocatedAddressRange] = []
    for global_decl in globals_list:
        rebuilt_address = address_map.get(global_decl.address)
        if rebuilt_address is None or global_decl.size <= 0:
            continue
        ranges.append(RelocatedAddressRange(
            original_start=global_decl.address,
            original_end=global_decl.address + global_decl.size,
            rebuilt_start=rebuilt_address,
        ))
    ranges.sort(key=lambda item: (item.original_start, item.original_end))
    return tuple(ranges)


def relocated_pointer_value(
    value: int,
    address_map: dict[int, int],
    relocated_ranges: tuple[RelocatedAddressRange, ...],
) -> int | None:
    mapped = address_map.get(value)
    if mapped is not None:
        return mapped
    for address_range in relocated_ranges:
        if address_range.original_start <= value < address_range.original_end:
            return address_range.rebuilt_start + (value - address_range.original_start)
    return None


def relocated_pointer_match(
    original_data: bytes,
    rebuilt_data: bytes,
    address_map: dict[int, int],
    relocated_ranges: tuple[RelocatedAddressRange, ...],
) -> bool:
    if len(original_data) != len(rebuilt_data):
        return False

    offset = 0
    saw_relocated_pointer = False
    while offset < len(original_data):
        if offset + 4 <= len(original_data):
            original_value = struct.unpack_from("<I", original_data, offset)[0]
            rebuilt_value = struct.unpack_from("<I", rebuilt_data, offset)[0]
            mapped_value = relocated_pointer_value(original_value, address_map, relocated_ranges)
            if mapped_value is not None and rebuilt_value == mapped_value:
                saw_relocated_pointer = True
                offset += 4
                continue
        if original_data[offset] != rebuilt_data[offset]:
            return False
        offset += 1
    return saw_relocated_pointer


def compare_global_data(
    original_path: str,
    rebuilt_path: str,
    map_path: str,
    globals_path: str,
    options: DataOptions | None = None,
    extra_type_sizes: dict[str, int] | None = None,
    relocated_address_map: dict[int, int] | None = None,
) -> DataCompareSummary:
    options = options or DataOptions()
    original = PEImage(original_path)
    rebuilt = PEImage(rebuilt_path)
    address_map = parse_encoded_address_map(map_path)
    pointer_address_map = dict(address_map)
    if relocated_address_map:
        pointer_address_map.update(relocated_address_map)
    globals_list = parse_globals_source(globals_path, extra_type_sizes)
    relocated_ranges = build_relocated_ranges(globals_list, address_map)

    comparisons: list[GlobalComparison] = []
    matches = 0
    mismatches = 0
    missing_symbols = 0

    for global_decl in globals_list:
        original_data = original.read(global_decl.address, global_decl.size)
        rebuilt_address = address_map.get(global_decl.address)
        if original_data is None:
            rebuilt_data = None
            status = "NOT_FOUND"
        elif rebuilt_address is None:
            rebuilt_data = None
            status = "NO_SYMBOL"
            missing_symbols += 1
        else:
            rebuilt_data = rebuilt.read(rebuilt_address, global_decl.size)
            if rebuilt_data is None:
                status = "MISSING"
                mismatches += 1
            elif original_data == rebuilt_data:
                status = "OK"
                matches += 1
            elif relocated_pointer_match(
                original_data,
                rebuilt_data,
                pointer_address_map,
                relocated_ranges,
            ):
                status = "OK_PTR"
                matches += 1
            else:
                status = "MISMATCH"
                mismatches += 1

        comparisons.append(GlobalComparison(
            global_decl=global_decl,
            rebuilt_address=rebuilt_address,
            original_data=original_data,
            rebuilt_data=rebuilt_data,
            status=status,
        ))

    return DataCompareSummary(
        original_path=original_path,
        rebuilt_path=rebuilt_path,
        map_path=map_path,
        globals_path=globals_path,
        symbol_count=len(address_map),
        global_count=len(globals_list),
        matches=matches,
        mismatches=mismatches,
        missing_symbols=missing_symbols,
        comparisons=tuple(comparisons),
    )


def compare_address(
    original_path: str,
    rebuilt_path: str,
    map_path: str,
    address: int,
    size: int,
) -> AddressComparison:
    original = PEImage(original_path)
    rebuilt = PEImage(rebuilt_path)
    address_map = parse_encoded_address_map(map_path)
    rebuilt_address = address_map.get(address, address)
    return AddressComparison(
        address=address,
        size=size,
        rebuilt_address=rebuilt_address,
        original_data=original.read(address, size),
        rebuilt_data=rebuilt.read(rebuilt_address, size),
    )


def is_covered(address: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def classify_candidate(image: PEImage, value: int, data: bytes) -> str:
    if image.section_for_va(value) is not None:
        return "PTR?"
    if data and data[0] != 0 and all(32 <= byte < 127 or byte == 0 for byte in data[:4]):
        return "TEXT?"
    return "DATA"


def find_missing_globals(
    original_path: str,
    globals_path: str,
    section_name: str = ".data",
    min_address: int | None = None,
    max_address: int | None = None,
    skip_ranges: tuple[tuple[int, int], ...] = (),
    extra_type_sizes: dict[str, int] | None = None,
) -> MissingGlobalsSummary:
    original = PEImage(original_path)
    section = original.section_named(section_name)
    if section is None:
        raise ValueError(f"section not found: {section_name}")

    globals_list = parse_globals_source(globals_path, extra_type_sizes)
    covered_ranges = [
        (global_decl.address, global_decl.address + global_decl.size)
        for global_decl in globals_list
    ]
    data = original.read(section.start, section.rawsize) or b""
    candidates: list[MissingDataCandidate] = []

    for offset in range(0, max(0, len(data) - 3), 4):
        address = section.start + offset
        if min_address is not None and address < min_address:
            continue
        if max_address is not None and address >= max_address:
            break
        if is_covered(address, skip_ranges):
            continue
        value = struct.unpack("<I", data[offset:offset + 4])[0]
        if value == 0 or is_covered(address, covered_ranges):
            continue
        chunk = data[offset:offset + 16]
        candidates.append(MissingDataCandidate(
            address=address,
            value=value,
            kind=classify_candidate(original, value, chunk),
            data=chunk,
        ))

    return MissingGlobalsSummary(
        original_path=original_path,
        globals_path=globals_path,
        section_name=section_name,
        section_start=section.start,
        section_end=section.start + section.rawsize,
        known_globals=len(globals_list),
        candidates=tuple(candidates),
        min_address=min_address,
        max_address=max_address,
        skip_ranges=tuple(skip_ranges),
    )


def format_comparison(summary: DataCompareSummary, verbose: bool = False) -> str:
    lines = [
        f"Original: {summary.original_path}",
        f"Rebuilt:  {summary.rebuilt_path}",
        f"Map:      {summary.map_path} ({summary.symbol_count} encoded-address symbols)",
        f"Globals:  {summary.globals_path} ({summary.global_count} globals)",
        "",
        f"{'Orig Addr':<12} {'Rebuilt Addr':<14} {'Name':<28} {'Status':<10} Description",
        "-" * 92,
    ]

    for comparison in summary.comparisons:
        global_decl = comparison.global_decl
        rebuilt = f"0x{comparison.rebuilt_address:08x}" if comparison.rebuilt_address is not None else "(not mapped)"
        lines.append(
            f"0x{global_decl.address:08x}   {rebuilt:<14} "
            f"{global_decl.name:<28} {comparison.status:<10} {global_decl.description}"
        )

        if verbose or comparison.status == "MISMATCH":
            lines.append(f"             Original: {format_bytes(comparison.original_data)}")
            lines.append(f"             Rebuilt:  {format_bytes(comparison.rebuilt_data)}")
            if global_decl.size == 4:
                lines.append(f"             Original value: {format_value(comparison.original_data)}")
                lines.append(f"             Rebuilt value:  {format_value(comparison.rebuilt_data)}")
            lines.append("")

    lines.extend([
        "-" * 92,
        (
            f"Summary: {summary.matches} matches, {summary.mismatches} mismatches, "
            f"{summary.missing_symbols} not in rebuilt map"
        ),
    ])
    return "\n".join(lines)


def format_missing_globals(summary: MissingGlobalsSummary) -> str:
    lines = [
        (
            f"Scanning {summary.section_name}: "
            f"0x{summary.section_start:08x} - 0x{summary.section_end:08x}"
        ),
    ]
    if summary.min_address is not None or summary.max_address is not None:
        min_text = f"0x{summary.min_address:08x}" if summary.min_address is not None else "section start"
        max_text = f"0x{summary.max_address:08x}" if summary.max_address is not None else "section end"
        lines.append(f"Restricted to: {min_text} - {max_text}")
    for start, end in summary.skip_ranges:
        lines.append(f"Skipping range: 0x{start:08x} - 0x{end:08x}")
    lines.extend([
        f"Known globals: {summary.known_globals}",
        f"Found {len(summary.candidates)} non-zero untracked dwords",
        "",
        f"{'Address':<12} {'Value':<12} {'Type':<8} Data",
        "-" * 80,
    ])
    for candidate in summary.candidates:
        hex_bytes = " ".join(f"{byte:02x}" for byte in candidate.data)
        ascii_text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in candidate.data)
        lines.append(
            f"0x{candidate.address:08x}   0x{candidate.value:08x}   "
            f"{candidate.kind:<8} {hex_bytes}  {ascii_text}"
        )
    lines.append("-" * 80)
    return "\n".join(lines)


def format_address_comparison(comparison: AddressComparison) -> str:
    lines = [
        f"Original address: 0x{comparison.address:08x}",
        f"Rebuilt address:  0x{comparison.rebuilt_address:08x}",
        f"Size: {comparison.size} bytes",
        "",
        f"Original: {format_bytes(comparison.original_data, comparison.size)}",
        f"Rebuilt:  {format_bytes(comparison.rebuilt_data, comparison.size)}",
    ]
    if comparison.matches:
        lines.append("Data matches")
    else:
        lines.append("Data differs")
    return "\n".join(lines)


def require_globals_source(path: str | None) -> str:
    if not path:
        raise ValueError("missing globals source path; set targets.<name>.globals_source or pass --globals-source")
    if not os.path.exists(path):
        raise FileNotFoundError(f"missing globals source: {path}")
    return path
