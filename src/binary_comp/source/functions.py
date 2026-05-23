"""Function inventory and source-to-map matching."""

from __future__ import annotations

import os
from dataclasses import dataclass

from binary_comp.core.mapfile import MapEntry, parse_msvc_map_by_obj
from binary_comp.core.symbols import symbol_matches, symbol_patterns_for_function

from .cpp import SourceFunctionGroup, parse_source_function_groups

SOURCE_EXTENSIONS = (".cpp", ".c", ".C")


@dataclass(frozen=True)
class FunctionGroup:
    source_path: str
    name: str
    line: int
    original_addrs: tuple[int, ...]
    rebuilt_addr: int
    rebuilt_symbol: str


def iter_cpp_files(source_dirs: tuple[str, ...], map_skip: str | None = None):
    for source_dir in source_dirs:
        for root, _, files in os.walk(source_dir):
            if map_skip and map_skip in root:
                continue
            for filename in sorted(files):
                if filename.endswith(SOURCE_EXTENSIONS):
                    yield os.path.join(root, filename)


def load_source_groups(
    source_dirs: tuple[str, ...],
    map_skip: str | None = None,
) -> dict[str, list[SourceFunctionGroup]]:
    groups_by_source: dict[str, list[SourceFunctionGroup]] = {}
    for path in iter_cpp_files(source_dirs, map_skip):
        groups = parse_source_function_groups(path, include_no_assembly=False)
        if groups:
            groups_by_source[path] = groups
    return groups_by_source


def map_source_groups(
    groups_by_source: dict[str, list[SourceFunctionGroup]],
    map_path: str,
) -> tuple[list[FunctionGroup], list[tuple[str, SourceFunctionGroup]], dict[str, list[MapEntry]]]:
    entries_by_obj = parse_msvc_map_by_obj(map_path)
    mapped: list[FunctionGroup] = []
    missing: list[tuple[str, SourceFunctionGroup]] = []

    for source_path in sorted(groups_by_source):
        obj = os.path.splitext(os.path.basename(source_path))[0] + ".obj"
        obj_entries = entries_by_obj.get(obj, [])
        used: set[int] = set()

        for group in groups_by_source[source_path]:
            patterns = symbol_patterns_for_function(group.name)
            hit = None
            for idx, entry in enumerate(obj_entries):
                if idx in used:
                    continue
                if symbol_matches(entry.symbol, patterns):
                    hit = (idx, entry)
                    break
            if hit is None:
                missing.append((source_path, group))
                continue

            idx, entry = hit
            used.add(idx)
            original_addrs = tuple(int(addr, 16) for addr in group.addresses)
            mapped.append(FunctionGroup(
                source_path=source_path,
                name=group.name,
                line=group.line,
                original_addrs=original_addrs,
                rebuilt_addr=entry.va,
                rebuilt_symbol=entry.symbol,
            ))

    return mapped, missing, entries_by_obj
