"""MSVC linker map parsing."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MapEntry:
    va: int
    symbol: str
    object_file: str


FUNCTION_LINE_RE = re.compile(
    r"0001:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{8})\s+f\s+(\S+\.obj)"
)
ENCODED_ADDRESS_SYMBOL_RE = re.compile(
    r"[\?_]\w+_([0-9a-fA-F]{6,8})(?:@@\S*)?\s+([0-9a-fA-F]{8})"
)


def parse_msvc_map_by_obj(map_path: str) -> dict[str, list[MapEntry]]:
    entries_by_obj: dict[str, list[MapEntry]] = {}
    if not os.path.exists(map_path):
        return entries_by_obj

    with open(map_path, "r", encoding="latin1", errors="ignore") as f:
        for line in f:
            match = FUNCTION_LINE_RE.search(line)
            if not match:
                continue
            symbol = match.group(1)
            va = int(match.group(2), 16)
            object_file = match.group(3)
            entries_by_obj.setdefault(object_file, []).append(MapEntry(va, symbol, object_file))

    for entries in entries_by_obj.values():
        entries.sort(key=lambda entry: entry.va)
    return entries_by_obj


def function_starts_from_map(entries_by_obj: dict[str, list[MapEntry]]) -> list[int]:
    starts = {entry.va for entries in entries_by_obj.values() for entry in entries}
    return sorted(starts)


def parse_encoded_address_map(map_path: str) -> dict[int, int]:
    """Map original encoded-address symbol suffixes to rebuilt addresses.

    Reimplementation projects often preserve the original address in global
    names, for example ``g_Table_00402000``. MSVC map output then provides the
    rebuilt VA for that symbol. This parser is intentionally narrow: it only
    returns symbols whose names contain a 6-8 digit hex suffix.
    """
    mapping: dict[int, int] = {}
    if not os.path.exists(map_path):
        return mapping

    with open(map_path, "r", encoding="latin1", errors="ignore") as f:
        for line in f:
            match = ENCODED_ADDRESS_SYMBOL_RE.search(line)
            if not match:
                continue
            original_va = int(match.group(1), 16)
            rebuilt_va = int(match.group(2), 16)
            mapping[original_va] = rebuilt_va

    return mapping
