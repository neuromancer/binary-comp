"""Compare the vtables the rebuilt binary actually emits against the original.

The source-driven check in :mod:`binary_comp.analyzers.vtables` asks "does slot
N of the *original* vtable point at a function we have implemented, and is that
function named what the header says it should be". It builds its model of our
vtable from the header declarations, which means a slot annotation such as
``// [11]`` or ``// (+0x2C)`` can override the real C++ semantics: a member that
was never declared ``virtual`` still gets placed in the modelled slot, and the
mismatch is invisible.

This check closes that hole by ignoring source annotations entirely. It reads
the vtable the compiler and linker really produced -- ``??_7<Class>@@6B@`` in
the rebuilt image, located via the linker map -- and diffs it slot-for-slot
against the original. A missing trailing slot means callers that dispatch
through it (``call [eax+N]``) jump into whatever follows the vtable.
"""

from __future__ import annotations

import os
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from binary_comp.config import ProjectTarget
from binary_comp.core.mapfile import parse_msvc_map_symbols
from binary_comp.core.pe import PEImage
from binary_comp.core.symbols import (
    is_destructor_method,
    msvc_method_symbol,
    msvc_vftable_class,
)


MISSING_SLOT = "missing_slot"
EXTRA_SLOT = "extra_slot"
WRONG_FUNCTION = "wrong_function"

UNKNOWN_NAME = "(unknown)"


@dataclass(frozen=True)
class RebuiltSlotIssue:
    slot: int
    kind: str
    original_addr: int | None
    rebuilt_addr: int | None
    expected: str
    actual: str


@dataclass(frozen=True)
class RebuiltClassDiff:
    class_name: str
    original_vtable: int
    rebuilt_vtable: int
    original_len: int
    rebuilt_len: int
    issues: tuple[RebuiltSlotIssue, ...]
    unresolved: int


@dataclass(frozen=True)
class RebuiltVtableSummary:
    skipped: str | None
    diffs: tuple[RebuiltClassDiff, ...]
    classes_checked: int
    slots_checked: int
    unlocatable: tuple[str, ...] = ()

    @property
    def has_failures(self) -> bool:
        return any(diff.issues for diff in self.diffs)


def _read_dword(image: PEImage, va: int) -> int | None:
    data = image.read(va, 4)
    return int.from_bytes(data, "little") if data and len(data) == 4 else None


def _read_entries(image: PEImage, va: int, code_start: int, code_end: int, cap: int) -> tuple[int, ...]:
    """Vtable entries at ``va``: consecutive code pointers, bounded by ``cap``.

    MSVC pads a vtable COMDAT with zeroes, so the first non-code dword ends the
    table. ``cap`` (the next map symbol) guards the case where the next COMDAT
    starts immediately with no padding.
    """
    entries: list[int] = []
    cursor = va
    while cursor < cap:
        value = _read_dword(image, cursor)
        if value is None or not (code_start <= value < code_end):
            break
        entries.append(value)
        cursor += 4
    return tuple(entries)


def _source_addresses_by_symbol(
    function_symbols: dict[int, list[dict[str, Any]]]
) -> dict[tuple[str, str], set[int]]:
    addresses: dict[tuple[str, str], set[int]] = defaultdict(set)
    for address, symbols in function_symbols.items():
        for symbol in symbols:
            addresses[(symbol["class_name"], symbol["method_name"])].add(address)
    return addresses


def _display_name(function_symbols: dict[int, list[dict[str, Any]]], address: int | None) -> str:
    if address is None:
        return UNKNOWN_NAME
    symbols = function_symbols.get(address)
    if not symbols:
        return UNKNOWN_NAME
    return ", ".join(f"{sym['class_name']}::{sym['method_name']}" for sym in symbols)


def read_rebuilt_vtables(
    rebuilt_exe: str,
    map_path: str,
) -> tuple[dict[str, tuple[int, tuple[int, ...]]], dict[int, list[str]]]:
    """``{class: (vtable_va, entries)}`` and ``{function_va: [mangled, ...]}``."""
    image = PEImage(rebuilt_exe)
    text = image.section_named(".text")
    if text is None:
        raise RuntimeError(f"rebuilt executable has no .text section: {rebuilt_exe}")

    symbols = parse_msvc_map_symbols(map_path)
    if not symbols:
        raise RuntimeError(f"no symbols parsed from linker map: {map_path}")

    addresses = sorted({symbol.va for symbol in symbols})

    def next_symbol_va(va: int) -> int:
        index = bisect_right(addresses, va)
        if index < len(addresses):
            return addresses[index]
        section = image.section_for_va(va)
        return section.end if section else va

    symbols_by_va: dict[int, list[str]] = defaultdict(list)
    for symbol in symbols:
        symbols_by_va[symbol.va].append(symbol.symbol)

    vtables: dict[str, tuple[int, tuple[int, ...]]] = {}
    for symbol in symbols:
        class_name = msvc_vftable_class(symbol.symbol)
        if class_name is None:
            continue
        entries = _read_entries(image, symbol.va, text.start, text.end, next_symbol_va(symbol.va))
        vtables[class_name] = (symbol.va, entries)

    return vtables, dict(symbols_by_va)


def _rebuilt_slot_symbols(
    rebuilt_addr: int,
    symbols_by_va: dict[int, list[str]],
) -> list[tuple[str, str]]:
    mangled = symbols_by_va.get(rebuilt_addr, [])
    return [parsed for parsed in (msvc_method_symbol(name) for name in mangled) if parsed]


def _rebuilt_slot_name(rebuilt_addr: int, symbols_by_va: dict[int, list[str]]) -> str:
    resolved = _rebuilt_slot_symbols(rebuilt_addr, symbols_by_va)
    if not resolved:
        return UNKNOWN_NAME
    return ", ".join(f"{cls}::{method}" for cls, method in resolved)


def _slot_matches(
    original_addr: int,
    rebuilt_addr: int,
    symbols_by_va: dict[int, list[str]],
    source_addresses: dict[tuple[str, str], set[int]],
) -> tuple[bool, str, bool]:
    """``(matches, actual_name, resolved)`` for one slot.

    ``resolved`` is False when the rebuilt slot cannot be attributed to a source
    function -- a compiler-generated deleting destructor, ``__purecall``, or a
    library thunk. Those are reported as unresolved rather than as failures.
    """
    resolved = _rebuilt_slot_symbols(rebuilt_addr, symbols_by_va)
    if not resolved:
        return True, UNKNOWN_NAME, False

    # The compiler picks between ~Class and its scalar-deleting thunk for the
    # destructor slot, and only one of them carries a source address marker.
    if any(is_destructor_method(method) for _, method in resolved):
        return True, ", ".join(f"{cls}::{method}" for cls, method in resolved), False

    actual = ", ".join(f"{cls}::{method}" for cls, method in resolved)
    known = [parsed for parsed in resolved if parsed in source_addresses]
    if not known:
        return True, actual, False

    if any(original_addr in source_addresses[parsed] for parsed in known):
        return True, actual, True

    # Deliberately no "same method name, different address" escape hatch here.
    # That would hide the most valuable finding this check exists for: a derived
    # class that fails to override a base method, leaving Base::Foo in a slot the
    # original fills with Derived::Foo.
    return False, actual, True


def compare_rebuilt_vtables(
    target: ProjectTarget,
    classes: dict[str, dict[str, Any]],
    original_vtables: dict[str, tuple[int, ...]],
    function_symbols: dict[int, list[dict[str, Any]]],
    skip_classes: frozenset[str] = frozenset(),
    filter_class: str | None = None,
) -> RebuiltVtableSummary:
    if getattr(target, "kind", "pe") != "pe":
        return RebuiltVtableSummary(f"target kind '{target.kind}' is not a PE image", (), 0, 0)
    if not target.rebuilt_exe or not os.path.exists(target.rebuilt_exe):
        return RebuiltVtableSummary(f"rebuilt executable not found: {target.rebuilt_exe or '(unset)'}", (), 0, 0)
    if not target.map_path or not os.path.exists(target.map_path):
        return RebuiltVtableSummary(f"linker map not found: {target.map_path or '(unset)'}", (), 0, 0)

    try:
        rebuilt_vtables, symbols_by_va = read_rebuilt_vtables(target.rebuilt_exe, target.map_path)
    except (RuntimeError, ValueError) as exc:
        return RebuiltVtableSummary(str(exc), (), 0, 0)

    if not rebuilt_vtables:
        return RebuiltVtableSummary("no ??_7<Class>@@6B@ vtable symbols in the linker map", (), 0, 0)

    source_addresses = _source_addresses_by_symbol(function_symbols)

    diffs: list[RebuiltClassDiff] = []
    unlocatable: list[str] = []
    slots_checked = 0

    for class_name in sorted(rebuilt_vtables):
        if class_name in skip_classes:
            continue
        if filter_class and class_name != filter_class:
            continue
        if class_name not in classes or class_name not in original_vtables:
            continue

        rebuilt_va, rebuilt_entries = rebuilt_vtables[class_name]
        original_entries = original_vtables[class_name]

        # An empty read means the documented original vtable address holds no
        # code pointers, so there is nothing to diff against. Reporting every
        # rebuilt slot as EXTRA would just be noise.
        if not original_entries:
            unlocatable.append(class_name)
            continue

        issues: list[RebuiltSlotIssue] = []
        unresolved = 0

        for slot in range(max(len(original_entries), len(rebuilt_entries))):
            original_addr = original_entries[slot] if slot < len(original_entries) else None
            rebuilt_addr = rebuilt_entries[slot] if slot < len(rebuilt_entries) else None

            if rebuilt_addr is None:
                issues.append(RebuiltSlotIssue(
                    slot=slot,
                    kind=MISSING_SLOT,
                    original_addr=original_addr,
                    rebuilt_addr=None,
                    expected=_display_name(function_symbols, original_addr),
                    actual="(slot absent)",
                ))
                continue

            if original_addr is None:
                issues.append(RebuiltSlotIssue(
                    slot=slot,
                    kind=EXTRA_SLOT,
                    original_addr=None,
                    rebuilt_addr=rebuilt_addr,
                    expected="(slot absent)",
                    actual=_rebuilt_slot_name(rebuilt_addr, symbols_by_va),
                ))
                continue

            slots_checked += 1
            matches, actual, resolved = _slot_matches(
                original_addr, rebuilt_addr, symbols_by_va, source_addresses
            )
            if not resolved:
                unresolved += 1
            if not matches:
                issues.append(RebuiltSlotIssue(
                    slot=slot,
                    kind=WRONG_FUNCTION,
                    original_addr=original_addr,
                    rebuilt_addr=rebuilt_addr,
                    expected=_display_name(function_symbols, original_addr),
                    actual=actual,
                ))

        diffs.append(RebuiltClassDiff(
            class_name=class_name,
            original_vtable=classes[class_name]["vtable_addr"],
            rebuilt_vtable=rebuilt_va,
            original_len=len(original_entries),
            rebuilt_len=len(rebuilt_entries),
            issues=tuple(issues),
            unresolved=unresolved,
        ))

    return RebuiltVtableSummary(None, tuple(diffs), len(diffs), slots_checked, tuple(unlocatable))


def format_rebuilt_vtable_summary(summary: RebuiltVtableSummary) -> str:
    lines = ["", "Rebuilt vtable verification (compiler output vs original)", "=" * 76]

    if summary.skipped:
        lines.append(f"  skipped: {summary.skipped}")
        return "\n".join(lines)

    failing = [diff for diff in summary.diffs if diff.issues]
    lines.append(f"  Classes compared: {summary.classes_checked}    Slots compared: {summary.slots_checked}")
    if summary.unlocatable:
        lines.append(
            f"  Skipped {len(summary.unlocatable)} classes whose original vtable address holds no code pointers: "
            + ", ".join(summary.unlocatable[:8])
            + (" ..." if len(summary.unlocatable) > 8 else "")
        )

    if not failing:
        lines.append("  All rebuilt vtables match the original slot for slot.")
        return "\n".join(lines)

    for diff in failing:
        length_note = ""
        if diff.rebuilt_len != diff.original_len:
            length_note = f"  [length {diff.rebuilt_len} vs original {diff.original_len}]"
        lines.append(
            f"\n  {diff.class_name}  rebuilt 0x{diff.rebuilt_vtable:08X}"
            f"  original 0x{diff.original_vtable:08X}{length_note}"
        )
        for issue in diff.issues:
            offset = issue.slot * 4
            if issue.kind == MISSING_SLOT:
                lines.append(
                    f"    slot {issue.slot:2d} (+0x{offset:02X}) MISSING     "
                    f"original 0x{issue.original_addr:08X} {issue.expected}"
                )
                lines.append(
                    "                          a call through this slot reads past the end of the vtable"
                )
            elif issue.kind == EXTRA_SLOT:
                lines.append(
                    f"    slot {issue.slot:2d} (+0x{offset:02X}) EXTRA       "
                    f"rebuilt 0x{issue.rebuilt_addr:08X} {issue.actual}"
                )
            else:
                lines.append(
                    f"    slot {issue.slot:2d} (+0x{offset:02X}) WRONG       "
                    f"expected {issue.expected} (0x{issue.original_addr:08X}), got {issue.actual}"
                )

    total = sum(len(diff.issues) for diff in failing)
    lines.append(f"\n  {total} slot issues across {len(failing)} classes")
    return "\n".join(lines)
