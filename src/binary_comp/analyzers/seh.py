"""Compare C++ exception-handling structure between original and rebuilt.

Mnemonic similarity treats the EH prologue/epilogue as ordinary instructions, so
a function can score "well" while unwinding the wrong set of objects (a member
typed ``SlimeDim`` that should be a plain pair, a missing/spurious frame, an
extra ``try`` block). This analyzer parses each side's ``FuncInfo`` and reports
those structural differences directly.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

import os

from binary_comp.analyzers.function_compare import (
    FunctionComparer,
    parse_original_address,
)
from binary_comp.core.eh import EHInfo, analyze_function_eh
from binary_comp.source.functions import load_source_groups


@dataclass(frozen=True)
class SehWarning:
    level: str        # "warn" | "info"
    message: str


@dataclass(frozen=True)
class SehComparison:
    function_name: str
    original_addr: int
    rebuilt_addr: int | None
    original: EHInfo
    rebuilt: EHInfo | None
    warnings: tuple[SehWarning, ...]


def _member_offsets(info: EHInfo) -> Counter:
    return Counter(t for t in info.targets if t.startswith("this+"))


def _other_targets(info: EHInfo) -> Counter:
    # bucket non-member objects by kind so counts can be compared even though the
    # exact ebp displacement differs between the two frame layouts
    buckets = Counter()
    for target in info.targets:
        if target.startswith("this+"):
            continue
        buckets[target.split("@", 1)[0]] += 1
    return buckets


def diff_eh(original: EHInfo, rebuilt: EHInfo) -> list[SehWarning]:
    warnings: list[SehWarning] = []

    if original.has_frame and not rebuilt.has_frame:
        warnings.append(SehWarning(
            "warn",
            f"rebuilt has NO C++ EH frame, original unwinds {original.max_state} "
            f"state(s) {list(original.targets)} — a local object/try block is missing "
            f"(small member destructors must be inline in a header to appear here)",
        ))
        return warnings
    if rebuilt.has_frame and not original.has_frame:
        warnings.append(SehWarning(
            "warn",
            f"rebuilt has a spurious EH frame ({rebuilt.max_state} state(s) "
            f"{list(rebuilt.targets)}); original has none",
        ))
        return warnings
    if not original.has_frame and not rebuilt.has_frame:
        return warnings

    orig_members, reb_members = _member_offsets(original), _member_offsets(rebuilt)
    for offset in sorted(set(reb_members) - set(orig_members)):
        warnings.append(SehWarning(
            "warn",
            f"rebuilt destructs EXTRA member object at {offset} — likely typed with a "
            f"destructor (SlimeDim/Rect) where the original used a dtor-less type",
        ))
    for offset in sorted(set(orig_members) - set(reb_members)):
        warnings.append(SehWarning(
            "warn",
            f"rebuilt is MISSING a member destructor at {offset}",
        ))

    orig_other, reb_other = _other_targets(original), _other_targets(rebuilt)
    for kind in sorted(set(orig_other) | set(reb_other)):
        if orig_other[kind] != reb_other[kind]:
            warnings.append(SehWarning(
                "warn",
                f"rebuilt unwinds {reb_other[kind]} '{kind}' object(s), original {orig_other[kind]}",
            ))

    if len(original.try_blocks) != len(rebuilt.try_blocks):
        warnings.append(SehWarning(
            "warn",
            f"try-block count differs: original {len(original.try_blocks)}, "
            f"rebuilt {len(rebuilt.try_blocks)}",
        ))

    if original.max_state != rebuilt.max_state and not any(w.level == "warn" for w in warnings):
        warnings.append(SehWarning(
            "info",
            f"unwind state count differs (original {original.max_state}, "
            f"rebuilt {rebuilt.max_state}) with matching objects — usually optimizer "
            f"state numbering, not a real difference",
        ))
    return warnings


def compare_function_seh(
    comparer: FunctionComparer,
    function_name: str,
    disassembled_code_path: str,
) -> SehComparison:
    original_addr = parse_original_address(disassembled_code_path)
    if original_addr is None:
        raise ValueError("could not determine original function address")

    rebuilt_addr = comparer.rebuilt_address(function_name, original_addr)
    original_image = comparer.pe_image(comparer.target.original_exe)
    original_eh = analyze_function_eh(original_image, original_addr)

    rebuilt_eh = None
    warnings: list[SehWarning] = []
    if rebuilt_addr is None:
        warnings.append(SehWarning("warn", "function not found in linker map"))
    else:
        rebuilt_image = comparer.pe_image(comparer.target.rebuilt_exe)
        rebuilt_eh = analyze_function_eh(rebuilt_image, rebuilt_addr)
        warnings = diff_eh(original_eh, rebuilt_eh)

    return SehComparison(
        function_name=function_name,
        original_addr=original_addr,
        rebuilt_addr=rebuilt_addr,
        original=original_eh,
        rebuilt=rebuilt_eh,
        warnings=tuple(warnings),
    )


def _format_eh(label: str, info: EHInfo | None) -> list[str]:
    if info is None or not info.has_frame:
        return [f"  {label:8} no EH frame"]
    lines = [
        f"  {label:8} FuncInfo=0x{info.funcinfo_addr:06X}  maxState={info.max_state}  "
        f"tryBlocks={len(info.try_blocks)}"
    ]
    for state in info.unwinds:
        flag = " [guarded]" if state.conditional else ""
        dtor = f" -> 0x{state.dtor:06X}" if state.dtor else ""
        lines.append(
            f"           state {state.index}: destroy {state.target}{dtor}"
            f" (toState={state.to_state}){flag}"
        )
    return lines


@dataclass(frozen=True)
class SehReportRow:
    source_file: str
    function_name: str
    original_addr: int
    warnings: tuple[SehWarning, ...]


def generate_seh_report(
    comparer: FunctionComparer, file_filter: str | None = None
) -> list[SehReportRow]:
    """Scan every source function and collect EH-structure differences.

    Only functions whose exception-handling differs are returned, so the output
    is a focused worklist (a member typed with the wrong dtor, a missing/extra
    frame, a mismatched try block).
    """
    groups_by_source = load_source_groups(
        comparer.target.source_dirs,
        comparer.target.map_skip,
        comparer.target.source_excludes,
        signature_names=comparer.signature_overloads,
    )
    original_image = comparer.pe_image(comparer.target.original_exe)
    rebuilt_image = comparer.pe_image(comparer.target.rebuilt_exe)

    rows: list[SehReportRow] = []
    for source_path in sorted(groups_by_source):
        for group in groups_by_source[source_path]:
            if file_filter and file_filter not in source_path and file_filter not in group.name:
                continue
            if not group.addresses:
                continue
            original_addr = min(int(addr, 16) for addr in group.addresses)
            original_eh = analyze_function_eh(original_image, original_addr)
            rebuilt_addr = comparer.rebuilt_address(group.name, original_addr)
            if rebuilt_addr is None:
                if original_eh.has_frame:
                    rows.append(SehReportRow(
                        os.path.basename(source_path), group.name, original_addr,
                        (SehWarning("warn", "not found in linker map but original has an EH frame"),),
                    ))
                continue
            rebuilt_eh = analyze_function_eh(rebuilt_image, rebuilt_addr)
            warnings = tuple(diff_eh(original_eh, rebuilt_eh))
            real = tuple(w for w in warnings if w.level == "warn")
            if real:
                rows.append(SehReportRow(
                    os.path.basename(source_path), group.name, original_addr, real
                ))
    return rows


def format_seh_report(rows: list[SehReportRow]) -> str:
    if not rows:
        return "No exception-handling differences found."
    lines = ["", "--- SEH structure differences ---"]
    current_file = None
    for row in rows:
        if row.source_file != current_file:
            lines.append(f"\n=== {row.source_file} ===")
            current_file = row.source_file
        lines.append(f"  {row.function_name}  (0x{row.original_addr:06X})")
        for warning in row.warnings:
            lines.append(f"      WARNING: {warning.message}")
    lines.append(f"\n{len(rows)} function(s) with EH-structure differences.")
    return "\n".join(lines)


def format_seh_comparison(comparison: SehComparison) -> str:
    lines = [f"SEH comparison for '{comparison.function_name}':"]
    lines += _format_eh("original", comparison.original)
    lines += _format_eh("rebuilt", comparison.rebuilt)
    lines.append("")
    if not comparison.warnings:
        lines.append("  OK: exception-handling structure matches.")
    else:
        for warning in comparison.warnings:
            tag = "WARNING" if warning.level == "warn" else "info"
            lines.append(f"  {tag}: {warning.message}")
    return "\n".join(lines)
