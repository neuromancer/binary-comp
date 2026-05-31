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


def _state_targets(info: EHInfo, *, active_only: bool = False) -> tuple[str, ...]:
    if active_only and info.active_states is not None:
        active = set(info.active_states)
        return tuple(
            state.target for state in info.unwinds
            if state.action is not None and state.index in active
        )
    return info.targets


def _member_offsets(info: EHInfo, *, active_only: bool = False) -> Counter:
    return Counter(t for t in _state_targets(info, active_only=active_only) if t.startswith("this+"))


def _target_bucket(target: str) -> str:
    """Stable bucket for default-mode comparison.

    Member subobjects are stable across the two binaries, but stack/temporary
    slots routinely move when the C source is still not mnemonic-perfect. Keep
    those broader by kind in the default report; strict mode compares the exact
    expression.
    """
    if target == "this" or target.startswith("this+"):
        return target
    if "@" in target:
        return target.split("@", 1)[0]
    return target


def _target_buckets(info: EHInfo, *, active_only: bool = False) -> Counter:
    return Counter(_target_bucket(t) for t in _state_targets(info, active_only=active_only))


def _other_targets(info: EHInfo, *, active_only: bool = False) -> Counter:
    # bucket non-member objects by kind so counts can be compared even though the
    # exact ebp displacement differs between the two frame layouts. Bare
    # ``this`` is deliberately skipped: MSVC often reuses the saved-this slot for
    # ordinary pointers, so only ``this+offset`` member subobjects are stable in
    # default mode.
    return Counter(
        _target_bucket(t)
        for t in _state_targets(info, active_only=active_only)
        if t != "this" and not t.startswith("this+")
    )


def _guarded_targets(info: EHInfo, *, active_only: bool = False) -> Counter:
    active = None if not active_only or info.active_states is None else set(info.active_states)
    return Counter(
        _target_bucket(state.target)
        for state in info.unwinds
        if state.action is not None
        and state.conditional
        and (active is None or state.index in active)
    )


def _format_state(state) -> str:
    guarded = " guarded" if state.conditional else ""
    return f"{state.target} toState={state.to_state}{guarded}"


def _strict_warnings(original: EHInfo, rebuilt: EHInfo) -> list[SehWarning]:
    warnings: list[SehWarning] = []

    if original.max_state != rebuilt.max_state:
        warnings.append(SehWarning(
            "warn",
            f"strict unwind state count differs: original {original.max_state}, "
            f"rebuilt {rebuilt.max_state}",
        ))

    limit = min(len(original.unwinds), len(rebuilt.unwinds))
    diffs = [
        index for index in range(limit)
        if (
            original.unwinds[index].target,
            original.unwinds[index].to_state,
            original.unwinds[index].conditional,
        ) != (
            rebuilt.unwinds[index].target,
            rebuilt.unwinds[index].to_state,
            rebuilt.unwinds[index].conditional,
        )
    ]
    for index in diffs[:3]:
        warnings.append(SehWarning(
            "warn",
            f"strict state {index} differs: original "
            f"{_format_state(original.unwinds[index])}; rebuilt "
            f"{_format_state(rebuilt.unwinds[index])}",
        ))
    if len(diffs) > 3:
        warnings.append(SehWarning(
            "warn",
            f"strict unwind sequence has {len(diffs) - 3} additional differing state(s)",
        ))

    if (
        len(original.unwinds) != len(rebuilt.unwinds)
        and original.max_state == rebuilt.max_state
    ):
        warnings.append(SehWarning(
            "warn",
            f"strict parsed unwind entry count differs: original {len(original.unwinds)}, "
            f"rebuilt {len(rebuilt.unwinds)}",
        ))

    if original.try_blocks != rebuilt.try_blocks:
        warnings.append(SehWarning(
            "warn",
            f"strict try-block layout differs: original {list(original.try_blocks)}, "
            f"rebuilt {list(rebuilt.try_blocks)}",
        ))

    return warnings


def diff_eh(original: EHInfo, rebuilt: EHInfo, *, strict: bool = False) -> list[SehWarning]:
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
    orig_active_members = _member_offsets(original, active_only=True)
    reb_active_members = _member_offsets(rebuilt, active_only=True)
    for offset in sorted(set(orig_members) | set(reb_members)):
        if reb_members[offset] > orig_members[offset]:
            if reb_active_members[offset] == orig_active_members[offset]:
                continue
            warnings.append(SehWarning(
                "warn",
                f"rebuilt destructs EXTRA member object at {offset} — likely typed with a "
                f"destructor (SlimeDim/Rect) where the original used a dtor-less type",
            ))
        elif orig_members[offset] > reb_members[offset]:
            if reb_active_members[offset] == orig_active_members[offset]:
                continue
            warnings.append(SehWarning(
                "warn",
                f"rebuilt is MISSING a member destructor at {offset}",
            ))

    orig_other, reb_other = _other_targets(original), _other_targets(rebuilt)
    orig_active_other = _other_targets(original, active_only=True)
    reb_active_other = _other_targets(rebuilt, active_only=True)
    for kind in sorted(set(orig_other) | set(reb_other)):
        if orig_other[kind] != reb_other[kind]:
            if orig_active_other[kind] == reb_active_other[kind]:
                continue
            warnings.append(SehWarning(
                "warn",
                f"rebuilt unwinds {reb_other[kind]} '{kind}' object(s), original {orig_other[kind]}",
            ))

    orig_buckets, reb_buckets = _target_buckets(original), _target_buckets(rebuilt)
    orig_guarded, reb_guarded = _guarded_targets(original), _guarded_targets(rebuilt)
    orig_active_guarded = _guarded_targets(original, active_only=True)
    reb_active_guarded = _guarded_targets(rebuilt, active_only=True)
    for kind in sorted(set(orig_guarded) | set(reb_guarded)):
        if kind == "stack":
            continue
        # If the object count already differs, that warning is clearer. This
        # catches same-object-count cases where only the cleanup guard changed.
        if orig_buckets[kind] != reb_buckets[kind]:
            continue
        if orig_guarded[kind] != reb_guarded[kind]:
            if orig_active_guarded[kind] == reb_active_guarded[kind]:
                continue
            warnings.append(SehWarning(
                "warn",
                f"guarded cleanup count differs for '{kind}': rebuilt "
                f"{reb_guarded[kind]}, original {orig_guarded[kind]}",
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
    if strict:
        warnings.extend(_strict_warnings(original, rebuilt))
    return warnings


def compare_function_seh(
    comparer: FunctionComparer,
    function_name: str,
    disassembled_code_path: str,
    *,
    strict: bool = False,
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
        warnings = diff_eh(original_eh, rebuilt_eh, strict=strict)

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
        if info.active_states is not None and state.index not in info.active_states:
            flag += " [inactive]"
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


@dataclass(frozen=True)
class SehReport:
    rows: tuple[SehReportRow, ...]
    scanned: int
    mapped: int
    missing: int
    original_frames: int
    rebuilt_frames: int
    both_frames: int
    original_only: int
    rebuilt_only: int
    strict: bool


def generate_seh_report(
    comparer: FunctionComparer,
    file_filter: str | None = None,
    *,
    strict: bool = False,
) -> SehReport:
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
    clean_original_addrs: set[int] = set()
    scanned = 0
    mapped = 0
    missing = 0
    original_frames = 0
    rebuilt_frames = 0
    both_frames = 0
    original_only = 0
    rebuilt_only = 0
    for source_path in sorted(groups_by_source):
        for group in groups_by_source[source_path]:
            if file_filter and file_filter not in source_path and file_filter not in group.name:
                continue
            if not group.addresses:
                continue
            scanned += 1
            original_addr = min(int(addr, 16) for addr in group.addresses)
            original_eh = analyze_function_eh(original_image, original_addr)
            if original_eh.has_frame:
                original_frames += 1
            rebuilt_addr = comparer.rebuilt_address(group.name, original_addr)
            if rebuilt_addr is None:
                missing += 1
                if original_eh.has_frame:
                    rows.append(SehReportRow(
                        os.path.basename(source_path), group.name, original_addr,
                        (SehWarning("warn", "not found in linker map but original has an EH frame"),),
                    ))
                continue
            mapped += 1
            rebuilt_eh = analyze_function_eh(rebuilt_image, rebuilt_addr)
            if rebuilt_eh.has_frame:
                rebuilt_frames += 1
            if original_eh.has_frame and rebuilt_eh.has_frame:
                both_frames += 1
            elif original_eh.has_frame:
                original_only += 1
            elif rebuilt_eh.has_frame:
                rebuilt_only += 1
            warnings = tuple(diff_eh(original_eh, rebuilt_eh, strict=strict))
            real = tuple(w for w in warnings if w.level == "warn")
            if real:
                rows.append(SehReportRow(
                    os.path.basename(source_path), group.name, original_addr, real
                ))
            else:
                clean_original_addrs.add(original_addr)
    rows = [
        row for row in rows
        if row.original_addr not in clean_original_addrs
    ]
    return SehReport(
        rows=tuple(rows),
        scanned=scanned,
        mapped=mapped,
        missing=missing,
        original_frames=original_frames,
        rebuilt_frames=rebuilt_frames,
        both_frames=both_frames,
        original_only=original_only,
        rebuilt_only=rebuilt_only,
        strict=strict,
    )


def format_seh_report(report: SehReport | list[SehReportRow]) -> str:
    rows = report.rows if isinstance(report, SehReport) else tuple(report)
    strict = isinstance(report, SehReport) and report.strict
    if not rows:
        lines = ["No exception-handling differences found."]
    else:
        label = "strict SEH structure differences" if strict else "SEH structure differences"
        lines = ["", f"--- {label} ---"]
        current_file = None
        for row in rows:
            if row.source_file != current_file:
                lines.append(f"\n=== {row.source_file} ===")
                current_file = row.source_file
            lines.append(f"  {row.function_name}  (0x{row.original_addr:06X})")
            for warning in row.warnings:
                lines.append(f"      WARNING: {warning.message}")
        lines.append(f"\n{len(rows)} function(s) with EH-structure differences.")
    if isinstance(report, SehReport):
        lines.append(
            "Scanned "
            f"{report.scanned} function(s), mapped {report.mapped}, missing {report.missing}; "
            f"EH frames original={report.original_frames}, rebuilt={report.rebuilt_frames}, "
            f"both={report.both_frames}, original-only={report.original_only}, "
            f"rebuilt-only={report.rebuilt_only}."
        )
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
