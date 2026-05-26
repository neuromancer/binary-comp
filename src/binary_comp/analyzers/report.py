"""Whole-project function similarity reporting."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from binary_comp.analyzers.function_compare import (
    FunctionCompareError,
    FunctionComparer,
    disassemble_exported_function,
    instruction_mnemonics,
    load_disassembly_policy,
    maybe_build,
    mnemonic_similarity,
)
from binary_comp.config import ProjectTarget
from binary_comp.core.disasm import normalize_mnemonic
from binary_comp.core.pe import PEImage
from binary_comp.source.functions import load_source_groups


@dataclass(frozen=True)
class SimilarityReportOptions:
    build: bool = True
    canonical_aliases: dict[str, str] | None = None


@dataclass(frozen=True)
class SimilarityReportRow:
    source_file: str
    function_name: str
    address: int
    similarity: float | None
    status: str


@dataclass(frozen=True)
class SimilarityReport:
    rows: tuple[SimilarityReportRow, ...]
    compared: int
    similarity_sum: float
    at_100: int
    above_90: int
    below_90: int
    errors: int
    asm_fallbacks: int


def disassembly_path(target: ProjectTarget, address: int) -> str | None:
    if not target.code_dir:
        return None
    candidates = (
        os.path.join(target.code_dir, f"FUN_{address:08X}.disassembled.txt"),
        os.path.join(target.code_dir, f"FUN_{address:06X}.disassembled.txt"),
        os.path.join(target.code_dir, f"FUN_{address:X}.disassembled.txt"),
    )
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]


def asm_path_for_source(target: ProjectTarget, source_path: str) -> str | None:
    if not target.asm_dir:
        return None
    basename = os.path.splitext(os.path.basename(source_path))[0] + ".asm"
    return os.path.join(target.asm_dir, basename)


def asm_line_mnemonic(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.endswith(":"):
        return None
    if stripped.startswith(";") or stripped.startswith("?"):
        return None
    if re.search(r"\b(SEGMENT|ENDS|END|PROC|ENDP|PUBLIC|EXTRN|COMDAT)\b", stripped):
        return None
    if "=" in stripped and not stripped.lower().startswith(("cmp", "test")):
        return None

    code = stripped.split(";", 1)[0].strip()
    if not code:
        return None
    parts = code.split()
    if not parts:
        return None

    mnemonic = parts[0].lower()
    if mnemonic in {"db", "dd", "dq", "dt", "dw", "npad"}:
        return None
    if mnemonic in {"rep", "repe", "repne", "repnz", "lock"} and len(parts) > 1:
        mnemonic = f"{mnemonic} {parts[1].lower()}"
    return normalize_mnemonic(mnemonic)


def extract_asm_mnemonics(
    asm_path: str,
    function_name: str,
    occurrence_index: int,
) -> list[str]:
    try:
        with open(asm_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    current_index = -1
    in_function = False
    mnemonics: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not in_function:
            if "PROC" not in stripped:
                continue
            if "; " not in stripped:
                continue
            comment = stripped.split("; ", 1)[1].strip()
            if comment.endswith(", COMDAT"):
                comment = comment[:-len(", COMDAT")].strip()
            if comment != function_name:
                continue
            current_index += 1
            if current_index != occurrence_index:
                continue
            in_function = True
            continue

        if re.search(r"\bENDP\b", stripped):
            break
        mnemonic = asm_line_mnemonic(stripped)
        if mnemonic is not None:
            mnemonics.append(mnemonic)

    return mnemonics


def compare_asm_fallback(
    target: ProjectTarget,
    original_image: PEImage,
    source_path: str,
    function_name: str,
    occurrence_index: int,
    original_addr: int,
    disasm_path: str,
    max_bytes: int,
    padding_mnemonics: frozenset[str],
) -> float | None:
    asm_path = asm_path_for_source(target, source_path)
    if asm_path is None:
        return None
    compiled_mnemonics = extract_asm_mnemonics(asm_path, function_name, occurrence_index)
    if not compiled_mnemonics:
        return None

    original = disassemble_exported_function(
        original_image,
        disasm_path,
        original_addr,
        max_bytes,
        padding_mnemonics,
    )
    original_mnemonics = instruction_mnemonics(original.instructions)
    if not original_mnemonics:
        return None
    return mnemonic_similarity(compiled_mnemonics, original_mnemonics)


def generate_similarity_report(
    target: ProjectTarget,
    options: SimilarityReportOptions = SimilarityReportOptions(),
) -> SimilarityReport:
    maybe_build(target, options.build)

    comparer = FunctionComparer(target, canonical_aliases=options.canonical_aliases)
    original_image = PEImage(target.original_exe)
    max_bytes, padding_mnemonics = load_disassembly_policy(target)
    groups_by_source = load_source_groups(target.source_dirs, target.map_skip, target.source_excludes)
    rows: list[SimilarityReportRow] = []
    compared = 0
    similarity_sum = 0.0
    at_100 = 0
    above_90 = 0
    below_90 = 0
    errors = 0
    asm_fallbacks = 0

    for source_path in sorted(groups_by_source):
        source_file = os.path.basename(source_path)
        occurrences: dict[str, int] = {}
        for group in groups_by_source[source_path]:
            occurrence_index = occurrences.get(group.name, 0)
            occurrences[group.name] = occurrence_index + 1
            for address_text in group.addresses:
                address = int(address_text, 16)
                path = disassembly_path(target, address)
                if path is None or not os.path.exists(path):
                    rows.append(SimilarityReportRow(source_file, group.name, address, None, "N/A"))
                    continue

                try:
                    comparison = comparer.compare(group.name, path, build=False)
                except (FunctionCompareError, FileNotFoundError, RuntimeError, ValueError):
                    similarity = compare_asm_fallback(
                        target,
                        original_image,
                        source_path,
                        group.name,
                        occurrence_index,
                        address,
                        path,
                        max_bytes,
                        padding_mnemonics,
                    )
                    if similarity is None:
                        errors += 1
                        rows.append(SimilarityReportRow(source_file, group.name, address, None, "NOT FOUND"))
                        continue
                    asm_fallbacks += 1
                else:
                    similarity = comparison.similarity

                compared += 1
                similarity_sum += similarity
                if similarity >= 99.99:
                    at_100 += 1
                if similarity >= 90.0:
                    above_90 += 1
                else:
                    below_90 += 1
                rows.append(SimilarityReportRow(
                    source_file,
                    group.name,
                    address,
                    similarity,
                    f"{similarity:.2f}%",
                ))

    return SimilarityReport(
        rows=tuple(rows),
        compared=compared,
        similarity_sum=similarity_sum,
        at_100=at_100,
        above_90=above_90,
        below_90=below_90,
        errors=errors,
        asm_fallbacks=asm_fallbacks,
    )


def format_similarity_report(report: SimilarityReport) -> str:
    lines = ["", "--- Similarity Report ---"]
    current_file = None
    for row in report.rows:
        if row.source_file != current_file:
            lines.extend(["", f"=== {row.source_file} ==="])
            current_file = row.source_file
        lines.append(f"  {row.function_name:45s} 0x{row.address:06X}  {row.status}")

    average = report.similarity_sum / report.compared if report.compared else 0.0
    lines.extend([
        "",
        "--- Summary ---",
        f"Total compared: {report.compared}",
        f"  100%: {report.at_100}",
        f"  >=90%: {report.above_90}",
        f"  <90%: {report.below_90}",
        f"  Errors/NOT FOUND: {report.errors}",
        f"  ASM fallback: {report.asm_fallbacks}",
        f"  Average similarity: {average:.2f}%",
    ])
    return "\n".join(lines)
