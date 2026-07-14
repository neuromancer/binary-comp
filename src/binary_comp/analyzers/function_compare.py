"""Capstone-backed single-function mnemonic comparison."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass

from binary_comp.analyzers.values import load_policy
from binary_comp.config import ConfigError, ProjectTarget
from binary_comp.core.disasm import (
    Instruction,
    disassemble_x86,
    has_msvc_seh_frame,
    unsigned32,
)
from binary_comp.core.mapfile import function_starts_from_map, parse_msvc_map_by_obj
from binary_comp.core.pe import PEImage
from binary_comp.core.symbols import (
    canonical_function_name,
    symbol_matches,
    symbol_patterns_for_function,
)
from binary_comp.source.functions import load_source_groups, map_source_groups


DEFAULT_MAX_DISASSEMBLY_BYTES = 0x20000
DEFAULT_PADDING_MNEMONICS = frozenset({"nop", "int3"})

# How much better (in percentage points) a sibling overload / deleting-destructor
# must score than the name-based default before it overrides it. Keeps genuine
# near-identical overloads stable while still correcting gross mispairings.
CANDIDATE_OVERRIDE_EPSILON = 1.0


class FunctionCompareError(RuntimeError):
    pass


@dataclass(frozen=True)
class DisassemblyResult:
    instructions: list[Instruction]
    excluded: list[Instruction]


@dataclass(frozen=True)
class FunctionComparison:
    function_name: str
    original_addr: int
    rebuilt_addr: int
    similarity: float
    rebuilt: DisassemblyResult
    original: DisassemblyResult


def maybe_build(target: ProjectTarget, do_build: bool) -> None:
    if not do_build:
        return
    if target.build.clean:
        subprocess.run(target.build.clean.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if not target.build.build:
        return
    build_command = target.build.build.split()
    if target.build.jobs and target.build.jobs > 1:
        build_command.append(f"-j{target.build.jobs}")
    if subprocess.run(build_command, check=False).returncode != 0:
        raise FunctionCompareError("build failed")


def load_disassembly_policy(target: ProjectTarget) -> tuple[int, frozenset[str]]:
    try:
        policy = load_policy(target.values_policy)
        return policy.max_disassembly_bytes, policy.padding_mnemonics
    except (ConfigError, FileNotFoundError, RuntimeError):
        return DEFAULT_MAX_DISASSEMBLY_BYTES, DEFAULT_PADDING_MNEMONICS


def parse_original_address(disassembled_code_path: str) -> int | None:
    filename = os.path.basename(disassembled_code_path)
    match = re.search(r"FUN_([0-9A-Fa-f]+)\.disassembled\.txt$", filename)
    if match:
        return int(match.group(1), 16)

    try:
        with open(disassembled_code_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(512)
    except OSError:
        return None

    match = re.search(r"Address:\s*0x([0-9A-Fa-f]+)", head)
    if match:
        return int(match.group(1), 16)
    return None


def instruction_count_from_disassembly(disassembled_code_path: str) -> int | None:
    try:
        with open(disassembled_code_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()[3:]
    except OSError:
        return None

    count = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":"):
            continue
        if stripped.startswith(";"):
            continue
        mnemonic = stripped.split()[0].lower()
        if mnemonic in {"db", "dd", "dw", "npad"}:
            continue
        count += 1
    return count or None


def is_instruction_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.endswith(":"):
        return False
    if stripped.startswith(";"):
        return False
    mnemonic = stripped.split()[0].lower()
    if mnemonic in {"db", "dd", "dw", "npad"}:
        return False
    return True


def disassembly_blocks_from_export(disassembled_code_path: str, function_start: int) -> list[tuple[int, int]]:
    try:
        with open(disassembled_code_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()[3:]
    except OSError:
        return []

    blocks: list[tuple[int, int]] = []
    current_addr = function_start
    current_count = 0

    for line in lines:
        stripped = line.strip()
        label = re.match(r"^(?:LAB|loc|FUN)_?([0-9A-Fa-f]{6,8}):$", stripped)
        if label:
            if current_count:
                blocks.append((current_addr, current_count))
            current_addr = int(label.group(1), 16)
            current_count = 0
            continue
        if is_instruction_line(line):
            current_count += 1

    if current_count:
        blocks.append((current_addr, current_count))
    return blocks


def levenshtein_distance(left: list[str], right: list[str]) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for i, left_item in enumerate(left, 1):
        current = [i]
        for j, right_item in enumerate(right, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (0 if left_item == right_item else 1),
            ))
        previous = current
    return previous[-1]


def mnemonic_similarity(left: list[str], right: list[str]) -> float:
    max_len = max(len(left), len(right))
    if max_len == 0:
        return 100.0
    distance = levenshtein_distance(left, right)
    return (1 - distance / max_len) * 100


def map_symbol_matches_function(mangled: str, function_name: str) -> bool:
    base = canonical_function_name(function_name).split("(", 1)[0]
    if "::" in base:
        return symbol_matches(mangled, symbol_patterns_for_function(function_name))
    return (
        mangled == f"_{base}"
        or mangled.startswith(f"_{base}@")
        or mangled.startswith(f"?{base}@@")
        or mangled.startswith(f"@{base}@")
    )


def next_function_boundary(starts: list[int], start: int, image: PEImage, max_bytes: int) -> int | None:
    section_end = image.section_end_for_va(start)
    if section_end is None:
        return None

    end = section_end
    for candidate in starts:
        if candidate > start:
            end = min(end, candidate)
            break
    return min(end, start + max_bytes)


def direct_branch_target(instr: Instruction) -> int | None:
    if not instr.operands:
        return None
    operand = instr.operands[0]
    if operand.kind != "imm":
        return None
    return unsigned32(operand.imm)


def switch_jump_targets(
    image: PEImage,
    instr: Instruction,
    func_start: int,
    func_end: int,
) -> list[int]:
    if instr.mnemonic != "jmp" or len(instr.operands) != 1:
        return []

    operand = instr.operands[0]
    if operand.kind != "mem":
        return []
    if operand.base or not operand.index or operand.scale != 4:
        return []

    table = unsigned32(operand.disp)
    if not (func_start <= table < func_end):
        return []

    targets = []
    cursor = table
    while cursor + 4 <= func_end:
        raw = image.read(cursor, 4)
        if raw is None or len(raw) != 4:
            break
        target = int.from_bytes(raw, "little")
        if not (func_start <= target < func_end):
            break
        targets.append(target)
        cursor += 4
    return targets


def instruction_size(image: PEImage, instr: Instruction) -> int:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ImportError as exc:
        raise RuntimeError("capstone is required") from exc

    data = image.read(instr.address, 15)
    if not data:
        return 0
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    decoded = next(md.disasm(data, instr.address), None)
    return decoded.size if decoded is not None else 0


def has_fallthrough(image: PEImage, instr: Instruction) -> bool:
    if instr.mnemonic == "ret":
        return False
    if instr.mnemonic == "jmp":
        return False
    if instr.mnemonic in {"int", "int3"}:
        return False
    return instruction_size(image, instr) != 0


def reachable_instruction_indices(
    image: PEImage,
    instrs: list[Instruction],
    func_start: int,
    func_end: int,
) -> set[int]:
    if not instrs:
        return set()

    by_address = {instr.address: index for index, instr in enumerate(instrs)}
    reachable = set()
    pending = [0]

    while pending:
        index = pending.pop()
        if index in reachable or index < 0 or index >= len(instrs):
            continue

        instr = instrs[index]
        reachable.add(index)

        if instr.mnemonic == "jmp":
            targets = switch_jump_targets(image, instr, func_start, func_end)
            target = direct_branch_target(instr)
            if target is not None:
                targets.append(target)
            for target in targets:
                target_index = by_address.get(target)
                if target_index is not None:
                    pending.append(target_index)
            continue

        if instr.mnemonic.startswith("j") or instr.mnemonic in {"loop", "loope", "loopne"}:
            target = direct_branch_target(instr)
            if target is not None:
                target_index = by_address.get(target)
                if target_index is not None:
                    pending.append(target_index)

        if has_fallthrough(image, instr) and index + 1 < len(instrs):
            next_instr = instrs[index + 1]
            size = instruction_size(image, instr)
            if size and next_instr.address == instr.address + size:
                pending.append(index + 1)

    return reachable


def trim_unreachable_instructions(
    image: PEImage,
    instrs: list[Instruction],
    func_start: int,
    func_end: int,
) -> tuple[list[Instruction], list[Instruction]]:
    if not instrs:
        return instrs, []

    reachable = reachable_instruction_indices(image, instrs, func_start, func_end)
    if not reachable:
        return instrs, []

    kept = []
    excluded = []
    for index, instr in enumerate(instrs):
        if index in reachable:
            kept.append(instr)
        else:
            excluded.append(instr)
    return kept, excluded


def disassemble_function(
    image: PEImage,
    start: int,
    starts: list[int],
    max_bytes: int,
    padding_mnemonics: frozenset[str],
    instruction_count: int | None = None,
) -> DisassemblyResult:
    decode_max_bytes = max_bytes
    if instruction_count is not None:
        decode_max_bytes = min(max_bytes, max(128, instruction_count * 32 + 256))
    if instruction_count is not None:
        starts = [start]
    func_end = next_function_boundary(starts, start, image, decode_max_bytes)
    if func_end is None:
        return DisassemblyResult([], [])

    instrs = disassemble_x86(
        image,
        start,
        starts,
        max_bytes=decode_max_bytes,
        padding_mnemonics=padding_mnemonics,
        trim_msvc_seh=False,
        remove_jump_tables=True,
    )
    if instruction_count is not None:
        instrs = instrs[:instruction_count]
    kept, excluded = trim_unreachable_instructions(image, instrs, start, func_end)
    return DisassemblyResult(kept, excluded if has_msvc_seh_frame(instrs) else [])


def disassemble_block(
    image: PEImage,
    start: int,
    instruction_count: int,
    max_bytes: int,
    padding_mnemonics: frozenset[str],
) -> list[Instruction]:
    decode_size = min(max_bytes, max(64, instruction_count * 16 + 32))
    while decode_size <= max_bytes:
        instrs = disassemble_x86(
            image,
            start,
            [start],
            max_bytes=decode_size,
            padding_mnemonics=padding_mnemonics,
            trim_msvc_seh=False,
            remove_jump_tables=False,
        )
        if len(instrs) >= instruction_count or decode_size == max_bytes:
            return instrs[:instruction_count]
        next_size = min(max_bytes, decode_size * 2)
        if next_size == decode_size:
            return instrs[:instruction_count]
        decode_size = next_size
    return []


def disassemble_exported_function(
    image: PEImage,
    disassembled_code_path: str,
    start: int,
    max_bytes: int,
    padding_mnemonics: frozenset[str],
) -> DisassemblyResult:
    blocks = disassembly_blocks_from_export(disassembled_code_path, start)
    if not blocks:
        return disassemble_function(
            image,
            start,
            [start],
            max_bytes,
            padding_mnemonics,
            instruction_count=instruction_count_from_disassembly(disassembled_code_path),
        )

    instructions: list[Instruction] = []
    seen: set[int] = set()
    for block_start, block_count in blocks:
        for instr in disassemble_block(image, block_start, block_count, max_bytes, padding_mnemonics):
            if instr.address in seen:
                continue
            seen.add(instr.address)
            instructions.append(instr)
    return DisassemblyResult(instructions, [])


def instruction_line(instr: Instruction) -> str:
    return f"{instr.address:08X}: {instr.raw}"


def render_instructions(instrs: list[Instruction]) -> str:
    return "\n".join(instruction_line(instr) for instr in instrs)


def instruction_mnemonics(instrs: list[Instruction]) -> list[str]:
    return [instr.mnemonic for instr in instrs]


def side_by_side(str1: str, str2: str, tab_size: int = 4) -> str:
    str1 = str1.replace("\t", " " * tab_size)
    str2 = str2.replace("\t", " " * tab_size)
    lines1 = str1.split("\n") if str1 else []
    lines2 = str2.split("\n") if str2 else []
    max_length = max(len(line) for line in lines1) if lines1 else 0
    max_length = min(max_length, 64)
    max_lines = max(len(lines1), len(lines2))
    result = []
    for i in range(max_lines):
        line1 = lines1[i] if i < len(lines1) else ""
        line2 = lines2[i] if i < len(lines2) else ""
        if len(line1) > max_length:
            line1 = line1[:max_length - 2] + ".."
        if len(line2) > max_length:
            line2 = line2[:max_length - 2] + ".."
        result.append(f"{line1.ljust(max_length)} | {line2}")
    return "\n".join(result)


class FunctionComparer:
    def __init__(
        self,
        target: ProjectTarget,
        canonical_aliases: dict[str, str] | None = None,
        signature_overloads: frozenset[str] = frozenset(),
    ):
        self.target = target
        self.canonical_aliases = canonical_aliases or {}
        self.signature_overloads = signature_overloads
        self.max_bytes, self.padding_mnemonics = load_disassembly_policy(target)
        self._source_groups = None
        self._map_entries = None
        self._pe_images: dict[str, PEImage] = {}

    def candidate_names(self, function_name: str) -> tuple[str, ...]:
        alias = self.canonical_aliases.get(function_name)
        if alias and alias != function_name:
            return (function_name, alias)
        return (function_name,)

    def source_groups(self):
        if self._source_groups is None:
            groups_by_source = load_source_groups(
                self.target.source_dirs,
                self.target.map_skip,
                self.target.source_excludes,
                signature_names=self.signature_overloads,
            )
            self._source_groups = map_source_groups(
                groups_by_source,
                self.target.map_path,
                signature_names=self.signature_overloads,
            )[0]
        return self._source_groups

    def map_entries(self):
        if self._map_entries is None:
            self._map_entries = parse_msvc_map_by_obj(self.target.map_path)
        return self._map_entries

    def pe_image(self, path: str) -> PEImage:
        image = self._pe_images.get(path)
        if image is None:
            image = PEImage(path)
            self._pe_images[path] = image
        return image

    def mapped_source_rebuilt_address(self, function_name: str, original_addr: int) -> int | None:
        try:
            mapped_groups = self.source_groups()
        except (ConfigError, FileNotFoundError, RuntimeError):
            return None

        for candidate_name in self.candidate_names(function_name):
            wanted = canonical_function_name(candidate_name)
            exact = [
                group
                for group in mapped_groups
                if (
                    canonical_function_name(group.name) == wanted
                    and original_addr in group.original_addrs
                    and map_symbol_matches_function(group.rebuilt_symbol, candidate_name)
                )
            ]
            if len(exact) == 1:
                return exact[0].rebuilt_addr

            by_name = [
                group
                for group in mapped_groups
                if (
                    canonical_function_name(group.name) == wanted
                    and map_symbol_matches_function(group.rebuilt_symbol, candidate_name)
                )
            ]
            if len(by_name) == 1:
                return by_name[0].rebuilt_addr
        return None

    def map_symbol_rebuilt_address(self, function_name: str) -> int | None:
        for candidate_name in self.candidate_names(function_name):
            matches = [
                entry
                for entries in self.map_entries().values()
                for entry in entries
                if map_symbol_matches_function(entry.symbol, candidate_name)
            ]
            if len(matches) == 1:
                return matches[0].va
            if matches:
                return matches[0].va
        return None

    def rebuilt_address(self, function_name: str, original_addr: int) -> int | None:
        mapped = self.mapped_source_rebuilt_address(function_name, original_addr)
        if mapped is not None:
            return mapped
        return self.map_symbol_rebuilt_address(function_name)

    def candidate_rebuilt_addresses(self, function_name: str, original_addr: int) -> list[int]:
        """Rebuilt addresses to score for this source function.

        The name-based resolution (the primary) never considers the
        compiler-generated *scalar/vector deleting destructor* COMDATs
        (``??_G``/``??_E``) that ``delete`` actually calls. When the original a
        destructor is annotated with is one of those (e.g. ``DrawEntry``'s only
        ``/* Function start */`` points at its sdtor), the primary ``??1``
        real-destructor is the wrong rebuilt pairing.

        Returns the primary first, then only those deleting-destructor COMDAT
        siblings. Overloads are deliberately NOT included here: picking the
        best-scoring overload would mask a genuinely poor match against a
        like-named sibling. Overload disambiguation is handled up front by the
        signature-aware source-to-map matching instead.
        """
        seen: set[int] = set()
        ordered: list[int] = []
        primary = self.rebuilt_address(function_name, original_addr)
        if primary is not None:
            seen.add(primary)
            ordered.append(primary)

        base = canonical_function_name(function_name)
        if "::" not in base:
            return ordered
        class_name, method_name = base.rsplit("::", 1)
        if not method_name.startswith("~"):
            return ordered

        class_leaf = class_name.rsplit("::", 1)[-1]
        variant_prefixes = (f"??_G{class_leaf}@@", f"??_E{class_leaf}@@")
        for entries in self.map_entries().values():
            for entry in entries:
                if entry.va in seen:
                    continue
                if any(entry.symbol.startswith(prefix) for prefix in variant_prefixes):
                    seen.add(entry.va)
                    ordered.append(entry.va)
        return ordered

    def _best_candidate(
        self,
        function_name: str,
        original_addr: int,
        original_mnemonics: list[str],
        rebuilt_image: PEImage,
    ) -> tuple[int, DisassemblyResult, float] | None:
        """Pick the rebuilt variant most similar to the supplied original.

        The first candidate (the name-based resolution) is the default; a
        sibling overload/deleting-destructor only wins if it beats the default
        by more than ``CANDIDATE_OVERRIDE_EPSILON``, so near-identical overloads
        are never flipped by mnemonic noise.
        """
        results: list[tuple[int, DisassemblyResult, float]] = []
        for candidate in self.candidate_rebuilt_addresses(function_name, original_addr):
            rebuilt = disassemble_function(
                rebuilt_image,
                candidate,
                self.rebuilt_function_starts(candidate),
                self.max_bytes,
                self.padding_mnemonics,
            )
            if not rebuilt.instructions:
                continue
            similarity = mnemonic_similarity(
                instruction_mnemonics(rebuilt.instructions),
                original_mnemonics,
            )
            results.append((candidate, rebuilt, similarity))

        if not results:
            return None
        primary = results[0]
        best = max(results, key=lambda result: result[2])
        if best is primary or best[2] > primary[2] + CANDIDATE_OVERRIDE_EPSILON:
            return best
        return primary

    def rebuilt_function_starts(self, rebuilt_addr: int) -> list[int]:
        starts = set(function_starts_from_map(self.map_entries()))
        starts.add(rebuilt_addr)
        return sorted(starts)

    def compare(
        self,
        function_name: str,
        disassembled_code_path: str,
        build: bool = True,
    ) -> FunctionComparison:
        maybe_build(self.target, build)

        original_addr = parse_original_address(disassembled_code_path)
        if original_addr is None:
            raise FunctionCompareError("could not determine original function address")

        if self.rebuilt_address(function_name, original_addr) is None:
            raise FunctionCompareError("function not found in linker map")

        for path, label in (
            (self.target.original_exe, "original executable"),
            (self.target.rebuilt_exe, "rebuilt executable"),
            (self.target.map_path, "linker map"),
        ):
            if not os.path.exists(path):
                raise FunctionCompareError(f"missing {label}: {path}")

        original_image = self.pe_image(self.target.original_exe)
        rebuilt_image = self.pe_image(self.target.rebuilt_exe)

        original = disassemble_exported_function(
            original_image,
            disassembled_code_path,
            original_addr,
            self.max_bytes,
            self.padding_mnemonics,
        )
        if not original.instructions:
            raise FunctionCompareError("could not disassemble original bytes")

        best = self._best_candidate(
            function_name,
            original_addr,
            instruction_mnemonics(original.instructions),
            rebuilt_image,
        )
        if best is None:
            raise FunctionCompareError("function found but could not disassemble rebuilt bytes")
        rebuilt_addr, rebuilt, similarity = best

        return FunctionComparison(
            function_name=function_name,
            original_addr=original_addr,
            rebuilt_addr=rebuilt_addr,
            similarity=similarity,
            rebuilt=rebuilt,
            original=original,
        )

    def compare_combined(
        self,
        function_name: str,
        disassembled_code_paths: list[str],
        build: bool = True,
    ) -> FunctionComparison:
        """Compare one rebuilt function against several original pieces at once.

        MSVC SEH functions are exported by Ghidra as multiple contiguous chunks
        (a short FS-frame prologue followed by the body), and the source carries
        one ``/* Function start: */`` annotation per chunk. The rebuilt binary,
        however, contains a single function. Comparing the whole rebuilt function
        against each chunk in isolation makes the prologue-only chunk look like a
        spurious ~5% match and understates the body chunk. Concatenating the
        original chunks (in address order) and comparing once yields the true
        similarity for the function as a whole.
        """
        maybe_build(self.target, build)

        addr_paths: list[tuple[int, str]] = []
        for path in disassembled_code_paths:
            addr = parse_original_address(path)
            if addr is not None:
                addr_paths.append((addr, path))
        if not addr_paths:
            raise FunctionCompareError("could not determine original function address")
        addr_paths.sort(key=lambda item: item[0])
        original_addr = addr_paths[0][0]

        if self.rebuilt_address(function_name, original_addr) is None:
            raise FunctionCompareError("function not found in linker map")

        for path, label in (
            (self.target.original_exe, "original executable"),
            (self.target.rebuilt_exe, "rebuilt executable"),
            (self.target.map_path, "linker map"),
        ):
            if not os.path.exists(path):
                raise FunctionCompareError(f"missing {label}: {path}")

        original_image = self.pe_image(self.target.original_exe)
        rebuilt_image = self.pe_image(self.target.rebuilt_exe)

        original_instructions: list[Instruction] = []
        seen: set[int] = set()
        for addr, path in addr_paths:
            piece = disassemble_exported_function(
                original_image,
                path,
                addr,
                self.max_bytes,
                self.padding_mnemonics,
            )
            for instr in piece.instructions:
                if instr.address in seen:
                    continue
                seen.add(instr.address)
                original_instructions.append(instr)
        if not original_instructions:
            raise FunctionCompareError("could not disassemble original bytes")

        best = self._best_candidate(
            function_name,
            original_addr,
            instruction_mnemonics(original_instructions),
            rebuilt_image,
        )
        if best is None:
            raise FunctionCompareError("function found but could not disassemble rebuilt bytes")
        rebuilt_addr, rebuilt, similarity = best

        return FunctionComparison(
            function_name=function_name,
            original_addr=original_addr,
            rebuilt_addr=rebuilt_addr,
            similarity=similarity,
            rebuilt=rebuilt,
            original=DisassemblyResult(original_instructions, []),
        )

    def _disasm_path(self, address: int) -> str | None:
        if not self.target.code_dir:
            return None
        candidates = (
            os.path.join(self.target.code_dir, f"FUN_{address:08X}.disassembled.txt"),
            os.path.join(self.target.code_dir, f"FUN_{address:06X}.disassembled.txt"),
            os.path.join(self.target.code_dir, f"FUN_{address:X}.disassembled.txt"),
        )
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def sibling_chunk_paths(self, function_name: str, disassembled_code_path: str) -> list[str] | None:
        """Disasm paths for all chunks of an SEH-split function, or None.

        If ``function_name`` is annotated in the source with several
        ``/* Function start: */`` addresses (the FS-frame prologue chunk plus the
        body chunk(s) that Ghidra exports separately) and the supplied path is one
        of them, return every chunk's disasm path in address order so the caller
        can compare the whole rebuilt function against the combined original.
        Returns None for ordinary single-chunk functions.
        """
        addr = parse_original_address(disassembled_code_path)
        if addr is None:
            return None
        try:
            groups = self.source_groups()
        except (ConfigError, FileNotFoundError, RuntimeError):
            return None
        wanted = canonical_function_name(function_name)
        for group in groups:
            if (
                canonical_function_name(group.name) == wanted
                and addr in group.original_addrs
                and len(group.original_addrs) > 1
            ):
                paths: list[str] = []
                for chunk_addr in sorted(group.original_addrs):
                    path = self._disasm_path(chunk_addr)
                    if path is None:
                        return None
                    paths.append(path)
                return paths
        return None


def format_side_by_side(comparison: FunctionComparison) -> str:
    return side_by_side(
        render_instructions(comparison.rebuilt.instructions),
        render_instructions(comparison.original.instructions),
    )


def format_excluded(comparison: FunctionComparison) -> str:
    return render_instructions(comparison.rebuilt.excluded)


def format_comparison(comparison: FunctionComparison) -> str:
    lines = [
        f"Comparison for function '{comparison.function_name}':",
        format_side_by_side(comparison),
        f"\nSimilarity: {comparison.similarity:.2f}%",
    ]
    excluded = format_excluded(comparison)
    if excluded.strip():
        lines.extend([
            "",
            "Detected SEH code (excluded from comparison):",
            excluded,
        ])
    return "\n".join(lines)
