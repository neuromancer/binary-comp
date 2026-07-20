"""Turbo Pascal / Borland Pascal compiled-unit (.TPU) comparison helpers.

This is the Pascal analog of the OMF helper. It reads Turbo Pascal 5.0
(``TPU5``), 5.5 (``TPU6``), and 6.0 (``TPU9``) units, extracts the emitted
CODE section together with its relocation fixups, and masks the relocated
operands before comparing against a raw original byte window. It is meant for
16-bit DOS reconstruction projects where the rebuilt artifact is a compiled
unit and the reference is a linked executable or an overlay code image.

The Turbo Pascal linker fills fixup operands (offsets, segments, and far
pointers) at link time, so those bytes are zero in the ``.TPU``. Masking them
lets an unlinked unit be compared against the final linked bytes, exactly the
way FIXUPP masking works for OMF objects in :mod:`binary_comp.analyzers.omf`.

TPU5 file layout (each section is padded up to a 16-byte paragraph):

    symbol section   [0, sym_size)          contains the header and code-block table
    code section     [.., code_size)        emitted machine code, blocks concatenated
    code relocations [.., reloc_size)       fixups for the code section
    const section    [.., const_size)       initialized data

TPU6 and TPU9 file layout:

    symbol section   [0, sym_size)          contains the header and code-block table
    code section     [.., code_size)        emitted machine code, blocks concatenated
    const section    [.., const_size)       initialized data
    code relocations [.., reloc_size)        fixups for the code section
    const relocations[.., vmt_size)          fixups for the const section

The header, code-block record, and relocation record layouts are documented in
the community "Inside Turbo Pascal Units" notes and the INTRFC63 TPU dumper.
The field positions and section orders are additionally checked against units
emitted by the corresponding original command-line compilers.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from binary_comp.analyzers.function_compare import (
    DisassemblyResult,
    FunctionComparison,
    instruction_mnemonics,
    mnemonic_similarity,
)
from binary_comp.analyzers.report import SimilarityReport, SimilarityReportOptions, SimilarityReportRow
from binary_comp.config import ProjectTarget
from binary_comp.core.disasm import Instruction, disassemble_raw_16


TPU5_SIGNATURE = b"TPU5"
TPU6_SIGNATURE = b"TPU6"
TPU9_SIGNATURE = b"TPU9"

# Header field byte offsets (all 16-bit words). TP5 stores code relocations
# before typed constants; TP6 moves constants ahead of both relocation tables.
_TPU5_OFS_CODE_BLOCKS = 0x0C
_TPU5_OFS_CONST_BLOCKS = 0x0E
_TPU5_OFS_SIZES = 0x18  # sym_size, code_size, reloc_size, const_size
_TPU5_OFS_FLAGS = 0x24
_TPU5_HEADER_MIN = 0x26

# TP5.5 introduces the section ordering later retained by TP6. Its header is
# two bytes shorter than TPU9: the table offsets match TPU9, while the size
# tuple and flags word are each shifted back by one word.
_TPU6_OFS_CODE_BLOCKS = 0x0E
_TPU6_OFS_CONST_BLOCKS = 0x10
_TPU6_OFS_SIZES = 0x1A  # sym_size, code_size, const_size, reloc_size, vmt_size
_TPU6_OFS_FLAGS = 0x28
_TPU6_HEADER_MIN = 0x2A

_TPU9_OFS_CODE_BLOCKS = 0x0E
_TPU9_OFS_CONST_BLOCKS = 0x10
_TPU9_OFS_SIZES = 0x1C  # sym_size, code_size, const_size, reloc_size, vmt_size
_TPU9_OFS_FLAGS = 0x2A
_TPU9_HEADER_MIN = 0x2C

# A relocation record's ``rtype`` byte encodes how the target is referenced in
# ``(rtype >> 4) & 3`` and what it targets in ``rtype >> 6``. The reference kind
# determines how many bytes the linker patches, i.e. how many to mask.
REF_RELATIVE = 0  # self-relative 16-bit displacement (near call/jmp)
REF_OFFSET = 1    # 16-bit offset
REF_SEGMENT = 2   # 16-bit segment
REF_POINTER = 3   # 32-bit far pointer (offset:segment)
_REF_LENGTH = {REF_RELATIVE: 2, REF_OFFSET: 2, REF_SEGMENT: 2, REF_POINTER: 4}
_REF_NAME = {REF_RELATIVE: "relative", REF_OFFSET: "offset", REF_SEGMENT: "segment", REF_POINTER: "pointer"}

_RELOC_RECORD_SIZE = 8
_BLOCK_RECORD_SIZE = 8
_COPROC_MARKER = 0xFF  # unit_num == rtype == 0xFF marks an 8087 coprocessor fixup

# TP6 symbol records begin [kind][name_len][name], with kind 0x53 for both
# procedures and functions. TP5 stores [name_len][name][kind], using 0x54 for a
# procedure and 0x55 for a function. In both formats a word at this offset past
# the name is a code-emission-order key (a pointer the compiler assigns in the
# order routine bodies are laid out). Sorting by that key reproduces the order
# of the concatenated code blocks even when a routine was forward-declared.
_TPU9_SYM_KIND_PROC = 0x53
_TPU5_SYM_KINDS_CODE = frozenset((0x54, 0x55))
_SYM_ORDER_KEY_OFFSET = 6
_SYM_NAME_MAX = 63  # Turbo Pascal identifiers are <= 63 chars


class TpuCompareError(RuntimeError):
    pass


@dataclass(frozen=True)
class TpuHeader:
    signature: bytes
    ofs_code_blocks: int
    ofs_const_blocks: int
    sym_size: int
    code_size: int
    const_size: int
    reloc_size: int
    vmt_size: int
    flags: int
    # Derived paragraph-aligned section offsets.
    off_code: int
    off_const: int
    off_code_reloc: int
    off_const_reloc: int
    total_size: int

    @property
    def has_overlays(self) -> bool:
        # Bit 1 of the unit flags word is the {$O+} overlay-allowed flag.
        return bool(self.flags & 0x0002)


@dataclass(frozen=True)
class TpuCodeBlock:
    index: int          # ordinal position in the code-block table
    code_offset: int    # start of this block within the concatenated code section
    size: int
    reloc_bytes: int    # bytes of relocation records that belong to this block
    owner: int          # symbol reference (0xFFFF when absent)


@dataclass(frozen=True)
class TpuFixup:
    offset: int         # absolute offset within the code section
    length: int         # bytes the linker patches here (to be masked)
    ref_type: int
    target_type: int
    unit_num: int
    rblock: int
    roffset: int


@dataclass(frozen=True)
class TpuCodeSymbol:
    name: str           # procedure/function name, as stored (Turbo Pascal upper-cases it)
    order_key: int      # code-emission-order key (monotonic with code-block order)
    table_offset: int   # byte offset of the record within the symbol section


@dataclass(frozen=True)
class TpuObject:
    path: str
    header: TpuHeader
    code: bytes
    blocks: tuple[TpuCodeBlock, ...]
    fixups: tuple[TpuFixup, ...]
    coproc_fixups: int  # count of skipped 8087 fixups, surfaced for transparency
    code_symbols: tuple[TpuCodeSymbol, ...] = ()  # procedures, in code-block order


@dataclass(frozen=True)
class TpuComparison:
    name: str
    original_path: str
    original_offset: int
    tpu_path: str
    code_offset: int
    block_index: int | None
    original: bytes
    rebuilt: bytes
    mask: bytes
    fixups: tuple[TpuFixup, ...]

    @property
    def compared_size(self) -> int:
        return len(self.rebuilt)

    @property
    def masked_count(self) -> int:
        return sum(1 for value in self.mask if value == 0)

    @property
    def mismatches(self) -> tuple[int, ...]:
        return tuple(
            index
            for index, (left, right, mask) in enumerate(zip(self.original, self.rebuilt, self.mask))
            if mask and left != right
        )

    @property
    def matches(self) -> bool:
        return not self.mismatches


@dataclass(frozen=True)
class TpuCompareSpec:
    name: str
    function_name: str
    original_path: str
    original_offset: int | None
    tpu_path: str
    size: int | None = None
    code_offset: int = 0
    block_offset: int = 0
    block_index: int | None = None
    locate: bool = False
    source_path: str | None = None
    target: str | None = None
    compiler_flags: str | None = None


def _roundup_paragraph(value: int) -> int:
    return (value + 15) & ~15


def parse_tpu_header(data: bytes) -> TpuHeader:
    if len(data) < 4:
        raise TpuCompareError("file too small to be a TPU unit")
    signature = data[:4]
    if signature == TPU5_SIGNATURE:
        if len(data) < _TPU5_HEADER_MIN:
            raise TpuCompareError("file too small to contain a TPU5 header")
        ofs_code_blocks, ofs_const_blocks = struct.unpack_from(
            "<2H", data, _TPU5_OFS_CODE_BLOCKS
        )
        sym_size, code_size, reloc_size, const_size = struct.unpack_from(
            "<4H", data, _TPU5_OFS_SIZES
        )
        vmt_size = 0
        flags = struct.unpack_from("<H", data, _TPU5_OFS_FLAGS)[0]

        off_code = _roundup_paragraph(sym_size)
        off_code_reloc = off_code + _roundup_paragraph(code_size)
        off_const = off_code_reloc + _roundup_paragraph(reloc_size)
        off_const_reloc = off_const + _roundup_paragraph(const_size)
        total_size = off_const_reloc
    elif signature in (TPU6_SIGNATURE, TPU9_SIGNATURE):
        if signature == TPU6_SIGNATURE:
            ofs_code_blocks_offset = _TPU6_OFS_CODE_BLOCKS
            sizes_offset = _TPU6_OFS_SIZES
            flags_offset = _TPU6_OFS_FLAGS
            header_min = _TPU6_HEADER_MIN
        else:
            ofs_code_blocks_offset = _TPU9_OFS_CODE_BLOCKS
            sizes_offset = _TPU9_OFS_SIZES
            flags_offset = _TPU9_OFS_FLAGS
            header_min = _TPU9_HEADER_MIN
        if len(data) < header_min:
            raise TpuCompareError(
                f"file too small to contain a {signature.decode('ascii')} header"
            )
        ofs_code_blocks, ofs_const_blocks = struct.unpack_from(
            "<2H", data, ofs_code_blocks_offset
        )
        sym_size, code_size, const_size, reloc_size, vmt_size = struct.unpack_from(
            "<5H", data, sizes_offset
        )
        flags = struct.unpack_from("<H", data, flags_offset)[0]

        off_code = _roundup_paragraph(sym_size)
        off_const = off_code + _roundup_paragraph(code_size)
        off_code_reloc = off_const + _roundup_paragraph(const_size)
        off_const_reloc = off_code_reloc + _roundup_paragraph(reloc_size)
        total_size = off_const_reloc + _roundup_paragraph(vmt_size)
    else:
        raise TpuCompareError(
            f"unsupported Turbo Pascal unit signature {signature!r}; "
            f"expected {TPU5_SIGNATURE!r}, {TPU6_SIGNATURE!r}, or {TPU9_SIGNATURE!r}"
        )
    return TpuHeader(
        signature=signature,
        ofs_code_blocks=ofs_code_blocks,
        ofs_const_blocks=ofs_const_blocks,
        sym_size=sym_size,
        code_size=code_size,
        const_size=const_size,
        reloc_size=reloc_size,
        vmt_size=vmt_size,
        flags=flags,
        off_code=off_code,
        off_const=off_const,
        off_code_reloc=off_code_reloc,
        off_const_reloc=off_const_reloc,
        total_size=total_size,
    )


def _parse_code_blocks(data: bytes, header: TpuHeader) -> tuple[TpuCodeBlock, ...]:
    base = header.ofs_code_blocks
    limit = header.ofs_const_blocks
    if base > limit or limit > len(data):
        raise TpuCompareError("code-block table bounds outside file")
    blocks: list[TpuCodeBlock] = []
    cursor = base
    running = 0
    index = 0
    while cursor + _BLOCK_RECORD_SIZE <= limit:
        _w1, size, reloc_bytes, owner = struct.unpack_from("<4H", data, cursor)
        blocks.append(TpuCodeBlock(
            index=index,
            code_offset=running,
            size=size,
            reloc_bytes=reloc_bytes,
            owner=owner,
        ))
        running += size
        cursor += _BLOCK_RECORD_SIZE
        index += 1
    if running != header.code_size:
        raise TpuCompareError(
            f"code-block sizes sum to {running} but header code_size is {header.code_size}"
        )
    return tuple(blocks)


def _parse_fixups(
    data: bytes,
    header: TpuHeader,
    blocks: tuple[TpuCodeBlock, ...],
) -> tuple[tuple[TpuFixup, ...], int]:
    reloc = data[header.off_code_reloc:header.off_code_reloc + header.reloc_size]
    fixups: list[TpuFixup] = []
    coproc = 0
    reloc_base = 0
    for block in blocks:
        block_end = reloc_base + block.reloc_bytes
        if block_end > len(reloc):
            raise TpuCompareError("relocation records extend past the reloc section")
        cursor = reloc_base
        while cursor + _RELOC_RECORD_SIZE <= block_end:
            unit_num, rtype, rblock, roffset, offset = struct.unpack_from("<BBHHH", reloc, cursor)
            cursor += _RELOC_RECORD_SIZE
            if unit_num == _COPROC_MARKER and rtype == _COPROC_MARKER:
                # 8087 emulation fixups patch a prefix/FWAIT byte and only appear
                # with coprocessor emulation. They are rare in integer code; count
                # them so callers can see they were not masked.
                coproc += 1
                continue
            ref_type = (rtype >> 4) & 0x3
            target_type = (rtype >> 6) & 0x3
            fixups.append(TpuFixup(
                offset=block.code_offset + offset,
                length=_REF_LENGTH[ref_type],
                ref_type=ref_type,
                target_type=target_type,
                unit_num=unit_num,
                rblock=rblock,
                roffset=roffset,
            ))
        reloc_base = block_end
    return tuple(fixups), coproc


def _is_identifier_bytes(raw: bytes) -> bool:
    """True if ``raw`` is a plausible Pascal identifier (A-Z, 0-9, _; not digit-first)."""
    if not raw:
        return False
    first = raw[0]
    if not (65 <= first <= 90 or first == 0x5F):  # A-Z or _
        return False
    return all(65 <= b <= 90 or 48 <= b <= 57 or b == 0x5F for b in raw)


def _parse_modern_code_symbols(data: bytes, header: TpuHeader) -> list[TpuCodeSymbol]:
    limit = min(header.ofs_code_blocks, header.sym_size, len(data))
    found: list[TpuCodeSymbol] = []
    seen: set[str] = set()
    cursor = (
        _TPU6_HEADER_MIN
        if header.signature == TPU6_SIGNATURE
        else _TPU9_HEADER_MIN
    )
    while cursor + 2 < limit:
        if data[cursor] != _TPU9_SYM_KIND_PROC:
            cursor += 1
            continue
        name_len = data[cursor + 1]
        name_start = cursor + 2
        name_end = name_start + name_len
        attr_end = name_end + _SYM_ORDER_KEY_OFFSET + 2
        if not (1 <= name_len <= _SYM_NAME_MAX) or attr_end > limit:
            cursor += 1
            continue
        raw = data[name_start:name_end]
        if not _is_identifier_bytes(raw):
            cursor += 1
            continue
        name = raw.decode("ascii")
        order_key = struct.unpack_from("<H", data, name_end + _SYM_ORDER_KEY_OFFSET)[0]
        if name not in seen:
            seen.add(name)
            found.append(TpuCodeSymbol(name=name, order_key=order_key, table_offset=cursor))
        cursor = name_end  # skip the name; attributes are re-scanned harmlessly
    return found


def _parse_tpu5_code_symbols(data: bytes, header: TpuHeader) -> list[TpuCodeSymbol]:
    limit = min(header.ofs_code_blocks, header.sym_size, len(data))
    found: list[TpuCodeSymbol] = []
    seen: set[str] = set()
    cursor = _TPU5_HEADER_MIN
    while cursor + 2 < limit:
        name_len = data[cursor]
        name_start = cursor + 1
        name_end = name_start + name_len
        attr_end = name_end + _SYM_ORDER_KEY_OFFSET + 2
        if not (1 <= name_len <= _SYM_NAME_MAX) or attr_end > limit:
            cursor += 1
            continue
        raw = data[name_start:name_end]
        if (
            not _is_identifier_bytes(raw)
            or data[name_end] not in _TPU5_SYM_KINDS_CODE
        ):
            cursor += 1
            continue
        name = raw.decode("ascii")
        order_key = struct.unpack_from("<H", data, name_end + _SYM_ORDER_KEY_OFFSET)[0]
        if name not in seen:
            seen.add(name)
            found.append(TpuCodeSymbol(name=name, order_key=order_key, table_offset=cursor))
        cursor = name_end + 1
    return found


def parse_code_symbols(data: bytes, header: TpuHeader) -> tuple[TpuCodeSymbol, ...]:
    """Extract procedure/function symbols from the TPU symbol table, in code order.

    TPU5 and the later formats encode symbol kinds on opposite sides of the
    identifier. All carry a code-order key in the following attributes, so
    name-based block selection remains stable across forward declarations and
    private routines.
    """
    if header.signature == TPU5_SIGNATURE:
        found = _parse_tpu5_code_symbols(data, header)
    else:
        found = _parse_modern_code_symbols(data, header)
    found.sort(key=lambda s: s.order_key)
    return tuple(found)


def load_tpu_object(path: str | Path) -> TpuObject:
    data = Path(path).read_bytes()
    header = parse_tpu_header(data)
    # A standalone .TPU is exactly total_size bytes; units read out of a .TPL are
    # concatenated, so only require that this unit's sections fit in the file.
    if header.total_size > len(data):
        raise TpuCompareError(
            f"TPU sections require {header.total_size} bytes but file has {len(data)}"
        )
    code = data[header.off_code:header.off_code + header.code_size]
    blocks = _parse_code_blocks(data, header)
    fixups, coproc = _parse_fixups(data, header, blocks)
    code_symbols = parse_code_symbols(data, header)
    return TpuObject(
        path=str(path),
        header=header,
        code=code,
        blocks=blocks,
        fixups=fixups,
        coproc_fixups=coproc,
        code_symbols=code_symbols,
    )


def format_tpu_info(obj: TpuObject) -> str:
    """Render the section, code-block, symbol, and fixup inventory of a unit."""

    header = obj.header
    lines = [
        f"Turbo Pascal unit: {Path(obj.path).name}",
        f"  signature:       {header.signature.decode('ascii')}",
        f"  total size:      {header.total_size} bytes",
        f"  symbol section:  {header.sym_size} bytes",
        f"  code section:    {header.code_size} bytes @ 0x{header.off_code:X}",
        f"  const section:   {header.const_size} bytes @ 0x{header.off_const:X}",
        f"  code relocations:{header.reloc_size:9d} bytes @ 0x{header.off_code_reloc:X}",
        f"  const relocs:    {header.vmt_size} bytes @ 0x{header.off_const_reloc:X}",
        f"  overlay enabled: {'yes' if header.has_overlays else 'no'}",
        f"  code blocks:     {len(obj.blocks)}",
        f"  code fixups:     {len(obj.fixups)}",
        f"  code symbols:    {len(obj.code_symbols)}",
        "",
        "Block  CodeOfs  Size  RelocBytes  Symbol",
    ]
    for block in obj.blocks:
        symbol = (
            obj.code_symbols[block.index].name
            if block.index < len(obj.code_symbols)
            else ""
        )
        lines.append(
            f"{block.index:5d}  0x{block.code_offset:06X}  {block.size:4d}  "
            f"{block.reloc_bytes:10d}  {symbol}"
        )
    if obj.coproc_fixups:
        lines.extend(("", f"8087 fixups not masked: {obj.coproc_fixups}"))
    return "\n".join(lines)


def block_index_for_name(obj: TpuObject, function_name: str) -> int:
    """Resolve a procedure name to its code-block index (case-insensitive).

    Procedures parsed from the symbol table are in code-emission order, so the
    Nth procedure is the Nth code block. A trailing unit-initialization block (a
    code block with no procedure symbol) is tolerated. Raises with an actionable
    message when the name is absent or the symbol/block counts disagree — which
    usually means the unit failed to recompile (a stale or truncated .TPU).
    """
    symbols = obj.code_symbols
    n_syms, n_blocks = len(symbols), len(obj.blocks)
    # TP appends at most one initialization block (no owning procedure symbol).
    if not symbols or n_syms > n_blocks or n_blocks - n_syms > 1:
        raise TpuCompareError(
            f"cannot map names to code blocks: {n_syms} procedure symbol(s) but "
            f"{n_blocks} code block(s). The .TPU may be stale or truncated "
            f"(did the unit compile?). Use an explicit block index to override."
        )
    target = function_name.upper()
    for index, symbol in enumerate(symbols):
        if symbol.name.upper() == target:
            return index
    available = ", ".join(s.name for s in symbols)
    raise TpuCompareError(
        f"procedure {function_name!r} not found in {Path(obj.path).name}. "
        f"Check the name and that the unit compiled. Available: {available}"
    )


def select_code_window(
    obj: TpuObject,
    *,
    block_index: int | None = None,
    function_name: str | None = None,
    code_offset: int = 0,
    block_offset: int = 0,
    size: int | None = None,
) -> tuple[int, bytes]:
    """Return ``(start, bytes)`` for a window of the concatenated code section.

    The block is chosen by, in order of precedence: an explicit ``block_index``
    (a manual override); a ``function_name`` resolved against the TPU's symbol
    table (the robust default — see :func:`block_index_for_name`); or the
    ``code_offset``/``size`` free window. Selecting one code block yields exactly
    one routine.
    """
    # Resolve by name only when the unit actually carries a symbol table; a
    # symbol-less unit (or a synthetic test fixture) falls through to block_index
    # or the free window, preserving the pre-name-selection behaviour.
    if block_index is None and function_name is not None and obj.code_symbols:
        block_index = block_index_for_name(obj, function_name)
    if block_index is not None:
        if block_index < 0 or block_index >= len(obj.blocks):
            raise TpuCompareError(
                f"block index {block_index} out of range (0..{len(obj.blocks) - 1}). "
                f"If this unit was just changed, the .TPU may be stale or the "
                f"compile may have failed silently — check the build log."
            )
        block = obj.blocks[block_index]
        if block_offset < 0 or block_offset > block.size:
            raise TpuCompareError("block_offset outside selected CODE block")
        start = block.code_offset + block_offset
        window = obj.code[start:block.code_offset + block.size]
        if size is not None:
            if size < 0:
                raise TpuCompareError("size must be non-negative")
            window = window[:size]
        return start, window

    if block_offset:
        raise TpuCompareError("block_offset requires block or function selection")
    if code_offset < 0 or code_offset > len(obj.code):
        raise TpuCompareError("code_offset outside CODE section")
    window = obj.code[code_offset:]
    if size is not None:
        if size < 0:
            raise TpuCompareError("size must be non-negative")
        window = window[:size]
    return code_offset, window


def build_mask(size: int, fixups: tuple[TpuFixup, ...], window_start: int = 0) -> bytes:
    mask = bytearray([0xFF] * size)
    for fixup in fixups:
        start = fixup.offset - window_start
        end = start + fixup.length
        if end <= 0 or start >= size:
            continue
        for index in range(max(0, start), min(size, end)):
            mask[index] = 0
    return bytes(mask)


def _longest_fixed_run(mask: bytes) -> tuple[int, int]:
    """Return (start, length) of the longest run of non-fixup (0xFF) bytes."""
    best_start = best_len = 0
    cur_start = cur = 0
    for index, value in enumerate(mask):
        if value:
            if cur == 0:
                cur_start = index
            cur += 1
            if cur > best_len:
                best_len, best_start = cur, cur_start
        else:
            cur = 0
    return best_start, best_len


def locate_code_window(original_data: bytes, window: bytes, mask: bytes) -> list[int]:
    """Find every offset in ``original_data`` where ``window`` matches, ignoring
    the fixup (masked) positions.

    Used to place a rebuilt code block inside a code image whose exact offset is
    not known ahead of time — e.g. a routine inside a Turbo Pascal overlay
    (``.OVR``) image, where the linker has filled in the relocated operands. The
    block's own relocation fixups are masked, so the non-fixup opcode bytes are
    the search key; a whole routine's worth of them is normally unique.
    """
    if not window:
        return []
    anchor_start, anchor_len = _longest_fixed_run(mask)
    if anchor_len == 0:
        return []  # nothing but fixups — cannot anchor a search
    anchor = window[anchor_start:anchor_start + anchor_len]
    size = len(window)
    candidates: list[int] = []
    pos = original_data.find(anchor)
    while pos != -1:
        start = pos - anchor_start
        if 0 <= start and start + size <= len(original_data):
            if all(not mask[j] or original_data[start + j] == window[j] for j in range(size)):
                candidates.append(start)
        pos = original_data.find(anchor, pos + 1)
    return sorted(set(candidates))


def compare_tpu_to_original(
    *,
    original_path: str | Path,
    original_offset: int | None = None,
    tpu_path: str | Path,
    size: int | None = None,
    code_offset: int = 0,
    block_offset: int = 0,
    block_index: int | None = None,
    function_name: str | None = None,
    locate: bool = False,
    name: str = "tpu-function",
) -> TpuComparison:
    obj = load_tpu_object(tpu_path)
    start, rebuilt = select_code_window(
        obj,
        block_index=block_index,
        function_name=function_name,
        code_offset=code_offset,
        block_offset=block_offset,
        size=size,
    )
    original_data = Path(original_path).read_bytes()
    mask = build_mask(len(rebuilt), obj.fixups, window_start=start)
    if locate:
        found = locate_code_window(original_data, rebuilt, mask)
        if not found:
            raise TpuCompareError(
                "block not found in original image (reconstruction mismatch or wrong image)"
            )
        if len(found) > 1:
            raise TpuCompareError(
                "ambiguous: block matches at "
                + ", ".join(f"0x{f:x}" for f in found[:8])
                + (" ..." if len(found) > 8 else "")
            )
        original_offset = found[0]
    if original_offset is None:
        raise TpuCompareError("original_offset is required unless locate=True")
    if original_offset < 0 or original_offset + len(rebuilt) > len(original_data):
        raise TpuCompareError("original byte window outside file")
    original = original_data[original_offset:original_offset + len(rebuilt)]
    return TpuComparison(
        name=name,
        original_path=str(original_path),
        original_offset=original_offset,
        tpu_path=str(tpu_path),
        code_offset=start,
        block_index=block_index,
        original=original,
        rebuilt=rebuilt,
        mask=mask,
        fixups=obj.fixups,
    )


def compare_tpu_spec(spec: TpuCompareSpec) -> FunctionComparison:
    byte_comparison = compare_tpu_to_original(
        original_path=spec.original_path,
        original_offset=spec.original_offset,
        tpu_path=spec.tpu_path,
        size=spec.size,
        code_offset=spec.code_offset,
        block_offset=spec.block_offset,
        block_index=spec.block_index,
        function_name=spec.function_name,
        locate=spec.locate,
        name=spec.name,
    )
    original = DisassemblyResult(
        disassemble_raw_16(byte_comparison.original, byte_comparison.original_offset),
        [],
    )
    rebuilt = DisassemblyResult(
        disassemble_raw_16(byte_comparison.rebuilt, byte_comparison.code_offset),
        [],
    )
    if byte_comparison.matches:
        similarity = 100.0
    else:
        if not original.instructions:
            raise TpuCompareError("could not disassemble original bytes")
        if not rebuilt.instructions:
            raise TpuCompareError("could not disassemble rebuilt TPU bytes")
        similarity = mnemonic_similarity(
            instruction_mnemonics(rebuilt.instructions),
            instruction_mnemonics(original.instructions),
        )
    return FunctionComparison(
        function_name=spec.function_name,
        original_addr=byte_comparison.original_offset,
        rebuilt_addr=byte_comparison.code_offset,
        similarity=similarity,
        rebuilt=rebuilt,
        original=original,
    )


def parse_config_int(value: Any, label: str, *, required: bool = True) -> int | None:
    if value in (None, ""):
        if required:
            raise TpuCompareError(f"missing required configuration value: {label}")
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise TpuCompareError(f"{label} must be an integer or integer string")


def require_config_string(config: dict[str, Any], key: str, label: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value:
        raise TpuCompareError(f"missing required configuration value: {label}")
    return value


def optional_config_string(config: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = config.get(key)
        if value in (None, ""):
            continue
        if not isinstance(value, str):
            raise TpuCompareError(f"{key} must be a string")
        return value
    return None


def resolve_config_path(config_path: str | Path, path: str | None) -> str | None:
    if path is None:
        return None
    candidate = Path(path)
    if candidate.is_absolute():
        return str(candidate)
    return str(Path(config_path).resolve().parent / candidate)


def load_tpu_specs(
    config: dict[str, Any],
    config_path: str | Path,
    target_name: str | None = None,
) -> tuple[TpuCompareSpec, ...]:
    section = config.get("tpu_compare", {})
    if not isinstance(section, dict):
        raise TpuCompareError("tpu_compare must be an object")
    functions = section.get("functions", [])
    if not isinstance(functions, list):
        raise TpuCompareError("tpu_compare.functions must be a list")

    specs: list[TpuCompareSpec] = []
    for index, item in enumerate(functions):
        label = f"tpu_compare.functions[{index}]"
        if not isinstance(item, dict):
            raise TpuCompareError(f"{label} must be an object")
        item_target = optional_config_string(item, "target")
        if target_name is not None and item_target not in (None, target_name):
            continue
        name = require_config_string(item, "name", f"{label}.name")
        original = require_config_string(item, "original", f"{label}.original")
        tpu_path = optional_config_string(item, "tpu", "object")
        if tpu_path is None:
            raise TpuCompareError(f"missing required configuration value: {label}.tpu")
        function_name = optional_config_string(item, "function") or name
        locate = bool(item.get("locate"))
        specs.append(TpuCompareSpec(
            name=name,
            function_name=function_name,
            original_path=resolve_config_path(config_path, original) or "",
            original_offset=parse_config_int(
                item.get("original_offset"), f"{label}.original_offset", required=not locate
            ),
            tpu_path=resolve_config_path(config_path, tpu_path) or "",
            size=parse_config_int(item.get("size"), f"{label}.size", required=False),
            code_offset=parse_config_int(item.get("code_offset", 0), f"{label}.code_offset") or 0,
            block_offset=parse_config_int(item.get("block_offset", 0), f"{label}.block_offset") or 0,
            block_index=parse_config_int(item.get("block_index"), f"{label}.block_index", required=False),
            locate=locate,
            source_path=resolve_config_path(config_path, optional_config_string(item, "source")),
            target=item_target,
            compiler_flags=optional_config_string(item, "compiler_flags"),
        ))
    return tuple(specs)


def find_tpu_spec(
    config: dict[str, Any],
    config_path: str | Path,
    target_name: str,
    function_name: str,
) -> TpuCompareSpec:
    specs = load_tpu_specs(config, config_path, target_name)
    for spec in specs:
        if function_name in (spec.function_name, spec.name):
            return spec
    raise TpuCompareError(f"TPU comparison entry not found for function: {function_name}")


def compare_tpu_config_function(
    config: dict[str, Any],
    config_path: str | Path,
    target_name: str,
    function_name: str,
) -> FunctionComparison:
    return compare_tpu_spec(find_tpu_spec(config, config_path, target_name, function_name))


def tpu_source_file(spec: TpuCompareSpec) -> str:
    if spec.source_path:
        return Path(spec.source_path).name
    return Path(spec.tpu_path).name


def generate_tpu_similarity_report(
    config: dict[str, Any],
    config_path: str | Path,
    target: ProjectTarget,
    options: SimilarityReportOptions = SimilarityReportOptions(),
) -> SimilarityReport:
    from binary_comp.analyzers.function_compare import maybe_build

    maybe_build(target, options.build)
    rows: list[SimilarityReportRow] = []
    compared = 0
    similarity_sum = 0.0
    at_100 = 0
    above_90 = 0
    below_90 = 0
    errors = 0

    for spec in load_tpu_specs(config, config_path, target.name):
        source_file = tpu_source_file(spec)
        if (
            options.file_filter
            and options.file_filter not in source_file
            and options.file_filter not in spec.function_name
            and options.file_filter not in spec.name
        ):
            continue
        try:
            comparison = compare_tpu_spec(spec)
        except (FileNotFoundError, OSError, RuntimeError, ValueError, TpuCompareError):
            errors += 1
            rows.append(SimilarityReportRow(source_file, spec.function_name, spec.original_offset or 0, None, "NOT FOUND"))
            continue

        similarity = comparison.similarity
        compared += 1
        similarity_sum += similarity
        if similarity >= 99.99:
            at_100 += 1
        if similarity >= 90.0:
            above_90 += 1
        else:
            below_90 += 1
        # For located (overlay) matches original_offset is resolved by the compare.
        rows.append(SimilarityReportRow(
            source_file,
            spec.function_name,
            comparison.original_addr,
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
        missing_asm=0,
        asm_fallbacks=0,
    )


def format_tpu_comparison(comparison: TpuComparison, context: int = 8) -> str:
    if comparison.block_index is not None:
        window = f"block {comparison.block_index}"
    else:
        window = f"code+0x{comparison.code_offset:x}"
    lines = [
        f"TPU comparison for {comparison.name}",
        f"  original: {comparison.original_path}+0x{comparison.original_offset:x}",
        f"  unit:     {comparison.tpu_path} {window}",
        f"  size:     {comparison.compared_size} byte(s), masked fixup byte(s): {comparison.masked_count}",
    ]
    if comparison.matches:
        lines.append("  result:   MATCH")
        return "\n".join(lines)

    mismatches = comparison.mismatches
    lines.append(f"  result:   MISMATCH ({len(mismatches)} unmasked byte difference(s))")
    for index in mismatches[:context]:
        lines.append(
            f"    +0x{index:04x}: original={comparison.original[index]:02x} rebuilt={comparison.rebuilt[index]:02x}"
        )
    if len(mismatches) > context:
        lines.append(f"    ... {len(mismatches) - context} more")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Operand / constant value check
#
# The similarity report scores instruction MNEMONICS only, so two code blocks
# with the same shape but different immediates ("cmp ax, 0x0d" vs "cmp ax,
# 0x0f") both score 100%. This check compares the actual bytes -- masking only
# the relocation fixups, exactly as the byte-locate does -- and decodes every
# surviving difference back to the instruction it lands in, so a constant that
# was reconstructed with the wrong value is pointed at directly. It does not
# touch how similarity is computed; it is a separate, stricter view.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TpuValueDiff:
    offset: int
    rebuilt_text: str
    original_text: str


@dataclass(frozen=True)
class TpuValuesRow:
    source_file: str
    function_name: str
    original_offset: int
    status: str
    diffs: tuple[TpuValueDiff, ...]


@dataclass(frozen=True)
class TpuValuesReport:
    rows: tuple[TpuValuesRow, ...]
    compared: int
    byte_exact: int
    with_diffs: int
    not_located: int
    total_diffs: int


def _instruction_containing(instructions: list[Instruction], offset: int) -> Instruction | None:
    for instr in instructions:
        if instr.address <= offset < instr.address + max(instr.size, 1):
            return instr
    return None


def _decode_value_diffs(comparison: TpuComparison) -> tuple[TpuValueDiff, ...]:
    # Disassemble both windows from a zero base so an instruction's address is
    # its offset within the window, which is how ``mismatches`` are indexed.
    rebuilt = disassemble_raw_16(comparison.rebuilt, 0)
    original = disassemble_raw_16(comparison.original, 0)
    original_by_addr = {instr.address: instr for instr in original}
    diffs: list[TpuValueDiff] = []
    seen: set[int] = set()
    for offset in comparison.mismatches:
        instr = _instruction_containing(rebuilt, offset)
        if instr is None or instr.address in seen:
            continue
        seen.add(instr.address)
        match = original_by_addr.get(instr.address)
        original_text = match.raw if match is not None else "<instruction boundaries differ>"
        diffs.append(TpuValueDiff(instr.address, instr.raw, original_text))
    return tuple(diffs)


def generate_tpu_values_report(
    config: dict[str, Any],
    config_path: str | Path,
    target: ProjectTarget,
    options: SimilarityReportOptions = SimilarityReportOptions(),
) -> TpuValuesReport:
    from binary_comp.analyzers.function_compare import maybe_build

    maybe_build(target, options.build)
    rows: list[TpuValuesRow] = []
    compared = byte_exact = with_diffs = not_located = total_diffs = 0

    for spec in load_tpu_specs(config, config_path, target.name):
        source_file = tpu_source_file(spec)
        if (
            options.file_filter
            and options.file_filter not in source_file
            and options.file_filter not in spec.function_name
            and options.file_filter not in spec.name
        ):
            continue
        try:
            comparison = compare_tpu_to_original(
                original_path=spec.original_path,
                original_offset=spec.original_offset,
                tpu_path=spec.tpu_path,
                size=spec.size,
                code_offset=spec.code_offset,
                block_offset=spec.block_offset,
                block_index=spec.block_index,
                function_name=spec.function_name,
                locate=spec.locate,
                name=spec.name,
            )
        except (FileNotFoundError, OSError, RuntimeError, ValueError, TpuCompareError):
            not_located += 1
            rows.append(TpuValuesRow(source_file, spec.function_name, spec.original_offset or 0, "NOT LOCATED", ()))
            continue

        compared += 1
        if comparison.matches:
            byte_exact += 1
            rows.append(TpuValuesRow(source_file, spec.function_name, comparison.original_offset, "byte-exact", ()))
            continue

        diffs = _decode_value_diffs(comparison)
        with_diffs += 1
        total_diffs += len(diffs)
        status = f"{len(diffs)} value diff(s) in {len(comparison.mismatches)} byte(s)"
        rows.append(TpuValuesRow(source_file, spec.function_name, comparison.original_offset, status, diffs))

    return TpuValuesReport(
        rows=tuple(rows),
        compared=compared,
        byte_exact=byte_exact,
        with_diffs=with_diffs,
        not_located=not_located,
        total_diffs=total_diffs,
    )


_BOUNDARY_MARKER = "<instruction boundaries differ>"


def format_tpu_values_report(report: TpuValuesReport, *, show_exact: bool = False, max_diffs: int = 12) -> str:
    lines = ["", "--- Operand Value Check (constants; relocation fixups masked) ---"]
    current_file = None
    for row in report.rows:
        if not show_exact and row.status == "byte-exact":
            continue
        if row.source_file != current_file:
            lines.extend(["", f"=== {row.source_file} ==="])
            current_file = row.source_file
        # When most differences are instruction-boundary shifts the two windows no
        # longer line up: that is a structural divergence (already visible as a low
        # mnemonic score), not a handful of wrong constants. Flag it so the genuine
        # constant/operand mismatches stand out.
        boundary = sum(1 for diff in row.diffs if _BOUNDARY_MARKER in diff.original_text)
        note = "  [structural: windows misalign]" if row.diffs and boundary * 2 >= len(row.diffs) else ""
        lines.append(f"  {row.function_name:45s} 0x{row.original_offset:06X}  {row.status}{note}")
        for diff in row.diffs[:max_diffs]:
            lines.append(f"      +0x{diff.offset:04x}  rebuilt : {diff.rebuilt_text}")
            lines.append(f"               original: {diff.original_text}")
        if len(row.diffs) > max_diffs:
            lines.append(f"      ... {len(row.diffs) - max_diffs} more")

    lines.extend([
        "",
        "--- Summary ---",
        f"Compared (located): {report.compared}",
        f"  Byte-exact (constants match): {report.byte_exact}",
        f"  With value differences: {report.with_diffs}",
        f"  Not located: {report.not_located}",
    ])
    return "\n".join(lines)
