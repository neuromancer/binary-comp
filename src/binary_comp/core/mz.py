"""Validated helpers for 16-bit DOS MZ executables.

The parser treats an executable as data: it validates the DOS header, exposes
the relocation table and load module, and preserves any bytes after the size
declared by the MZ page fields.  The encoder is intentionally small and emits a
canonical paragraph-aligned header suitable for reconstructed load modules.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


MZ_HEADER_SIZE = 0x1C
MZ_RELOCATION_SIZE = 4


class MzFormatError(RuntimeError):
    """Raised when bytes do not form a self-consistent DOS MZ image."""


@dataclass(frozen=True)
class MzRelocation:
    offset: int
    segment: int

    @property
    def linear_offset(self) -> int:
        return self.segment * 16 + self.offset


@dataclass(frozen=True)
class MzHeader:
    magic: bytes
    bytes_in_last_page: int
    pages: int
    relocation_count: int
    header_paragraphs: int
    minimum_allocation: int
    maximum_allocation: int
    ss: int
    sp: int
    checksum: int
    ip: int
    cs: int
    relocation_offset: int
    overlay_number: int

    @property
    def declared_size(self) -> int:
        if self.pages == 0:
            return 0
        if self.bytes_in_last_page == 0:
            return self.pages * 512
        return (self.pages - 1) * 512 + self.bytes_in_last_page

    @property
    def header_size(self) -> int:
        return self.header_paragraphs * 16

    @property
    def load_module_size(self) -> int:
        return self.declared_size - self.header_size

    @property
    def entry_image_offset(self) -> int:
        return self.cs * 16 + self.ip

    @property
    def entry_file_offset(self) -> int:
        return self.header_size + self.entry_image_offset


@dataclass(frozen=True)
class MzImage:
    header: MzHeader
    relocations: tuple[MzRelocation, ...]
    load_module: bytes
    trailing_data: bytes


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("alignment must be a positive power of two")
    return (value + alignment - 1) & ~(alignment - 1)


def parse_mz(data: bytes) -> MzImage:
    """Parse and validate a complete DOS MZ file."""

    if len(data) < MZ_HEADER_SIZE:
        raise MzFormatError("file too small to contain an MZ header")
    words = struct.unpack_from("<14H", data)
    magic_word = words[0]
    if magic_word not in (0x5A4D, 0x4D5A):
        raise MzFormatError("not a DOS MZ executable")

    magic = data[:2]
    header = MzHeader(
        magic=magic,
        bytes_in_last_page=words[1],
        pages=words[2],
        relocation_count=words[3],
        header_paragraphs=words[4],
        minimum_allocation=words[5],
        maximum_allocation=words[6],
        ss=words[7],
        sp=words[8],
        checksum=words[9],
        ip=words[10],
        cs=words[11],
        relocation_offset=words[12],
        overlay_number=words[13],
    )

    if header.pages == 0:
        raise MzFormatError("MZ page count is zero")
    if header.bytes_in_last_page >= 512:
        raise MzFormatError("MZ last-page byte count must be below 512")
    if header.header_size < MZ_HEADER_SIZE:
        raise MzFormatError("MZ header is shorter than its fixed fields")
    if header.header_size > header.declared_size:
        raise MzFormatError("MZ header extends beyond the declared file size")
    if header.declared_size > len(data):
        raise MzFormatError(
            f"MZ declares {header.declared_size} bytes but file has {len(data)}"
        )

    relocation_end = (
        header.relocation_offset
        + header.relocation_count * MZ_RELOCATION_SIZE
    )
    if header.relocation_offset < MZ_HEADER_SIZE and header.relocation_count:
        raise MzFormatError("MZ relocation table overlaps fixed header fields")
    if relocation_end > header.header_size:
        raise MzFormatError("MZ relocation table extends beyond the header")

    relocations = tuple(
        MzRelocation(*struct.unpack_from(
            "<HH", data, header.relocation_offset + index * MZ_RELOCATION_SIZE
        ))
        for index in range(header.relocation_count)
    )
    return MzImage(
        header=header,
        relocations=relocations,
        load_module=data[header.header_size:header.declared_size],
        trailing_data=data[header.declared_size:],
    )


def encode_mz(
    load_module: bytes,
    relocations: tuple[MzRelocation, ...] | list[MzRelocation] = (),
    *,
    minimum_allocation: int = 0,
    maximum_allocation: int = 0xFFFF,
    ss: int = 0,
    sp: int = 0,
    ip: int = 0,
    cs: int = 0,
    checksum: int = 0,
    overlay_number: int = 0,
    header_alignment: int = 16,
) -> bytes:
    """Encode a canonical MZ header, relocation table, and load module."""

    relocation_items = tuple(relocations)
    if len(relocation_items) > 0xFFFF:
        raise ValueError("MZ relocation count exceeds 65535")
    for label, value in (
        ("minimum_allocation", minimum_allocation),
        ("maximum_allocation", maximum_allocation),
        ("ss", ss),
        ("sp", sp),
        ("ip", ip),
        ("cs", cs),
        ("checksum", checksum),
        ("overlay_number", overlay_number),
    ):
        if not 0 <= value <= 0xFFFF:
            raise ValueError(f"{label} must fit in a word")

    relocation_offset = MZ_HEADER_SIZE
    unaligned_header_size = (
        relocation_offset + len(relocation_items) * MZ_RELOCATION_SIZE
    )
    header_size = _align_up(unaligned_header_size, header_alignment)
    if header_size % 16:
        raise ValueError("MZ header alignment must preserve paragraph alignment")
    header_paragraphs = header_size // 16
    if header_paragraphs > 0xFFFF:
        raise ValueError("MZ header is too large")

    total_size = header_size + len(load_module)
    pages = (total_size + 511) // 512
    if pages > 0xFFFF:
        raise ValueError("MZ file exceeds the 16-bit page-count limit")
    bytes_in_last_page = total_size % 512

    result = bytearray(header_size)
    struct.pack_into(
        "<14H",
        result,
        0,
        0x5A4D,
        bytes_in_last_page,
        pages,
        len(relocation_items),
        header_paragraphs,
        minimum_allocation,
        maximum_allocation,
        ss,
        sp,
        checksum,
        ip,
        cs,
        relocation_offset,
        overlay_number,
    )
    for index, relocation in enumerate(relocation_items):
        if not 0 <= relocation.offset <= 0xFFFF or not 0 <= relocation.segment <= 0xFFFF:
            raise ValueError("MZ relocation fields must fit in words")
        struct.pack_into(
            "<HH",
            result,
            relocation_offset + index * MZ_RELOCATION_SIZE,
            relocation.offset,
            relocation.segment,
        )
    result.extend(load_module)
    return bytes(result)


def format_mz(image: MzImage) -> str:
    header = image.header
    lines = [
        "DOS MZ image",
        f"  declared size:    {header.declared_size} (0x{header.declared_size:X})",
        f"  header size:      {header.header_size} (0x{header.header_size:X})",
        f"  load module:      {len(image.load_module)} bytes",
        f"  relocations:      {len(image.relocations)} @ 0x{header.relocation_offset:X}",
        f"  entry CS:IP:      {header.cs:04X}:{header.ip:04X}",
        f"  initial SS:SP:    {header.ss:04X}:{header.sp:04X}",
        f"  allocation:       min=0x{header.minimum_allocation:04X} "
        f"max=0x{header.maximum_allocation:04X} paragraphs",
    ]
    if image.trailing_data:
        lines.append(f"  trailing data:    {len(image.trailing_data)} bytes")
    return "\n".join(lines)
