"""Static Microsoft EXEPACK inspection and decompression.

No DOS code is executed.  The decoder reads the EXEPACK metadata, reverses the
backward RLE stream, expands the compact relocation groups, and emits a
canonical MZ file containing the recovered load module.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from binary_comp.core.mz import MzImage, MzRelocation, encode_mz, parse_mz


EXEPACK_SIGNATURE = 0x4252
EXEPACK_ERROR_TEXT = b"Packed file is corrupt"


class ExepackError(RuntimeError):
    """Raised when an MZ file is not a supported, self-consistent EXEPACK image."""


@dataclass(frozen=True)
class ExepackHeader:
    file_offset: int
    real_ip: int
    real_cs: int
    memory_start: int
    exepack_size: int
    real_sp: int
    real_ss: int
    destination_paragraphs: int
    skip_length: int | None
    header_size: int

    @property
    def destination_size(self) -> int:
        return self.destination_paragraphs * 16

    @property
    def region_end(self) -> int:
        return self.file_offset + self.exepack_size


@dataclass(frozen=True)
class ExepackResult:
    packed_mz: MzImage
    header: ExepackHeader
    load_module: bytes
    relocations: tuple[MzRelocation, ...]
    executable: bytes


def parse_exepack_header(data: bytes, mz: MzImage | None = None) -> ExepackHeader:
    """Locate and validate the EXEPACK header selected by the MZ entry segment."""

    mz = mz or parse_mz(data)
    offset = mz.header.header_size + mz.header.cs * 16
    if offset + 16 > mz.header.declared_size:
        raise ExepackError("EXEPACK header lies outside the declared MZ image")

    (
        real_ip,
        real_cs,
        memory_start,
        exepack_size,
        real_sp,
        real_ss,
        destination_paragraphs,
        signature_or_skip,
    ) = struct.unpack_from("<8H", data, offset)

    if signature_or_skip == EXEPACK_SIGNATURE:
        skip_length = None
        header_size = 16
    else:
        if offset + 18 > mz.header.declared_size:
            raise ExepackError("truncated EXEPACK header")
        signature = struct.unpack_from("<H", data, offset + 16)[0]
        if signature != EXEPACK_SIGNATURE:
            raise ExepackError("MZ entry segment does not contain an EXEPACK header")
        skip_length = signature_or_skip
        header_size = 18

    if exepack_size < header_size:
        raise ExepackError("EXEPACK region is shorter than its header")
    if destination_paragraphs == 0:
        raise ExepackError("EXEPACK destination length is zero")
    if offset + exepack_size > mz.header.declared_size:
        raise ExepackError("EXEPACK region extends beyond the declared MZ image")

    return ExepackHeader(
        file_offset=offset,
        real_ip=real_ip,
        real_cs=real_cs,
        memory_start=memory_start,
        exepack_size=exepack_size,
        real_sp=real_sp,
        real_ss=real_ss,
        destination_paragraphs=destination_paragraphs,
        skip_length=skip_length,
        header_size=header_size,
    )


def decode_exepack_stream(packed: bytes, destination_size: int) -> bytes:
    """Expand EXEPACK's backward RLE stream into a load module."""

    if destination_size <= 0:
        raise ExepackError("EXEPACK destination size must be positive")
    source = packed[::-1]
    cursor = 0
    while cursor < len(source) and source[cursor] == 0xFF:
        cursor += 1

    output = bytearray()
    terminated = False
    while cursor < len(source):
        if cursor + 3 > len(source):
            raise ExepackError("truncated EXEPACK command")
        opcode = source[cursor]
        count = (source[cursor + 1] << 8) | source[cursor + 2]
        cursor += 3
        command = opcode & 0xFE

        if command == 0xB0:
            if cursor >= len(source):
                raise ExepackError("truncated EXEPACK fill command")
            value = source[cursor]
            cursor += 1
            if len(output) + count > destination_size:
                raise ExepackError("EXEPACK fill command exceeds destination")
            output.extend(bytes((value,)) * count)
        elif command == 0xB2:
            if cursor + count > len(source):
                raise ExepackError("truncated EXEPACK literal command")
            if len(output) + count > destination_size:
                raise ExepackError("EXEPACK literal command exceeds destination")
            output.extend(source[cursor:cursor + count])
            cursor += count
        else:
            raise ExepackError(f"unsupported EXEPACK command 0x{opcode:02X}")

        if opcode & 1:
            terminated = True
            break

    if not terminated:
        raise ExepackError("EXEPACK stream has no terminating command")

    remainder = source[cursor:]
    if len(output) + len(remainder) > destination_size:
        raise ExepackError("EXEPACK trailing data exceeds destination")
    output.extend(remainder)
    if len(output) != destination_size:
        raise ExepackError(
            f"EXEPACK produced {len(output)} bytes; expected {destination_size}"
        )
    output.reverse()
    return bytes(output)


def parse_exepack_relocations(
    data: bytes, header: ExepackHeader, destination_size: int
) -> tuple[MzRelocation, ...]:
    """Expand the 16 segment-bucket relocation groups stored after the stub."""

    error_offset = data.find(
        EXEPACK_ERROR_TEXT,
        header.file_offset + header.header_size,
        header.region_end,
    )
    if error_offset < 0:
        raise ExepackError("EXEPACK relocation marker was not found")
    cursor = error_offset + len(EXEPACK_ERROR_TEXT)
    relocations: list[MzRelocation] = []

    for bucket in range(16):
        if cursor + 2 > header.region_end:
            raise ExepackError("truncated EXEPACK relocation group")
        count = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        group_end = cursor + count * 2
        if group_end > header.region_end:
            raise ExepackError("EXEPACK relocation group extends beyond its region")
        for _ in range(count):
            offset = struct.unpack_from("<H", data, cursor)[0]
            cursor += 2
            relocation = MzRelocation(offset=offset, segment=bucket * 0x1000)
            if relocation.linear_offset + 2 > destination_size:
                raise ExepackError(
                    "EXEPACK relocation points outside the recovered load module"
                )
            relocations.append(relocation)

    if any(data[cursor:header.region_end]):
        raise ExepackError("unexpected non-zero bytes after EXEPACK relocations")
    return tuple(relocations)


def unpack_exepack(data: bytes) -> ExepackResult:
    """Recover an EXEPACK-compressed executable without executing it."""

    try:
        packed_mz = parse_mz(data)
    except RuntimeError as exc:
        raise ExepackError(str(exc)) from exc
    header = parse_exepack_header(data, packed_mz)
    packed_data_end = header.file_offset
    packed_data_start = packed_mz.header.header_size
    if packed_data_end <= packed_data_start:
        raise ExepackError("EXEPACK compressed stream is empty")
    load_module = decode_exepack_stream(
        data[packed_data_start:packed_data_end], header.destination_size
    )
    relocations = parse_exepack_relocations(
        data, header, len(load_module)
    )

    packed_load_paragraphs = (len(packed_mz.load_module) + 15) // 16
    expansion_paragraphs = max(
        0, header.destination_paragraphs - packed_load_paragraphs
    )
    if expansion_paragraphs > packed_mz.header.minimum_allocation:
        raise ExepackError("EXEPACK allocation adjustment underflows")
    minimum_allocation = (
        packed_mz.header.minimum_allocation - expansion_paragraphs
    )

    executable = encode_mz(
        load_module,
        relocations,
        minimum_allocation=minimum_allocation,
        maximum_allocation=packed_mz.header.maximum_allocation,
        ss=header.real_ss,
        sp=header.real_sp,
        ip=header.real_ip,
        cs=header.real_cs,
        checksum=packed_mz.header.checksum,
        overlay_number=packed_mz.header.overlay_number,
    )
    return ExepackResult(
        packed_mz=packed_mz,
        header=header,
        load_module=load_module,
        relocations=relocations,
        executable=executable,
    )


def unpack_exepack_file(input_path: str | Path, output_path: str | Path) -> ExepackResult:
    result = unpack_exepack(Path(input_path).read_bytes())
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result.executable)
    return result


def format_exepack_summary(result: ExepackResult) -> str:
    unpacked = parse_mz(result.executable)
    return "\n".join((
        "Microsoft EXEPACK image",
        f"  packed load module:   {len(result.packed_mz.load_module)} bytes",
        f"  EXEPACK header:       0x{result.header.file_offset:X}",
        f"  recovered load module:{len(result.load_module):9d} bytes",
        f"  relocations:          {len(result.relocations)}",
        f"  entry CS:IP:          {unpacked.header.cs:04X}:{unpacked.header.ip:04X}",
        f"  initial SS:SP:        {unpacked.header.ss:04X}:{unpacked.header.sp:04X}",
        f"  output size:          {len(result.executable)} bytes",
    ))
