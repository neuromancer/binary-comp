from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.exepack import (
    EXEPACK_ERROR_TEXT,
    ExepackError,
    decode_exepack_stream,
    unpack_exepack,
)
from binary_comp.core.mz import encode_mz, parse_mz


def make_exepack_fixture() -> tuple[bytes, bytes]:
    unpacked = bytes(0x100)

    # The decoder walks the compressed bytes backward. After reversal it skips
    # 0xFF padding and sees one final fill command for all 256 zero bytes.
    reversed_stream = b"\xFF" * 12 + b"\xB1\x01\x00\x00"
    packed_stream = reversed_stream[::-1]

    relocation_groups = bytearray()
    for bucket in range(16):
        entries = (0x0010, 0x0042) if bucket == 0 else ()
        relocation_groups += struct.pack("<H", len(entries))
        relocation_groups += b"".join(struct.pack("<H", entry) for entry in entries)

    header_size = 18
    region_size = header_size + len(EXEPACK_ERROR_TEXT) + len(relocation_groups)
    exepack_header = struct.pack(
        "<9H",
        0x0012,  # real IP
        0x0000,  # real CS
        0x0000,
        region_size,
        0x4000,  # real SP
        0x0123,  # real SS
        len(unpacked) // 16,
        1,
        0x4252,
    )
    packed_load_module = (
        packed_stream + exepack_header + EXEPACK_ERROR_TEXT + relocation_groups
    )
    packed_paragraphs = (len(packed_load_module) + 15) // 16
    expansion = len(unpacked) // 16 - packed_paragraphs
    packed = encode_mz(
        packed_load_module,
        minimum_allocation=0x20 + expansion,
        maximum_allocation=0xBEEF,
        cs=len(packed_stream) // 16,
        ip=header_size,
    )
    return packed, unpacked


def test_exepack_static_unpack_recovers_load_module_header_and_relocations():
    packed, expected_load_module = make_exepack_fixture()

    result = unpack_exepack(packed)
    image = parse_mz(result.executable)

    assert result.load_module == expected_load_module
    assert image.load_module == expected_load_module
    assert image.header.minimum_allocation == 0x20
    assert image.header.maximum_allocation == 0xBEEF
    assert (image.header.cs, image.header.ip) == (0x0000, 0x0012)
    assert (image.header.ss, image.header.sp) == (0x0123, 0x4000)
    assert [item.linear_offset for item in image.relocations] == [0x10, 0x42]


def test_exepack_decoder_rejects_unknown_command():
    packed = bytes.fromhex("00 00 A0")

    with pytest.raises(ExepackError, match="unsupported EXEPACK command"):
        decode_exepack_stream(packed, 16)
