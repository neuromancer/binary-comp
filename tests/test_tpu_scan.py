from __future__ import annotations

import struct

from binary_comp.analyzers.tpu_scan import format_tpu_scan, scan_tpu_blocks
from binary_comp.core.mz import encode_mz


def roundup(value: int) -> int:
    return (value + 15) & ~15


def make_tpu6(code: bytes, name: str) -> bytes:
    raw_name = name.encode("ascii")
    symbol = bytes((0x53, len(raw_name))) + raw_name + bytes(6) + struct.pack("<H", 1)
    code_blocks = 0x40 + len(symbol)
    const_blocks = code_blocks + 8
    header = bytearray(0x40)
    header[:4] = b"TPU6"
    struct.pack_into("<2H", header, 0x0E, code_blocks, const_blocks)
    struct.pack_into("<5H", header, 0x1A, const_blocks, len(code), 0, 0, 0)
    block = struct.pack("<4H", 0, len(code), 0, 0xFFFF)
    return (bytes(header) + symbol + block).ljust(roundup(const_blocks), b"\0") + code.ljust(roundup(len(code)), b"\0")


def descriptor(file_offset: int, code_size: int) -> bytes:
    data = bytearray(32)
    struct.pack_into("<HHIHHHH", data, 0, 0x3FCD, 0, file_offset, code_size, 0, 1, 7)
    return bytes(data) + bytes.fromhex("cd 3f 00 00 00")


def test_tpu_scan_locates_unique_overlay_and_resident_blocks(tmp_path):
    overlay_code = bytes.fromhex("55 89 e5 b8 34 12 5d cb")
    resident_code = bytes.fromhex("55 89 e5 b8 78 56 5d cb")
    overlay = b"TPOV" + overlay_code
    resident = resident_code + bytes(9) + descriptor(4, len(overlay_code))
    executable = encode_mz(resident)

    overlay_tpu = tmp_path / "OVERLAY.TPU"
    resident_tpu = tmp_path / "RESIDENT.TPU"
    overlay_tpu.write_bytes(make_tpu6(overlay_code, "DRAW"))
    resident_tpu.write_bytes(make_tpu6(resident_code, "INPUT"))

    result = scan_tpu_blocks(
        executable,
        overlay,
        (overlay_tpu, resident_tpu),
    )

    assert result.unique_count == 2
    assert result.ambiguous_count == 0
    assert {match.locations[0].image for match in result.matches} == {"overlay", "resident"}
    assert "2 uniquely located block(s)" in format_tpu_scan(result)
