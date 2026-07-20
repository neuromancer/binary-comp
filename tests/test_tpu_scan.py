from __future__ import annotations

import struct

from binary_comp.analyzers.tpu_scan import (
    format_tpu_scan,
    parse_tpu_scan_regions,
    scan_tpu_blocks,
)
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


def test_tpu_scan_uses_explicit_regions_and_reports_missing_blocks(tmp_path):
    overlay_code = bytes.fromhex("55 89 e5 b8 34 12 5d cb")
    resident_code = bytes.fromhex("55 89 e5 b8 78 56 5d cb")
    missing_code = bytes.fromhex("55 89 e5 b8 bc 9a 5d cb")
    overlay = b"FLAT" + overlay_code + bytes(5)
    resident = bytes(3) + resident_code + bytes(7)
    executable = encode_mz(resident)

    paths = []
    for filename, code, name in (
        ("OVERLAY.TPU", overlay_code, "DRAW"),
        ("RESIDENT.TPU", resident_code, "INPUT"),
        ("MISSING.TPU", missing_code, "ABSENT"),
    ):
        path = tmp_path / filename
        path.write_bytes(make_tpu6(code, name))
        paths.append(path)

    regions = parse_tpu_scan_regions({
        "scan_regions": {
            "resident": [
                {"label": "root-code", "index": 7, "start": 3, "end": 11},
            ],
            "overlay": [
                {"label": "flat-unit", "index": 12, "start": 4, "end": 12},
            ],
        }
    })
    result = scan_tpu_blocks(
        executable,
        overlay,
        tuple(paths),
        regions=regions,
        include_missing=True,
    )

    assert result.overlay_count == 1
    assert result.unique_count == 2
    assert result.ambiguous_count == 0
    assert result.missing_count == 1
    assert result.exact_bytes == 16
    by_unit = {match.unit: match for match in result.matches}
    assert by_unit["OVERLAY"].locations[0].overlay_index == 12
    assert by_unit["OVERLAY"].locations[0].region == "flat-unit"
    assert by_unit["RESIDENT"].locations[0].region_index == 7
    assert by_unit["MISSING"].status == "missing"
    assert "1 missing block(s)" in format_tpu_scan(result)
