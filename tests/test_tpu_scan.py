from __future__ import annotations

import struct

from binary_comp.analyzers.tpu_scan import (
    TpuBlockLocation,
    TpuBlockMatch,
    format_tpu_scan,
    parse_tpu_scan_regions,
    resolve_adjacent_matches,
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


def test_tpu_scan_discovers_fbov_regions_automatically(tmp_path):
    code = bytes.fromhex("55 89 e5 b8 34 12 5d cb")
    payload = code
    overlay = b"FBOV" + struct.pack("<I", len(payload)) + payload
    resident = bytes(9) + descriptor(8, len(code))
    executable = encode_mz(resident)
    tpu = tmp_path / "OVERLAY.TPU"
    tpu.write_bytes(make_tpu6(code, "DRAW"))

    result = scan_tpu_blocks(executable, overlay, (tpu,))

    assert result.overlay_count == 1
    assert result.unique_count == 1
    assert result.matches[0].locations[0].overlay_index == 1


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


def test_tpu_scan_can_report_units_without_scannable_blocks(tmp_path):
    code = bytes.fromhex("55 89 e5 b8 34 12 5d cb")
    overlay = b"TPOV" + code
    executable = encode_mz(bytes(9) + descriptor(4, len(code)))
    populated = tmp_path / "POPULATED.TPU"
    empty = tmp_path / "EMPTY.TPU"
    populated.write_bytes(make_tpu6(code, "DRAW"))
    empty.write_bytes(make_tpu6(b"\x90" * 5, "EMPTY"))

    result = scan_tpu_blocks(executable, overlay, (populated, empty))
    report = format_tpu_scan(result, show_all_units=True)

    assert result.units == ("EMPTY", "POPULATED")
    assert "EMPTY                0       0          0        0            0" in report
    assert "target-only routines are outside the source-side denominator" in report


def test_tpu_scan_resolves_runs_of_identical_blocks_from_adjacency():
    def location(offset: int) -> TpuBlockLocation:
        return TpuBlockLocation(
            image="overlay",
            file_offset=offset,
            image_offset=offset - 100,
            overlay_index=7,
            region="unit-seven",
            region_index=7,
        )

    duplicate_locations = (location(140), location(180), location(220))
    matches = (
        TpuBlockMatch("UNIT", "BEFORE", 13, 40, 40, (location(100),)),
        TpuBlockMatch("UNIT", "FIRST", 14, 40, 40, duplicate_locations),
        TpuBlockMatch("UNIT", "SECOND", 15, 40, 40, duplicate_locations),
        TpuBlockMatch("UNIT", "THIRD", 16, 40, 40, duplicate_locations),
        TpuBlockMatch("UNIT", "AFTER", 17, 40, 40, (location(260),)),
    )

    resolved = resolve_adjacent_matches(matches)

    assert [match.locations[0].file_offset for match in resolved] == [100, 140, 180, 220, 260]
    assert all(match.is_unique for match in resolved)
    assert resolved[1].resolution == "adjacent-left"
    assert resolved[3].resolution in {
        "adjacent-left", "adjacent-right", "adjacent-left-right"
    }


def test_tpu_scan_does_not_resolve_across_a_block_or_region_gap():
    anchor = TpuBlockLocation("overlay", 100, 0, 7, "unit-seven", 7)
    other_region = TpuBlockLocation("overlay", 140, 0, 8, "unit-eight", 8)
    matches = (
        TpuBlockMatch("UNIT", "BEFORE", 1, 40, 40, (anchor,)),
        TpuBlockMatch("UNIT", "DUP", 3, 40, 40, (other_region, TpuBlockLocation(
            "overlay", 180, 80, 7, "unit-seven", 7
        ))),
    )

    resolved = resolve_adjacent_matches(matches)

    assert resolved[1].status == "ambiguous"
    assert resolved[1].resolution is None
