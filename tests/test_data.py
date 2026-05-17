from __future__ import annotations

import struct

from binary_comp.analyzers.data import (
    DataOptions,
    compare_address,
    compare_global_data,
    find_missing_globals,
    format_comparison,
    format_missing_globals,
)
from binary_comp.source.globals import parse_globals_source


def test_parse_global_declarations(fixture_root):
    globals_list = parse_globals_source(str(fixture_root / "src" / "globals.cpp"))

    assert [item.name for item in globals_list] == [
        "g_Text_00402000",
        "g_Number_00402010",
        "g_CommentAddress",
    ]
    assert globals_list[0].address == 0x402000
    assert globals_list[0].size == 6
    assert globals_list[1].size == 4
    assert globals_list[2].address == 0x402018


def test_parse_pointer_declarations_with_adjacent_star(tmp_path):
    globals_path = tmp_path / "globals.cpp"
    globals_path.write_text(
        "char *g_Buffer_00402020 = 0;\n"
        "char* g_Text_00402024 = 0;\n"
        "static const unsigned int g_Count_00402028 = 1;\n",
        encoding="utf-8",
    )

    globals_list = parse_globals_source(str(globals_path))

    assert [item.address for item in globals_list] == [0x402020, 0x402024, 0x402028]
    assert [item.size for item in globals_list] == [4, 4, 4]


def test_parse_global_declarations_with_multiline_initializer(tmp_path):
    globals_path = tmp_path / "globals.cpp"
    globals_path.write_text(
        "int g_Table_00402030[3] = {\n"
        "    1,\n"
        "    2,\n"
        "    3,\n"
        "};\n",
        encoding="utf-8",
    )

    globals_list = parse_globals_source(str(globals_path))

    assert len(globals_list) == 1
    assert globals_list[0].address == 0x402030
    assert globals_list[0].size == 12


def test_compare_global_data_matches(fixture_root, sample_binaries):
    original, rebuilt = sample_binaries

    summary = compare_global_data(
        str(original),
        str(rebuilt),
        str(fixture_root / "rebuilt.map"),
        str(fixture_root / "src" / "globals.cpp"),
        DataOptions(),
    )

    assert summary.global_count == 3
    assert summary.matches == 2
    assert summary.mismatches == 0
    assert summary.missing_symbols == 1
    assert "Summary: 2 matches, 0 mismatches, 1 not in rebuilt map" in format_comparison(summary)


def test_compare_global_data_reports_mismatch(fixture_root, tmp_path):
    from conftest import write_tiny_pe

    original = tmp_path / "original.exe"
    rebuilt = tmp_path / "rebuilt.exe"
    write_tiny_pe(original)
    write_tiny_pe(rebuilt, data_overrides={0x10: struct.pack("<I", 9)})

    summary = compare_global_data(
        str(original),
        str(rebuilt),
        str(fixture_root / "rebuilt.map"),
        str(fixture_root / "src" / "globals.cpp"),
        DataOptions(),
    )

    assert summary.matches == 1
    assert summary.mismatches == 1
    assert [item.status for item in summary.comparisons] == ["OK", "MISMATCH", "NO_SYMBOL"]
    assert "Original value: 0x00000007 (7)" in format_comparison(summary)
    assert "Rebuilt value:  0x00000009 (9)" in format_comparison(summary)


def test_compare_one_address_uses_map(fixture_root, sample_binaries):
    original, rebuilt = sample_binaries
    comparison = compare_address(
        str(original),
        str(rebuilt),
        str(fixture_root / "rebuilt.map"),
        0x402010,
        4,
    )

    assert comparison.matches
    assert comparison.rebuilt_address == 0x402010


def test_find_missing_globals_reports_uncovered_dwords(fixture_root, tmp_path):
    from conftest import write_tiny_pe

    original = tmp_path / "original.exe"
    write_tiny_pe(original, data_overrides={0x1C: struct.pack("<I", 0x12345678)})

    summary = find_missing_globals(
        str(original),
        str(fixture_root / "src" / "globals.cpp"),
    )

    assert summary.known_globals == 3
    assert [candidate.address for candidate in summary.candidates] == [0x40201C]
    assert "0x0040201c" in format_missing_globals(summary)
