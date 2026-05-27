from __future__ import annotations

from binary_comp.core.ghidra import function_starts_from_export_dir
from binary_comp.core.mapfile import (
    function_starts_from_map,
    parse_encoded_address_map,
    parse_msvc_map_by_obj,
)
from binary_comp.core.pe import PEImage

from conftest import DATA_VA, TEXT_VA


def test_parse_msvc_map_by_object(fixture_root):
    entries_by_obj = parse_msvc_map_by_obj(str(fixture_root / "rebuilt.map"))

    assert list(entries_by_obj) == ["sample.obj"]
    assert [entry.symbol for entry in entries_by_obj["sample.obj"]] == [
        "_sample_function",
        "_sample_boundary",
    ]
    assert function_starts_from_map(entries_by_obj) == [0x401000, 0x401010]


def test_parse_encoded_address_map(fixture_root):
    address_map = parse_encoded_address_map(str(fixture_root / "rebuilt.map"))

    assert address_map[0x402000] == 0x402000
    assert address_map[0x402010] == 0x402010


def test_function_starts_from_ghidra_export(fixture_root):
    assert function_starts_from_export_dir(str(fixture_root / "code")) == [0x401000, 0x401010]


def test_pe_image_reads_sections_and_strings(sample_binaries):
    original, _ = sample_binaries
    image = PEImage(str(original))

    assert image.image_base == 0x400000
    assert image.entry_point == TEXT_VA
    assert image.section_named(".text").start == TEXT_VA
    assert image.read(TEXT_VA, 1) == b"\xB8"
    assert image.c_string_at(DATA_VA) == "hello"
    assert image.read(DATA_VA + 0x18, 4) == b"\0\0\0\0"
