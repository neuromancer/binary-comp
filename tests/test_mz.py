from __future__ import annotations

import pytest

from binary_comp.core.mz import (
    MzFormatError,
    MzRelocation,
    compare_mz,
    encode_mz,
    format_mz_comparison,
    parse_mz,
)
from binary_comp.core.binary import compare_binary


def test_mz_round_trip_preserves_header_load_module_and_relocations():
    load_module = bytes(range(64))
    relocations = (
        MzRelocation(offset=0x0010, segment=0x0020),
        MzRelocation(offset=0x1234, segment=0x0001),
    )
    data = encode_mz(
        load_module,
        relocations,
        minimum_allocation=0x30,
        maximum_allocation=0x4000,
        ss=0x20,
        sp=0x100,
        cs=0x01,
        ip=0x02,
    )

    image = parse_mz(data)

    assert image.header.header_size == 0x30
    assert image.header.declared_size == len(data)
    assert image.header.minimum_allocation == 0x30
    assert image.header.maximum_allocation == 0x4000
    assert image.header.entry_image_offset == 0x12
    assert image.relocations == relocations
    assert image.load_module == load_module
    assert image.trailing_data == b""


def test_mz_parser_preserves_data_after_declared_image():
    executable = encode_mz(b"payload")
    image = parse_mz(executable + b"debug trailer")

    assert image.load_module == b"payload"
    assert image.trailing_data == b"debug trailer"


def test_mz_parser_rejects_relocation_table_outside_header():
    data = bytearray(encode_mz(b"payload"))
    data[6:8] = (2).to_bytes(2, "little")

    with pytest.raises(MzFormatError, match="relocation table"):
        parse_mz(bytes(data))


def test_binary_comparison_reports_positional_identity_and_runs():
    comparison = compare_binary(b"abcXYZ", b"abc123!")

    assert comparison.original_size == 6
    assert comparison.rebuilt_size == 7
    assert comparison.matching_positions == 3
    assert comparison.differing_positions == 4
    assert comparison.differing_runs == 1
    assert comparison.common_prefix == 3
    assert comparison.common_suffix == 0
    assert comparison.positional_identity == pytest.approx(3 / 7 * 100)
    assert not comparison.exact


def test_mz_comparison_masks_only_common_relocation_words():
    relocation = MzRelocation(offset=2, segment=0)
    original = encode_mz(b"AA\x34\x12ZZ", (relocation,), ss=1)
    rebuilt = encode_mz(b"AA\x78\x56ZZ", (relocation,), ss=2)

    comparison = compare_mz(original, rebuilt)

    assert comparison.common_relocation_sites == 1
    assert comparison.relocation_tables_exact
    assert not comparison.load_module.exact
    assert comparison.relocation_masked_load_module.exact
    assert not comparison.whole_file.exact
    report = format_mz_comparison(comparison)
    assert "common sites:        1 / 1 original / 1 rebuilt" in report
    assert "initial SS:SP" in report
