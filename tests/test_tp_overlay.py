from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.tp_overlay import (
    TpOverlayError,
    format_tp_overlay,
    parse_tp_overlay,
)
from binary_comp.core.mz import encode_mz


def make_descriptor(
    file_offset: int,
    code_size: int,
    fixup_size: int,
    procedure_count: int,
    unit_number: int,
) -> bytes:
    descriptor = bytearray(32)
    struct.pack_into(
        "<HHIHHHH",
        descriptor,
        0,
        0x3FCD,
        0,
        file_offset,
        code_size,
        fixup_size,
        procedure_count,
        unit_number,
    )
    return bytes(descriptor) + bytes.fromhex("cd 3f 00 00 00") * procedure_count


def make_overlay_pair() -> tuple[bytes, bytes]:
    resident = (
        bytes(17)
        + make_descriptor(4, 3, 2, 1, 9)
        + bytes(11)
        + make_descriptor(9, 4, 0, 2, 12)
    )
    overlay = b"TPOV" + b"abc" + b"de" + b"WXYZ"
    return encode_mz(resident, cs=0, ip=0), overlay


def test_tp_overlay_parser_recovers_gap_free_descriptor_chain():
    executable, overlay = make_overlay_pair()

    image = parse_tp_overlay(executable, overlay)

    assert len(image.descriptors) == 2
    first, second = image.descriptors
    assert (first.file_offset, first.code_size, first.fixup_size) == (4, 3, 2)
    assert (second.file_offset, second.code_size, second.procedure_count) == (9, 4, 2)
    assert second.extent_end == len(overlay)
    assert "descriptors cover overlay" in format_tp_overlay(image)


def test_tp_overlay_parser_rejects_gap_in_coverage():
    executable, overlay = make_overlay_pair()
    broken = overlay[:9] + b"!" + overlay[9:]

    with pytest.raises(TpOverlayError, match="descriptor for overlay offset"):
        parse_tp_overlay(executable, broken)
