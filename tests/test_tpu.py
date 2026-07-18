from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.function_compare import format_comparison
from binary_comp.analyzers.report import SimilarityReportOptions, format_similarity_report
from binary_comp.analyzers.tpu import (
    TpuCompareError,
    TpuCompareSpec,
    block_index_for_name,
    compare_tpu_spec,
    compare_tpu_to_original,
    generate_tpu_similarity_report,
    generate_tpu_values_report,
    load_tpu_object,
    parse_code_symbols,
)
from binary_comp.config import BuildConfig, ProjectTarget


def _roundup(value: int, n: int = 16) -> int:
    return (value + n - 1) & ~(n - 1)


def make_proc_symbol(name: str, order_key: int) -> bytes:
    """A procedure symbol-table record: kind 0x53, length-prefixed name, then
    attributes with the code-order key at offset +6 past the name."""
    raw = name.encode("ascii")
    return bytes([0x53, len(raw)]) + raw + b"\x00" * 6 + struct.pack("<H", order_key)


def make_tpu5_code_symbol(
    name: str, order_key: int, *, function: bool = False
) -> bytes:
    """A TPU5 code symbol: length-prefixed name, kind, then attributes."""
    raw = name.encode("ascii")
    kind = 0x55 if function else 0x54
    return bytes([len(raw)]) + raw + bytes([kind]) + b"\x00" * 5 + struct.pack("<H", order_key)


def make_tpu(blocks, *, const: bytes = b"", symbols: bytes = b"") -> bytes:
    """Assemble a minimal but valid TPU9 unit.

    ``blocks`` is a list of ``(code_bytes, relocs)`` where each reloc is a tuple
    ``(unit_num, rtype, rblock, roffset, offset)``. ``symbols`` is optional raw
    procedure symbol-table bytes (see :func:`make_proc_symbol`), placed right
    after the header so :func:`parse_code_symbols` can find them. The layout
    mirrors a real Turbo Pascal 6.0 unit closely enough for the parser: header,
    symbol records, code-block table, code section, const section, and
    code-relocation records, each padded to a paragraph.
    """
    ofs_code_blocks = 0x40 + len(symbols)
    ofs_const_blocks = ofs_code_blocks + 8 * len(blocks)
    sym_size = ofs_const_blocks
    code = b"".join(code for code, _ in blocks)
    reloc = b"".join(
        struct.pack("<BBHHH", *rec) for _, relocs in blocks for rec in relocs
    )

    header = bytearray(0x40)
    header[0:4] = b"TPU9"
    struct.pack_into("<H", header, 0x0E, ofs_code_blocks)
    struct.pack_into("<H", header, 0x10, ofs_const_blocks)
    struct.pack_into("<H", header, 0x1C, sym_size)
    struct.pack_into("<H", header, 0x1E, len(code))
    struct.pack_into("<H", header, 0x20, len(const))
    struct.pack_into("<H", header, 0x22, len(reloc))
    struct.pack_into("<H", header, 0x24, 0)  # vmt_size

    block_table = bytearray()
    for code_bytes, relocs in blocks:
        block_table += struct.pack("<4H", 0, len(code_bytes), 8 * len(relocs), 0xFFFF)

    symbol_section = bytes(header) + symbols + bytes(block_table)
    symbol_section = symbol_section.ljust(_roundup(sym_size), b"\x00")

    out = bytearray(symbol_section)
    out += code.ljust(_roundup(len(code)), b"\x00")
    out += const.ljust(_roundup(len(const)), b"\x00")
    out += reloc.ljust(_roundup(len(reloc)), b"\x00")
    return bytes(out)


def make_tpu5(
    blocks, *, const: bytes = b"", symbols: bytes = b"", flags: int = 0
) -> bytes:
    """Assemble a minimal TPU5 unit using TP5's code/reloc/const order."""
    ofs_code_blocks = 0x40 + len(symbols)
    ofs_const_blocks = ofs_code_blocks + 8 * len(blocks)
    sym_size = ofs_const_blocks
    code = b"".join(code for code, _ in blocks)
    reloc = b"".join(
        struct.pack("<BBHHH", *rec) for _, relocs in blocks for rec in relocs
    )

    header = bytearray(0x40)
    header[0:4] = b"TPU5"
    struct.pack_into("<H", header, 0x0C, ofs_code_blocks)
    struct.pack_into("<H", header, 0x0E, ofs_const_blocks)
    struct.pack_into("<H", header, 0x18, sym_size)
    struct.pack_into("<H", header, 0x1A, len(code))
    struct.pack_into("<H", header, 0x1C, len(reloc))
    struct.pack_into("<H", header, 0x1E, len(const))
    struct.pack_into("<H", header, 0x24, flags)

    block_table = bytearray()
    for code_bytes, relocs in blocks:
        block_table += struct.pack("<4H", 0, len(code_bytes), 8 * len(relocs), 0xFFFF)

    out = bytearray(bytes(header) + symbols + bytes(block_table))
    out = bytearray(bytes(out).ljust(_roundup(sym_size), b"\x00"))
    out += code.ljust(_roundup(len(code)), b"\x00")
    out += reloc.ljust(_roundup(len(reloc)), b"\x00")
    out += const.ljust(_roundup(len(const)), b"\x00")
    return bytes(out)


# A far call whose 4-byte pointer operand is a link-time fixup, followed by retf.
FAR_CALL = bytes.fromhex("9a 00 00 00 00 cb")
POINTER_FIXUP = (0, 0x30, 0, 0, 1)  # pointer(ref=3)/code(tgt=0), patch 4 bytes at offset 1


def test_tpu_parser_reads_header_code_and_fixups(tmp_path):
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, [POINTER_FIXUP])]))

    obj = load_tpu_object(tpu)

    assert obj.header.code_size == len(FAR_CALL)
    assert obj.code == FAR_CALL
    assert len(obj.blocks) == 1
    assert obj.blocks[0].code_offset == 0
    assert [(f.offset, f.length) for f in obj.fixups] == [(1, 4)]


def test_tpu5_parser_reads_header_sections_code_and_fixups(tmp_path):
    typed_const = bytes.fromhex("01 02 03")
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(
        make_tpu5([(FAR_CALL, [POINTER_FIXUP])], const=typed_const, flags=2)
    )

    obj = load_tpu_object(tpu)

    assert obj.header.signature == b"TPU5"
    assert obj.header.has_overlays
    assert obj.header.code_size == len(FAR_CALL)
    assert obj.header.const_size == len(typed_const)
    assert obj.header.off_code_reloc == obj.header.off_code + _roundup(len(FAR_CALL))
    assert obj.header.off_const == obj.header.off_code_reloc + _roundup(8)
    assert obj.code == FAR_CALL
    assert [(f.offset, f.length) for f in obj.fixups] == [(1, 4)]


def test_tpu_rejects_unsupported_signature(tmp_path):
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(b"TPU6" + bytes(0x40))

    with pytest.raises(TpuCompareError, match="expected b'TPU5' or b'TPU9'"):
        load_tpu_object(tpu)


def test_tpu_compare_masks_fixup_operands(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("9a 78 56 34 12 cb"))
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, [POINTER_FIXUP])]))

    comparison = compare_tpu_to_original(
        original_path=original,
        original_offset=0,
        tpu_path=tpu,
        name="caller",
    )

    assert comparison.matches
    assert comparison.mask == bytes.fromhex("ff 00 00 00 00 ff")
    assert comparison.masked_count == 4


def test_tpu_compare_reports_unmasked_differences(tmp_path):
    original = tmp_path / "original.bin"
    # Same fixup operand region, but the trailing retf differs (cb vs c3).
    original.write_bytes(bytes.fromhex("9a 78 56 34 12 c3"))
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, [POINTER_FIXUP])]))

    comparison = compare_tpu_to_original(
        original_path=original,
        original_offset=0,
        tpu_path=tpu,
        name="caller",
    )

    assert not comparison.matches
    assert comparison.mismatches == (5,)


def test_tpu_block_selection_and_absolute_fixup_offset(tmp_path):
    # Two blocks; the second block's fixup offset must become absolute.
    block0 = (bytes.fromhex("55 89 e5 5d cb"), [])           # 5 bytes, no relocs
    block1 = (FAR_CALL, [POINTER_FIXUP])                     # fixup at block-offset 1
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([block0, block1]))

    obj = load_tpu_object(tpu)
    assert [b.code_offset for b in obj.blocks] == [0, 5]
    # Block 1 starts at 5, so its offset-1 fixup is absolute offset 6.
    assert [(f.offset, f.length) for f in obj.fixups] == [(6, 4)]

    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("9a 78 56 34 12 cb"))
    comparison = compare_tpu_to_original(
        original_path=original,
        original_offset=0,
        tpu_path=tpu,
        block_index=1,
        name="block1",
    )
    assert comparison.code_offset == 5
    assert comparison.rebuilt == FAR_CALL
    assert comparison.matches


def test_tpu_block_selection_supports_intra_block_offset(tmp_path):
    prefix = bytes.fromhex("de ad be ef")
    prefixed_call = prefix + FAR_CALL
    prefixed_fixup = (0, 0x30, 0, 0, len(prefix) + 1)
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(prefixed_call, [prefixed_fixup])]))

    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("9a 78 56 34 12 cb"))
    comparison = compare_tpu_to_original(
        original_path=original,
        original_offset=0,
        tpu_path=tpu,
        block_index=0,
        block_offset=len(prefix),
        name="block_tail",
    )

    assert comparison.code_offset == len(prefix)
    assert comparison.rebuilt == FAR_CALL
    assert comparison.mask == bytes.fromhex("ff 00 00 00 00 ff")
    assert comparison.matches


def test_name_selection_follows_code_order_not_table_order(tmp_path):
    # Two blocks. In the symbol table SECOND appears before FIRST (as a forward
    # declaration would), but its code-order key is higher, so name resolution
    # must map FIRST->block 0 and SECOND->block 1 regardless of table order.
    block0 = (bytes.fromhex("55 89 e5 5d cb"), [])   # 5 bytes
    block1 = (FAR_CALL, [POINTER_FIXUP])             # 6 bytes
    syms = make_proc_symbol("SECOND", 0x200) + make_proc_symbol("FIRST", 0x100)
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([block0, block1], symbols=syms))

    obj = load_tpu_object(tpu)
    assert [s.name for s in obj.code_symbols] == ["FIRST", "SECOND"]
    assert block_index_for_name(obj, "first") == 0    # case-insensitive
    assert block_index_for_name(obj, "SECOND") == 1

    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("9a 78 56 34 12 cb"))
    comparison = compare_tpu_to_original(
        original_path=original,
        original_offset=0,
        tpu_path=tpu,
        function_name="second",   # resolves to block 1 (the far call)
        name="second",
    )
    assert comparison.code_offset == 5
    assert comparison.rebuilt == FAR_CALL
    assert comparison.matches


def test_tpu5_name_selection_handles_procedure_and_function_order(tmp_path):
    private_function = (bytes.fromhex("55 89 e5 5d cb"), [])
    exported_procedure = (FAR_CALL, [POINTER_FIXUP])
    # Interface symbols precede private implementation symbols in the table,
    # while the order key still places the private function's body first.
    syms = (
        make_tpu5_code_symbol("EXPORTED", 0x200)
        + make_tpu5_code_symbol("PRIVATEFN", 0x100, function=True)
    )
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu5([private_function, exported_procedure], symbols=syms))

    obj = load_tpu_object(tpu)

    assert [s.name for s in obj.code_symbols] == ["PRIVATEFN", "EXPORTED"]
    assert block_index_for_name(obj, "privatefn") == 0
    assert block_index_for_name(obj, "EXPORTED") == 1


def test_name_selection_unknown_name_lists_available(tmp_path):
    syms = make_proc_symbol("ALPHA", 0x100) + make_proc_symbol("BETA", 0x200)
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, []), (FAR_CALL, [])], symbols=syms))
    obj = load_tpu_object(tpu)
    with pytest.raises(TpuCompareError, match="GAMMA.*ALPHA, BETA"):
        block_index_for_name(obj, "GAMMA")


def test_name_selection_count_mismatch_errors(tmp_path):
    # One symbol but two code blocks (more than one extra) -> unmappable.
    syms = make_proc_symbol("ONLY", 0x100)
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, []), (FAR_CALL, []), (FAR_CALL, [])], symbols=syms))
    obj = load_tpu_object(tpu)
    with pytest.raises(TpuCompareError, match="stale or truncated"):
        block_index_for_name(obj, "ONLY")


def test_name_selection_tolerates_trailing_init_block(tmp_path):
    # A unit-initialization block (no symbol) may trail the procedures.
    syms = make_proc_symbol("PROC0", 0x100) + make_proc_symbol("PROC1", 0x200)
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, []), (FAR_CALL, []), (FAR_CALL, [])], symbols=syms))
    obj = load_tpu_object(tpu)
    assert block_index_for_name(obj, "PROC0") == 0
    assert block_index_for_name(obj, "PROC1") == 1


def test_tpu_skips_and_counts_coprocessor_fixups(tmp_path):
    coproc = (0xFF, 0xFF, 5, 0, 0)  # 8087 fixup marker
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, [coproc, POINTER_FIXUP])]))

    obj = load_tpu_object(tpu)

    assert obj.coproc_fixups == 1
    assert [(f.offset, f.length) for f in obj.fixups] == [(1, 4)]


# push bp; mov bp, sp; mov ax, imm16; retf  (imm is a link-time fixup)
LOC_BLOCK = bytes.fromhex("55 89 e5 b8 00 00 cb")
LOC_FIXUP = (0, 0x10, 0, 0, 4)  # offset(ref=1)/code, 2 bytes at block offset 4


def test_tpu_compare_locate_finds_block(tmp_path):
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(LOC_BLOCK, [LOC_FIXUP])]))
    # An image with the linked block (fixup operand filled) buried at offset 0x30.
    linked = bytearray(LOC_BLOCK)
    linked[4:6] = bytes.fromhex("34 12")
    image = tmp_path / "image.bin"
    image.write_bytes(bytes(0x30) + bytes(linked) + bytes(0x20))

    comparison = compare_tpu_to_original(
        original_path=image,
        tpu_path=tpu,
        block_index=0,
        locate=True,
        name="f",
    )

    assert comparison.matches
    assert comparison.original_offset == 0x30


def test_tpu_locate_raises_when_absent(tmp_path):
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(LOC_BLOCK, [LOC_FIXUP])]))
    image = tmp_path / "image.bin"
    image.write_bytes(bytes(0x80))  # block not present

    with pytest.raises(TpuCompareError):
        compare_tpu_to_original(original_path=image, tpu_path=tpu, block_index=0, locate=True)


def test_load_rejects_non_tpu(tmp_path):
    bad = tmp_path / "bad.tpu"
    bad.write_bytes(b"MZ\x00\x00" + bytes(0x40))

    with pytest.raises(TpuCompareError):
        load_tpu_object(bad)


def test_tpu_compare_spec_uses_function_compare_format(tmp_path):
    pytest.importorskip("capstone")

    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("9a 78 56 34 12 cb"))
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(FAR_CALL, [POINTER_FIXUP])]))

    comparison = compare_tpu_spec(TpuCompareSpec(
        name="ovr_caller",
        function_name="caller",
        original_path=str(original),
        original_offset=0,
        tpu_path=str(tpu),
    ))
    text = format_comparison(comparison)

    assert comparison.similarity == pytest.approx(100.0)
    assert "Comparison for function 'caller':" in text
    assert "Similarity: 100.00%" in text
    assert "retf" in text


def test_tpu_compare_spec_scores_masked_byte_match_as_exact(tmp_path):
    pytest.importorskip("capstone")

    # These linked fixup bytes are in a region that Capstone decodes as code.
    # If mnemonic scoring runs on the zeroed TPU fixup bytes, instruction
    # boundaries shift and an exact masked byte match scores below 100%.
    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("2e 02 0e e8 f4 d5 31 c0 cb"))
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([
        (
            bytes.fromhex("2e 02 0e e8 00 00 31 c0 cb"),
            [(0, 0x10, 0, 0, 4)],
        )
    ]))

    byte_comparison = compare_tpu_to_original(
        original_path=original,
        original_offset=0,
        tpu_path=tpu,
        name="fn",
    )
    assert byte_comparison.matches

    comparison = compare_tpu_spec(TpuCompareSpec(
        name="fn",
        function_name="fn",
        original_path=str(original),
        original_offset=0,
        tpu_path=str(tpu),
    ))

    assert comparison.similarity == pytest.approx(100.0)


def test_tpu_compare_spec_accepts_exact_non_code_prefix(tmp_path):
    pytest.importorskip("capstone")

    original = tmp_path / "original.bin"
    original.write_bytes(b"\x0f")
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(b"\x0f", [])]))

    comparison = compare_tpu_spec(TpuCompareSpec(
        name="data_prefixed_fn",
        function_name="data_prefixed_fn",
        original_path=str(original),
        original_offset=0,
        tpu_path=str(tpu),
    ))

    assert comparison.similarity == pytest.approx(100.0)
    assert comparison.original.instructions == []
    assert comparison.rebuilt.instructions == []


def test_tpu_report_reads_config_entries(tmp_path):
    pytest.importorskip("capstone")

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    source = src_dir / "CALLER.PAS"
    source.write_text("procedure Caller; begin end;\n", encoding="utf-8")

    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("9a 78 56 34 12 cb"))
    tpu = tmp_path / "unit.tpu"
    prefix = bytes.fromhex("90 90")
    prefixed_fixup = (0, 0x30, 0, 0, len(prefix) + 1)
    tpu.write_bytes(make_tpu([(prefix + FAR_CALL, [prefixed_fixup])]))

    config_path = config_dir / "binary-comp.json"
    config = {
        "tpu_compare": {
            "functions": [
                {
                    "target": "sample",
                    "name": "ovr_caller",
                    "function": "caller",
                    "source": "../src/CALLER.PAS",
                    "original": "../original.bin",
                    "original_offset": "0x0",
                    "tpu": "../unit.tpu",
                    "block_index": 0,
                    "block_offset": "0x2",
                    "size": "0x6",
                }
            ]
        }
    }
    target = ProjectTarget(
        name="sample",
        original_exe=str(original),
        rebuilt_exe="",
        map_path="",
        source_dirs=(str(src_dir),),
        build=BuildConfig(),
        kind="dos16-tpu",
    )

    report = generate_tpu_similarity_report(
        config,
        config_path,
        target,
        SimilarityReportOptions(build=False),
    )
    text = format_similarity_report(report)

    assert report.compared == 1
    assert report.at_100 == 1
    assert "=== CALLER.PAS ===" in text
    assert "caller" in text
    assert "Average similarity: 100.00%" in text

    values = generate_tpu_values_report(
        config,
        config_path,
        target,
        SimilarityReportOptions(build=False),
    )
    assert values.compared == 1
    assert values.byte_exact == 1
    assert values.with_diffs == 0


def test_tpu_values_check_flags_constant_that_mnemonic_score_misses(tmp_path):
    # A wrong immediate ("cmp ax, 0x0d" vs "cmp ax, 0x0f") is invisible to the
    # mnemonic-only similarity score but must be caught by the value check.
    pytest.importorskip("capstone")
    from binary_comp.analyzers.tpu import _decode_value_diffs, compare_tpu_spec, TpuCompareSpec

    original = tmp_path / "original.bin"
    original.write_bytes(bytes.fromhex("3d 0f 00 cb"))  # cmp ax, 0x0f ; retf
    tpu = tmp_path / "unit.tpu"
    tpu.write_bytes(make_tpu([(bytes.fromhex("3d 0d 00 cb"), [])]))  # cmp ax, 0x0d ; retf

    comparison = compare_tpu_to_original(
        original_path=original, original_offset=0, tpu_path=tpu, name="fn"
    )
    # Byte view sees the one differing immediate byte...
    assert not comparison.matches
    assert comparison.mismatches == (1,)

    # ...but the mnemonic-only similarity score is 100% (same instruction types).
    spec = TpuCompareSpec(
        name="fn", function_name="fn", original_path=str(original),
        original_offset=0, tpu_path=str(tpu),
    )
    assert compare_tpu_spec(spec).similarity >= 99.99

    # The value check decodes the specific offending instruction.
    diffs = _decode_value_diffs(comparison)
    assert len(diffs) == 1
    assert "cmp" in diffs[0].rebuilt_text
    assert diffs[0].rebuilt_text != diffs[0].original_text
