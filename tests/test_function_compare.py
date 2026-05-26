from __future__ import annotations

import pytest

from binary_comp.analyzers.function_compare import (
    FunctionComparer,
    disassemble_exported_function,
    disassemble_function,
    format_comparison,
)
from binary_comp.config import BuildConfig, ProjectTarget
from binary_comp.core.pe import PEImage

from conftest import TEXT_VA, write_tiny_pe


def test_function_compare_decodes_original_and_rebuilt_bytes(fixture_root, sample_binaries):
    pytest.importorskip("capstone")
    original, rebuilt = sample_binaries
    target = ProjectTarget(
        name="full",
        original_exe=str(original),
        rebuilt_exe=str(rebuilt),
        map_path=str(fixture_root / "rebuilt.map"),
        source_dirs=(str(fixture_root / "src"),),
        code_dir=str(fixture_root / "code"),
        build=BuildConfig(),
    )

    comparison = FunctionComparer(target).compare(
        "sample_function",
        str(fixture_root / "code" / "FUN_00401000.disassembled.txt"),
        build=False,
    )

    assert comparison.original_addr == 0x401000
    assert comparison.rebuilt_addr == 0x401000
    assert comparison.similarity == 100.0
    text = format_comparison(comparison)
    assert "00401000: mov eax, 7" in text
    assert "Similarity: 100.00%" in text


def test_disassemble_export_uses_ghidra_block_layout(tmp_path):
    pytest.importorskip("capstone")
    code = bytearray(b"\xE9" + (0x1B).to_bytes(4, "little"))  # jmp 0x401020
    code.extend(b"\xFF" * (0x20 - len(code)))
    code.extend(b"\x33\xC0\xC3")  # xor eax,eax; ret
    exe = tmp_path / "sample.exe"
    write_tiny_pe(exe, bytes(code))
    export = tmp_path / "FUN_00401000.disassembled.txt"
    export.write_text(
        "Function: sample\n"
        "Address: 0x00401000\n"
        "\n"
        "JMP LAB_00401020\n"
        "\n"
        "LAB_00401020:\n"
        "XOR EAX,EAX\n"
        "RET\n",
        encoding="utf-8",
    )

    result = disassemble_exported_function(
        PEImage(str(exe)),
        str(export),
        TEXT_VA,
        max_bytes=0x100,
        padding_mnemonics=frozenset({"nop", "int3"}),
    )

    assert [instr.address for instr in result.instructions] == [TEXT_VA, TEXT_VA + 0x20, TEXT_VA + 0x22]
    assert [instr.mnemonic for instr in result.instructions] == ["jmp", "xor", "ret"]


def test_disassemble_function_trims_unreachable_tail_data(tmp_path):
    pytest.importorskip("capstone")
    code = b"\x33\xC0\xC3\x00\x00\x00\x00"
    exe = tmp_path / "sample.exe"
    write_tiny_pe(exe, code)

    result = disassemble_function(
        PEImage(str(exe)),
        TEXT_VA,
        [TEXT_VA, TEXT_VA + 0x20],
        max_bytes=0x20,
        padding_mnemonics=frozenset({"nop", "int3"}),
    )

    assert [instr.mnemonic for instr in result.instructions] == ["xor", "ret"]
