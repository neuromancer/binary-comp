from __future__ import annotations

import pytest

from binary_comp.analyzers.export_asm import ExportAsmOptions, export_asm
from binary_comp.analyzers.function_compare import disassemble_exported_function
from binary_comp.config import BuildConfig, ProjectTarget
from binary_comp.core.pe import PEImage

from conftest import TEXT_VA, write_tiny_pe


def make_target(tmp_path, exe, source_dir, code_dir, map_path=None) -> ProjectTarget:
    return ProjectTarget(
        name="full",
        original_exe=str(exe),
        rebuilt_exe=str(exe),
        map_path=str(map_path or tmp_path / "rebuilt.map"),
        source_dirs=(str(source_dir),),
        code_dir=str(code_dir),
        build=BuildConfig(),
    )


def test_export_asm_generates_ghidra_style_files_from_source_annotations(tmp_path):
    pytest.importorskip("capstone")
    exe = tmp_path / "original.exe"
    write_tiny_pe(exe)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "sample.cpp").write_text(
        "/* Function start: 0x00401000 */\n"
        "int sample_function() { return 7; }\n",
        encoding="utf-8",
    )
    code_dir = tmp_path / "code"

    summary = export_asm(
        make_target(tmp_path, exe, source_dir, code_dir),
        ExportAsmOptions(clean=True),
    )

    export_path = code_dir / "FUN_00401000.disassembled.txt"
    text = export_path.read_text(encoding="utf-8")
    assert summary.out_dir == str(code_dir)
    assert len(summary.written) == 1
    assert "Function: sample_function" in text
    assert "Address: 0x00401000" in text
    assert "MOV eax, 7" in text
    assert "CMP eax, 7" in text
    assert "RET" in text


def test_export_asm_can_select_functions_from_original_map_object(tmp_path):
    pytest.importorskip("capstone")
    exe = tmp_path / "original.exe"
    write_tiny_pe(exe)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    code_dir = tmp_path / "code"
    original_map = tmp_path / "original.map"
    original_map.write_text(
        " 0001:00000000       _sample_function 00401000 f sample.obj\n"
        " 0001:00000010       _other_function 00401010 f other.obj\n",
        encoding="utf-8",
    )

    summary = export_asm(
        make_target(tmp_path, exe, source_dir, code_dir),
        ExportAsmOptions(
            clean=True,
            include_source=False,
            original_map=str(original_map),
            objects=("sample.obj",),
        ),
    )

    assert [item.address for item in summary.written] == [TEXT_VA]
    assert (code_dir / "FUN_00401000.disassembled.txt").exists()
    assert not (code_dir / "FUN_00401010.disassembled.txt").exists()


def test_export_asm_auto_discovers_functions_without_annotations(tmp_path):
    pytest.importorskip("capstone")
    code = bytearray(b"\xE8" + (0x1B).to_bytes(4, "little") + b"\xC3")
    code.extend(b"\xCC" * (0x20 - len(code)))
    code.extend(b"\x55\x8B\xEC\xB8\x2A\x00\x00\x00\x5D\xC3")
    code.extend(b"\xCC" * (0x40 - len(code)))
    code.extend(b"\x55\x8B\xEC\x33\xC0\x5D\xC3")
    exe = tmp_path / "original.exe"
    write_tiny_pe(exe, bytes(code))
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    code_dir = tmp_path / "code"

    summary = export_asm(
        make_target(tmp_path, exe, source_dir, code_dir),
        ExportAsmOptions(clean=True),
    )

    exported = {item.address for item in summary.written}
    assert TEXT_VA in exported
    assert TEXT_VA + 0x20 in exported
    assert TEXT_VA + 0x40 in exported
    assert summary.source_targets == 0
    assert summary.map_targets == 0
    assert summary.discovered_targets >= 3
    assert "CALL 0x401020" in (code_dir / "FUN_00401000.disassembled.txt").read_text(encoding="utf-8")
    assert "MOV eax, 0x2a" in (code_dir / "FUN_00401020.disassembled.txt").read_text(encoding="utf-8")


def test_export_asm_labels_gapped_reachable_blocks(tmp_path):
    pytest.importorskip("capstone")
    code = bytearray(b"\xE9" + (0x1B).to_bytes(4, "little"))  # jmp 0x401020
    code.extend(b"\xCC" * (0x20 - len(code)))
    code.extend(b"\x33\xC0\xC3")  # xor eax,eax; ret
    exe = tmp_path / "original.exe"
    write_tiny_pe(exe, bytes(code))
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "sample.cpp").write_text(
        "/* Function start: 0x00401000 */\n"
        "int sample_function() { return 0; }\n",
        encoding="utf-8",
    )
    code_dir = tmp_path / "code"

    export_asm(
        make_target(tmp_path, exe, source_dir, code_dir),
        ExportAsmOptions(clean=True),
    )

    export_path = code_dir / "FUN_00401000.disassembled.txt"
    text = export_path.read_text(encoding="utf-8")
    assert "LAB_00401020:" in text

    result = disassemble_exported_function(
        PEImage(str(exe)),
        str(export_path),
        TEXT_VA,
        max_bytes=0x100,
        padding_mnemonics=frozenset({"nop", "int3"}),
    )
    assert [instr.address for instr in result.instructions] == [TEXT_VA, TEXT_VA + 0x20, TEXT_VA + 0x22]
