from __future__ import annotations

from binary_comp.analyzers.global_access import (
    extract_compiled_global_accesses,
    extract_original_global_accesses,
)
from binary_comp.analyzers.globals import AutoGlobalRange


def test_extract_original_global_accesses_classifies_reads_and_writes(tmp_path):
    disasm = tmp_path / "FUN_401000.disassembled.txt"
    disasm.write_text(
        """
Function: FUN_00401000
Address: 0x401000

MOV EAX,[0x00402010]
ADD dword ptr [0x00402018],EAX
LEA EDI,[0x00402020]
MOV EAX,dword ptr [EBX + EDI*0x1]
MOV byte ptr [EBX + 0x00402030],AL
MOV ECX,0x00402020
MOV dword ptr [ECX + 0x4],EAX
MOV EDI,0x00402020
MOV ESI,0x00402010
MOVSD.REP ES:EDI,ESI
PUSH 0x00402010
""",
        encoding="utf-8",
    )
    ranges = [
        AutoGlobalRange(0x402010, 0x402014, "g_Source_00402010", 1),
        AutoGlobalRange(0x402018, 0x40201C, "g_Target_00402018", 2),
        AutoGlobalRange(0x402020, 0x402030, "g_Array_00402020", 3),
        AutoGlobalRange(0x402030, 0x402040, "g_Indexed_00402030", 4),
    ]

    assert extract_original_global_accesses(str(disasm), ranges, [(0x402000, 0x402100)]) == [
        "READ:g_Source_00402010",
        "READ:g_Target_00402018",
        "WRITE:g_Target_00402018",
        "READ:g_Array_00402020",
        "WRITE:g_Indexed_00402030",
        "WRITE:g_Array_00402020+0x4",
        "WRITE:g_Array_00402020",
        "READ:g_Source_00402010",
    ]
    assert extract_original_global_accesses(
        str(disasm),
        ranges,
        [(0x402000, 0x402100)],
        include_address_immediates=True,
    ) == [
        "READ:g_Source_00402010",
        "READ:g_Target_00402018",
        "WRITE:g_Target_00402018",
        "ADDR:g_Array_00402020",
        "READ:g_Array_00402020",
        "WRITE:g_Indexed_00402030",
        "ADDR:g_Array_00402020",
        "WRITE:g_Array_00402020+0x4",
        "ADDR:g_Array_00402020",
        "ADDR:g_Source_00402010",
        "WRITE:g_Array_00402020",
        "READ:g_Source_00402010",
        "ADDR:g_Source_00402010",
    ]


def test_extract_original_global_accesses_tracks_register_moves_and_subregister_clobbers(tmp_path):
    disasm = tmp_path / "FUN_401100.disassembled.txt"
    disasm.write_text(
        """
Function: FUN_00401100
Address: 0x401100

LEA EDX,[0x00402020]
MOV EDI,EDX
MOV ESI,0x00402010
REP MOVSD
LEA EDI,[ESI + 0x2]
MOV EDX,dword ptr [EDI]
MOVSX EDI,word ptr [0x00402020]
MOV EDX,dword ptr [EDI]
LEA EAX,[0x00402020]
MOV AX,word ptr [EAX]
SUB AX,0x1
MOV ECX,dword ptr [EAX + 0x4]
""",
        encoding="utf-8",
    )
    ranges = [
        AutoGlobalRange(0x402010, 0x402014, "g_Source_00402010", 1),
        AutoGlobalRange(0x402020, 0x402030, "g_Array_00402020", 2),
    ]

    assert extract_original_global_accesses(str(disasm), ranges, [(0x402000, 0x402100)]) == [
        "WRITE:g_Array_00402020",
        "READ:g_Source_00402010",
        "READ:g_Source_00402010+0x2",
        "READ:g_Array_00402020",
        "READ:g_Array_00402020",
    ]


def test_extract_original_global_accesses_preserves_callee_saved_register_bases_across_calls(tmp_path):
    disasm = tmp_path / "FUN_401200.disassembled.txt"
    disasm.write_text(
        """
Function: FUN_00401200
Address: 0x401200

MOV ESI,0x00402010
MOV EAX,0x00402020
CALL 0x00401000
MOV ECX,dword ptr [ESI + 0x2]
MOV EDX,dword ptr [EAX]
""",
        encoding="utf-8",
    )
    ranges = [
        AutoGlobalRange(0x402010, 0x402014, "g_Source_00402010", 1),
        AutoGlobalRange(0x402020, 0x402030, "g_Array_00402020", 2),
    ]

    assert extract_original_global_accesses(str(disasm), ranges, [(0x402000, 0x402100)]) == [
        "READ:g_Source_00402010+0x2",
    ]


def test_extract_compiled_global_accesses_classifies_symbols(tmp_path):
    asm = tmp_path / "sample.asm"
    asm.write_text(
        """
_TEXT SEGMENT
?Run@@YAXXZ PROC NEAR ; Run
    mov eax, DWORD PTR ?g_Source_00402010@@3HA ; g_Source_00402010
    mov DWORD PTR ?g_Target_00402018@@3HA, eax ; g_Target_00402018
    mov eax, DWORD PTR ?g_Array_00402020@@3PAHA+12 ; g_Array_00402020
    mov eax, DWORD PTR ?g_Array_00402020@@3PAHA[ecx+8] ; g_Array_00402020
    mov ecx, OFFSET FLAT:?g_Array_00402020@@3PAHA ; g_Array_00402020
    mov DWORD PTR [ecx+4], eax
    mov edi, OFFSET FLAT:?g_Array_00402020@@3PAHA ; g_Array_00402020
    mov esi, OFFSET FLAT:?g_Source_00402010@@3HA ; g_Source_00402010
    rep movsd
    push OFFSET FLAT:?g_Source_00402010@@3HA ; g_Source_00402010
    push OFFSET FLAT:?g_Array_00402020@@3PAHA+16 ; g_Array_00402020
?Run@@YAXXZ ENDP
_TEXT ENDS
""",
        encoding="utf-8",
    )

    assert extract_compiled_global_accesses(
        str(asm),
        "Run",
        0,
        frozenset({"g_Source_00402010", "g_Target_00402018", "g_Array_00402020"}),
        frozenset(),
    ) == [
        "READ:g_Source_00402010",
        "WRITE:g_Target_00402018",
        "READ:g_Array_00402020+0xc",
        "READ:g_Array_00402020+0x8",
        "WRITE:g_Array_00402020+0x4",
        "WRITE:g_Array_00402020",
        "READ:g_Source_00402010",
    ]
    assert extract_compiled_global_accesses(
        str(asm),
        "Run",
        0,
        frozenset({"g_Source_00402010", "g_Target_00402018", "g_Array_00402020"}),
        frozenset(),
        include_address_immediates=True,
    ) == [
        "READ:g_Source_00402010",
        "WRITE:g_Target_00402018",
        "READ:g_Array_00402020+0xc",
        "READ:g_Array_00402020+0x8",
        "ADDR:g_Array_00402020",
        "WRITE:g_Array_00402020+0x4",
        "ADDR:g_Array_00402020",
        "ADDR:g_Source_00402010",
        "WRITE:g_Array_00402020",
        "READ:g_Source_00402010",
        "ADDR:g_Source_00402010",
        "ADDR:g_Array_00402020+0x10",
    ]


def test_extract_compiled_global_accesses_classifies_c_symbols(tmp_path):
    asm = tmp_path / "sample_c.asm"
    asm.write_text(
        """
_TEXT SEGMENT
_Run PROC NEAR ; Run
    mov eax, DWORD PTR _g_Source_00402010
    mov DWORD PTR _g_Target_00402018, eax
    mov eax, DWORD PTR _g_Array_00402020+12
    mov eax, DWORD PTR _g_Array_00402020[ecx+8]
    mov ecx, OFFSET FLAT:_g_Array_00402020
    mov DWORD PTR [ecx+4], eax
    push OFFSET FLAT:_g_Source_00402010
_Run ENDP
_TEXT ENDS
""",
        encoding="utf-8",
    )

    assert extract_compiled_global_accesses(
        str(asm),
        "Run",
        0,
        frozenset({"g_Source_00402010", "g_Target_00402018", "g_Array_00402020"}),
        frozenset(),
    ) == [
        "READ:g_Source_00402010",
        "WRITE:g_Target_00402018",
        "READ:g_Array_00402020+0xc",
        "READ:g_Array_00402020+0x8",
        "WRITE:g_Array_00402020+0x4",
    ]
    assert extract_compiled_global_accesses(
        str(asm),
        "Run",
        0,
        frozenset({"g_Source_00402010", "g_Target_00402018", "g_Array_00402020"}),
        frozenset(),
        include_address_immediates=True,
    ) == [
        "READ:g_Source_00402010",
        "WRITE:g_Target_00402018",
        "READ:g_Array_00402020+0xc",
        "READ:g_Array_00402020+0x8",
        "ADDR:g_Array_00402020",
        "WRITE:g_Array_00402020+0x4",
        "ADDR:g_Source_00402010",
    ]


def test_extract_compiled_global_accesses_tracks_register_moves_and_subregister_clobbers(tmp_path):
    asm = tmp_path / "sample_registers.asm"
    asm.write_text(
        """
_TEXT SEGMENT
_Run PROC NEAR ; Run
    mov edx, OFFSET FLAT:_g_Array_00402020
    mov edi, edx
    mov esi, OFFSET FLAT:_g_Source_00402010
    rep movsd
    lea edi, DWORD PTR [esi+2]
    mov edx, DWORD PTR [edi]
    movsx edi, WORD PTR _g_Array_00402020
    mov edx, DWORD PTR [edi]
    mov eax, OFFSET FLAT:_g_Array_00402020
    mov ax, WORD PTR [eax]
    sub ax, 1
    mov ecx, DWORD PTR [eax+4]
_Run ENDP
_TEXT ENDS
""",
        encoding="utf-8",
    )

    assert extract_compiled_global_accesses(
        str(asm),
        "Run",
        0,
        frozenset({"g_Source_00402010", "g_Array_00402020"}),
        frozenset(),
    ) == [
        "WRITE:g_Array_00402020",
        "READ:g_Source_00402010",
        "READ:g_Source_00402010+0x2",
        "READ:g_Array_00402020",
        "READ:g_Array_00402020",
    ]


def test_extract_compiled_global_accesses_preserves_callee_saved_register_bases_across_calls(tmp_path):
    asm = tmp_path / "sample_call_registers.asm"
    asm.write_text(
        """
_TEXT SEGMENT
_Run PROC NEAR ; Run
    mov esi, OFFSET FLAT:_g_Source_00402010
    mov eax, OFFSET FLAT:_g_Array_00402020
    call _Something
    mov ecx, DWORD PTR [esi+2]
    mov edx, DWORD PTR [eax]
_Run ENDP
_TEXT ENDS
""",
        encoding="utf-8",
    )

    assert extract_compiled_global_accesses(
        str(asm),
        "Run",
        0,
        frozenset({"g_Source_00402010", "g_Array_00402020"}),
        frozenset(),
    ) == [
        "READ:g_Source_00402010+0x2",
    ]
