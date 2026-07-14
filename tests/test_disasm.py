from __future__ import annotations

import struct

import pytest

from binary_comp.core.disasm import disassemble_x86
from binary_comp.core.pe import PEImage

from conftest import TEXT_VA, write_tiny_pe


pytest.importorskip("capstone")


def test_disassemble_removes_msvc_byte_switch_map(tmp_path):
    code = bytearray()
    code.extend(b"\x83\xf8\x03")  # cmp eax, 3
    code.extend(b"\x77\x08")      # ja default
    code.extend(b"\x33\xd2")      # xor edx, edx
    code.extend(b"\x8a\x90" + struct.pack("<I", TEXT_VA + 0x20))
    code.extend(b"\xff\x24\x95" + struct.pack("<I", TEXT_VA + 0x28))
    code.extend(b"\xc3")
    code = code.ljust(0x20, b"\x90")
    code.extend(b"\x00\x01\x02\x03")
    code = code.ljust(0x28, b"\x90")
    code.extend(struct.pack("<IIII", TEXT_VA, TEXT_VA + 2, TEXT_VA + 4, TEXT_VA + 6))

    exe = tmp_path / "sample.exe"
    write_tiny_pe(exe, bytes(code))

    instrs = disassemble_x86(
        PEImage(str(exe)),
        TEXT_VA,
        [TEXT_VA, TEXT_VA + 0x40],
        max_bytes=0x40,
        padding_mnemonics=frozenset({"nop", "int3"}),
    )

    assert {instr.address for instr in instrs}.isdisjoint(range(TEXT_VA + 0x20, TEXT_VA + 0x38))


def test_disassemble_resyncs_after_an_inline_jump_table(tmp_path):
    """A switch table sitting between the dispatch and the case bodies must not
    drag the decoder off the instruction boundaries of the code that follows it.

    The four table entries here decode into instructions that straddle the end of
    the table, so a sweep that runs straight through the table lands mid-opcode
    and never recovers the case bodies.
    """
    table = TEXT_VA + 0x0c
    body = TEXT_VA + 0x1c

    code = bytearray()
    code.extend(b"\x83\xf8\x03")                                # cmp eax, 3
    code.extend(b"\x77\x14")                                    # ja default
    code.extend(b"\xff\x24\x85" + struct.pack("<I", table))     # jmp [eax*4 + table]
    assert len(code) == 0x0c
    code.extend(struct.pack("<IIII", body, body, body, body))   # the table
    assert len(code) == 0x1c
    code.extend(b"\x40\x40\xc3")                                # case body
    code.extend(b"\x33\xc0\xc3")                                # default

    exe = tmp_path / "sample.exe"
    write_tiny_pe(exe, bytes(code))

    instrs = disassemble_x86(
        PEImage(str(exe)),
        TEXT_VA,
        [TEXT_VA, TEXT_VA + 0x40],
        max_bytes=0x40,
        padding_mnemonics=frozenset({"nop", "int3"}),
    )
    addresses = {instr.address for instr in instrs}

    # The table is data, so none of it may show up as instructions ...
    assert addresses.isdisjoint(range(table, body))
    # ... and every instruction after it must land on a real boundary.
    assert {body, body + 1, body + 2, body + 3, body + 5} <= addresses
