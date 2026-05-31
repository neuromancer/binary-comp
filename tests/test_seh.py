from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.seh import (
    SehReport,
    SehWarning,
    diff_eh,
    format_seh_comparison,
    format_seh_report,
    SehComparison,
    SehReportRow,
)
from binary_comp.core.eh import (
    EHInfo,
    UnwindState,
    analyze_function_eh,
    decode_unwind_funclet,
    find_active_unwind_states,
    find_funcinfo,
    find_this_slot,
    parse_funcinfo,
)
from binary_comp.core.pe import PEImage

from conftest import TEXT_VA, write_tiny_pe


# --------------------------------------------------------------------------- #
# diff_eh — the warning logic (no binary needed)
# --------------------------------------------------------------------------- #

def _state(index, target, to_state=-1, conditional=False):
    return UnwindState(
        index=index,
        to_state=to_state,
        action=0x401000 + index,
        dtor=0x402000 + index,
        target=target,
        conditional=conditional,
    )


def _eh(has_frame=True, targets=(), try_blocks=(), max_state=None, unwinds=None, active_states=None):
    if unwinds is None:
        unwinds = tuple(_state(index, target) for index, target in enumerate(targets))
    else:
        targets = tuple(state.target for state in unwinds if state.action is not None)
    return EHInfo(
        has_frame=has_frame,
        funcinfo_addr=0x460000 if has_frame else None,
        magic=0x19930520 if has_frame else None,
        max_state=len(targets) if max_state is None else max_state,
        unwinds=tuple(unwinds),
        try_blocks=tuple(try_blocks),
        targets=tuple(targets),
        active_states=active_states,
    )


def _levels(warnings):
    return [w.level for w in warnings]


def _messages(warnings):
    return [w.message for w in warnings]


def test_diff_no_frame_on_either_side_is_clean():
    assert diff_eh(_eh(has_frame=False), _eh(has_frame=False)) == []


def test_diff_matching_members_is_clean():
    members = ("this+0xb4", "this+0xcc", "this+0xe8")
    assert diff_eh(_eh(targets=members), _eh(targets=members)) == []


def test_diff_rebuilt_missing_frame_warns():
    warnings = diff_eh(_eh(targets=("arg@ebp+8",)), _eh(has_frame=False))
    assert _levels(warnings) == ["warn"]
    assert "NO C++ EH frame" in warnings[0].message
    assert "arg@ebp+8" in warnings[0].message


def test_diff_rebuilt_spurious_frame_warns():
    warnings = diff_eh(_eh(has_frame=False), _eh(targets=("this+0x10",)))
    assert _levels(warnings) == ["warn"]
    assert "spurious EH frame" in warnings[0].message


def test_diff_extra_member_object_warns_with_offset():
    original = ("this+0xb4", "this+0xcc")
    rebuilt = ("this+0xb4", "this+0xcc", "this+0xe0", "this+0xf0")
    warnings = diff_eh(_eh(targets=original), _eh(targets=rebuilt))
    messages = _messages(warnings)
    assert any("EXTRA member object at this+0xe0" in m for m in messages)
    assert any("EXTRA member object at this+0xf0" in m for m in messages)
    assert all(w.level == "warn" for w in warnings)


def test_diff_missing_member_object_warns():
    original = ("this+0xb4", "this+0xcc", "this+0x114")
    rebuilt = ("this+0xb4", "this+0xcc")
    warnings = diff_eh(_eh(targets=original), _eh(targets=rebuilt))
    assert any("MISSING a member destructor at this+0x114" in m for m in _messages(warnings))


def test_diff_bare_this_mismatch_is_ignored_in_default_mode():
    warnings = diff_eh(_eh(targets=("this",)), _eh(targets=()))
    assert not any(w.level == "warn" for w in warnings)
    assert any("strict state" in m or "strict unwind" in m for m in _messages(diff_eh(_eh(targets=("this",)), _eh(targets=()), strict=True)))


def test_diff_member_count_mismatch_warns_even_when_offset_exists_on_both_sides():
    warnings = diff_eh(
        _eh(targets=("this+0xb4", "this+0xb4")),
        _eh(targets=("this+0xb4",)),
    )
    assert any("MISSING a member destructor at this+0xb4" in m for m in _messages(warnings))


def test_diff_pointer_object_count_mismatch_warns():
    original = ("ptr@ebp-0x14", "ptr@ebp-0x10")
    rebuilt = ("ptr@ebp-0x14",)
    warnings = diff_eh(_eh(targets=original), _eh(targets=rebuilt))
    assert any("'ptr' object" in m for m in _messages(warnings))


def test_diff_stack_object_count_mismatch_warns():
    warnings = diff_eh(
        _eh(targets=("stack@ebp-0x4c",)),
        _eh(targets=("stack@ebp-0xa0", "stack@ebp-0xb0")),
    )
    assert any("'stack' object" in m for m in _messages(warnings))


def test_diff_try_block_count_mismatch_warns():
    warnings = diff_eh(
        _eh(targets=("this+0x10",), try_blocks=(("t",),)),
        _eh(targets=("this+0x10",), try_blocks=()),
    )
    assert any("try-block count differs" in m for m in _messages(warnings))


def test_diff_guarded_cleanup_count_mismatch_warns_with_matching_targets():
    warnings = diff_eh(
        _eh(unwinds=(_state(0, "ptr@ebp-0x20", conditional=True),)),
        _eh(unwinds=(_state(0, "ptr@ebp-0x24", conditional=False),)),
    )
    assert any("guarded cleanup count differs for 'ptr'" in m for m in _messages(warnings))


def test_diff_state_count_difference_with_matching_objects_is_info_only():
    members = ("this+0xb4",)
    warnings = diff_eh(
        _eh(targets=members, max_state=2),
        _eh(targets=members, max_state=1),
    )
    assert _levels(warnings) == ["info"]
    assert "unwind state count differs" in warnings[0].message


def test_diff_ignores_inactive_constructor_cleanup_in_default_mode():
    original = _eh(
        unwinds=(
            _state(0, "ptr@ebp-0x10", to_state=-1),
            _state(1, "ptr@ebp-0x10", to_state=0),
        ),
        max_state=2,
        active_states=(0,),
    )
    rebuilt = _eh(
        unwinds=(_state(0, "ptr@ebp-0x10", to_state=-1),),
        max_state=1,
        active_states=(0,),
    )
    warnings = diff_eh(original, rebuilt)
    assert not any(w.level == "warn" for w in warnings)
    assert any("strict unwind state count differs" in m for m in _messages(diff_eh(original, rebuilt, strict=True)))


def test_diff_strict_catches_same_kind_different_exact_stack_slot():
    original = _eh(unwinds=(_state(0, "stack@ebp-0x20"),))
    rebuilt = _eh(unwinds=(_state(0, "stack@ebp-0x24"),))
    assert diff_eh(original, rebuilt) == []
    warnings = diff_eh(original, rebuilt, strict=True)
    assert any("strict state 0 differs" in m for m in _messages(warnings))


def test_diff_strict_catches_to_state_difference():
    original = _eh(unwinds=(_state(0, "this+0xb4", to_state=-1),))
    rebuilt = _eh(unwinds=(_state(0, "this+0xb4", to_state=1),))
    assert diff_eh(original, rebuilt) == []
    warnings = diff_eh(original, rebuilt, strict=True)
    assert any("strict state 0 differs" in m for m in _messages(warnings))


# --------------------------------------------------------------------------- #
# core/eh.py — parsing against a hand-built C++ EH function
# --------------------------------------------------------------------------- #

def _build_eh_blob() -> bytes:
    """A 0x200-byte .text image with one full C++ EH function at TEXT_VA.

    Layout (VA): function 0x401000, ehhandler thunk 0x401040, FuncInfo 0x401050,
    unwind map 0x401064, member-dtor funclet 0x401080, operator-delete funclet
    0x401090, (dummy dtor/operator-delete targets 0x4011A0/0x4011B0).
    """
    blob = bytearray(b"\x90" * 0x200)

    def put(va: int, data: bytes) -> None:
        off = va - TEXT_VA
        blob[off:off + len(data)] = data

    # function prologue (+ this save + ret)
    put(0x401000, bytes([
        0x64, 0xA1, 0, 0, 0, 0,                 # mov eax, fs:[0]
        0x55,                                   # push ebp
        0x8B, 0xEC,                             # mov ebp, esp
        0x6A, 0xFF,                             # push -1
        0x68, 0x40, 0x10, 0x40, 0x00,           # push 0x401040 (ehhandler)
        0x50,                                   # push eax
        0x64, 0x89, 0x25, 0, 0, 0, 0,           # mov fs:[0], esp
        0x83, 0xEC, 0x08,                       # sub esp, 8
        0x89, 0x4D, 0xF0,                       # mov [ebp-0x10], ecx  (this save)
        0xC3,                                   # ret
    ]))
    # ehhandler thunk: mov eax, <FuncInfo>; jmp +0
    put(0x401040, bytes([0xB8, 0x50, 0x10, 0x40, 0x00, 0xE9, 0, 0, 0, 0]))
    # FuncInfo
    put(0x401050, struct.pack("<IiIiI", 0x19930520, 2, 0x401064, 0, 0))
    # UnwindMap: state0 -> -1 via funclet0 (member); state1 -> 0 via funclet1 (delete)
    put(0x401064, struct.pack("<iI", -1, 0x401080) + struct.pack("<iI", 0, 0x401090))
    # funclet0: mov ecx,[ebp-0x10]; add ecx,0x114; jmp 0x4011A0
    rel0 = (0x4011A0 - 0x40108E) & 0xFFFFFFFF
    put(0x401080, bytes([0x8B, 0x4D, 0xF0, 0x81, 0xC1, 0x14, 0x01, 0x00, 0x00, 0xE9]) + struct.pack("<I", rel0))
    # funclet1: mov eax,[ebp-0x14]; push eax; call 0x4011B0; add esp,4; ret
    rel1 = (0x4011B0 - 0x401099) & 0xFFFFFFFF
    put(0x401090, bytes([0x8B, 0x45, 0xEC, 0x50, 0xE8]) + struct.pack("<I", rel1) + bytes([0x83, 0xC4, 0x04, 0xC3]))
    return bytes(blob)


@pytest.fixture
def eh_image(tmp_path):
    pytest.importorskip("capstone")
    exe = tmp_path / "eh.exe"
    write_tiny_pe(exe, _build_eh_blob())
    return PEImage(str(exe))


def test_find_funcinfo_and_this_slot(eh_image):
    assert find_funcinfo(eh_image, TEXT_VA) == 0x401050
    assert find_this_slot(eh_image, TEXT_VA) == "ebp-0x10"


def test_find_funcinfo_returns_none_without_eh_frame(tmp_path):
    pytest.importorskip("capstone")
    # default tiny PE function is `mov eax,7; cmp eax,7; ret` — no EH prologue
    exe = tmp_path / "plain.exe"
    write_tiny_pe(exe)
    assert find_funcinfo(PEImage(str(exe)), TEXT_VA) is None


def test_parse_funcinfo_unwind_map(eh_image):
    max_state, unwinds, try_blocks = parse_funcinfo(eh_image, 0x401050, this_slot="ebp-0x10")
    assert max_state == 2
    assert try_blocks == ()
    assert [u.target for u in unwinds] == ["this+0x114", "ptr@ebp-0x14"]
    assert [u.to_state for u in unwinds] == [-1, 0]
    assert unwinds[0].dtor == 0x4011A0


def test_decode_member_funclet_uses_this_slot(eh_image):
    dtor, target, conditional = decode_unwind_funclet(eh_image, 0x401080, this_slot="ebp-0x10")
    assert target == "this+0x114"
    assert dtor == 0x4011A0
    assert conditional is False


def test_decode_member_funclet_without_this_slot_is_pointer(eh_image):
    # Without the this-slot it cannot know [ebp-0x10] is `this`, so it stays a ptr.
    _, target, _ = decode_unwind_funclet(eh_image, 0x401080, this_slot=None)
    assert target == "ptr@ebp-0x10+0x114"


def test_decode_operator_delete_funclet(eh_image):
    dtor, target, _ = decode_unwind_funclet(eh_image, 0x401090, this_slot="ebp-0x10")
    assert target == "ptr@ebp-0x14"
    assert dtor == 0x4011B0


def test_normalize_lea_argument_funclet(tmp_path):
    pytest.importorskip("capstone")
    blob = bytearray(b"\x90" * 0x80)
    blob[0x40:0x4A] = bytes([
        0x8D, 0x4D, 0x08,                       # lea ecx,[ebp+0x8]
        0xE9, 0x58, 0x01, 0x00, 0x00,           # jmp 0x4011A0
        0x90, 0x90,
    ])
    exe = tmp_path / "lea_arg.exe"
    write_tiny_pe(exe, bytes(blob))
    dtor, target, _ = decode_unwind_funclet(PEImage(str(exe)), TEXT_VA + 0x40)
    assert target == "arg@ebp+8"
    assert dtor == 0x4011A0


def test_analyze_function_eh_end_to_end(eh_image):
    info = analyze_function_eh(eh_image, TEXT_VA)
    assert info.has_frame is True
    assert info.funcinfo_addr == 0x401050
    assert info.magic == 0x19930520
    assert info.max_state == 2
    assert info.targets == ("this+0x114", "ptr@ebp-0x14")


def test_find_active_unwind_states_follows_to_state_chain(eh_image, tmp_path):
    max_state, unwinds, _ = parse_funcinfo(eh_image, 0x401050, this_slot="ebp-0x10")
    assert max_state == 2
    blob = bytearray(_build_eh_blob())
    # Replace the function ret with:
    #   mov eax, 1
    #   mov byte ptr [ebp-4], al
    #   ret
    off = (TEXT_VA + 0x1E) - TEXT_VA
    blob[off:off + 9] = bytes([0xB8, 0x01, 0, 0, 0, 0x88, 0x45, 0xFC, 0xC3])
    exe = tmp_path / "active_state.exe"
    write_tiny_pe(exe, bytes(blob))
    active = find_active_unwind_states(PEImage(str(exe)), TEXT_VA, unwinds)
    assert active == (0, 1)


def test_analyze_function_eh_no_frame(tmp_path):
    pytest.importorskip("capstone")
    exe = tmp_path / "plain.exe"
    write_tiny_pe(exe)
    info = analyze_function_eh(PEImage(str(exe)), TEXT_VA)
    assert info.has_frame is False
    assert info.targets == ()


def test_analyze_then_diff_reports_no_difference_against_itself(eh_image):
    info = analyze_function_eh(eh_image, TEXT_VA)
    assert diff_eh(info, info) == []


# --------------------------------------------------------------------------- #
# formatting smoke tests
# --------------------------------------------------------------------------- #

def test_format_seh_comparison_ok_and_warning():
    matching = _eh(targets=("this+0xb4",))
    ok = format_seh_comparison(SehComparison("F", 0x1000, 0x2000, matching, matching, ()))
    assert "OK: exception-handling structure matches." in ok

    warned = format_seh_comparison(SehComparison(
        "F", 0x1000, 0x2000, matching, _eh(has_frame=False),
        (SehWarning("warn", "rebuilt has NO C++ EH frame"),),
    ))
    assert "WARNING: rebuilt has NO C++ EH frame" in warned


def test_format_seh_report_groups_by_file():
    rows = [
        SehReportRow("A.cpp", "A::f", 0x401000, (SehWarning("warn", "missing dtor"),)),
        SehReportRow("A.cpp", "A::g", 0x401050, (SehWarning("warn", "extra dtor"),)),
    ]
    text = format_seh_report(rows)
    assert "=== A.cpp ===" in text
    assert "A::f  (0x401000)" in text
    assert "2 function(s) with EH-structure differences." in text
    assert format_seh_report([]) == "No exception-handling differences found."


def test_format_seh_report_summary_for_report_object():
    report = SehReport(
        rows=(
            SehReportRow("A.cpp", "A::f", 0x401000, (SehWarning("warn", "missing dtor"),)),
        ),
        scanned=3,
        mapped=2,
        missing=1,
        original_frames=2,
        rebuilt_frames=1,
        both_frames=1,
        original_only=1,
        rebuilt_only=0,
        strict=True,
    )
    text = format_seh_report(report)
    assert "--- strict SEH structure differences ---" in text
    assert "Scanned 3 function(s), mapped 2, missing 1" in text
