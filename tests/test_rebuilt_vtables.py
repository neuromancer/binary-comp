from __future__ import annotations

import struct

import pytest

from binary_comp.analyzers.rebuilt_vtables import (
    EXTRA_SLOT,
    MISSING_SLOT,
    WRONG_FUNCTION,
    compare_rebuilt_vtables,
    read_rebuilt_vtables,
)
from binary_comp.config import ProjectTarget
from binary_comp.core.symbols import msvc_method_symbol, msvc_vftable_class

from conftest import DATA_VA, TEXT_VA, write_tiny_pe


ALPHA = TEXT_VA + 0x00
BETA = TEXT_VA + 0x10
GAMMA = TEXT_VA + 0x20

# Original addresses are arbitrary; only the source markers tie them to names.
ORIG_ALPHA = 0x00500000
ORIG_BETA = 0x00500010
ORIG_GAMMA = 0x00500020


def write_rebuilt(tmp_path, slots):
    """A rebuilt PE whose .data holds ``??_7Sample@@6B@`` = ``slots``."""
    exe = tmp_path / "rebuilt.exe"
    overrides = {index * 4: struct.pack("<I", value) for index, value in enumerate(slots)}
    write_tiny_pe(exe, data_overrides=overrides)
    return exe


def write_map(tmp_path, function_symbols):
    """A minimal MSVC map: the vftable in segment 2, functions in segment 1."""
    lines = [" 0002:00000000       ??_7Sample@@6B@            %08X     sample.obj" % DATA_VA]
    for va, mangled in function_symbols.items():
        lines.append(" 0001:00000000       %s      %08X f   sample.obj" % (mangled, va))
    path = tmp_path / "rebuilt.map"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def make_target(tmp_path, exe, map_path, kind="pe"):
    return ProjectTarget(
        name="test",
        original_exe=str(tmp_path / "original.exe"),
        rebuilt_exe=str(exe),
        map_path=str(map_path),
        source_dirs=(str(tmp_path),),
        kind=kind,
    )


DEFAULT_FUNCTION_SYMBOLS = {
    ORIG_ALPHA: [{"class_name": "Sample", "method_name": "Alpha"}],
    ORIG_BETA: [{"class_name": "Sample", "method_name": "Beta"}],
    ORIG_GAMMA: [{"class_name": "Sample", "method_name": "Gamma"}],
}

CLASSES = {"Sample": {"vtable_addr": 0x00460000}}


def run(tmp_path, rebuilt_slots, rebuilt_map, original_entries, kind="pe"):
    exe = write_rebuilt(tmp_path, rebuilt_slots)
    map_path = write_map(tmp_path, rebuilt_map)
    target = make_target(tmp_path, exe, map_path, kind=kind)
    return compare_rebuilt_vtables(
        target,
        CLASSES,
        {"Sample": original_entries},
        DEFAULT_FUNCTION_SYMBOLS,
    )


def test_msvc_vftable_class():
    assert msvc_vftable_class("??_7SC_Wahoo@@6B@") == "SC_Wahoo"
    assert msvc_vftable_class("?ProcessClick@SC_Wahoo@@UAEHPAVProjectile@@@Z") is None


@pytest.mark.parametrize(
    "mangled, expected",
    [
        ("?ProcessClick@SC_Wahoo@@UAEHPAVProjectile@@@Z", ("SC_Wahoo", "ProcessClick")),
        ("?Serialize@Handler@@UAEXPAX@Z", ("Handler", "Serialize")),
        ("??_ESC_Wahoo@@UAEPAXI@Z", ("SC_Wahoo", "~SC_Wahoo")),
        ("??1Parser@@UAE@XZ", ("Parser", "~Parser")),
        ("??0Sprite@@QAE@PAD@Z", ("Sprite", "Sprite")),
        ("??_7SC_Wahoo@@6B@", None),
        ("__purecall", None),
        ("_WinMain@16", None),
    ],
)
def test_msvc_method_symbol(mangled, expected):
    assert msvc_method_symbol(mangled) == expected


def test_reads_rebuilt_vtable_and_stops_at_padding(tmp_path):
    exe = write_rebuilt(tmp_path, [ALPHA, BETA, 0, GAMMA])
    map_path = write_map(tmp_path, {ALPHA: "?Alpha@Sample@@UAEXXZ"})
    vtables, symbols_by_va = read_rebuilt_vtables(str(exe), str(map_path))
    assert vtables["Sample"] == (DATA_VA, (ALPHA, BETA))
    assert symbols_by_va[ALPHA] == ["?Alpha@Sample@@UAEXXZ"]


def test_missing_trailing_slot_is_reported(tmp_path):
    """The SC_Wahoo bug: a non-virtual member leaves the last slot unemitted."""
    summary = run(
        tmp_path,
        rebuilt_slots=[ALPHA, BETA],
        rebuilt_map={ALPHA: "?Alpha@Sample@@UAEXXZ", BETA: "?Beta@Sample@@UAEXXZ"},
        original_entries=(ORIG_ALPHA, ORIG_BETA, ORIG_GAMMA),
    )
    assert summary.has_failures
    diff = summary.diffs[0]
    assert (diff.rebuilt_len, diff.original_len) == (2, 3)
    assert [issue.kind for issue in diff.issues] == [MISSING_SLOT]
    assert diff.issues[0].slot == 2
    assert diff.issues[0].expected == "Sample::Gamma"


def test_wrong_function_in_slot_is_reported(tmp_path):
    """A method sliding down into the wrong slot."""
    summary = run(
        tmp_path,
        rebuilt_slots=[ALPHA, GAMMA],
        rebuilt_map={ALPHA: "?Alpha@Sample@@UAEXXZ", GAMMA: "?Gamma@Sample@@UAEXXZ"},
        original_entries=(ORIG_ALPHA, ORIG_BETA),
    )
    assert summary.has_failures
    issues = summary.diffs[0].issues
    assert [issue.kind for issue in issues] == [WRONG_FUNCTION]
    assert issues[0].slot == 1
    assert issues[0].expected == "Sample::Beta"
    assert issues[0].actual == "Sample::Gamma"


def test_missing_override_with_same_method_name_is_reported(tmp_path):
    """Base::Update left in a slot the original fills with Derived::Update.

    The method names are identical, so only the address distinguishes them.
    """
    function_symbols = {
        ORIG_ALPHA: [{"class_name": "Derived", "method_name": "Alpha"}],
        ORIG_BETA: [{"class_name": "Derived", "method_name": "Update"}],
        ORIG_GAMMA: [{"class_name": "Base", "method_name": "Update"}],
    }
    exe = write_rebuilt(tmp_path, [ALPHA, GAMMA])
    map_path = write_map(
        tmp_path,
        {ALPHA: "?Alpha@Derived@@UAEXXZ", GAMMA: "?Update@Base@@UAEXXZ"},
    )
    summary = compare_rebuilt_vtables(
        make_target(tmp_path, exe, map_path),
        CLASSES,
        {"Sample": (ORIG_ALPHA, ORIG_BETA)},
        function_symbols,
    )
    assert summary.has_failures
    issue = summary.diffs[0].issues[0]
    assert issue.kind == WRONG_FUNCTION
    assert issue.expected == "Derived::Update"
    assert issue.actual == "Base::Update"


def test_extra_slot_is_reported(tmp_path):
    summary = run(
        tmp_path,
        rebuilt_slots=[ALPHA, BETA],
        rebuilt_map={ALPHA: "?Alpha@Sample@@UAEXXZ", BETA: "?Beta@Sample@@UAEXXZ"},
        original_entries=(ORIG_ALPHA,),
    )
    assert summary.has_failures
    issues = summary.diffs[0].issues
    assert [issue.kind for issue in issues] == [EXTRA_SLOT]
    assert issues[0].actual == "Sample::Beta"


def test_matching_vtable_has_no_failures(tmp_path):
    summary = run(
        tmp_path,
        rebuilt_slots=[ALPHA, BETA],
        rebuilt_map={ALPHA: "?Alpha@Sample@@UAEXXZ", BETA: "?Beta@Sample@@UAEXXZ"},
        original_entries=(ORIG_ALPHA, ORIG_BETA),
    )
    assert not summary.has_failures
    assert summary.classes_checked == 1
    assert summary.slots_checked == 2


def test_destructor_slot_is_not_flagged(tmp_path):
    """The sdtor thunk has no source marker; it must not read as a mismatch."""
    summary = run(
        tmp_path,
        rebuilt_slots=[ALPHA, BETA],
        rebuilt_map={ALPHA: "?Alpha@Sample@@UAEXXZ", BETA: "??_ESample@@UAEPAXI@Z"},
        original_entries=(ORIG_ALPHA, ORIG_BETA),
    )
    assert not summary.has_failures
    assert summary.diffs[0].unresolved == 1


def test_unknown_rebuilt_symbol_is_unresolved_not_a_failure(tmp_path):
    summary = run(
        tmp_path,
        rebuilt_slots=[ALPHA, BETA],
        rebuilt_map={ALPHA: "?Alpha@Sample@@UAEXXZ", BETA: "__purecall"},
        original_entries=(ORIG_ALPHA, ORIG_BETA),
    )
    assert not summary.has_failures
    assert summary.diffs[0].unresolved == 1


def test_non_pe_target_is_skipped(tmp_path):
    summary = run(
        tmp_path,
        rebuilt_slots=[ALPHA],
        rebuilt_map={ALPHA: "?Alpha@Sample@@UAEXXZ"},
        original_entries=(ORIG_ALPHA, ORIG_BETA),
        kind="dos16-tpu",
    )
    assert summary.skipped is not None
    assert not summary.has_failures
    assert summary.diffs == ()


def test_missing_rebuilt_exe_is_skipped_not_fatal(tmp_path):
    map_path = write_map(tmp_path, {ALPHA: "?Alpha@Sample@@UAEXXZ"})
    target = make_target(tmp_path, tmp_path / "absent.exe", map_path)
    summary = compare_rebuilt_vtables(
        target, CLASSES, {"Sample": (ORIG_ALPHA,)}, DEFAULT_FUNCTION_SYMBOLS
    )
    assert summary.skipped is not None
    assert not summary.has_failures
