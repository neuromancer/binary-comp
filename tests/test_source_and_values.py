from __future__ import annotations

from pathlib import Path

import pytest

from binary_comp.analyzers.calls import (
    auto_detect_named_functions,
    build_same_address_aliases,
    check_calls,
    collect_source_address_issues,
    canonicalize,
    CallsOptions,
    CallsSummary,
    extract_calls_from_compiled,
    extract_calls_from_original,
    extract_calls_from_original_instructions,
    filter_proven_source_aliases,
    format_calls_summary,
    load_calls_policy,
    merge_call_lists_max,
    normalize_compiled,
    parse_indirect_call,
    policy_with_same_address_aliases,
    resolve_original_call,
    SourceAddressWarning,
)
from binary_comp.analyzers.values import (
    CheckResult,
    CompareContext,
    ValuesOptions,
    ValuesSummary,
    check_values,
    compare_instruction_pair,
    format_summary,
    load_policy,
    same_effective_lea_displacement,
)
from binary_comp.config import BuildConfig, ProjectTarget, load_project_target
from binary_comp.core.disasm import Instruction, Operand
from binary_comp.source.cpp import parse_source_function_groups
from binary_comp.source.functions import FunctionGroup, load_source_groups, map_source_groups


pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_cpp")


class NoStringsImage:
    def c_string_at(self, *_args, **_kwargs):
        return None


def test_source_function_groups_from_cpp_fixture(fixture_root):
    groups = parse_source_function_groups(str(fixture_root / "src" / "sample.cpp"))

    assert len(groups) == 1
    assert groups[0].name == "sample_function"
    assert groups[0].addresses == ("00401000",)


def test_source_function_groups_can_add_configured_signatures(tmp_path):
    source = tmp_path / "overload.cpp"
    source.write_text(
        """
struct Item {};
struct Box {
  Item* Take(Item* item);
};
/* Function start: 0x00401000 */
Item* Box::Take(Item* item) { return item; }
""",
        encoding="utf-8",
    )

    groups = parse_source_function_groups(str(source), signature_names=frozenset({"Box::Take"}))

    assert groups[0].name == "Box::Take(Item*)"


def test_msvc_member_name_can_use_configured_signature():
    symbol = "?Take@Box@@QAEPAVItem@@PAV2@@Z"

    assert normalize_compiled(symbol, frozenset({"Box::Take"})) == "Box::Take(Item*)"


def test_msvc_member_name_can_decode_primitive_signature():
    symbol = "?SetScale@CDrawablePart@@QAEXMM@Z"

    assert normalize_compiled(symbol, frozenset({"CDrawablePart::SetScale"})) == (
        "CDrawablePart::SetScale(float,float)"
    )


def test_msvc_member_name_can_decode_value_type_signature():
    symbol = "?SetScale@CDrawablePart@@UAEXUxRect@@@Z"

    assert normalize_compiled(symbol, frozenset({"CDrawablePart::SetScale"})) == (
        "CDrawablePart::SetScale(xRect)"
    )


def test_call_policy_auto_aliases_same_original_address(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "a.cpp").write_text(
        "/* Function start: 0x00401000 */\nvoid Alpha() {}\n",
        encoding="utf-8",
    )
    (source_dir / "b.cpp").write_text(
        "/* Function start: 0x00401000 */\nvoid Beta() {}\n",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe="",
        rebuilt_exe="",
        map_path="",
        source_dirs=(str(source_dir),),
    )
    policy = load_calls_policy({})

    assert build_same_address_aliases(target, policy) == {"Alpha": "Beta"}

    effective = policy_with_same_address_aliases(target, policy)

    assert canonicalize("Alpha", effective) == "Beta"


def test_call_source_address_issues_report_duplicate_markers(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "a.cpp").write_text(
        "/* Function start: 0x00401000 */\nvoid Alpha() {}\n",
        encoding="utf-8",
    )
    (source_dir / "b.cpp").write_text(
        "/* Function start: 0x00401000 */\nvoid Beta() {}\n",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe="",
        rebuilt_exe="",
        map_path="",
        source_dirs=(str(source_dir),),
    )
    policy = load_calls_policy({})

    issues = collect_source_address_issues(target, policy)

    assert 0x401000 in issues
    assert any(issue.kind == "duplicate" for issue in issues[0x401000])


def test_call_source_address_issues_suppress_proven_asm_aliases(tmp_path):
    source_dir = tmp_path / "src"
    asm_dir = tmp_path / "out"
    source_dir.mkdir()
    asm_dir.mkdir()
    (source_dir / "a.cpp").write_text(
        "/* Function start: 0x00401000 */\nint Alpha() { return 0; }\n",
        encoding="utf-8",
    )
    (source_dir / "b.cpp").write_text(
        "/* Function start: 0x00401000 */\nint Beta() { return 0; }\n",
        encoding="utf-8",
    )
    (asm_dir / "a.asm").write_text(
        "?Alpha@@YAHXZ PROC NEAR ; Alpha, COMDAT\n"
        "    xor eax, eax\n"
        "    ret 0\n"
        "?Alpha@@YAHXZ ENDP\n",
        encoding="utf-8",
    )
    (asm_dir / "b.asm").write_text(
        "?Beta@@YAHXZ PROC NEAR ; Beta, COMDAT\n"
        "    xor eax, eax\n"
        "    ret 0\n"
        "?Beta@@YAHXZ ENDP\n",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe="",
        rebuilt_exe="",
        map_path="",
        source_dirs=(str(source_dir),),
        asm_dir=str(asm_dir),
    )
    policy = load_calls_policy({})

    issues = filter_proven_source_aliases(
        collect_source_address_issues(target, policy),
        target,
        policy,
    )

    assert 0x401000 not in issues


def test_call_source_address_issues_keep_different_asm_bodies(tmp_path):
    source_dir = tmp_path / "src"
    asm_dir = tmp_path / "out"
    source_dir.mkdir()
    asm_dir.mkdir()
    (source_dir / "a.cpp").write_text(
        "/* Function start: 0x00401000 */\nint Alpha() { return 0; }\n",
        encoding="utf-8",
    )
    (source_dir / "b.cpp").write_text(
        "/* Function start: 0x00401000 */\nint Beta() { return 1; }\n",
        encoding="utf-8",
    )
    (asm_dir / "a.asm").write_text(
        "?Alpha@@YAHXZ PROC NEAR ; Alpha, COMDAT\n"
        "    xor eax, eax\n"
        "    ret 0\n"
        "?Alpha@@YAHXZ ENDP\n",
        encoding="utf-8",
    )
    (asm_dir / "b.asm").write_text(
        "?Beta@@YAHXZ PROC NEAR ; Beta, COMDAT\n"
        "    mov eax, 1\n"
        "    ret 0\n"
        "?Beta@@YAHXZ ENDP\n",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe="",
        rebuilt_exe="",
        map_path="",
        source_dirs=(str(source_dir),),
        asm_dir=str(asm_dir),
    )
    policy = load_calls_policy({})

    issues = filter_proven_source_aliases(
        collect_source_address_issues(target, policy),
        target,
        policy,
    )

    assert 0x401000 in issues


def test_call_source_address_issues_report_address_islands(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "engine.cpp").write_text(
        """
/* Function start: 0x00449000 */
void Engine_A() {}
/* Function start: 0x00449100 */
void Engine_B() {}
/* Function start: 0x00449200 */
void Engine_C() {}
/* Function start: 0x0042BF00 */
void Engine_WrongHelper() {}
""",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe="",
        rebuilt_exe="",
        map_path="",
        source_dirs=(str(source_dir),),
    )
    policy = load_calls_policy({})

    issues = collect_source_address_issues(target, policy)

    assert 0x42BF00 in issues
    assert any(issue.kind == "island" for issue in issues[0x42BF00])


def test_call_summary_shows_source_address_warnings_on_clean_call_match():
    summary = CallsSummary(
        functions_selected=1,
        functions_checked=1,
        mismatches=(),
        skipped_no_disasm=(),
        source_address_warnings=(
            SourceAddressWarning(
                address=0x42BF00,
                resolved_name="Engine::StopAndCleanup",
                details=("address island in src/Engine.cpp",),
                callers=("SC_Pods::ShutDown",),
            ),
        ),
        iat_loaded=1,
        report_all=False,
        strict_memory=False,
        include_trivial=False,
    )

    text = format_calls_summary(summary)

    assert "All call targets match!" in text
    assert "Source address resolution warnings:" in text
    assert "0x0042BF00 resolved as Engine::StopAndCleanup" in text


def test_call_checker_warns_when_clean_match_depends_on_address_island(tmp_path):
    source_dir = tmp_path / "src"
    code_dir = tmp_path / "code"
    asm_dir = tmp_path / "out"
    source_dir.mkdir()
    code_dir.mkdir()
    asm_dir.mkdir()

    (source_dir / "engine.cpp").write_text(
        """
/* Function start: 0x00449000 */
void Engine_A() {}
/* Function start: 0x00449100 */
void Engine_B() {}
/* Function start: 0x00449200 */
void Engine_C() {}
/* Function start: 0x0042BF00 */
void WrongHelper() {}
/* Function start: 0x004419E0 */
void Caller() {}
""",
        encoding="utf-8",
    )
    (code_dir / "FUN_4419E0.disassembled.txt").write_text(
        """
Function: FUN_004419e0
Address: 0x004419E0

CALL 0x0042BF00
RET
""",
        encoding="utf-8",
    )
    (asm_dir / "engine.asm").write_text(
        """
_TEXT SEGMENT
?Caller@@YAXXZ PROC NEAR ; Caller
    call WrongHelper ; WrongHelper
?Caller@@YAXXZ ENDP
_TEXT ENDS
""",
        encoding="utf-8",
    )
    target = ProjectTarget(
        name="full",
        original_exe="",
        rebuilt_exe="",
        map_path="",
        source_dirs=(str(source_dir),),
        code_dir=str(code_dir),
        asm_dir=str(asm_dir),
    )

    summary = check_calls({}, target, CallsOptions(filters=("Caller",), build=False))

    assert not summary.mismatches
    assert len(summary.source_address_warnings) == 1
    assert summary.source_address_warnings[0].address == 0x42BF00
    assert summary.source_address_warnings[0].resolved_name == "WrongHelper"


def test_source_groups_respect_excluded_files(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    keep = source_dir / "keep.cpp"
    skip = source_dir / "skip.cpp"
    keep.write_text("/* Function start: 0x00401000 */\nvoid Keep() {}\n", encoding="utf-8")
    skip.write_text("/* Function start: 0x00401010 */\nvoid Skip() {}\n", encoding="utf-8")

    groups = load_source_groups((str(source_dir),), source_excludes=(str(skip),))

    assert tuple(Path(path).name for path in groups) == ("keep.cpp",)


def test_call_address_map_uses_named_disassembly_headers(tmp_path):
    code_dir = tmp_path / "code"
    code_dir.mkdir()
    (code_dir / "FUN_00401000.disassembled.txt").write_text(
        "Function: NamedHelper\nAddress: 0x401000\n\nRET\n",
        encoding="utf-8",
    )

    detected = auto_detect_named_functions(str(code_dir))

    assert detected[0x401000] == "NamedHelper"


def test_named_disassembly_header_resolves_only_when_compiled_target_matches():
    policy = load_calls_policy({"calls": {"canonical_aliases": {"ThunkHelper": "RealHelper"}}})

    assert resolve_original_call(
        0x401000,
        {},
        {0x401000: "ThunkHelper"},
        frozenset({"RealHelper"}),
        policy,
    ) == "ThunkHelper"
    assert resolve_original_call(
        0x401010,
        {},
        {0x401010: "UnrelatedHelper"},
        frozenset({"RealHelper"}),
        policy,
    ) == "FUN_00401010"


def test_stack_indirect_calls_are_not_vtable_calls(tmp_path):
    policy = load_calls_policy({})

    assert parse_indirect_call("CALL dword ptr [ESP + 0x28]", policy) == "__indirect__"
    assert parse_indirect_call("CALL dword ptr [EAX + 0x28]", policy) == "indirect[0x28]"

    asm_path = tmp_path / "stack-callback.asm"
    asm_path.write_text(
        """
_TEXT SEGMENT
?Run@@YAXXZ PROC NEAR ; Run, COMDAT
    call DWORD PTR _cmpFunc$[esp+20]
?Run@@YAXXZ ENDP
_TEXT ENDS
""",
        encoding="utf-8",
    )

    assert extract_calls_from_compiled(str(asm_path), "Run") == ["__indirect__"]


def test_original_tail_jump_to_known_pointer_counts_as_call(tmp_path):
    policy = load_calls_policy({
        "calls": {
            "function_pointer_globals": {
                "0x004B84F4": "GetTickCount",
            },
        },
    })
    disasm_path = tmp_path / "tail.disassembled.txt"
    disasm_path.write_text(
        """
Function: TailThunk
Address: 0x401000

JMP dword ptr [0x004b84f4]
JMP      LAB_00401020
""",
        encoding="utf-8",
    )

    assert extract_calls_from_original(str(disasm_path), policy) == ["GetTickCount"]


def test_capstone_original_calls_use_same_target_vocabulary(monkeypatch):
    policy = load_calls_policy({
        "calls": {
            "function_pointer_globals": {
                "0x004B9000": "GlobalCallback",
            },
        },
    })
    monkeypatch.setattr(
        "binary_comp.analyzers.calls.IAT_ADDRESSES",
        {0x004B8000: "GetTickCount"},
    )
    instructions = [
        Instruction(0x401000, "call", "0x402000", (Operand("imm", "", imm=0x402000),), "call 0x402000"),
        Instruction(
            0x401005,
            "call",
            "dword ptr [eax + 0x18]",
            (Operand("mem", "", base="eax", disp=0x18),),
            "call dword ptr [eax + 0x18]",
        ),
        Instruction(
            0x401008,
            "call",
            "dword ptr [0x4b8000]",
            (Operand("mem", "", disp=0x004B8000),),
            "call dword ptr [0x4b8000]",
        ),
        Instruction(
            0x40100E,
            "jmp",
            "dword ptr [0x4b9000]",
            (Operand("mem", "", disp=0x004B9000),),
            "jmp dword ptr [0x4b9000]",
        ),
        Instruction(
            0x401014,
            "jmp",
            "dword ptr [ecx*4 + 0x401100]",
            (Operand("mem", "", index="ecx", scale=4, disp=0x00401100),),
            "jmp dword ptr [ecx*4 + 0x401100]",
        ),
    ]

    assert extract_calls_from_original_instructions(instructions, policy) == [
        0x402000,
        "indirect[0x18]",
        "GetTickCount",
        "GlobalCallback",
    ]


def test_capstone_calls_supplement_overlapping_text_without_double_counting():
    assert merge_call_lists_max(
        ["Constructor", "Constructor", "Allocator"],
        ["Constructor", "Allocator", "Allocator", "SharedTail"],
    ) == ["Constructor", "Constructor", "Allocator", "Allocator", "SharedTail"]


def test_compiled_calls_ignore_exception_unwind_funclet_segment(tmp_path):
    asm_path = tmp_path / "unwind.asm"
    asm_path.write_text(
        """
_TEXT SEGMENT
?Run@Thing@@QAEXXZ PROC NEAR ; Thing::Run, COMDAT
    call ?NormalCall@@YAXXZ ; NormalCall
    ret 0
_TEXT ENDS
text$x SEGMENT
$Lcleanup:
    call ?CleanupCall@@YAXXZ ; CleanupCall
    ret 0
text$x ENDS
?Run@Thing@@QAEXXZ ENDP ; Thing::Run
"""
    )

    assert extract_calls_from_compiled(str(asm_path), "Thing::Run") == ["NormalCall"]


def test_compiled_tail_jump_to_vtable_counts_as_call(tmp_path):
    asm_path = tmp_path / "tail-vtable.asm"
    asm_path.write_text(
        """
_TEXT SEGMENT
?Run@@YAXXZ PROC NEAR ; Run, COMDAT
    jmp DWORD PTR [eax+148]
    jmp DWORD PTR $L2[eax*4]
    jmp SHORT $L1
?Run@@YAXXZ ENDP
_TEXT ENDS
""",
        encoding="utf-8",
    )

    assert extract_calls_from_compiled(str(asm_path), "Run") == ["indirect[0x94]"]


def test_source_groups_map_to_rebuilt_symbols(fixture_root):
    groups_by_source = load_source_groups((str(fixture_root / "src"),))
    mapped, missing, entries_by_obj = map_source_groups(groups_by_source, str(fixture_root / "rebuilt.map"))

    assert not missing
    assert len(mapped) == 1
    assert mapped[0].name == "sample_function"
    assert mapped[0].original_addrs == (0x401000,)
    assert mapped[0].rebuilt_addr == 0x401000
    assert "sample.obj" in entries_by_obj


def test_source_groups_include_c_files_and_map_to_obj(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "module.c").write_text(
        "/* Function start: 0x00401000 */\nint c_function(void) { return 1; }\n",
        encoding="utf-8",
    )
    map_path = tmp_path / "rebuilt.map"
    map_path.write_text(
        " 0001:00000000       _c_function 00401000 f module.obj\n",
        encoding="utf-8",
    )

    groups_by_source = load_source_groups((str(source_dir),))
    mapped, missing, entries_by_obj = map_source_groups(groups_by_source, str(map_path))

    assert not missing
    assert len(mapped) == 1
    assert mapped[0].name == "c_function"
    assert mapped[0].rebuilt_symbol == "_c_function"
    assert "module.obj" in entries_by_obj


def test_load_minimal_project_config(fixture_root):
    _, target = load_project_target(str(fixture_root / "binary-comp.json"), "full")

    assert target.name == "full"
    assert target.original_exe == str(fixture_root / "original.exe")
    assert target.rebuilt_exe == str(fixture_root / "rebuilt.exe")
    assert target.map_path == str(fixture_root / "rebuilt.map")
    assert target.source_dirs == (str(fixture_root / "src"),)
    assert target.source_excludes == ()
    assert target.globals_source == str(fixture_root / "src" / "globals.cpp")
    assert target.globals_header == str(fixture_root / "src" / "globals.h")
    assert target.code_globals_header == str(fixture_root / "code" / "globals.h")
    assert target.define_headers == (str(fixture_root / "src" / "constants.h"),)
    assert target.auto_complete == str(fixture_root / "src" / "auto_complete.txt")
    assert target.asm_dir == str(fixture_root / "out")


def test_standalone_values_policy_is_relative_to_config(tmp_path):
    config_path = tmp_path / "config" / "binary-comp.json"
    config_path.parent.mkdir()
    config_path.write_text(
        """
{
  "targets": {
    "full": {
      "original_exe": "../original.exe",
      "rebuilt_exe": "../rebuilt.exe",
      "map": "../rebuilt.map",
      "source_dirs": ["../src"],
      "source_excludes": ["../src/generated.cpp"],
      "values": {"policy": "values-policy.json"}
    }
  }
}
""",
        encoding="utf-8",
    )

    _, target = load_project_target(str(config_path), "full")

    assert target.values_policy == str(config_path.parent / "values-policy.json")
    assert tuple(Path(path).resolve() for path in target.source_excludes) == (
        (tmp_path / "src" / "generated.cpp").resolve(),
    )


def test_value_checker_on_generated_fixture_project(fixture_root, sample_binaries):
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

    summary = check_values(
        target,
        load_policy(),
        ValuesOptions(build=False, min_similarity=90.0),
    )

    assert summary.functions_checked == 1
    assert summary.with_value_mismatches == 0
    assert summary.total_mismatches == 0
    expected = (fixture_root / "expected" / "values-summary.txt").read_text(encoding="utf-8").rstrip("\n")
    assert format_summary(summary, min_similarity=90.0) == expected


def test_value_summary_includes_mismatch_breakdown():
    instr = Instruction(0x401000, "push", "1", (), "push 1")
    group_a = FunctionGroup("a.cpp", "A::Run", 1, (0x401000,), 0x501000, "?Run@A@@QAEXXZ")
    group_b = FunctionGroup("b.cpp", "B::Run", 1, (0x402000,), 0x502000, "?Run@B@@QAEXXZ")
    result_a = CheckResult(
        original_addr=0x401000,
        rebuilt_addr=0x501000,
        similarity=91.5,
        original_count=4,
        rebuilt_count=4,
        warnings=(
            ("imm", 1, 2, instr, instr),
            ("string", "left", "right", instr, instr),
        ),
    )
    result_b = CheckResult(
        original_addr=0x402000,
        rebuilt_addr=0x502000,
        similarity=95.0,
        original_count=4,
        rebuilt_count=4,
        warnings=(("offset", 0x10, 0x20, instr, instr),),
    )
    summary = ValuesSummary(
        functions_checked=2,
        with_value_mismatches=2,
        total_mismatches=3,
        skipped_no_bytes=0,
        skipped_below_threshold=0,
        unmapped_source_groups=0,
        boundary_inventory={},
        reports=((group_a, result_a), (group_b, result_b)),
    )

    text = format_summary(summary)

    assert "--- Mismatch Breakdown ---" in text
    assert "By kind: IMM 1, STRING 1, OFFSET 1" in text
    assert "  A::Run: 2 (IMM 1, STRING 1; 91.5%)" in text
    assert "  B::Run: 1 (OFFSET 1; 95.0%)" in text


def test_stack_local_offsets_are_opt_in():
    policy = load_policy()
    compiled = [
        Instruction(0x1000, "lea", "eax, [ebp - 0x20]", (
            Operand("reg", "eax", reg="eax"),
            Operand("mem", "", base="ebp", scale=1, disp=-0x20),
        ), "lea eax, [ebp - 0x20]"),
    ]
    original = [
        Instruction(0x2000, "lea", "eax, [ebp - 0x40]", (
            Operand("reg", "eax", reg="eax"),
            Operand("mem", "", base="ebp", scale=1, disp=-0x40),
        ), "lea eax, [ebp - 0x40]"),
    ]
    default_context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    stack_context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=True,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    assert compare_instruction_pair(compiled, original, None, None, 0, 0, default_context) == []

    warnings = compare_instruction_pair(compiled, original, None, None, 0, 0, stack_context)
    assert len(warnings) == 1
    assert warnings[0][0] == "offset"


def test_msvc_eh_state_stack_slot_is_not_a_value_mismatch():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=True,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    def eh_prefix(base: int) -> list[Instruction]:
        return [
            Instruction(base + 0, "mov", "eax, dword ptr fs:[0]", (), "mov eax, dword ptr fs:[0]"),
            Instruction(base + 1, "push", "-1", (Operand("imm", "-1", imm=-1),), "push -1"),
            Instruction(base + 2, "push", "0x401000", (Operand("imm", "0x401000", imm=0x401000),), "push 0x401000"),
            Instruction(base + 3, "push", "eax", (Operand("reg", "eax", reg="eax"),), "push eax"),
            Instruction(base + 4, "mov", "dword ptr fs:[0], esp", (), "mov dword ptr fs:[0], esp"),
        ]

    def eh_state_write(addr: int, imm: int) -> Instruction:
        return Instruction(addr, "mov", f"dword ptr [ebp - 4], {imm}", (
            Operand("mem", "", base="ebp", scale=1, disp=-4, size=4),
            Operand("imm", str(imm), imm=imm, size=4),
        ), f"mov dword ptr [ebp - 4], {imm}")

    compiled = eh_prefix(0x1000) + [eh_state_write(0x1005, 0)]
    original = eh_prefix(0x2000) + [eh_state_write(0x2005, 1)]

    assert compare_instruction_pair(compiled, original, NoStringsImage(), NoStringsImage(), 5, 5, context) == []

    warnings = compare_instruction_pair(
        [eh_state_write(0x3000, 0)],
        [eh_state_write(0x4000, 1)],
        NoStringsImage(),
        NoStringsImage(),
        0,
        0,
        context,
    )
    assert len(warnings) == 1
    assert warnings[0][0] == "imm"


def test_value_offsets_compare_effective_alias_after_pointer_increment():
    policy = load_policy()
    compiled = [
        Instruction(0x1000, "lea", "edx, [ecx + 1]", (
            Operand("reg", "edx", reg="edx"),
            Operand("mem", "", base="ecx", scale=1, disp=1),
        ), "lea edx, [ecx + 1]"),
        Instruction(0x1004, "mov", "bl, byte ptr [edx + 3]", (
            Operand("reg", "bl", reg="bl"),
            Operand("mem", "", base="edx", scale=1, disp=3),
        ), "mov bl, byte ptr [edx + 3]"),
        Instruction(0x1008, "add", "edx, 4", (
            Operand("reg", "edx", reg="edx"),
            Operand("imm", "4", imm=4),
        ), "add edx, 4"),
        Instruction(0x100C, "mov", "bl, byte ptr [edx + 1]", (
            Operand("reg", "bl", reg="bl"),
            Operand("mem", "", base="edx", scale=1, disp=1),
        ), "mov bl, byte ptr [edx + 1]"),
    ]
    original = [
        Instruction(0x2000, "lea", "edx, [ecx + 5]", (
            Operand("reg", "edx", reg="edx"),
            Operand("mem", "", base="ecx", scale=1, disp=5),
        ), "lea edx, [ecx + 5]"),
        Instruction(0x2004, "mov", "bl, byte ptr [edx - 1]", (
            Operand("reg", "bl", reg="bl"),
            Operand("mem", "", base="edx", scale=1, disp=-1),
        ), "mov bl, byte ptr [edx - 1]"),
        Instruction(0x2008, "add", "edx, 4", (
            Operand("reg", "edx", reg="edx"),
            Operand("imm", "4", imm=4),
        ), "add edx, 4"),
        Instruction(0x200C, "mov", "bl, byte ptr [edx - 3]", (
            Operand("reg", "bl", reg="bl"),
            Operand("mem", "", base="edx", scale=1, disp=-3),
        ), "mov bl, byte ptr [edx - 3]"),
    ]

    assert same_effective_lea_displacement(
        compiled, original, 1, 1,
        compiled[1].operands[1], original[1].operands[1], policy,
    )
    assert same_effective_lea_displacement(
        compiled, original, 3, 3,
        compiled[3].operands[1], original[3].operands[1], policy,
    )


def test_value_immediates_compare_effective_stack_pointer_alias():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = [
        Instruction(0x1000, "mov", "dword ptr [ebp - 4], eax", (
            Operand("mem", "", base="ebp", scale=1, disp=-4, size=4),
            Operand("reg", "eax", reg="eax"),
        ), "mov dword ptr [ebp - 4], eax"),
        Instruction(0x1004, "mov", "edx, dword ptr [ebp - 4]", (
            Operand("reg", "edx", reg="edx"),
            Operand("mem", "", base="ebp", scale=1, disp=-4, size=4),
        ), "mov edx, dword ptr [ebp - 4]"),
        Instruction(0x1008, "add", "edx, 0x3c", (
            Operand("reg", "edx", reg="edx"),
            Operand("imm", "60", imm=60),
        ), "add edx, 0x3c"),
    ]
    original = [
        Instruction(0x2000, "mov", "dword ptr [ebp - 4], eax", (
            Operand("mem", "", base="ebp", scale=1, disp=-4, size=4),
            Operand("reg", "eax", reg="eax"),
        ), "mov dword ptr [ebp - 4], eax"),
        Instruction(0x2004, "mov", "ecx, dword ptr [ebp - 4]", (
            Operand("reg", "ecx", reg="ecx"),
            Operand("mem", "", base="ebp", scale=1, disp=-4, size=4),
        ), "mov ecx, dword ptr [ebp - 4]"),
        Instruction(0x2008, "add", "ecx, 0x2c", (
            Operand("reg", "ecx", reg="ecx"),
            Operand("imm", "44", imm=44),
        ), "add ecx, 0x2c"),
        Instruction(0x200C, "mov", "dword ptr [ebp - 8], ecx", (
            Operand("mem", "", base="ebp", scale=1, disp=-8, size=4),
            Operand("reg", "ecx", reg="ecx"),
        ), "mov dword ptr [ebp - 8], ecx"),
        Instruction(0x2010, "mov", "edx, dword ptr [ebp - 8]", (
            Operand("reg", "edx", reg="edx"),
            Operand("mem", "", base="ebp", scale=1, disp=-8, size=4),
        ), "mov edx, dword ptr [ebp - 8]"),
        Instruction(0x2014, "add", "edx, 0x10", (
            Operand("reg", "edx", reg="edx"),
            Operand("imm", "16", imm=16),
        ), "add edx, 0x10"),
    ]

    assert compare_instruction_pair(compiled, original, NoStringsImage(), NoStringsImage(), 2, 5, context) == []

    changed_original = list(original)
    changed_original[-1] = Instruction(0x2014, "add", "edx, 0x14", (
        Operand("reg", "edx", reg="edx"),
        Operand("imm", "20", imm=20),
    ), "add edx, 0x14")
    warnings = compare_instruction_pair(
        compiled,
        changed_original,
        NoStringsImage(),
        NoStringsImage(),
        2,
        5,
        context,
    )
    assert len(warnings) == 1
    assert warnings[0][0] == "imm"
