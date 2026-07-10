from __future__ import annotations

from binary_comp.analyzers.values import (
    CompareContext,
    compare_instruction_pair,
    following_call_signature,
    load_policy,
)
from binary_comp.core.disasm import Instruction, Operand


class NoStringsImage:
    def c_string_at(self, *_args, **_kwargs):
        return None


def test_following_call_signature_follows_tail_merge_jump():
    instrs = [
        Instruction(0x1000, "push", "0", (Operand("imm", "0", imm=0),), "push 0"),
        Instruction(0x1002, "push", "1", (Operand("imm", "1", imm=1),), "push 1"),
        Instruction(0x1004, "jmp", "0x1010", (Operand("imm", "0x1010", imm=0x1010),), "jmp 0x1010"),
        Instruction(0x1010, "push", "edx", (Operand("reg", "edx", reg="edx"),), "push edx"),
        Instruction(
            0x1011,
            "call",
            "dword ptr [eax + 0xac]",
            (Operand("mem", "", base="eax", disp=0xAC, size=4),),
            "call dword ptr [eax + 0xac]",
        ),
    ]

    assert following_call_signature(instrs, 0) == ("mem", "", 0, 0xAC)


def test_cmp_same_immediate_reports_adjacent_branch_condition_mismatch():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = [
        Instruction(0x1000, "cmp", "dword ptr [ebx + 0x818], 3", (
            Operand("mem", "", base="ebx", scale=1, disp=0x818, size=4),
            Operand("imm", "3", imm=3, size=4),
        ), "cmp dword ptr [ebx + 0x818], 3"),
        Instruction(0x1007, "jnl", "0x1100", (Operand("imm", "0x1100", imm=0x1100),), "jge 0x1100"),
    ]
    original = [
        Instruction(0x2000, "cmp", "dword ptr [ebx + 0x818], 3", (
            Operand("mem", "", base="ebx", scale=1, disp=0x818, size=4),
            Operand("imm", "3", imm=3, size=4),
        ), "cmp dword ptr [ebx + 0x818], 3"),
        Instruction(0x2007, "jnle", "0x2100", (Operand("imm", "0x2100", imm=0x2100),), "jg 0x2100"),
    ]

    warnings = compare_instruction_pair(compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context)

    assert len(warnings) == 1
    assert warnings[0][0] == "branch"
    assert warnings[0][1:3] == ("jnl", "jnle")


def test_cmp_shifted_immediate_equivalent_branch_condition_stays_quiet():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = [
        Instruction(0x1000, "cmp", "dword ptr [ebx + 0x818], 4", (
            Operand("mem", "", base="ebx", scale=1, disp=0x818, size=4),
            Operand("imm", "4", imm=4, size=4),
        ), "cmp dword ptr [ebx + 0x818], 4"),
        Instruction(0x1007, "jnl", "0x1100", (Operand("imm", "0x1100", imm=0x1100),), "jge 0x1100"),
    ]
    original = [
        Instruction(0x2000, "cmp", "dword ptr [ebx + 0x818], 3", (
            Operand("mem", "", base="ebx", scale=1, disp=0x818, size=4),
            Operand("imm", "3", imm=3, size=4),
        ), "cmp dword ptr [ebx + 0x818], 3"),
        Instruction(0x2007, "jnle", "0x2100", (Operand("imm", "0x2100", imm=0x2100),), "jg 0x2100"),
    ]

    assert compare_instruction_pair(compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context) == []
