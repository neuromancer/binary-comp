from __future__ import annotations

from binary_comp.analyzers.values import (
    CompareContext,
    compare_instruction_pair,
    following_call_signature,
    load_policy,
    stack_argument_origin_at,
)
from binary_comp.core.disasm import Instruction, Operand


class NoStringsImage:
    def c_string_at(self, *_args, **_kwargs):
        return None


def instruction(address, mnemonic, operands=()):
    raw_operands = ", ".join(operand.text for operand in operands)
    raw = f"{mnemonic} {raw_operands}".rstrip()
    return Instruction(address, mnemonic, raw_operands, operands, raw)


def register(name):
    return Operand("reg", name, reg=name)


def stack_memory(displacement):
    return Operand("mem", "", base="esp", scale=1, disp=displacement, size=4)


def immediate(value):
    return Operand("imm", str(value), imm=value, size=4)


def forwarded_argument_sequence(first_call_arg, second_call_arg, base):
    return [
        instruction(base + 0, "push", (register("esi"),)),
        instruction(base + 1, "push", (register("edi"),)),
        instruction(base + 2, "push", (register("ebx"),)),
        instruction(base + 3, "mov", (register("ebx"), stack_memory(0x14))),
        instruction(base + 4, "push", (register("ebp"),)),
        instruction(base + 5, "mov", (register("ebp"), stack_memory(0x14))),
        instruction(base + 6, "push", (immediate(1),)),
        instruction(base + 7, "push", (immediate(1),)),
        instruction(base + 8, "push", (register(first_call_arg),)),
        instruction(base + 9, "push", (register(second_call_arg),)),
        Instruction(
            base + 10,
            "call",
            "dword ptr [edx + 0x58]",
            (Operand("mem", "", base="edx", disp=0x58, size=4),),
            "call dword ptr [edx + 0x58]",
        ),
    ]


def test_stack_argument_origin_accounts_for_prologue_pushes():
    instrs = forwarded_argument_sequence("ebx", "ebp", 0x1000)

    assert stack_argument_origin_at(instrs, 8, "ebx") == 8
    assert stack_argument_origin_at(instrs, 9, "ebp") == 4


def test_swapped_forwarded_stack_arguments_are_reported():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = forwarded_argument_sequence("ebp", "ebx", 0x1000)
    original = forwarded_argument_sequence("ebx", "ebp", 0x2000)

    first = compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 8, 8, context
    )
    second = compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 9, 9, context
    )

    assert [warning[:3] for warning in first + second] == [
        ("arg", 4, 8),
        ("arg", 8, 4),
    ]


def test_matching_forwarded_stack_arguments_stay_quiet():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = forwarded_argument_sequence("ebx", "ebp", 0x1000)
    original = forwarded_argument_sequence("ebx", "ebp", 0x2000)

    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 8, 8, context
    ) == []
    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 9, 9, context
    ) == []


def test_same_stack_argument_in_different_registers_stays_quiet():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    def sequence(saved_register, base):
        return [
            instruction(base + 0, "push", (register(saved_register),)),
            instruction(base + 1, "mov", (register(saved_register), stack_memory(8))),
            instruction(base + 2, "push", (register(saved_register),)),
            Instruction(
                base + 3,
                "call",
                "dword ptr [edx + 0x58]",
                (Operand("mem", "", base="edx", disp=0x58, size=4),),
                "call dword ptr [edx + 0x58]",
            ),
        ]

    compiled = sequence("esi", 0x1000)
    original = sequence("edi", 0x2000)

    assert stack_argument_origin_at(compiled, 2, "esi") == 4
    assert stack_argument_origin_at(original, 2, "edi") == 4
    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 2, 2, context
    ) == []


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


def test_push_immediate_mismatch_is_ignored_for_different_resolved_direct_calls():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
        compiled_call_targets={0x1100: "MemReAllocPtr"},
        original_call_targets={0x2100: "MemDefaultPool"},
    )
    compiled = [
        Instruction(0x1000, "push", "5", (Operand("imm", "5", imm=5),), "push 5"),
        Instruction(0x1002, "call", "0x1100", (Operand("imm", "0x1100", imm=0x1100),), "call 0x1100"),
    ]
    original = [
        Instruction(0x2000, "push", "0", (Operand("imm", "0", imm=0),), "push 0"),
        Instruction(0x2002, "call", "0x2100", (Operand("imm", "0x2100", imm=0x2100),), "call 0x2100"),
    ]

    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context
    ) == []


def test_push_immediate_mismatch_is_kept_for_same_resolved_direct_call():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
        compiled_call_targets={0x1100: "MemAllocPtr"},
        original_call_targets={0x2100: "MemAllocPtr"},
    )
    compiled = [
        Instruction(0x1000, "push", "5", (Operand("imm", "5", imm=5),), "push 5"),
        Instruction(0x1002, "call", "0x1100", (Operand("imm", "0x1100", imm=0x1100),), "call 0x1100"),
    ]
    original = [
        Instruction(0x2000, "push", "0", (Operand("imm", "0", imm=0),), "push 0"),
        Instruction(0x2002, "call", "0x2100", (Operand("imm", "0x2100", imm=0x2100),), "call 0x2100"),
    ]

    warnings = compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context
    )

    assert len(warnings) == 1
    assert warnings[0][0:3] == ("imm", 5, 0)
