from __future__ import annotations

from binary_comp.analyzers.values import (
    CompareContext,
    comparable_operands,
    compare_instruction_pair,
    contiguous_tail_fragment_start,
    equivalent_reordered_push_values,
    equivalent_reordered_x87_status_masks,
    equivalent_structurally_reordered_displacements,
    equivalent_structurally_reordered_immediates,
    following_call_signature,
    is_stack_probe_size_load,
    load_policy,
    same_affine_memory_address,
    sign_step_outputs,
    stack_argument_origin_at,
    value_aware_align,
)
from binary_comp.core.disasm import Instruction, Operand


class NoStringsImage:
    def c_string_at(self, *_args, **_kwargs):
        return None


class StringsImage:
    def __init__(self, strings):
        self.strings = strings

    def c_string_at(self, address, *_args, **_kwargs):
        return self.strings.get(address)


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


def member_memory(base, displacement, size=4):
    return Operand("mem", "", base=base, scale=1, disp=displacement, size=size)


def dialogue_blocks(order, base):
    instrs = []
    addresses = {"A": 0x5000, "B": 0x5100}
    frames = {"A": 5, "B": 0}
    for name in order:
        block = base + len(instrs) * 4
        instrs.extend([
            instruction(block + 0, "push", (immediate(frames[name]),)),
            instruction(block + 1, "push", (immediate(addresses[name]),)),
            instruction(block + 2, "push", (immediate(0),)),
            Instruction(
                block + 3,
                "call",
                "dword ptr [edx + 0xac]",
                (Operand("mem", "", base="edx", disp=0xAC, size=4),),
                "call dword ptr [edx + 0xac]",
            ),
            instruction(block + 4, "ret"),
        ])
    return instrs


def numeric_call_blocks(order, base):
    instrs = []
    for value in order:
        block = base + len(instrs) * 4
        instrs.extend([
            instruction(block + 0, "push", (immediate(value),)),
            instruction(block + 1, "push", (register("eax"),)),
            Instruction(
                block + 2,
                "call",
                "dword ptr [edx + 0xac]",
                (Operand("mem", "", base="edx", disp=0xAC, size=4),),
                "call dword ptr [edx + 0xac]",
            ),
            instruction(block + 3, "ret"),
        ])
    return instrs


def immediate_blocks(order, base):
    instrs = []
    for value in order:
        block = base + len(instrs) * 4
        instrs.extend(instruction(block + offset, "nop") for offset in range(8))
        body = base + len(instrs) * 4
        instrs.extend([
            instruction(body + 0, "call", (immediate(body + 0x100),)),
            instruction(body + 1, "cdq"),
            instruction(body + 2, "mov", (register("ecx"), immediate(value))),
            instruction(body + 3, "idiv", (register("ecx"),)),
            instruction(body + 4, "sub", (register("edx"), immediate(0))),
            instruction(body + 5, "jz", (immediate(body + 8),)),
            instruction(body + 6, "xor", (register("eax"), register("eax"))),
            instruction(body + 7, "ret"),
        ])
        tail = base + len(instrs) * 4
        instrs.extend(instruction(tail + offset, "nop") for offset in range(8))
    return instrs


def immediate_index(instrs, value, occurrence=0):
    matches = [
        idx for idx, instr in enumerate(instrs)
        if instr.mnemonic == "mov"
        and len(instr.operands) > 1
        and instr.operands[1].kind == "imm"
        and instr.operands[1].imm == value
    ]
    return matches[occurrence]


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


def test_member_loads_consumed_by_different_calls_are_not_compared():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    def sequence(base, displacement, call_slot):
        return [
            instruction(base, "mov", (
                register("eax"), member_memory("esi", displacement),
            )),
            instruction(base + 1, "push", (register("eax"),)),
            Instruction(
                base + 2,
                "call",
                f"dword ptr [edx + {call_slot:#x}]",
                (member_memory("edx", call_slot),),
                f"call dword ptr [edx + {call_slot:#x}]",
            ),
        ]

    compiled = sequence(0x1000, 0x11B0, 0xB0)
    original = sequence(0x2000, 0x11AC, 0xAC)
    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context
    ) == []

    original_same_call = sequence(0x2000, 0x11AC, 0xB0)
    warnings = compare_instruction_pair(
        compiled, original_same_call,
        NoStringsImage(), NoStringsImage(), 0, 0, context,
    )
    assert [warning[:3] for warning in warnings] == [("offset", 0x11B0, 0x11AC)]


def test_complementary_branch_with_swapped_effect_edge_stays_quiet():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    compiled = [
        instruction(0x1000, "cmp", (member_memory("esi", 0x10), immediate(0))),
        instruction(0x1001, "jz", (immediate(0x1010),)),
        instruction(0x1003, "inc", (register("eax"),)),
        instruction(0x1004, "ret"),
        instruction(0x1010, "mov", (member_memory("esi", 0x20), register("eax"))),
        instruction(0x1011, "ret"),
    ]
    original = [
        instruction(0x2000, "cmp", (member_memory("esi", 0x10), immediate(0))),
        instruction(0x2001, "jnz", (immediate(0x2010),)),
        instruction(0x2003, "mov", (member_memory("esi", 0x20), register("eax"))),
        instruction(0x2004, "ret"),
        instruction(0x2010, "inc", (register("eax"),)),
        instruction(0x2011, "ret"),
    ]

    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context
    ) == []

    original[2], original[4] = original[4], original[2]
    original[2] = instruction(0x2003, "inc", (register("eax"),))
    original[4] = instruction(
        0x2010, "mov", (member_memory("esi", 0x20), register("eax"))
    )
    warnings = compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context
    )
    assert [warning[:3] for warning in warnings] == [("branch", "jz", "jnz")]


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


def test_immediate_and_register_operands_are_not_structurally_comparable():
    compiled = instruction(0x1000, "mov", (stack_memory(4), immediate(1)))
    original = instruction(0x2000, "mov", (stack_memory(4), register("eax")))

    assert not comparable_operands(compiled, original)


def test_contiguous_branched_tail_is_recognized_as_a_function_fragment():
    instrs = [
        instruction(0x1000, "cmp", (register("eax"), immediate(0xCB))),
        Instruction(0x1005, "jnz", "0x1010", (immediate(0x1010),), "jne 0x1010", size=2),
        Instruction(0x1007, "mov", "al, 1", (register("al"), immediate(1)), "mov al, 1", size=2),
        Instruction(0x1009, "ret", "4", (immediate(4),), "ret 4", size=7),
    ]

    assert contiguous_tail_fragment_start(instrs, {0x1000, 0x1010}) == 0x1010
    assert contiguous_tail_fragment_start(instrs, {0x1000, 0x1020}) is None


def test_branchless_sign_step_mask_variants_have_identical_outputs():
    def sequence(base, setcc, mask, adjustment):
        return [
            instruction(base + 0, "test", (register("esi"), register("esi"))),
            instruction(base + 1, setcc, (register("dl"),)),
            instruction(base + 2, "dec", (register("edx"),)),
            instruction(base + 3, "and", (register("edx"), immediate(mask))),
            instruction(base + 4, adjustment, (register("edx"),)),
        ]

    compiled = sequence(0x1000, "setge", -2, "inc")
    original = sequence(0x2000, "setl", 2, "dec")

    assert sign_step_outputs(compiled, 3) == (1, -1)
    assert sign_step_outputs(original, 3) == (1, -1)


def test_value_aware_alignment_prefers_exact_repeated_loads():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates", "offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    def memory(displacement):
        return Operand("mem", "", base="eax", scale=1, disp=displacement, size=4)

    compiled = [
        instruction(0x1000, "mov", (register("ecx"), memory(0x0C))),
        instruction(0x1001, "cmp", (register("ecx"), immediate(0x138E5))),
        instruction(0x1002, "mov", (register("ecx"), memory(0x1C))),
        instruction(0x1003, "cmp", (register("ecx"), immediate(0x0B))),
    ]
    original = [
        instruction(0x2000, "mov", (register("ecx"), memory(0x0C))),
        instruction(0x2001, "cmp", (register("ecx"), immediate(0x138E5))),
        instruction(0x2002, "mov", (register("ecx"), memory(0x1C))),
        instruction(0x2003, "cmp", (register("ecx"), immediate(0x0B))),
    ]

    assert value_aware_align(
        compiled,
        original,
        NoStringsImage(),
        NoStringsImage(),
        context,
    ) == [(0, 0), (1, 1), (2, 2), (3, 3)]


def test_nested_lea_aliases_compare_effective_memory_addresses():
    compiled = [
        Instruction(0x1000, "lea", "eax, [esi + esi*4]", (
            register("eax"), Operand("mem", "", base="esi", index="esi", scale=4),
        ), "lea eax, [esi + esi*4]"),
        Instruction(0x1001, "lea", "edi, [ebp + eax*4]", (
            register("edi"), Operand("mem", "", base="ebp", index="eax", scale=4),
        ), "lea edi, [ebp + eax*4]"),
        Instruction(0x1002, "mov", "[edi + 0x108], eax", (
            Operand("mem", "", base="edi", disp=0x108, size=4), register("eax"),
        ), "mov [edi + 0x108], eax"),
    ]
    original = [
        Instruction(0x2000, "lea", "edx, [esi + esi*4 + 0x41]", (
            register("edx"), Operand("mem", "", base="esi", index="esi", scale=4, disp=0x41),
        ), "lea edx, [esi + esi*4 + 0x41]"),
        Instruction(0x2001, "lea", "edi, [ebp + edx*4]", (
            register("edi"), Operand("mem", "", base="ebp", index="edx", scale=4),
        ), "lea edi, [ebp + edx*4]"),
        Instruction(0x2002, "mov", "[edi + 4], eax", (
            Operand("mem", "", base="edi", disp=4, size=4), register("eax"),
        ), "mov [edi + 4], eax"),
    ]

    assert same_affine_memory_address(
        compiled, original, 2, 2, compiled[2].operands[0], original[2].operands[0]
    )


def test_stack_spilled_pointer_increment_compares_same_effective_address():
    compiled = [
        instruction(0x1000, "push", (register("ebp"),)),
        instruction(0x1001, "mov", (register("ebp"), register("esp"))),
        instruction(0x1002, "mov", (register("eax"), Operand(
            "mem", "", base="ebp", scale=1, disp=8, size=4
        ))),
        instruction(0x1003, "mov", (
            Operand("mem", "", base="eax", scale=1, disp=4, size=4),
            register("edx"),
        )),
    ]
    original = [
        instruction(0x2000, "push", (register("ebp"),)),
        instruction(0x2001, "mov", (register("ebp"), register("esp"))),
        instruction(0x2002, "mov", (register("ecx"), Operand(
            "mem", "", base="ebp", scale=1, disp=8, size=4
        ))),
        instruction(0x2003, "lea", (register("eax"), Operand(
            "mem", "", base="ecx", scale=1, disp=4, size=4
        ))),
        instruction(0x2004, "mov", (
            Operand("mem", "", base="ebp", scale=1, disp=8, size=4),
            register("eax"),
        )),
        instruction(0x2005, "mov", (register("eax"), Operand(
            "mem", "", base="ebp", scale=1, disp=8, size=4
        ))),
        instruction(0x2006, "mov", (
            Operand("mem", "", base="eax", scale=1, disp=0, size=4),
            register("edx"),
        )),
    ]

    assert same_affine_memory_address(
        compiled,
        original,
        3,
        6,
        compiled[3].operands[0],
        original[6].operands[0],
    )


def test_stack_probe_size_load_allows_msvc_seh_setup_store():
    instrs = [
        instruction(0x1000, "push", (immediate(-1),)),
        Instruction(0x1001, "mov", "eax, dword ptr fs:[0]", (
            register("eax"), Operand("mem", "", disp=0, size=4),
        ), "mov eax, dword ptr fs:[0]"),
        instruction(0x1002, "push", (immediate(0x480000),)),
        instruction(0x1003, "push", (register("eax"),)),
        instruction(0x1004, "mov", (register("eax"), immediate(0x2050))),
        Instruction(0x1005, "mov", "dword ptr fs:[0], esp", (
            Operand("mem", "", disp=0, size=4), register("esp"),
        ), "mov dword ptr fs:[0], esp"),
        instruction(0x1006, "call", (immediate(0x1100),)),
    ]

    assert is_stack_probe_size_load(instrs, 4)


def test_shifted_global_array_base_offsets_stay_quiet():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    def memory(displacement):
        return Operand("mem", "", base="ebx", scale=1, disp=displacement, size=2)

    compiled = [
        instruction(0x1000, "mov", (register("ebx"), immediate(0x4A8468))),
        instruction(0x1001, "mov", (register("cx"), memory(-4))),
        instruction(0x1002, "mov", (register("cx"), memory(0))),
        instruction(0x1003, "mov", (register("cx"), memory(-2))),
        instruction(0x1004, "mov", (register("cx"), memory(2))),
    ]
    original = [
        instruction(0x2000, "mov", (stack_memory(0x14), immediate(0x4B48BA))),
        instruction(0x2001, "mov", (register("ebx"), stack_memory(0x14))),
        instruction(0x2002, "mov", (register("cx"), memory(-2))),
        instruction(0x2003, "mov", (register("cx"), memory(2))),
        instruction(0x2004, "mov", (register("cx"), memory(0))),
        instruction(0x2005, "mov", (register("cx"), memory(4))),
    ]

    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 4, 5, context
    ) == []


def test_two_shifted_global_array_accesses_are_enough_to_prove_rebasing():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    def memory(displacement):
        return Operand("mem", "", base="eax", scale=1, disp=displacement, size=4)

    compiled = [
        instruction(0x1000, "mov", (register("eax"), immediate(0x4A1000))),
        instruction(0x1001, "cmp", (memory(0), register("ebx"))),
        instruction(0x1002, "cmp", (memory(4), register("edi"))),
    ]
    original = [
        instruction(0x2000, "mov", (register("eax"), immediate(0x4B2004))),
        instruction(0x2001, "cmp", (memory(-4), register("ebx"))),
        instruction(0x2002, "cmp", (memory(0), register("edi"))),
    ]

    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 1, 1, context
    ) == []
    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 2, 2, context
    ) == []


def test_single_shifted_global_access_is_not_assumed_to_be_rebased():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = [
        instruction(0x1000, "mov", (register("eax"), immediate(0x4A1000))),
        instruction(0x1001, "cmp", (member_memory("eax", 0), register("ebx"))),
    ]
    original = [
        instruction(0x2000, "mov", (register("eax"), immediate(0x4B2004))),
        instruction(0x2001, "cmp", (member_memory("eax", -4), register("ebx"))),
    ]

    warnings = compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 1, 1, context
    )
    assert [warning[:3] for warning in warnings] == [("offset", 0, -4)]


def test_repeated_class_member_shift_is_not_treated_as_pointer_rebasing():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"offsets"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )

    def member(displacement):
        return Operand("mem", "", base="esi", scale=1, disp=displacement, size=4)

    compiled = [
        instruction(0x1000 + index, "mov", (register("eax"), member(offset)))
        for index, offset in enumerate((0x90, 0x94, 0x98))
    ]
    original = [
        instruction(0x2000 + index, "mov", (register("eax"), member(offset)))
        for index, offset in enumerate((0x80, 0x84, 0x88))
    ]

    warnings = compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 1, 1, context
    )
    assert [warning[:3] for warning in warnings] == [("offset", 0x94, 0x84)]


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


def test_reordered_push_values_are_reconciled_by_call_argument_and_literal():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    image = StringsImage({0x5000: "dialogue A", 0x5100: "dialogue B"})
    compiled = dialogue_blocks(("A", "B"), 0x1000)
    original = dialogue_blocks(("B", "A"), 0x2000)

    assert equivalent_reordered_push_values(
        compiled, original, image, image, 0, 0, 5, 0, context
    )


def test_changed_push_value_is_not_hidden_by_reordered_blocks():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    image = StringsImage({0x5000: "dialogue A", 0x5100: "dialogue B"})
    compiled = dialogue_blocks(("A", "B"), 0x1000)
    original = dialogue_blocks(("B", "A"), 0x2000)
    original[5] = instruction(original[5].address, "push", (immediate(6),))

    assert not equivalent_reordered_push_values(
        compiled, original, image, image, 0, 0, 5, 0, context
    )


def test_reordered_unanchored_push_values_use_context_multiplicity():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = numeric_call_blocks((3, 7), 0x1000)
    original = numeric_call_blocks((7, 3), 0x2000)

    assert equivalent_reordered_push_values(
        compiled,
        original,
        NoStringsImage(),
        NoStringsImage(),
        0,
        0,
        3,
        7,
        context,
    )


def test_changed_unanchored_push_value_has_unmatched_multiplicity():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = numeric_call_blocks((3, 7), 0x1000)
    original = numeric_call_blocks((7, 4), 0x2000)

    assert not equivalent_reordered_push_values(
        compiled,
        original,
        NoStringsImage(),
        NoStringsImage(),
        0,
        0,
        3,
        7,
        context,
    )


def test_reordered_non_push_immediates_use_structural_neighborhoods():
    compiled = immediate_blocks((3, 6), 0x1000)
    original = immediate_blocks((6, 3), 0x2000)

    assert equivalent_structurally_reordered_immediates(
        compiled,
        original,
        immediate_index(compiled, 3),
        immediate_index(original, 6),
        1,
        3,
        6,
    )


def test_changed_non_push_immediate_is_not_reconciled():
    compiled = immediate_blocks((3, 6), 0x1000)
    original = immediate_blocks((6, 4), 0x2000)

    assert not equivalent_structurally_reordered_immediates(
        compiled,
        original,
        immediate_index(compiled, 3),
        immediate_index(original, 6),
        1,
        3,
        6,
    )


def test_misaligned_immediate_uses_much_better_exact_structural_match():
    compiled = immediate_blocks((3,), 0x1000)
    original = [
        instruction(0x2000, "push", (immediate(0),)),
        instruction(0x2001, "xor", (register("eax"), register("eax"))),
        instruction(0x2002, "mov", (register("ecx"), immediate(4))),
        instruction(0x2003, "add", (register("eax"), register("ecx"))),
        instruction(0x2004, "ret"),
    ] + immediate_blocks((3,), 0x2100)

    assert equivalent_structurally_reordered_immediates(
        compiled,
        original,
        immediate_index(compiled, 3),
        immediate_index(original, 4),
        1,
        3,
        4,
    )


def test_misaligned_immediate_rejects_weak_exact_match():
    compiled = immediate_blocks((3,), 0x1000)
    original = [
        instruction(0x2000, "push", (immediate(0),)),
        instruction(0x2001, "xor", (register("eax"), register("eax"))),
        instruction(0x2002, "mov", (register("ecx"), immediate(4))),
        instruction(0x2003, "add", (register("eax"), register("ecx"))),
        instruction(0x2004, "ret"),
        instruction(0x2005, "sub", (register("eax"), register("edx"))),
        instruction(0x2006, "mov", (register("ecx"), immediate(3))),
        instruction(0x2007, "ret"),
    ]

    assert not equivalent_structurally_reordered_immediates(
        compiled,
        original,
        immediate_index(compiled, 3),
        immediate_index(original, 4),
        1,
        3,
        4,
    )


def test_misaligned_displacement_uses_much_better_exact_structural_match():
    before = ("mov", "dec", "sub", "cmp", "mov", "jnl", "movsx", "add")
    after = ("cmp", "ja", "jmp", "xor", "mov", "inc", "mov", "test")
    compiled = [instruction(0x1000 + i, name) for i, name in enumerate(before)]
    compiled.append(instruction(0x1008, "mov", (member_memory("esi", 7, 1), register("cl"))))
    compiled.extend(instruction(0x1009 + i, name) for i, name in enumerate(after))

    original = [
        instruction(0x2000 + i, name)
        for i, name in enumerate(("push", "xor", "and", "or", "mov", "cmp", "mov", "add"))
    ]
    original.append(instruction(0x2008, "mov", (member_memory("esi", -2, 1), register("cl"))))
    original.extend(instruction(0x2009 + i, name) for i, name in enumerate(("cmp", "ja", "jmp", "sub", "mov", "dec", "test", "ret")))
    original.extend(instruction(0x2100 + i, name) for i, name in enumerate(before))
    original.append(instruction(0x2108, "mov", (member_memory("esi", 7, 1), register("cl"))))
    original.extend(instruction(0x2109 + i, name) for i, name in enumerate(after))

    assert equivalent_structurally_reordered_displacements(
        compiled, original, 8, 8, 0, 7, -2
    )


def test_misaligned_displacement_rejects_weak_exact_match():
    compiled = [
        instruction(0x1000, "xor"),
        instruction(0x1001, "add"),
        instruction(0x1002, "mov", (member_memory("esi", 7, 1), register("cl"))),
        instruction(0x1003, "test"),
        instruction(0x1004, "jz"),
    ]
    original = [
        instruction(0x2000, "xor"),
        instruction(0x2001, "add"),
        instruction(0x2002, "mov", (member_memory("esi", -2, 1), register("cl"))),
        instruction(0x2003, "test"),
        instruction(0x2004, "jz"),
        instruction(0x2005, "sub"),
        instruction(0x2006, "mov", (member_memory("esi", 7, 1), register("cl"))),
        instruction(0x2007, "ret"),
    ]

    assert not equivalent_structurally_reordered_displacements(
        compiled, original, 2, 2, 0, 7, -2
    )


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


def test_complemented_branch_with_swapped_successors_stays_quiet():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = [
        instruction(0x1000, "cmp", (register("eax"), immediate(5))),
        instruction(0x1001, "jnz", (immediate(0x1005),)),
        instruction(0x1002, "mov", (register("eax"), immediate(1))),
        instruction(0x1003, "ret"),
        instruction(0x1005, "xor", (register("eax"), register("eax"))),
        instruction(0x1006, "ret"),
    ]
    original = [
        instruction(0x2000, "cmp", (register("eax"), immediate(5))),
        instruction(0x2001, "jz", (immediate(0x2005),)),
        instruction(0x2002, "xor", (register("eax"), register("eax"))),
        instruction(0x2003, "ret"),
        instruction(0x2005, "mov", (register("eax"), immediate(1))),
        instruction(0x2006, "ret"),
    ]

    assert compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context
    ) == []


def test_complemented_branch_with_same_successors_is_reported():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = [
        instruction(0x1000, "cmp", (register("eax"), immediate(5))),
        instruction(0x1001, "jnz", (immediate(0x1005),)),
        instruction(0x1002, "mov", (register("eax"), immediate(1))),
        instruction(0x1003, "ret"),
        instruction(0x1005, "xor", (register("eax"), register("eax"))),
        instruction(0x1006, "ret"),
    ]
    original = [
        instruction(0x2000, "cmp", (register("eax"), immediate(5))),
        instruction(0x2001, "jz", (immediate(0x2005),)),
        instruction(0x2002, "mov", (register("eax"), immediate(1))),
        instruction(0x2003, "ret"),
        instruction(0x2005, "xor", (register("eax"), register("eax"))),
        instruction(0x2006, "ret"),
    ]

    warnings = compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 0, 0, context
    )
    assert [warning[0] for warning in warnings] == ["branch"]


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


def x87_status_blocks(masks, base):
    instrs = []
    for mask in masks:
        address = base + len(instrs)
        instrs.extend([
            instruction(address, "fcomp", (member_memory("esi", 0x80),)),
            instruction(address + 1, "fnstsw", (register("ax"),)),
            instruction(address + 2, "test", (register("ah"), immediate(mask))),
        ])
    return instrs


def test_reordered_repeated_x87_status_masks_stay_quiet():
    compiled = x87_status_blocks((1, 0x41, 1, 0x41), 0x1000)
    original = x87_status_blocks((0x41, 1, 0x41, 1), 0x2000)

    assert equivalent_reordered_x87_status_masks(
        compiled, original, 2, 2
    )


def test_one_off_x87_status_mask_change_is_not_reconciled():
    policy = load_policy()
    context = CompareContext(
        enabled_kinds=frozenset({"immediates"}),
        policy=policy,
        include_stack_locals=False,
        compiled_diagnostic_targets=frozenset(),
        original_diagnostic_targets=frozenset(),
    )
    compiled = x87_status_blocks((1,), 0x1000)
    original = x87_status_blocks((0x41,), 0x2000)

    warnings = compare_instruction_pair(
        compiled, original, NoStringsImage(), NoStringsImage(), 2, 2, context
    )

    assert [warning[:3] for warning in warnings] == [("imm", 1, 0x41)]
