"""MSVC x86 C++ exception-handling (FuncInfo) extraction.

MSVC 4.x installs a C++ EH frame with the prologue::

    mov  eax, fs:[0]
    push ebp / mov ebp, esp
    push -1                 ; initial unwind state
    push <ehhandler>        ; thunk: ``mov eax, <FuncInfo>; jmp __CxxFrameHandler``
    push eax
    mov  fs:[0], esp

The ``FuncInfo`` it points at enumerates every object with a destructor (the
unwind map) and every ``try`` block. Each unwind entry's *action* is a small
funclet that loads the object into ``ecx`` and jumps to its destructor; decoding
it tells us *what* a function unwinds (a member at ``this+off``, a stack local,
or a parameter), independent of the per-binary destructor address.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from binary_comp.core.pe import PEImage

FUNCINFO_MAGICS = frozenset({0x19930520, 0x19930521, 0x19930522})


@dataclass(frozen=True)
class UnwindState:
    index: int
    to_state: int
    action: int | None          # funclet address, or None for a bare transition
    dtor: int | None            # destructor jumped to by the funclet
    target: str                 # normalized object expression ("this+0x114", ...)
    conditional: bool           # funclet guards the call with a flag test


@dataclass(frozen=True)
class TryBlock:
    try_low: int
    try_high: int
    catch_high: int
    catch_count: int


@dataclass(frozen=True)
class EHInfo:
    has_frame: bool
    funcinfo_addr: int | None
    magic: int | None
    max_state: int
    unwinds: tuple[UnwindState, ...]
    try_blocks: tuple[TryBlock, ...]
    # The unwind targets ("this+0x114", "arg@ebp+0x8", ...), in declaration order
    # (reverse of destruction order). In default analysis this only includes
    # states that can become live; strict analysis still uses ``unwinds``.
    targets: tuple[str, ...]
    active_states: tuple[int, ...] | None = None


def _md():
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    return Cs(CS_ARCH_X86, CS_MODE_32)


def _u32(image: PEImage, addr: int) -> int | None:
    raw = image.read(addr, 4)
    if raw is None or len(raw) != 4:
        return None
    return struct.unpack("<I", raw)[0]


def _i32(image: PEImage, addr: int) -> int | None:
    value = _u32(image, addr)
    if value is None:
        return None
    return value - 0x100000000 if value >= 0x80000000 else value


def find_funcinfo(image: PEImage, func_start: int, max_scan: int = 64) -> int | None:
    """Return the FuncInfo address for ``func_start`` or ``None`` if it has no
    C++ EH frame.
    """
    section_end = image.section_end_for_va(func_start)
    scan_size = max_scan if section_end is None else min(max_scan, section_end - func_start)
    data = image.read(func_start, scan_size)
    if not data:
        return None
    instrs = list(_md().disasm(data, func_start))
    # A C++ EH function's prologue ALWAYS starts by reading the SEH chain head
    # (`mov reg, fs:[0]`). Requiring it keeps a small frame-less function from
    # picking up the next function's frame when the fixed-size scan overruns it.
    if not instrs or instrs[0].mnemonic != "mov" or "fs:[0]" not in instrs[0].op_str.replace(" ", ""):
        return None

    handler = None
    for index, instr in enumerate(instrs[:8]):
        normalized = instr.op_str.replace(" ", "")
        if instr.mnemonic == "mov" and "fs:[0]" in normalized and normalized.endswith("esp"):
            for prev in range(index - 1, -1, -1):
                if instrs[prev].mnemonic == "push" and instrs[prev].op_str.startswith("0x"):
                    handler = int(instrs[prev].op_str, 16)
                    break
            break
    if handler is None:
        return None

    thunk = image.read(handler, 16)
    if not thunk:
        return None
    decoded = list(_md().disasm(thunk, handler))
    # __CxxFrameHandler thunk: ``mov eax, <FuncInfo>; jmp <dispatcher>``
    if decoded and decoded[0].mnemonic == "mov" and decoded[0].op_str.startswith("eax,"):
        return int(decoded[0].op_str.split(",", 1)[1].strip(), 16)
    return None


def find_this_slot(image: PEImage, func_start: int, max_scan: int = 64) -> str | None:
    """The ``[ebp-N]`` slot the prologue saves ``this`` (ecx) into, if any.

    Member-subobject unwind funclets reload ``this`` from this slot, so knowing
    it lets us tell ``this+0xNN`` apart from a member of some other local pointer.
    """
    section_end = image.section_end_for_va(func_start)
    scan_size = max_scan if section_end is None else min(max_scan, section_end - func_start)
    data = image.read(func_start, scan_size)
    if not data:
        return None
    for instr in _md().disasm(data, func_start):
        ops = instr.op_str.replace(" ", "")
        if instr.mnemonic == "mov" and ops.endswith(",ecx") and ops.startswith("dwordptr[ebp-"):
            return ops[len("dwordptr["):].split("]", 1)[0]
        if instr.mnemonic in ("call", "jmp"):
            break
    return None


def decode_unwind_funclet(
    image: PEImage, action: int, this_slot: str | None = None
) -> tuple[int | None, str, bool]:
    """Decode an unwind funclet → ``(dtor, object_expr, conditional)``.

    The funclet loads the object being destroyed into ``ecx`` then jumps to its
    destructor; ``object_expr`` normalizes how ``ecx`` is formed so it is
    comparable across the two binaries.
    """
    data = image.read(action, 40)
    if not data:
        return None, "?", False

    base = None          # how the object pointer is seeded ((kind, expr))
    obj_reg = None       # register currently holding the object pointer
    add_off = 0          # accumulated `add <obj_reg>, imm`
    dtor = None
    conditional = False
    for instr in _md().disasm(data, action):
        mnem, ops = instr.mnemonic, instr.op_str
        head, _, tail = ops.partition(",")
        head, tail = head.strip(), tail.strip()
        if mnem in ("test", "cmp") and "ptr" in ops:
            conditional = True
        elif mnem == "lea" and "[" in tail:
            base = ("lea", tail.split("[", 1)[1].rstrip("]"))
            obj_reg, add_off = head, 0
        elif mnem == "mov" and "[" in tail:
            # object pointer loaded from a frame slot (this, a local, or a param)
            base = ("mov", tail.split("[", 1)[1].rstrip("]"))
            obj_reg, add_off = head, 0
        elif mnem == "add" and head == obj_reg and tail.startswith("0x"):
            try:
                add_off += int(tail, 16)
            except ValueError:
                pass
        elif mnem == "jmp" and ops.startswith("0x"):
            dtor = int(ops, 16)              # tail-call to the destructor
            break
        elif mnem == "call" and ops.startswith("0x"):
            dtor = int(ops, 16)              # destructor or operator delete
        elif mnem == "ret":
            break

    return dtor, _normalize_target(base, add_off, this_slot), conditional


def _normalize_target(base, add_off: int, this_slot: str | None = None) -> str:
    """Canonical, cross-binary-comparable description of the destroyed object.

    - ``this+0xNN``  member subobject (``this`` is the saved this-pointer + offset)
    - ``arg@ebp+N``  a by-pointer parameter
    - ``stack@ebp-N``a stack-local object (SEH temporary)
    - ``ptr@ebp-N``  a saved object pointer (e.g. a ``delete``d member pointer)
    """
    if base is None:
        return f"this+0x{add_off:x}" if add_off else "(unknown)"
    kind, expr = base
    expr = expr.replace(" ", "")
    add = f"+0x{add_off:x}" if add_off else ""
    if kind == "lea" and expr.startswith("ebp+"):
        return f"arg@{expr}{add}"
    if kind == "lea" and expr.startswith("ebp-"):
        return f"stack@{expr}{add}"
    if kind == "mov" and expr.startswith("ebp+"):
        return f"arg@{expr}{add}"
    if kind == "mov" and expr.startswith("ebp-"):
        # A pointer reloaded from a frame slot; +offset => a subobject of it.
        # If the slot is the saved this-pointer it's a member of *this* (a stable,
        # cross-binary offset); otherwise it's a member of some other local pointer.
        if this_slot is not None and expr == this_slot:
            return f"this+0x{add_off:x}" if add_off else "this"
        return f"ptr@{expr}{add}"
    return f"{kind}({expr}){add}"


def parse_funcinfo(
    image: PEImage, funcinfo_addr: int, this_slot: str | None = None
) -> tuple[int, tuple[UnwindState, ...], tuple[TryBlock, ...]] | None:
    magic = _u32(image, funcinfo_addr)
    if magic is None or magic not in FUNCINFO_MAGICS:
        return None
    max_state = _i32(image, funcinfo_addr + 0x04) or 0
    p_unwind = _u32(image, funcinfo_addr + 0x08) or 0
    n_try = _i32(image, funcinfo_addr + 0x0C) or 0
    p_try = _u32(image, funcinfo_addr + 0x10) or 0

    unwinds: list[UnwindState] = []
    for i in range(max(max_state, 0)):
        entry = p_unwind + i * 8
        to_state = _i32(image, entry)
        action = _u32(image, entry + 4)
        if to_state is None:
            break
        if action:
            dtor, target, conditional = decode_unwind_funclet(image, action, this_slot)
        else:
            dtor, target, conditional = None, "(none)", False
        unwinds.append(UnwindState(i, to_state, action or None, dtor, target, conditional))

    try_blocks: list[TryBlock] = []
    for i in range(max(n_try, 0)):
        entry = p_try + i * 0x14
        try_low = _i32(image, entry)
        if try_low is None:
            break
        try_blocks.append(TryBlock(
            try_low=try_low,
            try_high=_i32(image, entry + 4) or 0,
            catch_high=_i32(image, entry + 8) or 0,
            catch_count=_i32(image, entry + 0xC) or 0,
        ))

    return max_state, tuple(unwinds), tuple(try_blocks)


_LOW_REGS = {
    "al": "eax",
    "bl": "ebx",
    "cl": "ecx",
    "dl": "edx",
}

_FULL_REGS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"})


def _parse_imm(text: str) -> int | None:
    text = text.strip().lower()
    if text.startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        return int(text, 10)
    except ValueError:
        return None


def _state_slot_operand(text: str) -> bool:
    compact = text.replace(" ", "").lower()
    return compact.endswith("[ebp-4]") and (
        compact.startswith("byteptr")
        or compact.startswith("wordptr")
        or compact.startswith("dwordptr")
    )


def _reg_value(reg_values: dict[str, int], operand: str) -> int | None:
    operand = operand.strip().lower()
    if operand in reg_values:
        return reg_values[operand]
    full = _LOW_REGS.get(operand)
    if full is not None and full in reg_values:
        return reg_values[full] & 0xFF
    return None


def _reachable_unwind_states(
    unwinds: tuple[UnwindState, ...], assigned_states: set[int]
) -> tuple[int, ...]:
    reachable: set[int] = set()
    pending = [state for state in assigned_states if 0 <= state < len(unwinds)]
    while pending:
        index = pending.pop()
        if index in reachable:
            continue
        reachable.add(index)
        to_state = unwinds[index].to_state
        if 0 <= to_state < len(unwinds):
            pending.append(to_state)
    return tuple(sorted(reachable))


def find_active_unwind_states(
    image: PEImage,
    func_start: int,
    unwinds: tuple[UnwindState, ...],
    max_scan: int = 4096,
) -> tuple[int, ...] | None:
    """Return unwind states that can be reached through ``[ebp-4]``.

    MSVC often leaves constructor-cleanup funclets in FuncInfo even when the
    function body never assigns that state number. Those states are useful in
    strict metadata comparisons but should not drive the default semantic audit.
    ``None`` means the state variable could not be recognized, so callers should
    conservatively treat every parsed state as active.
    """
    first_funclet = min(
        (state.action for state in unwinds if state.action is not None and state.action > func_start),
        default=None,
    )
    scan_limit = max_scan
    if first_funclet is not None:
        scan_limit = min(scan_limit, first_funclet - func_start)
    section_end = image.section_end_for_va(func_start)
    scan_size = scan_limit if section_end is None else min(scan_limit, section_end - func_start)
    data = image.read(func_start, scan_size)
    if not data:
        return None

    reg_values: dict[str, int] = {}
    assigned_states: set[int] = set()
    saw_state_write = False

    for instr in _md().disasm(data, func_start):
        mnem = instr.mnemonic.lower()
        head, sep, tail = instr.op_str.partition(",")
        head = head.strip().lower()
        tail = tail.strip().lower()

        if sep and mnem == "mov" and _state_slot_operand(head):
            saw_state_write = True
            value = _parse_imm(tail)
            if value is None:
                value = _reg_value(reg_values, tail)
            if value is not None and value >= 0:
                assigned_states.add(value)
            continue

        if sep and mnem == "and" and _state_slot_operand(head):
            saw_state_write = True
            value = _parse_imm(tail)
            if value is not None and (value & 0xFF) == 0:
                assigned_states.add(0)
            continue

        if mnem in ("xor", "sub") and sep and head == tail and head in _FULL_REGS:
            reg_values[head] = 0
            continue

        if mnem == "mov" and sep and head in _FULL_REGS:
            value = _parse_imm(tail)
            if value is None:
                reg_values.pop(head, None)
            else:
                reg_values[head] = value
            continue

        if mnem == "call":
            for reg in ("eax", "ecx", "edx"):
                reg_values.pop(reg, None)
            continue

        if head in _FULL_REGS:
            reg_values.pop(head, None)

    if not saw_state_write:
        return None
    return _reachable_unwind_states(unwinds, assigned_states)


def analyze_function_eh(image: PEImage, func_start: int) -> EHInfo:
    funcinfo_addr = find_funcinfo(image, func_start)
    if funcinfo_addr is None:
        return EHInfo(False, None, None, 0, (), (), ())
    this_slot = find_this_slot(image, func_start)
    parsed = parse_funcinfo(image, funcinfo_addr, this_slot)
    if parsed is None:
        return EHInfo(True, funcinfo_addr, _u32(image, funcinfo_addr), 0, (), (), ())
    max_state, unwinds, try_blocks = parsed
    magic = _u32(image, funcinfo_addr)
    active_states = find_active_unwind_states(image, func_start, unwinds)
    # Declaration order = reverse of unwind (highest state destroyed first).
    targets = tuple(u.target for u in unwinds if u.action is not None)
    return EHInfo(True, funcinfo_addr, magic, max_state, unwinds, try_blocks, targets, active_states)
