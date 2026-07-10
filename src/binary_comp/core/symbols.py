"""Symbol name normalization and matching."""

from __future__ import annotations

import re


_PRIMITIVE_TYPES = {
    "X": "void",
    "D": "char",
    "E": "unsigned char",
    "F": "short",
    "G": "unsigned short",
    "H": "int",
    "I": "unsigned int",
    "J": "long",
    "K": "unsigned long",
    "M": "float",
    "N": "double",
}


def split_name_parameters(name: str) -> str:
    return name.split("(", 1)[0]


def decode_msvc_pointer_class_tokens(encoded: str) -> list[str]:
    """Class names of the ``PAV<class>@@`` pointer tokens in a mangled tail.

    Numeric back-references (``PAV2@@``) repeat the previous token.
    """
    tokens: list[str] = []
    for match in re.finditer(r"PAV([^@]+)@@", encoded):
        token = match.group(1)
        if token.isdigit():
            if tokens:
                tokens.append(tokens[-1])
            continue
        tokens.append(token.replace("@", "::"))
    return tokens


def _decode_msvc_named_type(encoded: str, pos: int, previous_class_tokens: list[str]) -> tuple[str | None, int]:
    if pos >= len(encoded) or encoded[pos] not in "UV":
        return None, pos

    end = encoded.find("@@", pos + 1)
    if end < 0:
        return None, pos

    token = encoded[pos + 1:end]
    if token.isdigit() and previous_class_tokens:
        type_name = previous_class_tokens[-1]
    else:
        type_name = token.replace("@", "::")
    previous_class_tokens.append(type_name)
    return type_name, end + 2


def _decode_msvc_type(encoded: str, pos: int, previous_class_tokens: list[str]) -> tuple[str | None, int]:
    if pos >= len(encoded):
        return None, pos

    start = pos
    code = encoded[pos]
    primitive = _PRIMITIVE_TYPES.get(code)
    if primitive is not None:
        return primitive, pos + 1

    named, next_pos = _decode_msvc_named_type(encoded, pos, previous_class_tokens)
    if named is not None:
        return named, next_pos

    if code == "P":
        pos += 1
        while pos < len(encoded) and encoded[pos] in "ABCDQ":
            pos += 1
        pointee, next_pos = _decode_msvc_type(encoded, pos, previous_class_tokens)
        if pointee is None:
            return None, start
        return f"{pointee}*", next_pos

    return None, start


def _decode_msvc_parameters(encoded: str) -> list[str]:
    # Member functions start with access/cv/calling-convention flags, then the
    # return type, then the parameter type stream.
    pos = 3
    previous_class_tokens: list[str] = []
    _, pos = _decode_msvc_type(encoded, pos, previous_class_tokens)

    parameters: list[str] = []
    while pos < len(encoded):
        if encoded.startswith("@Z", pos) or encoded[pos] == "Z":
            break
        if encoded[pos] == "@":
            pos += 1
            continue
        type_name, next_pos = _decode_msvc_type(encoded, pos, previous_class_tokens)
        if type_name is None or next_pos <= pos:
            break
        if type_name != "void":
            parameters.append(type_name)
        pos = next_pos
    return parameters


def normalize_compiled(name: str, signature_names: frozenset[str] = frozenset()) -> str:
    """Demangle a rebuilt MSVC symbol to a readable ``Class::method`` form.

    For names listed in ``signature_names`` (overloaded methods), the decoded
    pointer-parameter types are appended, e.g.
    ``?PopSafe@TimedEventPool@@QAEPAVSpriteAction@@PAV2@@Z`` ->
    ``TimedEventPool::PopSafe(SpriteAction*)``.
    """
    name = name.strip()
    if name.startswith("??0") and "@@" in name:
        match = re.match(r"\?\?0(\w+)@@", name)
        if match:
            return f"{match.group(1)}::{match.group(1)}"
    if name.startswith("??1") and "@@" in name:
        match = re.match(r"\?\?1(\w+)@@", name)
        if match:
            return f"{match.group(1)}::~{match.group(1)}"
    if name.startswith("??2@"):
        return "operator_new"
    if name.startswith("??3@"):
        return "operator_delete"
    if name.startswith("?") and "@@" in name:
        match = re.match(r"\?(\w+)@(\w+)@@", name)
        if match:
            normalized = f"{match.group(2)}::{match.group(1)}"
            if normalized in signature_names:
                parameters = _decode_msvc_parameters(name[match.end():])
                return f"{normalized}({','.join(parameters)})"
            return normalized
        match = re.match(r"\?(\w+)@@", name)
        if match:
            return match.group(1)
    if name.startswith("_") and "::" not in name and "@" not in name:
        return name[1:]
    match = re.match(r"@([\w]+)@\d+", name)
    if match:
        return match.group(1)
    match = re.match(r"_?(\w+)@\d+$", name)
    if match:
        return match.group(1)
    if "eh vector constructor iterator" in name:
        return "__eh_vec_ctor__"
    if "eh vector destructor iterator" in name:
        return "__eh_vec_dtor__"
    return name


def canonical_function_name(name: str) -> str:
    return split_name_parameters(name)


def symbol_patterns_for_function(name: str) -> list[str]:
    base = split_name_parameters(name)
    if "::" in base:
        class_name, method_name = base.rsplit("::", 1)
        class_leaf = class_name.rsplit("::", 1)[-1]
        if method_name == class_leaf:
            return [f"??0{class_leaf}@@"]
        if method_name.startswith("~"):
            return [f"??1{class_leaf}@@"]
        return [f"?{method_name}@{class_leaf}@@"]
    return [f"?{base}@@", f"_{base}@", f"_{base}"]


def symbol_matches(mangled: str, patterns: list[str]) -> bool:
    return any(pattern == mangled or mangled.startswith(pattern) or pattern in mangled for pattern in patterns)


VFTABLE_SYMBOL_RE = re.compile(r"^\?\?_7(?P<cls>\w+)@@6B")
DELETING_DTOR_SYMBOL_RE = re.compile(r"^\?\?_[EG](?P<cls>\w+)@@")
DTOR_SYMBOL_RE = re.compile(r"^\?\?1(?P<cls>\w+)@@")
CTOR_SYMBOL_RE = re.compile(r"^\?\?0(?P<cls>\w+)@@")
METHOD_SYMBOL_RE = re.compile(r"^\?(?P<method>\w+)@(?P<cls>\w+)@@")

PURECALL_SYMBOLS = frozenset({"_purecall", "__purecall"})


def msvc_vftable_class(mangled: str) -> str | None:
    """Class name of a ``??_7<Class>@@6B@`` vftable symbol, else None."""
    match = VFTABLE_SYMBOL_RE.match(mangled)
    return match.group("cls") if match else None


def msvc_method_symbol(mangled: str) -> tuple[str, str] | None:
    """``(class, method)`` for a mangled MSVC member function, else None.

    Deleting destructors (``??_E``/``??_G``) and plain destructors (``??1``)
    all report as ``~Class`` so callers can treat them interchangeably; the
    compiler chooses which one lands in a vtable slot.  Free functions,
    vftables and unrecognized decorations return None.
    """
    if mangled in PURECALL_SYMBOLS:
        return None
    if VFTABLE_SYMBOL_RE.match(mangled):
        return None
    for pattern in (DELETING_DTOR_SYMBOL_RE, DTOR_SYMBOL_RE):
        match = pattern.match(mangled)
        if match:
            cls = match.group("cls")
            return cls, f"~{cls}"
    match = CTOR_SYMBOL_RE.match(mangled)
    if match:
        cls = match.group("cls")
        return cls, cls
    match = METHOD_SYMBOL_RE.match(mangled)
    if match:
        return match.group("cls"), match.group("method")
    return None


def is_destructor_method(method_name: str) -> bool:
    return method_name.startswith("~")
