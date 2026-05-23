"""Generic global declaration inventory.

This parser is intentionally small. It recognizes simple C/C++ global
declarations where an original address is either encoded in the symbol name or
placed in a trailing line comment.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


TYPE_SIZES = {
    "char": 1,
    "unsigned char": 1,
    "signed char": 1,
    "short": 2,
    "unsigned short": 2,
    "signed short": 2,
    "int": 4,
    "unsigned int": 4,
    "signed int": 4,
    "long": 4,
    "unsigned long": 4,
    "signed long": 4,
    "float": 4,
    "double": 8,
    "void*": 4,
}

DECL_RE = re.compile(
    r'^\s*(?P<leading>(?:/\*[^*]*(?:\*(?!/)[^*]*)*\*/\s*)*)'
    r'(?:extern\s+(?:"C"\s+)?)?(?:(?:static|const|volatile)\s+)*'
    r"(?P<type>[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*?)"
    r"(?:\s*(?P<pointers>\*+)\s*|\s+)"
    r"(?P<name>[A-Za-z_]\w*)"
    r"(?P<arrays>(?:\s*\[\s*(?:0[xX][0-9A-Fa-f]+|\d*)\s*\])*)"
    r"\s*(?:=\s*(?P<initializer>[\s\S]*?))?\s*;"
    r"(?P<trailing>[^\n]*)$",
    re.MULTILINE,
)
ADDRESS_SUFFIX_RE = re.compile(r"_([0-9A-Fa-f]{6,8})(?:$|_)")
COMMENT_ADDRESS_RE = re.compile(r"0x([0-9A-Fa-f]{6,8})")
ARRAY_DIM_RE = re.compile(r"\[\s*((?:0[xX][0-9A-Fa-f]+)|\d+)\s*\]")
EMPTY_ARRAY_RE = re.compile(r"\[\s*\]")
STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')


@dataclass(frozen=True)
class GlobalDecl:
    address: int
    size: int
    name: str
    type_name: str
    description: str


def address_from_name(name: str) -> int | None:
    match = ADDRESS_SUFFIX_RE.search(name)
    if not match:
        return None
    return int(match.group(1), 16)


def address_from_comment(comment: str) -> int | None:
    match = COMMENT_ADDRESS_RE.search(comment)
    if not match:
        return None
    return int(match.group(1), 16)


def element_size(type_name: str, extra_sizes: dict[str, int] | None = None) -> int:
    normalized = " ".join(type_name.replace("*", " *").split())
    if "*" in normalized:
        return 4
    if extra_sizes is not None and normalized in extra_sizes:
        return extra_sizes[normalized]
    return TYPE_SIZES.get(normalized, 4)


def array_count(arrays: str) -> int:
    count = 1
    for dim in ARRAY_DIM_RE.findall(arrays or ""):
        count *= int(dim, 0)
    return count


def _decode_c_string_bytes(literal: str) -> bytes:
    out = bytearray()
    index = 0
    while index < len(literal):
        ch = literal[index]
        if ch == "\\" and index + 1 < len(literal):
            esc = literal[index + 1]
            if esc in "\\\"'?":
                out.append(ord(esc))
                index += 2
                continue
            simple = {"n": 0x0A, "r": 0x0D, "t": 0x09, "b": 0x08,
                      "f": 0x0C, "v": 0x0B, "a": 0x07, "0": 0x00}
            if esc in simple:
                out.append(simple[esc])
                index += 2
                continue
            if esc == "x":
                end = index + 2
                while end < len(literal) and literal[end] in "0123456789abcdefABCDEF":
                    end += 1
                out.append(int(literal[index + 2:end], 16) & 0xFF)
                index = end
                continue
            out.append(ord(esc))
            index += 2
            continue
        out.append(ord(ch) & 0xFF)
        index += 1
    return bytes(out)


def string_initializer_size(initializer: str | None) -> int | None:
    if initializer is None:
        return None
    text = initializer.strip()
    if not text.startswith('"'):
        return None
    total = 0
    for match in STRING_LITERAL_RE.finditer(text):
        total += len(_decode_c_string_bytes(match.group(1)))
    return total + 1  # trailing NUL


def describe_initializer(initializer: str | None) -> str:
    if initializer is None:
        return "uninitialized"
    text = initializer.strip()
    if len(text) > 30:
        text = text[:30] + "..."
    return f"init: {text}"


def parse_globals_source(path: str, extra_type_sizes: dict[str, int] | None = None) -> list[GlobalDecl]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    globals_list: list[GlobalDecl] = []
    for match in DECL_RE.finditer(content):
        name = match.group("name")
        trailing = match.group("trailing") or ""
        leading = match.group("leading") or ""
        address = address_from_name(name)
        if address is None:
            address = address_from_comment(trailing)
        if address is None:
            address = address_from_comment(leading)
        if address is None:
            continue

        pointers = match.group("pointers") or ""
        type_name = " ".join(match.group("type").split()) + ("*" * pointers.count("*"))
        arrays_text = match.group("arrays") or ""
        elem_size = element_size(type_name, extra_type_sizes)
        if EMPTY_ARRAY_RE.search(arrays_text) and elem_size == 1:
            string_size = string_initializer_size(match.group("initializer"))
            if string_size is not None:
                size = string_size * array_count(arrays_text)
            else:
                size = elem_size * array_count(arrays_text)
        else:
            size = elem_size * array_count(arrays_text)
        globals_list.append(GlobalDecl(
            address=address,
            size=size,
            name=name,
            type_name=type_name,
            description=describe_initializer(match.group("initializer")),
        ))

    globals_list.sort(key=lambda item: item.address)
    return globals_list
