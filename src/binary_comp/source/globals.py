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
    r'^\s*(?:extern\s+(?:"C"\s+)?)?(?:(?:static|const|volatile)\s+)*'
    r"(?P<type>[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*?)"
    r"(?:\s*(?P<pointers>\*+)\s*|\s+)"
    r"(?P<name>[A-Za-z_]\w*)"
    r"(?P<arrays>(?:\s*\[\s*\d+\s*\])*)"
    r"\s*(?:=\s*(?P<initializer>.*?))?\s*;"
    r"(?P<trailing>[^\n]*)$",
    re.MULTILINE,
)
ADDRESS_SUFFIX_RE = re.compile(r"_([0-9A-Fa-f]{6,8})(?:$|_)")
COMMENT_ADDRESS_RE = re.compile(r"0x([0-9A-Fa-f]{6,8})")
ARRAY_DIM_RE = re.compile(r"\[\s*(\d+)\s*\]")


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


def element_size(type_name: str) -> int:
    normalized = " ".join(type_name.replace("*", " *").split())
    if "*" in normalized:
        return 4
    return TYPE_SIZES.get(normalized, 4)


def array_count(arrays: str) -> int:
    count = 1
    for dim in ARRAY_DIM_RE.findall(arrays or ""):
        count *= int(dim)
    return count


def describe_initializer(initializer: str | None) -> str:
    if initializer is None:
        return "uninitialized"
    text = initializer.strip()
    if len(text) > 30:
        text = text[:30] + "..."
    return f"init: {text}"


def parse_globals_source(path: str) -> list[GlobalDecl]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    globals_list: list[GlobalDecl] = []
    for match in DECL_RE.finditer(content):
        name = match.group("name")
        trailing = match.group("trailing") or ""
        address = address_from_name(name)
        if address is None:
            address = address_from_comment(trailing)
        if address is None:
            continue

        pointers = match.group("pointers") or ""
        type_name = " ".join(match.group("type").split()) + ("*" * pointers.count("*"))
        size = element_size(type_name) * array_count(match.group("arrays") or "")
        globals_list.append(GlobalDecl(
            address=address,
            size=size,
            name=name,
            type_name=type_name,
            description=describe_initializer(match.group("initializer")),
        ))

    globals_list.sort(key=lambda item: item.address)
    return globals_list
