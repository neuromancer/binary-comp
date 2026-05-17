"""Symbol name normalization and matching."""

from __future__ import annotations


def split_name_parameters(name: str) -> str:
    return name.split("(", 1)[0]


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
