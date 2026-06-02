"""Helpers for Ghidra-style text exports.

Ghidra files and ``binary-comp export-asm`` files are used as
function-boundary/name inventory only. Operand-level semantics must come from
binary disassembly.
"""

from __future__ import annotations

import glob
import os
import re


FUN_DISASSEMBLY_RE = re.compile(r"FUN_([0-9A-Fa-f]+)\.disassembled\.txt$")


def function_starts_from_export_dir(code_dir: str | None) -> list[int]:
    if not code_dir or not os.path.isdir(code_dir):
        return []

    starts = set()
    for path in glob.glob(os.path.join(code_dir, "FUN_*.disassembled.txt")):
        match = FUN_DISASSEMBLY_RE.search(os.path.basename(path))
        if match:
            starts.add(int(match.group(1), 16))
    return sorted(starts)
