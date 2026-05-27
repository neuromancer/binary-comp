# binary-comp

Standalone binary comparison and verification tools for C/C++ reimplementation
projects.

The package is being extracted from project-specific scripts into reusable
library modules plus a CLI. The current analyzers cover executable layout
comparison, call target verification, Capstone-backed operand value checks,
global data comparison, global declaration audits, and vtable verification:

```bash
binary-comp calls --config path/to/binary-comp.json --target full
binary-comp compare --config path/to/binary-comp.json --target full FunctionName code/FUN_ADDR.disassembled.txt
binary-comp exe --config path/to/binary-comp.json --target demo --functions
binary-comp values --config path/to/binary-comp.json --target full
binary-comp data --config path/to/binary-comp.json --target full
binary-comp globals --config path/to/binary-comp.json --target full
binary-comp report --config path/to/binary-comp.json --target full
binary-comp vtables --config path/to/binary-comp.json --target full
```

## Design principles

Tools should require the minimum practical configuration to run. Each analyzer
must document the exact inputs it needs, provide sensible defaults for analyzer
policy, and include a minimal config file whenever project-specific paths are
required.

## Minimal configuration

The value checker needs only a target description: original binary, rebuilt
binary, linker map, and source directory. The call target checker needs source
annotations, a Ghidra disassembly export directory, and compiler assembly
listings via `asm_dir`. The vtable checker needs the original binary, source
directory, and a Ghidra export directory for function-boundary hints. The data
checker and globals audit also need a globals source file with original
addresses encoded in symbol names or comments.

The globals audit can use optional `globals_header`, `code_globals_header`,
`define_headers`, and `auto_complete` paths for broader coverage. Analyzer
policy such as custom type sizes and reviewed auto-complete effects lives in
top-level config sections when needed; absent optional sections are treated as
empty. Function boundaries from a Ghidra export directory are hints only;
operands and vtable writes are decoded from the binaries with Capstone.
The executable comparer can use optional target `library_ranges` to exclude
known CRT/library address ranges from function mapping summaries.

The value checker prints a mismatch breakdown by operand kind and highlights
the functions with the most mismatches. It also normalizes equivalent pointer
aliases where compiler scheduling changes a temporary register but the final
effective address is the same.

The vtable checker separates invalid parent references from parent classes
that exist in source but do not yet have vtable metadata. When possible, it
reports candidate parent vtables discovered from constructor vptr writes so the
source annotations or config can be completed without guessing.

```json
{
  "targets": {
    "full": {
      "original_exe": "path/to/original.exe",
      "rebuilt_exe": "path/to/rebuilt.exe",
      "map": "path/to/rebuilt.map",
      "source_dirs": ["path/to/src"],
      "globals_source": "path/to/src/globals.cpp",
      "code_export_dir": "path/to/ghidra-export",
      "asm_dir": "path/to/asm-output",
      "library_ranges": [["0x00424540", "0x004304E0"]]
    }
  }
}
```

A copy of this minimal config is kept at
[`examples/minimal-binary-comp.json`](examples/minimal-binary-comp.json).

For local development from a checkout:

```bash
PYTHONPATH=src python3 -m binary_comp.cli values --help
```

Or install it editable with the optional analyzer dependencies:

```bash
python3 -m pip install -e ".[all]"
binary-comp values --help
```

Run the test suite with:

```bash
python3 -m pytest
```
