# binary-comp

Standalone binary comparison and verification tools for C/C++ reimplementation
projects. The package is extracted from project-specific scripts into reusable
library modules plus a CLI.

`binary-comp` is built around the workflow used by many MSVC-era reverse
engineering projects:

1. Keep the original executable as the reference.
2. Rebuild C/C++ source with the matching compiler and linker.
3. Use source annotations, linker maps, and optional Ghidra-style text exports
   to map original functions and globals to rebuilt symbols.
4. Compare layout, function bytes, decoded operands, global data, calls,
   global accesses, vtables, and C++ exception-handling metadata.

## Platform Scope

`binary-comp` is currently optimized for MSVC-built 32-bit PE reconstruction
projects. Some analyzers are reusable for other binaries when equivalent
address mappings are available, but several important pieces assume MSVC-era
conventions: linker maps and symbol names, PE image layout, x86 disassembly,
common MSVC function prologues, and MSVC C++ exception metadata such as
`FuncInfo` and `__CxxFrameHandler`.

## Install

For local development from a checkout, install it editable with all optional
analyzer dependencies:

```bash
python3 -m pip install -e ".[all]"
binary-comp values --help
```

The optional dependencies are split by feature:

- `binary-comp[capstone]` for PE disassembly-backed analyzers.
- `binary-comp[cpp]` for C/C++ source annotation parsing.
- `binary-comp[all]` for both plus pytest.

## Configuration

The standalone config is target-oriented. A target describes the original PE,
the rebuilt PE, the rebuilt linker map, and the source tree that carries the
original-address annotations.

```json
{
  "targets": {
    "full": {
      "original_exe": "path/to/original.exe",
      "rebuilt_exe": "path/to/rebuilt.exe",
      "map": "path/to/rebuilt.map",
      "source_dirs": ["path/to/src"],
      "globals_source": "path/to/src/globals.cpp",
      "globals_header": "path/to/src/globals.h",
      "code_globals_header": "path/to/code/globals.h",
      "define_headers": ["path/to/src/constants.h"],
      "auto_complete": "path/to/src/auto_complete.txt",
      "code_export_dir": "path/to/ghidra-export",
      "asm_dir": "path/to/asm-output",
      "source_excludes": ["path/to/src/generated.cpp"],
      "library_ranges": [["0x00424540", "0x004304e0"]]
    }
  }
}
```

Relative paths are resolved from the config file directory. A copy of the
minimum shape is kept at
[`examples/minimal-binary-comp.json`](examples/minimal-binary-comp.json).

### Source Function Annotations

Place a `Function start` comment immediately before the rebuilt source function
that represents an original function:

```cpp
/* Function start: 0x00401000 */
int ScoreTable::score(int value) const
{
    return value + 7;
}
```

Multiple comments before the same function are allowed. This is useful when
Ghidra splits one MSVC SEH function into several original chunks but the rebuilt
compiler emits one function.

### Global Annotations

Global data analyzers need original addresses either encoded in symbol names or
placed in comments:

```cpp
int g_Bias_00405038 = 7;
char g_Label[6] = "alien"; // 0x00405030
```

The rebuilt MAP file provides the rebuilt VA for each encoded-address symbol,
allowing `binary-comp data` to compare original bytes against relocated rebuilt
bytes.

### Optional Inputs By Analyzer

| Analyzer | Required target fields | Extra notes |
| --- | --- | --- |
| `exe` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs` | `--functions` uses function annotations and the rebuilt MAP. `library_ranges` can exclude known CRT/library ranges. |
| `export-asm` | `original_exe`, `code_export_dir` | Generates Ghidra-style `FUN_*.disassembled.txt` exports with Capstone. Source annotations and an original map are optional boundary inputs; existing Ghidra exports remain compatible. |
| `compare` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs` | Also takes one Ghidra-style `FUN_*.disassembled.txt` path. |
| `report` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs`, `code_export_dir` | Uses one export per annotated original address. Generate them with `export-asm` or Ghidra. |
| `values` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs` | `code_export_dir` improves original function boundaries. Capstone is required. |
| `data` | `original_exe`, `rebuilt_exe`, `map`, `globals_source` | Compares globals with encoded or commented original addresses. |
| `globals` | `original_exe`, `globals_source` | Optional headers and `auto_complete` broaden coverage. |
| `calls` | `source_dirs`, `code_export_dir`, `asm_dir` | Compares call target multisets from original exports and rebuilt assembly listings. |
| `global-access` | `source_dirs`, `code_export_dir`, `asm_dir` | Compares read/write multisets for global data references. |
| `vtables` | `original_exe`, `source_dirs`, `code_export_dir` | Reads vtable bytes and constructor vptr writes from the original PE. |
| `seh` | `original_exe`, `rebuilt_exe`, `map`, `source_dirs` | Compares MSVC C++ EH FuncInfo metadata for a function or report. |

## CLI Examples

```bash
binary-comp exe --config path/to/binary-comp.json --target full --functions
binary-comp export-asm --config path/to/binary-comp.json --target full --clean
binary-comp compare --config path/to/binary-comp.json --target full ScoreTable::score code/FUN_00401000.disassembled.txt
binary-comp values --config path/to/binary-comp.json --target full --filter ScoreTable::score
binary-comp data --config path/to/binary-comp.json --target full --verbose
binary-comp globals --config path/to/binary-comp.json --target full --fail-on-issues
binary-comp calls --config path/to/binary-comp.json --target full --fail-on-mismatches
binary-comp global-access --config path/to/binary-comp.json --target full --include-address-immediates
binary-comp report --config path/to/binary-comp.json --target full
binary-comp vtables --config path/to/binary-comp.json --target full --dump
binary-comp seh --config path/to/binary-comp.json --target full --report
```

Most analyzers that read rebuilt code will run the configured build command
first unless `--no-build` is supplied.

`binary-comp export-asm` is a lightweight replacement for manual Ghidra
disassembly exports when exact Ghidra recovery is not needed. It writes to
`code_export_dir` using the same `FUN_XXXXXXXX.disassembled.txt` convention as
Ghidra, so projects can mix generated and real Ghidra exports. If source
`Function start` annotations or an original MSVC linker map are available, it
uses those as boundaries. Without them, it falls back to a PE-aware discovery
pass seeded from the entry point, direct calls/jumps, and common MSVC prologues;
use `--discover` to merge discovered functions with annotated/map functions.

## Reconstruction Mismatch Demo

[`examples/reconstruction-mismatch-demo`](examples/reconstruction-mismatch-demo)
contains a small, partially reconstructed C++ console program built with MSVC
4.x. It is designed to show the analyzers on a non-perfect rebuild, not just a
100% match. It includes:

- Original and rebuilt C++ source files.
- Real 32-bit PE executables compiled by MSVC 4.2.
- MSVC linker maps and assembly listings.
- A Makefile step that generates Capstone-based Ghidra-style
  `FUN_*.disassembled.txt` exports.
- A `binary-comp.json` target that runs the package against those artifacts.
- A Makefile that downloads `wibo` and MSVC420 into a local `.tools/`
  directory; no submodules are required.
- A Makefile step that replaces `MSVC420/bin/msvcrt40.dll` with the known-good
  DLL required by `wibo` before compiling.

From the example directory:

```bash
make setup
make build
binary-comp exe --config binary-comp.json --target demo --functions
binary-comp report --config binary-comp.json --target demo --no-build
binary-comp compare --config binary-comp.json --target demo --no-build LessonLog::severity code/FUN_004010E8.disassembled.txt
binary-comp values --config binary-comp.json --target demo --no-build --include-stack-locals
binary-comp data --config binary-comp.json --target demo
binary-comp seh --config binary-comp.json --target demo --report --no-build
```

`make build` invokes `binary-comp export-asm --config binary-comp.json --target demo --clean --no-source`,
so the local `code/FUN_*.disassembled.txt` files are regenerated from
auto-discovery rather than committed Ghidra exports or an original linker map.

The example intentionally includes discrepancies across four small reconstructed
classes plus an original-only cleanup helper: function similarity differences,
a focused single-function diff, an immediate-value mismatch, a global data
mismatch, shifted function addresses, and an original-only C++ EH frame.
`binary-comp data` and `binary-comp seh --report` exit nonzero in this example
because they find the expected mismatches.

Small excerpts from the generated reports:

```text
--- Similarity Report ---

=== rebuilt.cpp ===
  Door::canOpen                                 0x40109E  80.00%
  LessonLog::severity                           0x4010E8  52.94%
```

```text
Comparison for function 'LessonLog::severity':
004010AB: sub esp, 8                            | 004010EB: push -1
004010AE: push ebx                              | 004010ED: push 0x40116a
004010AF: push esi                              | 004010F2: mov eax, dword ptr fs:[0]
004010B0: push edi                              | 004010F8: push eax
004010B1: mov dword ptr [ebp - 8], ecx          | 004010F9: mov dword ptr fs:[0], esp
004010B4: mov eax, dword ptr [ebp - 8]          | 00401100: sub esp, 0x10
...
004010DF: mov eax, dword ptr [ebp - 4]          | 00401118: lea ecx, [ebp - 0x10]
004010E2: jmp 0x4010e7                          | 0040111B: call 0x401220
004010E7: pop edi                               | 00401120: mov dword ptr [ebp - 4], 0
004010E8: pop esi                               | 00401127: movsx eax, byte ptr [0x407030]
004010E9: pop ebx                               | 0040112E: cmp eax, 0x41
004010EA: leave                                 | 00401131: jne 0x401147
004010EB: ret 4                                 | 00401137: mov eax, dword ptr [ebp + 8]
                                                | 0040113A: and eax, 1
                                                | ...
                                                | 00401154: call 0x401161

Similarity: 52.94%
```

```text
0x00407038   0x00405038     g_Bonus_00407038             MISMATCH   init: 9
             Original value: 0x00000007 (7)
             Rebuilt value:  0x00000009 (9)
```

```text
LessonLog::severity  (0x4010E8)
    WARNING: rebuilt has NO C++ EH frame, original unwinds 1 state(s) ['stack@ebp-0x10']
```

## Development

Run the test suite with:

```bash
python3 -m pytest
```

The project still understands the legacy verification config shape used during
the first extraction, but new projects should prefer the standalone `targets`
schema shown above.
