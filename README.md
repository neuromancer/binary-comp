# binary-comp

Standalone binary comparison and verification tools for C/C++ reimplementation
projects. The package is extracted from project-specific scripts into reusable
library modules plus a CLI.

It is used by this source-code reconstruction and two additional undisclosed
reconstruction projects.

The goal is to reduce the cost of bugs found near the end of source-code
reconstruction, when most functions are close to 100% matching but the remaining
differences are small, hard to localize, and still expected to be matchable.

Platform scope: `binary-comp` is currently optimized for MSVC-built 32-bit PE
reconstruction projects, with some analyzers reusable elsewhere when equivalent
address mappings are available.

`binary-comp` is built around the workflow used by many MSVC-era reverse
engineering projects:

1. Keep the original executable as the reference.
2. Rebuild C/C++ source with the matching compiler and linker.
3. Use source annotations, linker maps, and optional Ghidra-style text exports
   to map original functions and globals to rebuilt symbols.
4. Compare layout, function bytes, decoded operands, global data, calls,
   global accesses, vtables, and C++ exception-handling metadata.

## Reconstruction Mismatch Demo

[`examples/reconstruction-mismatch-demo`](examples/reconstruction-mismatch-demo)
is a small end-to-end MSVC 4.2 C++ reconstruction with real 32-bit PE
executables, four reconstructed classes, an intentional global mismatch, and an
original-only C++ EH cleanup path.

The Makefile downloads `wibo`, MSVC420, and the `msvcrt40.dll` copy required by
`wibo`; no submodules or Ghidra export step are needed. `make build` compiles
both executables and runs `binary-comp export-asm --clean --no-source`, so the
local `code/FUN_*.disassembled.txt` files are regenerated from auto-discovery.

```bash
cd examples/reconstruction-mismatch-demo
make demo
```

Small excerpts from the generated reports:

The similarity score compares instruction kinds and control-flow shape; it does
not decide whether operands such as constants, stack offsets, or referenced
addresses are correct.

```text
--- Similarity Report ---

=== rebuilt.cpp ===
  Door::canOpen                                 0x40109E  80.00%
  LessonLog::severity                           0x4010E8  50.00%
```

The assembly diff below prints reconstructed code on the left and original code
on the right. It comes from this source-level mismatch:

```cpp
// Reconstructed
int LessonLog::severity(int channel) const
{
    int severity = base_ + channel;
    if (g_Title_00407030[1] == 'L') {
        severity += g_Rotor_00407040[(channel + 1) & 1];
    }
    return severity;
}

// Original
int LessonLog::severity(int channel) const
{
    int severity = base_ + channel;
    CleanupProbe probe(&severity);
    if (g_Title_00407030[0] == 'A') {
        severity += g_Rotor_00407040[channel & 1];
    }
    return severity;
}
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
004010BF: movsx eax, byte ptr [0x405031]        | 00401106: mov dword ptr [ebp - 0x1c], ecx
004010C6: cmp eax, 0x4c                         | 00401109: mov eax, dword ptr [ebp - 0x1c]
004010D2: dec eax                               | 00401111: mov dword ptr [ebp - 0x14], eax
004010D6: mov eax, dword ptr [eax*4 + 0x405040] | 00401117: push eax
                                                | ...
                                                | 00401154: call 0x401161

Similarity: 50.00%
```

The values analyzer is the follow-up pass for those incorrect operands. Here it
reduces the noisy assembly diff to the changed immediate that came from the
reconstructed `'L'` check versus the original `'A'` check:

```text
LessonLog::severity (orig 0x4010E8, rebuilt 0x4010A8, 58.8%) - 4 mismatch(es):
    IMM 76 vs 65: 0x004010C6 cmp eax, 0x4c  |  0x0040112E cmp eax, 0x41
```

The SEH analyzer explains the extra frame setup and cleanup call on the original
side:

```text
LessonLog::severity  (0x4010E8)
    WARNING: rebuilt has NO C++ EH frame, original unwinds 1 state(s) ['stack@ebp-0x10']
```

The demo also runs the global detector as a separate project-level check:

```text
Global initialization/layout audit
  definitions:  4
  issues:       1
  auto-complete global side effects: 3 (0 reviewed, 3 unreviewed)

INIT_MISMATCH                   0x00407038 g_Bonus_00407038:2 size=4
  original: 07 00 00 00  ?...
  source:   09 00 00 00  ?...

Auto-complete global side effects (unreviewed)
UNREVIEWED 0x00403460
  note: CRT initializer table 0x00407000..0x00407008
```

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

## Development

Run the test suite with:

```bash
python3 -m pytest
```

The project still understands the legacy verification config shape used during
the first extraction, but new projects should prefer the standalone `targets`
schema shown above.
