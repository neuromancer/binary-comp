# binary-comp

Standalone binary comparison and verification tools for C/C++ reimplementation
projects. The package is extracted from project-specific scripts into reusable
library modules plus a CLI.

It is used by the
[`my-teacher-is-an-alien-re`](https://github.com/neuromancer/my-teacher-is-an-alien-re)
source-code reconstruction and by two additional undisclosed reconstruction
projects.

The goal is to reduce the cost of bugs found near the end of source-code
reconstruction, when most functions are close to 100% matching but the remaining
differences are small, hard to localize, and still expected to be matchable.

Platform scope: `binary-comp` supports MSVC-built 32-bit PE reconstruction and
16-bit DOS reconstruction based on OMF objects or Turbo Pascal compiled units.

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
binary-comp mz-info PROGRAM.EXE
binary-comp exepack-unpack PACKED.EXE build/UNPACKED.EXE
binary-comp tpov-info --exe build/UNPACKED.EXE --overlay PROGRAM.OVR
binary-comp tpu-info build/UNIT.TPU
binary-comp tpu-scan --exe build/UNPACKED.EXE --overlay PROGRAM.OVR --tpu-dir build/tpus
binary-comp tpu-scan --exe build/UNPACKED.EXE --overlay FLAT.OVR --tpu-dir build/tpus \
  --regions build/code-regions.json --include-missing --resolve-adjacent
binary-comp omf-compare --original overlay.bin --original-offset 0x0 --object UNIT.OBJ --size 0x20
binary-comp tpu-compare --original overlay.bin --original-offset 0x1a40 --tpu UNIT.TPU --block 3
binary-comp tpu-compare --original PROG.OVR --tpu UNIT.TPU --block 3 --locate
```

Most analyzers that read rebuilt code will run the configured build command
first unless `--no-build` is supplied.

`binary-comp omf-compare` is for 16-bit DOS reconstruction work where the
rebuilt artifact is an OMF `.OBJ` instead of a linked executable. It compares
raw original bytes against a selected OMF `LEDATA` range and masks `FIXUPP`
relocation operands, which is useful for early Borland C/C++ matching before
the RTLink/link step is modeled.

`mz-info` validates a DOS MZ header, relocation table, load module, and optional
trailing data. `exepack-unpack` statically recovers Microsoft EXEPACK images: it
does not execute the packed program or unpacking stub. `tpov-info` discovers the
resident Turbo Pascal overlay descriptors and accepts them only when their code
and fixup extents form a unique, gap-free chain across the complete `TPOV`
image. Together these commands produce a stable resident/overlay layout for
subsequent routine matching.

`tpu-info` inventories compiled-unit sections, procedure code blocks, symbols,
and linker fixups. `tpu-scan` compiles that information into a first-pass
continuity report by locating every sufficiently distinctive, relocation-masked
code block in the resident MZ load module and descriptor-bounded overlay code.
For flat overlay formats whose bounds come from external evidence,
`--regions` accepts a generic JSON manifest instead of assuming `TPOV`:

```json
{
  "scan_regions": {
    "resident": [{"label": "resident-code", "index": 1, "start": 0, "end": 4096}],
    "overlay": [{"label": "overlay-a", "index": 7, "start": 8, "end": 8192}]
  }
}
```

Bounds are validated and may be non-contiguous, but may not overlap within an
image. Labels and indices are opaque project-supplied identifiers. Use
`--include-missing` for a complete examined-block inventory and `--exclude`
for generated aggregate TPU filename globs. `--resolve-adjacent` assigns an
otherwise duplicated block only when a consecutive block from the same TPU and
scan region uniquely anchors it on the left or right; resolution is iterative
for runs of identical routines and is recorded in JSON. Optional JSON output
can be retained as generated research data.

`binary-comp tpu-compare` is the Turbo Pascal / Borland Pascal counterpart for
projects whose rebuilt artifact is a compiled unit. It reads Turbo Pascal 5.0
(`TPU5`), 5.5 (`TPU6`), and 6.0 (`TPU9`, also used by Turbo Pascal for Windows
1.0) `.TPU` files, extracts the emitted CODE section, and masks the relocation
operands that the linker fills in (16-bit offsets, segments, and far pointers)
before comparing against a raw original byte window. Because Turbo Pascal
emits one code block per routine, `--block N` compares a single routine
directly; alternatively `--code-offset`/`--size` select an explicit window.
When the routine's exact
offset in the original is unknown — e.g. a routine inside a Turbo Pascal overlay
(`.OVR`) image, which is a flat concatenation of linked code — `--locate`
searches the image for the block by content (masking the block's own fixups) and
reports where it matched. This supports early per-unit Pascal matching before the
linked `.EXE`/`.OVR` is modeled. A
`dos16-tpu` target with a `tpu_compare.functions` config list drives the
`compare` and `report` commands the same way `dos16-omf` does:

```json
{
  "targets": { "sample": { "kind": "dos16-tpu", "original_exe": "original.bin", "source_dirs": ["src"] } },
  "tpu_compare": {
    "functions": [
      { "target": "sample", "name": "reset_state", "function": "reset_state",
        "original": "overlay.bin", "original_offset": "0x1a40", "tpu": "build/UNIT.TPU" }
    ]
  }
}
```

The compiled block is chosen by `function` (the Pascal routine name), resolved
against the unit's symbol table. This is robust to source reordering, forward
declarations, and compiler-emitted helper blocks, and a missing name or a
truncated `.TPU` produces a clear error instead of a silent mismatch. Set
`block_index` instead to pin a specific block when name resolution can't apply.
For a routine block with leading embedded data, `block_offset` skips that many
bytes within the selected block while preserving block-relative fixup masking.

`binary-comp values` also understands `dos16-tpu` targets. The `report`
similarity score matches instruction *types* only, so a block with the right
shape but a wrong immediate or stack-frame offset (`sub sp, 4` vs `sub sp,
0x12`, `cmp ax, 0x0d` vs `cmp ax, 0x0f`) still scores 100%. For a `dos16-tpu`
target `values` compares the actual bytes — masking only the relocation fixups,
exactly as the byte-locate does — and decodes every surviving difference back to
the instruction it lands in, printing rebuilt vs original side by side. It
reports each located function as byte-exact or lists its operand/constant
differences (functions whose windows no longer line up are flagged
`[structural]`). `--fail-on-diffs` exits non-zero for CI; `--filter NAME` scopes
to one function; `--show-exact` also lists the byte-exact functions.

`binary-comp export-asm` is a lightweight replacement for manual Ghidra
disassembly exports when exact Ghidra recovery is not needed. It writes to
`code_export_dir` using the same `FUN_XXXXXXXX.disassembled.txt` convention as
Ghidra, so projects can mix generated and real Ghidra exports. If source
`Function start` annotations or an original MSVC linker map are available, it
uses those as boundaries. Without them, it falls back to a PE-aware discovery
pass seeded from the entry point, direct calls/jumps, and common MSVC prologues;
use `--discover` to merge discovered functions with annotated/map functions.

### Ghidra Export Script

Use `binary-comp export-asm` for fast Capstone-based exports. Use the companion
Ghidra script when a project needs Ghidra's exact function recovery, including
manually created function boundaries and labels:
[`ghidra_scripts/ExportToCompile.java`](ghidra_scripts/ExportToCompile.java).

From the Ghidra UI:

1. Open the original executable in Ghidra.
2. Run analysis and verify the functions you care about exist in the listing.
3. Open `Window -> Script Manager`.
4. Add this checkout's `ghidra_scripts/` directory to the script directories,
   or copy `ExportToCompile.java` into `~/ghidra_scripts/`.
5. Run `ExportToCompile` and choose the target's configured `code_export_dir`
   when prompted.

The script writes:

```text
FUN_XXXXXXXX.disassembled.txt  # Ghidra-style assembly consumed by compare/report/calls
FUN_XXXXXXXX.decompiled.txt    # optional decompiler text used by call checks
globals.h                      # conservative global inventory helper
strings.txt                    # string inventory helper
```

The exported directory can then be used directly by the normal commands:

```bash
binary-comp compare --config path/to/binary-comp.json --target full ScoreTable::score code/FUN_00401000.disassembled.txt
binary-comp report --config path/to/binary-comp.json --target full
binary-comp calls --config path/to/binary-comp.json --target full
```

For automation, pass the export directory as the first script argument. This
avoids the UI directory chooser. For example, with Ghidra MCP script execution
enabled:

```bash
curl -sS -X POST http://127.0.0.1:8089/run_ghidra_script \
  -H 'Content-Type: application/json' \
  -d '{
    "script_name": "/path/to/binary-comp/ghidra_scripts/ExportToCompile.java",
    "args": "/path/to/code_export_dir",
    "program": "original.exe",
    "timeout_seconds": 120,
    "capture_output": true
  }'
```

Direct calls are normalized to absolute targets, so `binary-comp calls` sees
Ghidra exports and `binary-comp export-asm` output consistently.

## Development

Run the test suite with:

```bash
python3 -m pytest
```

The project still understands the legacy verification config shape used during
the first extraction, but new projects should prefer the standalone `targets`
schema shown above.
