# Reconstruction Mismatch Demo

This directory is a small end-to-end fixture using real 32-bit PE files built
with MSVC 4.x. It is intentionally not a perfect reconstruction: the rebuilt
source has several small differences so the analyzers have something useful to
report.

The example has four tiny reconstructed classes:

- `ScoreTable`
- `Reactor`
- `Door`
- `LessonLog`

The original source also has a small `CleanupProbe` helper with a destructor.
`LessonLog::severity` owns one on the stack, so MSVC emits a C++ EH cleanup
frame. The rebuilt source deliberately omits that local object so the `seh`
analyzer has a meaningful difference to report.

The rebuilt source carries the annotations that `binary-comp` uses to map
source functions back to original addresses:

```cpp
/* Function start: 0x00401029 */
int ScoreTable::score(int value) const
```

The globals encode their original addresses in their names:

```cpp
char g_Title_00407030[8] = "ALIEN!";
int g_Bonus_00407038 = 9;
```

## Tool Setup

This example does not use submodules. The Makefile downloads local tools under
`.tools/`:

- `decompals/wibo` release binary
- `itsmattkc/MSVC420` source archive
- a known-good `msvcrt40.dll`, copied into `MSVC420/bin/`

From this directory:

```bash
make setup
make build
```

Override paths when you already have local copies:

```bash
make build WIBO=/path/to/wibo MSVC42_DIR=/path/to/MSVC420
```

`make build` compiles both executables, writes MSVC maps and assembly listings
under `artifacts/`, and runs `binary-comp export-asm --no-source` to
auto-discover functions from the original executable. The generated
`code/FUN_*.disassembled.txt` files use the same shape as Ghidra disassembly
exports, but this example does not require Ghidra or an original linker map.

The `msvcrt40.dll` copy is required for `wibo`: the DLL bundled in the MSVC420
archive is replaced before `CL.EXE` is invoked.

## Step By Step

From this directory, with `binary-comp` installed:

1. Download the local toolchain and the known-good DLL used by `wibo`:

   ```bash
   make setup
   ```

2. Compile the original and rebuilt MSVC 4.x executables, then auto-discover
   Ghidra-style exports from the original PE:

   ```bash
   make build
   ```

`make build` runs the export step automatically. To run that step by hand:

```bash
binary-comp export-asm --config binary-comp.json --target demo --clean --no-source
```

The export summary should show discovered targets only:

```text
Wrote 92 disassembly export(s) to .../code
Selected 0 source target(s), 0 map target(s), 92 discovered target(s); 92 boundary marker(s).
```

3. Inspect executable layout and function address mapping:

   ```bash
   binary-comp exe --config binary-comp.json --target demo --functions
   ```

4. Generate the function similarity report:

   ```bash
   binary-comp report --config binary-comp.json --target demo --no-build
   ```

5. Drill into one mismatching function:

   ```bash
   binary-comp compare --config binary-comp.json --target demo --no-build Door::canOpen code/FUN_0040109E.disassembled.txt
   ```

6. Check operand value, global data, and SEH differences:

   ```bash
   binary-comp values --config binary-comp.json --target demo --no-build --include-stack-locals
   binary-comp data --config binary-comp.json --target demo
   binary-comp seh --config binary-comp.json --target demo --report --no-build
   ```

Or run the demonstration target:

```bash
make demo
```

Expected discrepancies include:

- `report`: `Door::canOpen` is below 90% similarity because the rebuilt method
  is missing one passcode branch. `LessonLog::severity` is also below 90%
  because the original has a local object cleanup path.
- `compare`: the single-function diff for `Door::canOpen` shows the missing
  `g_Bonus_00407038` branch in context.
- `values --include-stack-locals`: `ScoreTable::score` compares `12` against
  the original `10` threshold. It also shows the stack-offset differences caused
  by the EH frame in `LessonLog::severity`.
- `data`: `g_Bonus_00407038` is `9` in the rebuilt executable but `7` in the
  original. This command exits `1` by design.
- `seh --report`: `LessonLog::severity` has an original-only C++ EH frame. This
  command exits `1` by design.
- `exe --functions`: reconstructed functions are shifted because the original
  has an extra `CleanupProbe` destructor and EH support before the rebuilt
  class methods.

Small excerpts from the expected output:

```text
--- Similarity Report ---

=== rebuilt.cpp ===
  ScoreTable::score                             0x401029  100.00%
  Reactor::tick                                 0x401061  96.15%
  Door::canOpen                                 0x40109E  80.00%
  LessonLog::severity                           0x4010E8  52.94%
```

```text
Comparison for function 'Door::canOpen':
0040108A: jne 0x40109a                 | 004010B2: jne 0x4010c2
00401090: mov eax, 1                   | 004010B8: mov eax, 1
00401095: jmp 0x4010a1                 | 004010BD: jmp 0x4010e1
0040109A: xor eax, eax                 | 004010C2: mov eax, dword ptr [0x4070..
0040109C: jmp 0x4010a1                 | 004010C7: cmp dword ptr [ebp + 8], eax

Similarity: 80.00%
```

```text
ScoreTable::score (orig 0x401029, rebuilt 0x401000, 100.0%) - 1 mismatch(es):
    IMM 12 vs 10: 0x00401017 cmp dword ptr [ebp - 4], 0xc  |  0x00401040 cmp dword ptr [ebp - 4], 0xa
```

```text
0x00407038   0x00405038     g_Bonus_00407038             MISMATCH   init: 9
             Original value: 0x00000007 (7)
             Rebuilt value:  0x00000009 (9)
```

```text
--- SEH structure differences ---

=== rebuilt.cpp ===
  LessonLog::severity  (0x4010E8)
      WARNING: rebuilt has NO C++ EH frame, original unwinds 1 state(s) ['stack@ebp-0x10']
```

```text
First misalignment: 0x00401029 (expected) -> 0x00401000 (actual)
```
