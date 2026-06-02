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

## Run

From this directory, with `binary-comp` installed:

```bash
make demo
```

`make demo` downloads `wibo`, MSVC420, and the known-good `msvcrt40.dll` under
`.tools/`, compiles both PE files, and runs `binary-comp export-asm --no-source`
to auto-discover Ghidra-style `code/FUN_*.disassembled.txt` exports. The exports
are ignored and regenerated on first use; this example does not require Ghidra
or an original linker map.

When local tool copies already exist:

```bash
make demo WIBO=/path/to/wibo MSVC42_DIR=/path/to/MSVC420
```

## What It Shows

The expected discrepancies are:

- `report`: `Door::canOpen` is below 90% similarity because the rebuilt method
  is missing one passcode branch. `LessonLog::severity` is also below 90%
  because the rebuilt function changed the title check/indexing and the original
  has a local object cleanup path.
- `compare`: the single-function diff for `LessonLog::severity` shows the
  changed character/index logic plus the original-only SEH setup and cleanup
  path in context.
- `values --include-stack-locals`: `ScoreTable::score` compares `12` against
  the original `10` threshold. It catches operand mistakes that the similarity
  score does not account for, including the `LessonLog::severity` change from
  `'L'`/`0x4c` to `'A'`/`0x41` and the stack-offset differences caused by the
  EH frame.
- `data`: `g_Bonus_00407038` is `9` in the rebuilt executable but `7` in the
  original. This command exits `1` by design.
- `globals --fail-on-issues`: flags the same intentional global initializer
  mismatch and unreviewed global side effects discovered from CRT initializer
  tables. This command exits `1` by design.
- `seh --report`: `LessonLog::severity` has an original-only C++ EH frame. This
  command exits `1` by design.
- `exe --functions`: reconstructed functions are shifted because the original
  has an extra `CleanupProbe` destructor and EH support before the rebuilt
  class methods.

Small excerpts from the expected output:

The similarity score compares instruction kinds and control-flow shape; it does
not decide whether operands such as constants, stack offsets, or referenced
addresses are correct.

```text
--- Similarity Report ---

=== rebuilt.cpp ===
  ScoreTable::score                             0x401029  100.00%
  Reactor::tick                                 0x401061  96.15%
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
004010A8: push ebp                              | 004010E8: push ebp
004010A9: mov ebp, esp                          | 004010E9: mov ebp, esp
004010AB: sub esp, 8                            | 004010EB: push -1
004010AE: push ebx                              | 004010ED: push 0x40116a
004010AF: push esi                              | 004010F2: mov eax, dword ptr fs:[0]
004010B0: push edi                              | 004010F8: push eax
004010B1: mov dword ptr [ebp - 8], ecx          | 004010F9: mov dword ptr fs:[0], esp
004010B4: mov eax, dword ptr [ebp - 8]          | 00401100: sub esp, 0x10
004010B7: mov eax, dword ptr [eax]              | 00401103: push ebx
004010B9: add eax, dword ptr [ebp + 8]          | 00401104: push esi
004010BC: mov dword ptr [ebp - 4], eax          | 00401105: push edi
004010BF: movsx eax, byte ptr [0x405031]        | 00401106: mov dword ptr [ebp - 0x1c], ecx
004010C6: cmp eax, 0x4c                         | 00401109: mov eax, dword ptr [ebp - 0x1c]
004010C9: jne 0x4010e0                          | 0040110C: mov eax, dword ptr [eax]
004010CF: mov eax, dword ptr [ebp + 8]          | 0040110E: add eax, dword ptr [ebp + 8]
004010D2: dec eax                               | 00401111: mov dword ptr [ebp - 0x14], eax
004010D3: and eax, 1                            | 00401114: lea eax, [ebp - 0x14]
004010D6: mov eax, dword ptr [eax*4 + 0x405040] | 00401117: push eax
004010DD: add dword ptr [ebp - 4], eax          | 00401118: lea ecx, [ebp - 0x10]
004010E0: mov eax, dword ptr [ebp - 4]          | 0040111B: call 0x401220
004010E3: jmp 0x4010e8                          | 00401120: mov dword ptr [ebp - 4], 0
004010E8: pop edi                               | 00401127: movsx eax, byte ptr [0x407030]
004010E9: pop esi                               | 0040112E: cmp eax, 0x41
004010EA: pop ebx                               | 00401131: jne 0x401147
004010EB: leave                                 | 00401137: mov eax, dword ptr [ebp + 8]
004010EC: ret 4                                 | 0040113A: and eax, 1
                                                | 0040113D: mov eax, dword ptr [eax*4 + 0x407040]
                                                | 00401144: add dword ptr [ebp - 0x14], eax
                                                | 00401147: mov eax, dword ptr [ebp - 0x14]
                                                | 0040114A: mov dword ptr [ebp - 0x18], eax
                                                | 0040114D: mov dword ptr [ebp - 4], 0xffffffff
                                                | 00401154: call 0x401161
                                                | 00401159: mov eax, dword ptr [ebp - 0x18]
                                                | 0040115C: jmp 0x401174

Similarity: 50.00%
```

The values analyzer is the follow-up pass for those incorrect operands. Here it
reduces the noisy assembly diff to the changed immediate that came from the
reconstructed `'L'` check versus the original `'A'` check:

```text
ScoreTable::score (orig 0x401029, rebuilt 0x401000, 100.0%) - 1 mismatch(es):
    IMM 12 vs 10: 0x00401017 cmp dword ptr [ebp - 4], 0xc  |  0x00401040 cmp dword ptr [ebp - 4], 0xa

LessonLog::severity (orig 0x4010E8, rebuilt 0x4010A8, 58.8%) - 4 mismatch(es):
    IMM 76 vs 65: 0x004010C6 cmp eax, 0x4c  |  0x0040112E cmp eax, 0x41
```

The SEH analyzer explains the extra frame setup and cleanup call on the original
side:

```text
--- SEH structure differences ---

=== rebuilt.cpp ===
  LessonLog::severity  (0x4010E8)
      WARNING: rebuilt has NO C++ EH frame, original unwinds 1 state(s) ['stack@ebp-0x10']
```

The global detector is a separate project-level check. It catches the intentional
initializer mismatch and also points at unreviewed auto-complete side effects:

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
  DIRECT_WRITE      0x00403488 0x0040824c  MOV dword ptr [0x40824c], eax
```

```text
First misalignment: 0x00401029 (expected) -> 0x00401000 (actual)
```
