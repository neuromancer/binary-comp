# binary-comp

Standalone binary comparison and verification tools for C/C++ reimplementation
projects.

The package is being extracted from project-specific scripts into reusable
library modules plus a CLI. The current first port is the Capstone-backed value
checker:

```bash
binary-comp values --config path/to/binary-comp.json --target full
```

## Design principles

Tools should require the minimum practical configuration to run. Each analyzer
must document the exact inputs it needs, provide sensible defaults for analyzer
policy, and include a minimal config file whenever project-specific paths are
required.

## Minimal configuration

The value checker needs only a target description: original binary, rebuilt
binary, linker map, and source directory. Function boundaries from a Ghidra
export directory are optional hints; operands are always decoded from the
binaries with Capstone.

```json
{
  "targets": {
    "full": {
      "original_exe": "path/to/original.exe",
      "rebuilt_exe": "path/to/rebuilt.exe",
      "map": "path/to/rebuilt.map",
      "source_dirs": ["path/to/src"],
      "code_export_dir": "path/to/ghidra-export"
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
