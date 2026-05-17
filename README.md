# binary-comp

Standalone binary comparison and verification tools for C/C++ reimplementation
projects.

The package is being extracted from project-specific scripts into reusable
library modules plus a CLI. The current first port is the Capstone-backed value
checker:

```bash
binary-comp values --config path/to/binary-comp.json --target full
```

For local development from a checkout:

```bash
PYTHONPATH=src python3 -m binary_comp.cli values --help
```

Or install it editable with the optional analyzer dependencies:

```bash
python3 -m pip install -e ".[all]"
binary-comp values --help
```
