"""Command line interface for binary-comp."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from binary_comp.analyzers.calls import CallsOptions, check_calls, format_calls_summary
from binary_comp.analyzers.data import (
    DataOptions,
    compare_address,
    compare_global_data,
    find_missing_globals,
    format_address_comparison,
    format_comparison,
    format_missing_globals,
    require_globals_source,
)
from binary_comp.analyzers.function_compare import (
    FunctionCompareError,
    FunctionComparer,
    format_comparison as format_function_comparison,
    maybe_build,
)
from binary_comp.analyzers.exepack import (
    ExepackError,
    format_exepack_summary,
    unpack_exepack_file,
)
from binary_comp.analyzers.seh import (
    compare_function_seh,
    format_seh_comparison,
    format_seh_report,
    generate_seh_report,
)
from binary_comp.analyzers.exe import ExeCompareOptions, compare_executable, format_executable_comparison
from binary_comp.analyzers.export_asm import ExportAsmOptions, export_asm, format_export_asm_summary
from binary_comp.analyzers.global_access import (
    GlobalAccessOptions,
    check_global_accesses,
    format_global_access_summary,
)
from binary_comp.analyzers.globals import GlobalsAuditOptions, audit_globals, format_report
from binary_comp.analyzers.omf import (
    OmfCompareError,
    compare_omf_config_function,
    compare_omf_to_original,
    format_omf_comparison,
    generate_omf_similarity_report,
)
from binary_comp.analyzers.tpu import (
    TpuCompareError,
    compare_tpu_config_function,
    compare_tpu_to_original,
    format_tpu_comparison,
    format_tpu_info,
    format_tpu_values_report,
    generate_tpu_similarity_report,
    generate_tpu_values_report,
    load_tpu_object,
)
from binary_comp.analyzers.tp_overlay import (
    TpOverlayError,
    format_tp_overlay,
    load_tp_overlay,
)
from binary_comp.analyzers.tpu_scan import (
    format_tpu_scan,
    load_tpu_scan_regions,
    scan_tpu_directory,
    write_tpu_scan_json,
)
from binary_comp.analyzers.report import (
    SimilarityReportOptions,
    format_similarity_report,
    generate_similarity_report,
)
from binary_comp.analyzers.values import ValuesOptions, check_values, format_summary, load_policy
from binary_comp.analyzers.vtables import VtableOptions, check_vtables, format_vtable_summary
from binary_comp.config import ConfigError, DEFAULT_CONFIG_PATH, ProjectTarget, load_project_target
from binary_comp.source.functions import load_source_groups, map_source_groups
from binary_comp.core.mz import MzFormatError, format_mz, parse_mz


def add_values_parser(subparsers) -> None:
    parser = subparsers.add_parser("values", help="Check operand value mismatches with Capstone")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--policy", help="Value-check policy JSON override")
    parser.add_argument("--filter", dest="file_filter", help="Only include functions or source files containing this text")
    parser.add_argument("--no-build", action="store_true", help="Use existing rebuilt binary and map")
    parser.add_argument("--min-similarity", type=float, default=0.0,
                        help="Only report mismatches at or above this similarity percentage")
    parser.add_argument("--boundary-report", action="store_true", help="Print function-boundary inventory")
    parser.add_argument("--strings-only", action="store_true", help="Only report string literal mismatches")
    parser.add_argument("--no-strings", action="store_true", help="Do not report string literal mismatches")
    parser.add_argument("--no-immediates", action="store_true", help="Do not report small numeric immediate mismatches")
    parser.add_argument("--no-offsets", action="store_true", help="Do not report member displacement mismatches")
    parser.add_argument(
        "--include-stack-locals",
        action="store_true",
        help="Also report stack-local memory displacement and stack-store value mismatches",
    )
    parser.add_argument(
        "--show-exact",
        action="store_true",
        help="(dos16-tpu) Also list byte-exact functions, not only those with value differences",
    )
    parser.add_argument(
        "--fail-on-diffs",
        action="store_true",
        help="(dos16-tpu) Exit non-zero if any located function has an operand/constant difference",
    )
    parser.set_defaults(handler=run_values)


def add_calls_parser(subparsers) -> None:
    parser = subparsers.add_parser("calls", help="Verify call target multisets against original disassembly")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("filters", nargs="*", help="Optional function name or source-file filters")
    parser.add_argument("--all", action="store_true", help="Show all mismatches, including unresolved original targets")
    parser.add_argument("--no-build", action="store_true", help="Use existing assembly output")
    parser.add_argument("--include-trivial", action="store_true", help="Report configured trivial calls")
    parser.add_argument("--strict-memory", action="store_true", help="Do not canonicalize configured memory wrapper calls")
    parser.add_argument("--build-arg", action="append", dest="build_args", help="Extra build argument; can be repeated")
    parser.add_argument("--fail-on-mismatches", action="store_true", help="Exit 1 when call target mismatches are reported")
    parser.set_defaults(handler=run_calls)


def add_global_access_parser(subparsers) -> None:
    parser = subparsers.add_parser("global-access", help="Verify global access multisets against original disassembly")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("filters", nargs="*", help="Optional function name or source-file filters")
    parser.add_argument("--all", action="store_true", help="Show all mismatches, including unresolved address tokens")
    parser.add_argument("--no-build", action="store_true", help="Use existing assembly output")
    parser.add_argument("--include-address-immediates", action="store_true",
                        help="Also compare immediate data-address references such as PUSH/OFFSET globals")
    parser.add_argument("--build-arg", action="append", dest="build_args", help="Extra build argument; can be repeated")
    parser.add_argument("--fail-on-mismatches", action="store_true",
                        help="Exit 1 when global access mismatches are reported")
    parser.set_defaults(handler=run_global_access)


def add_vtables_parser(subparsers) -> None:
    parser = subparsers.add_parser("vtables", help="Verify vtables against source and original PE data")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--dump", action="store_true", help="Show full vtable dump")
    parser.add_argument("--class", dest="filter_class", help="Filter to specific class")
    parser.add_argument("--rdata-min", type=lambda value: int(value, 0), help="Fallback .rdata start address")
    parser.add_argument("--rdata-max", type=lambda value: int(value, 0), help="Fallback .rdata end address")
    parser.add_argument(
        "--no-rebuilt",
        dest="check_rebuilt",
        action="store_false",
        help="Skip diffing the vtables the rebuilt binary emits against the original",
    )
    parser.set_defaults(handler=run_vtables, check_rebuilt=True)


def add_data_parser(subparsers) -> None:
    parser = subparsers.add_parser("data", help="Compare global data between original and rebuilt PE files")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--globals-source", help="Global declarations source override")
    parser.add_argument("--section", default=".data", help="Section to scan for --find-missing (default: .data)")
    parser.add_argument("--verbose", action="store_true", help="Show data bytes for all globals")
    parser.add_argument("--address", type=lambda value: int(value, 0), help="Compare one original VA")
    parser.add_argument("--size", type=int, default=32, help="Byte count for --address (default: 32)")
    parser.add_argument("--find-missing", action="store_true", help="Scan original section for untracked non-zero dwords")
    parser.add_argument("--min-address", type=lambda value: int(value, 0),
                        help="Only scan addresses >= this VA when using --find-missing")
    parser.add_argument("--max-address", type=lambda value: int(value, 0),
                        help="Only scan addresses < this VA when using --find-missing")
    parser.add_argument("--skip-range", action="append", dest="skip_ranges", default=[],
                        help="Exclude an address range from --find-missing scanning; "
                             "format START:END (END exclusive). May be repeated.")
    parser.set_defaults(handler=run_data)


def add_compare_parser(subparsers) -> None:
    parser = subparsers.add_parser("compare", help="Compare one rebuilt function against original bytes")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("function_name", help="Function name to compare")
    parser.add_argument(
        "disassembled_code",
        nargs="?",
        help="Path to the Ghidra-style disassembly export for the function; omitted for dos16-omf/dos16-tpu targets",
    )
    parser.add_argument("--no-build", action="store_true", help="Use existing rebuilt binary and map")
    parser.set_defaults(handler=run_compare)


def add_omf_compare_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "omf-compare",
        help="Compare raw original bytes against a 16-bit OMF LEDATA record, masking FIXUPP operands",
    )
    parser.add_argument("--original", required=True, help="Original raw binary/overlay image")
    parser.add_argument("--original-offset", required=True, type=lambda value: int(value, 0),
                        help="Offset in original file/image")
    parser.add_argument("--object", required=True, dest="object_path", help="Borland/TASM OMF object file")
    parser.add_argument("--size", type=lambda value: int(value, 0),
                        help="Byte count to compare; defaults to remaining selected LEDATA")
    parser.add_argument("--object-offset", type=lambda value: int(value, 0), default=0,
                        help="Offset within selected LEDATA (default: 0)")
    parser.add_argument("--segment-index", type=lambda value: int(value, 0),
                        help="OMF segment index to select (default: first LEDATA)")
    parser.add_argument("--ledata-index", type=int, default=0,
                        help="LEDATA record index within selected segment (default: 0)")
    parser.add_argument("--name", default="omf-function", help="Display name for this comparison")
    parser.set_defaults(handler=run_omf_compare)


def add_tpu_compare_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "tpu-compare",
        help="Compare raw original bytes against a Turbo Pascal .TPU code block, masking relocation operands",
    )
    parser.add_argument("--original", required=True, help="Original raw binary/overlay image")
    parser.add_argument("--original-offset", type=lambda value: int(value, 0),
                        help="Offset in original file/image (omit with --locate)")
    parser.add_argument("--tpu", required=True, dest="tpu_path", help="Turbo Pascal compiled unit (.TPU)")
    parser.add_argument("--size", type=lambda value: int(value, 0),
                        help="Byte count to compare; defaults to remaining CODE section or block")
    parser.add_argument("--code-offset", type=lambda value: int(value, 0), default=0,
                        help="Offset within the unit's CODE section (default: 0)")
    parser.add_argument("--block", dest="block_index", type=lambda value: int(value, 0),
                        help="Compare exactly one code block by index instead of --code-offset/--size")
    parser.add_argument("--function", dest="function_name",
                        help="Select the code block by procedure name via the unit's symbol table "
                             "(robust to source order; overridden by --block)")
    parser.add_argument("--locate", action="store_true",
                        help="Find the block in the image by content (masking fixups) instead of --original-offset; "
                             "for routines inside a Turbo Pascal overlay (.OVR) image")
    parser.add_argument("--name", default="tpu-function", help="Display name for this comparison")
    parser.set_defaults(handler=run_tpu_compare)


def add_mz_info_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "mz-info",
        help="Validate and describe a 16-bit DOS MZ executable without running it",
    )
    parser.add_argument("input", help="DOS MZ executable to inspect")
    parser.set_defaults(handler=run_mz_info)


def add_exepack_unpack_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "exepack-unpack",
        help="Statically decompress a Microsoft EXEPACK MZ executable",
    )
    parser.add_argument("input", help="EXEPACK-compressed MZ input")
    parser.add_argument("output", help="Path for the recovered canonical MZ file")
    parser.set_defaults(handler=run_exepack_unpack)


def add_tpov_info_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "tpov-info",
        help="Discover and validate a resident Turbo Pascal TPOV directory",
    )
    parser.add_argument("--exe", required=True, help="Associated unpacked MZ executable")
    parser.add_argument("--overlay", required=True, help="TPOV overlay image")
    parser.add_argument("--expect-count", type=int, help="Fail unless this many overlay units are found")
    parser.set_defaults(handler=run_tpov_info)


def add_tpu_info_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "tpu-info",
        help="Describe Turbo Pascal unit sections, code blocks, symbols, and fixups",
    )
    parser.add_argument("tpu", help="Compiled Turbo Pascal unit")
    parser.set_defaults(handler=run_tpu_info)


def add_tpu_scan_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "tpu-scan",
        help="Locate relocation-masked TPU code blocks in bounded resident and overlay code",
    )
    parser.add_argument("--exe", required=True, help="Associated unpacked MZ executable")
    parser.add_argument("--overlay", required=True, help="TPOV or explicitly bounded overlay image")
    parser.add_argument("--tpu-dir", required=True, help="Directory containing compiled .TPU files")
    parser.add_argument(
        "--regions",
        help="JSON manifest of bounded resident/overlay code regions; "
             "use for flat overlay formats without a TPOV directory",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="TPU filename glob to exclude; may be repeated",
    )
    parser.add_argument(
        "--include-missing",
        action="store_true",
        help="Include examined blocks with no match in reports and JSON",
    )
    parser.add_argument(
        "--resolve-adjacent",
        action="store_true",
        help="Resolve duplicate matches anchored by consecutive TPU block adjacency",
    )
    parser.add_argument("--function", help="Case-insensitive procedure-name filter")
    parser.add_argument("--min-block-size", type=int, default=8, help="Minimum code-block size (default: 8)")
    parser.add_argument("--min-fixed-bytes", type=int, default=8, help="Minimum non-fixup bytes (default: 8)")
    parser.add_argument("--minimum-unique", type=int, default=0, help="Fail if fewer unique blocks are found")
    parser.add_argument("--json", dest="json_path", help="Write the complete match inventory as JSON")
    parser.add_argument("--verbose", action="store_true", help="List every located block")
    parser.set_defaults(handler=run_tpu_scan)


def add_export_asm_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "export-asm",
        help="Generate Ghidra-style disassembly exports from the original PE with Capstone",
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--out-dir", help="Output directory override (default: target code_export_dir)")
    parser.add_argument("--clean", action="store_true", help="Remove existing FUN_*.disassembled.txt files before exporting")
    parser.add_argument("--map", dest="original_map", help="Optional original MSVC linker map for denser boundaries")
    parser.add_argument("--object", action="append", dest="objects", default=[],
                        help="Object file to export from --map; can be repeated. Defaults to all map functions.")
    parser.add_argument("--no-source", action="store_true", help="Do not export source Function start annotations")
    discover_group = parser.add_mutually_exclusive_group()
    discover_group.add_argument("--discover", dest="discover", action="store_true", default=None,
                                help="Also discover function starts from PE entry, calls, jumps, and prologues")
    discover_group.add_argument("--no-discover", dest="discover", action="store_false",
                                help="Disable automatic discovery when no source/map targets are found")
    parser.add_argument("--max-bytes", type=lambda value: int(value, 0), help="Maximum bytes to decode per function")
    parser.add_argument("--max-functions", type=int, default=4096, help="Maximum discovered/exported functions")
    parser.set_defaults(handler=run_export_asm)


def add_seh_parser(subparsers) -> None:
    parser = subparsers.add_parser("seh", help="Compare C++ exception-handling (FuncInfo) structure and warn on differences")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("function_name", nargs="?", help="Function name to compare (omit with --report)")
    parser.add_argument("disassembled_code", nargs="?", help="Path to the Ghidra-style disassembly export for the function")
    parser.add_argument("--no-build", action="store_true", help="Use existing rebuilt binary and map")
    parser.add_argument("--report", action="store_true", help="Scan every function and list EH-structure differences")
    parser.add_argument("--filter", dest="file_filter", default=None, help="Restrict --report to matching files or function names")
    parser.add_argument("--strict", action="store_true", help="Compare exact unwind states, toState links, and guards")
    parser.set_defaults(handler=run_seh)


def run_seh(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        comparer = FunctionComparer(
            target,
            canonical_aliases=extract_canonical_aliases(config),
            signature_overloads=extract_signature_overloads(config),
        )
        maybe_build(target, not args.no_build)
        if args.report:
            report = generate_seh_report(comparer, file_filter=args.file_filter, strict=args.strict)
            print(format_seh_report(report))
            return 1 if report.rows else 0
        if not args.function_name or not args.disassembled_code:
            print("error: function_name and disassembled_code are required without --report", file=sys.stderr)
            return 2
        comparison = compare_function_seh(
            comparer,
            args.function_name,
            args.disassembled_code,
            strict=args.strict,
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError, FunctionCompareError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_seh_comparison(comparison))
    return 1 if any(w.level == "warn" for w in comparison.warnings) else 0


def add_exe_parser(subparsers) -> None:
    parser = subparsers.add_parser("exe", help="Compare PE layout, section bytes, and optional function mapping")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--functions", action="store_true", help="Include function address and raw byte comparison")
    parser.add_argument(
        "--section",
        action="append",
        dest="sections",
        help="Section to include in byte summary; can be repeated (default: .text, .rdata, .data)",
    )
    parser.set_defaults(handler=run_exe)


def add_report_parser(subparsers) -> None:
    parser = subparsers.add_parser("report", help="Generate a whole-project function similarity report")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--filter", dest="file_filter", help="Only include matching source files or function names")
    parser.add_argument("--no-build", action="store_true", help="Use existing rebuilt binary and map")
    parser.set_defaults(handler=run_report)


def add_globals_parser(subparsers) -> None:
    parser = subparsers.add_parser("globals", help="Audit global declarations against original PE data")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
    parser.add_argument("--globals-source", "--globals-c", dest="globals_source", help="Global definitions source override")
    parser.add_argument("--globals-h", dest="globals_header", help="Global declarations header override")
    parser.add_argument("--code-globals-h", dest="code_globals_header", help="Code export globals header override")
    parser.add_argument("--define-header", action="append", dest="define_headers",
                        help="Header to scan for integer #define constants; can be repeated")
    parser.add_argument("--code-dir", help="Code export directory used for function-boundary hints")
    parser.add_argument("--asm-dir", help="Rebuilt assembly directory used for global span checks")
    parser.add_argument("--auto-complete", help="Function list for global side-effect auditing")
    parser.add_argument("--data-section", action="append", dest="data_sections",
                        help="Writable section to scan for auto-complete side effects; defaults to .data")
    parser.add_argument("--min-address", type=lambda value: int(value, 0), help="Ignore lower original addresses")
    parser.add_argument("--max-address", type=lambda value: int(value, 0), help="Ignore higher original addresses")
    parser.add_argument("--issue-kind", action="append", dest="issue_kinds",
                        help="Only report this issue category; can be repeated or comma-separated")
    parser.add_argument("--max-issues", type=int, default=200, help="Maximum issues to print; 0 prints all")
    parser.add_argument("--max-auto-facts", type=int, default=12,
                        help="Maximum auto-complete facts to print per function; 0 prints all")
    parser.add_argument("--auto-complete-max-function-bytes", type=int, default=4096,
                        help="Maximum bytes to disassemble per auto-complete function")
    parser.add_argument("--include-code-globals", action="store_true",
                        help="Report nonzero code-export globals not covered by source")
    parser.add_argument("--include-symbolic", action="store_true",
                        help="Report nonzero globals with symbolic or unparsed initializers")
    parser.add_argument("--include-auto-complete-data-args", action="store_true",
                        help="Report generic PUSH data-address arguments in listed functions")
    parser.add_argument("--no-auto-complete-this-calls", action="store_true",
                        help="Do not report MOV ECX,global followed by CALL/JMP in listed functions")
    parser.add_argument("--no-auto-complete-global-effects", action="store_true",
                        help="Disable listed-function global side-effect auditing")
    parser.add_argument("--no-address-warnings", action="store_true",
                        help="Do not report globals without address annotations")
    parser.add_argument("--show-auto-complete-reviewed", action="store_true",
                        help="Print reviewed listed-function global side-effect details")
    parser.add_argument("--no-source-order", action="store_true",
                        help="Disable source-order decrease warnings for implicit-zero globals")
    parser.add_argument("--source-order-all", action="store_true",
                        help="Warn on source-order decreases for initialized globals too")
    parser.add_argument("--check-rebuilt-layout", action="store_true",
                        help="Report split rebuilt global layout and global accesses that escape source ranges")
    parser.add_argument("--fail-on-issues", action="store_true", help="Exit 1 when suspicious issues are found")
    parser.add_argument("--fail-on-warnings", action="store_true",
                        help="Exit 1 when globals without address annotations are found")
    parser.set_defaults(handler=run_globals)


def enabled_kinds_from_args(args) -> frozenset[str]:
    enabled = {"strings", "immediates", "offsets"}
    if args.strings_only:
        return frozenset({"strings"})
    if args.no_strings:
        enabled.discard("strings")
    if args.no_immediates:
        enabled.discard("immediates")
    if args.no_offsets:
        enabled.discard("offsets")
    return frozenset(enabled)


def run_values(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        if target.kind == "dos16-tpu":
            report = generate_tpu_values_report(
                config,
                args.config,
                target,
                SimilarityReportOptions(build=not args.no_build, file_filter=args.file_filter),
            )
            print(format_tpu_values_report(report, show_exact=args.show_exact))
            if args.fail_on_diffs and report.with_diffs:
                return 1
            return 0
        policy = load_policy(args.policy or target.values_policy)
        summary = check_values(
            target,
            policy,
            ValuesOptions(
                file_filter=args.file_filter,
                min_similarity=args.min_similarity,
                build=not args.no_build,
                enabled_kinds=enabled_kinds_from_args(args),
                boundary_report=args.boundary_report,
                include_stack_locals=args.include_stack_locals,
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_summary(summary, min_similarity=args.min_similarity))
    return 0


def run_calls(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        summary = check_calls(
            config,
            target,
            CallsOptions(
                filters=tuple(args.filters),
                show_all=args.all,
                build=not args.no_build,
                include_trivial=args.include_trivial,
                strict_memory=args.strict_memory,
                build_args=tuple(args.build_args or ()),
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_calls_summary(summary))
    if args.fail_on_mismatches and summary.mismatches:
        return 1
    return 0


def run_global_access(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        summary = check_global_accesses(
            config,
            target,
            GlobalAccessOptions(
                filters=tuple(args.filters),
                build=not args.no_build,
                include_address_immediates=args.include_address_immediates,
                build_args=tuple(args.build_args or ()),
                show_all=args.all,
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_global_access_summary(summary))
    if args.fail_on_mismatches and summary.mismatches:
        return 1
    return 0


def run_vtables(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        summary = check_vtables(
            config,
            target,
            VtableOptions(
                dump=args.dump,
                filter_class=args.filter_class,
                rdata_min=args.rdata_min,
                rdata_max=args.rdata_max,
                check_rebuilt=args.check_rebuilt,
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_vtable_summary(summary, dump=args.dump))
    return 1 if summary.has_failures else 0


def extract_globals_type_sizes(config: dict) -> dict[str, int]:
    globals_section = config.get("globals", {})
    if not isinstance(globals_section, dict):
        return {}
    type_sizes = globals_section.get("type_sizes", {})
    if not isinstance(type_sizes, dict):
        return {}
    out: dict[str, int] = {}
    for name, size in type_sizes.items():
        if isinstance(size, int):
            out[str(name)] = size
        elif isinstance(size, str):
            try:
                out[str(name)] = int(size, 0)
            except ValueError:
                continue
    return out


def extract_canonical_aliases(config: dict) -> dict[str, str]:
    calls = config.get("calls", {})
    if not isinstance(calls, dict):
        return {}
    aliases = calls.get("canonical_aliases", {})
    if not isinstance(aliases, dict):
        return {}
    return {
        str(source): str(target)
        for source, target in aliases.items()
        if isinstance(source, str) and isinstance(target, str) and source and target
    }


def extract_signature_overloads(config: dict) -> frozenset[str]:
    calls = config.get("calls", {})
    if not isinstance(calls, dict):
        return frozenset()
    overloads = calls.get("signature_overloads", [])
    if not isinstance(overloads, list):
        return frozenset()
    return frozenset(str(item) for item in overloads if isinstance(item, str) and item)


def parse_skip_ranges(values: list[str]) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    for value in values or ():
        for separator in (":", "-"):
            if separator in value:
                left, right = value.split(separator, 1)
                break
        else:
            raise ConfigError(f"--skip-range expects START:END, got {value!r}")
        start = int(left, 0)
        end = int(right, 0)
        if end <= start:
            raise ConfigError(f"--skip-range END must be > START, got {value!r}")
        ranges.append((start, end))
    return tuple(ranges)


def build_source_function_address_map(target: ProjectTarget) -> dict[int, int]:
    groups_by_source = load_source_groups(
        target.source_dirs,
        target.map_skip,
        target.source_excludes,
    )
    mapped_groups, _, _ = map_source_groups(groups_by_source, target.map_path)
    mapping: dict[int, int] = {}
    for group in mapped_groups:
        for address in group.original_addrs:
            mapping[address] = group.rebuilt_addr
    return mapping


def run_data(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        globals_source = require_globals_source(args.globals_source or target.globals_source)
        extra_type_sizes = extract_globals_type_sizes(config)
        if args.find_missing:
            skip_ranges = parse_skip_ranges(args.skip_ranges)
            summary = find_missing_globals(
                target.original_exe,
                globals_source,
                section_name=args.section,
                min_address=args.min_address,
                max_address=args.max_address,
                skip_ranges=skip_ranges,
                extra_type_sizes=extra_type_sizes,
            )
            print(format_missing_globals(summary))
            return 0
        if args.address is not None:
            comparison = compare_address(
                target.original_exe,
                target.rebuilt_exe,
                target.map_path,
                args.address,
                args.size,
            )
            print(format_address_comparison(comparison))
            return 0 if comparison.matches else 1

        summary = compare_global_data(
            target.original_exe,
            target.rebuilt_exe,
            target.map_path,
            globals_source,
            DataOptions(section_name=args.section, verbose=args.verbose),
            extra_type_sizes=extra_type_sizes,
            relocated_address_map=build_source_function_address_map(target),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_comparison(summary, verbose=args.verbose))
    return 0 if summary.mismatches == 0 else 1


def run_compare(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        if target.kind == "dos16-omf":
            maybe_build(target, not args.no_build)
            comparison = compare_omf_config_function(
                config,
                args.config,
                target.name,
                args.function_name,
            )
            print(format_function_comparison(comparison))
            return 0

        if target.kind == "dos16-tpu":
            maybe_build(target, not args.no_build)
            comparison = compare_tpu_config_function(
                config,
                args.config,
                target.name,
                args.function_name,
            )
            print(format_function_comparison(comparison))
            return 0

        if not args.disassembled_code:
            print("error: disassembled_code is required for this target", file=sys.stderr)
            return 2
        comparer = FunctionComparer(
            target,
            canonical_aliases=extract_canonical_aliases(config),
            signature_overloads=extract_signature_overloads(config),
        )
        # SEH-split functions span several original chunks (FS-frame prologue +
        # body); when the requested function is one of them, compare against all
        # chunks combined so a prologue-only chunk isn't scored in isolation as a
        # spurious ~5% match.
        siblings = comparer.sibling_chunk_paths(args.function_name, args.disassembled_code)
        if siblings and len(siblings) > 1:
            comparison = comparer.compare_combined(
                args.function_name,
                siblings,
                build=not args.no_build,
            )
        else:
            comparison = comparer.compare(
                args.function_name,
                args.disassembled_code,
                build=not args.no_build,
            )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError, FunctionCompareError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_function_comparison(comparison))
    return 0


def run_omf_compare(args) -> int:
    try:
        comparison = compare_omf_to_original(
            original_path=args.original,
            original_offset=args.original_offset,
            object_path=args.object_path,
            size=args.size,
            object_offset=args.object_offset,
            segment_index=args.segment_index,
            ledata_index=args.ledata_index,
            name=args.name,
        )
    except (FileNotFoundError, OSError, OmfCompareError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_omf_comparison(comparison))
    return 0 if comparison.matches else 1


def run_tpu_compare(args) -> int:
    if args.original_offset is None and not args.locate:
        print("error: --original-offset is required unless --locate is given", file=sys.stderr)
        return 2
    try:
        comparison = compare_tpu_to_original(
            original_path=args.original,
            original_offset=args.original_offset,
            tpu_path=args.tpu_path,
            size=args.size,
            code_offset=args.code_offset,
            block_index=args.block_index,
            function_name=args.function_name,
            locate=args.locate,
            name=args.name,
        )
    except (FileNotFoundError, OSError, TpuCompareError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_tpu_comparison(comparison))
    return 0 if comparison.matches else 1


def run_mz_info(args) -> int:
    try:
        image = parse_mz(Path(args.input).read_bytes())
    except (FileNotFoundError, OSError, MzFormatError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(format_mz(image))
    return 0


def run_exepack_unpack(args) -> int:
    try:
        result = unpack_exepack_file(args.input, args.output)
    except (FileNotFoundError, OSError, ExepackError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(format_exepack_summary(result))
    print(f"  wrote:                {args.output}")
    return 0


def run_tpov_info(args) -> int:
    try:
        image = load_tp_overlay(args.exe, args.overlay)
    except (FileNotFoundError, OSError, TpOverlayError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(format_tp_overlay(image))
    if args.expect_count is not None and len(image.descriptors) != args.expect_count:
        print(
            f"error: found {len(image.descriptors)} overlay units; "
            f"expected {args.expect_count}",
            file=sys.stderr,
        )
        return 1
    return 0


def run_tpu_info(args) -> int:
    try:
        obj = load_tpu_object(args.tpu)
    except (FileNotFoundError, OSError, TpuCompareError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(format_tpu_info(obj))
    return 0


def run_tpu_scan(args) -> int:
    try:
        regions = load_tpu_scan_regions(args.regions) if args.regions else None
        result = scan_tpu_directory(
            args.exe,
            args.overlay,
            args.tpu_dir,
            exclude_patterns=tuple(args.exclude),
            minimum_block_size=args.min_block_size,
            minimum_fixed_bytes=args.min_fixed_bytes,
            function_filter=args.function,
            regions=regions,
            include_missing=args.include_missing,
            resolve_adjacent=args.resolve_adjacent,
        )
        if args.json_path:
            write_tpu_scan_json(result, args.json_path)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(format_tpu_scan(result, verbose=args.verbose))
    if args.json_path:
        print(f"wrote {args.json_path}")
    return 1 if result.unique_count < args.minimum_unique else 0


def resolve_cli_path(config_path: str, path: str | None) -> str | None:
    if not path:
        return None
    if os.path.isabs(path):
        return path
    return os.path.join(os.path.dirname(os.path.abspath(config_path)), path)


def run_export_asm(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        summary = export_asm(
            target,
            ExportAsmOptions(
                out_dir=resolve_cli_path(args.config, args.out_dir),
                clean=args.clean,
                original_map=resolve_cli_path(args.config, args.original_map),
                objects=tuple(args.objects or ()),
                include_source=not args.no_source,
                discover=args.discover,
                max_bytes=args.max_bytes,
                max_functions=args.max_functions,
                signature_overloads=extract_signature_overloads(config),
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_export_asm_summary(summary))
    return 0


def run_exe(args) -> int:
    try:
        _, target = load_project_target(args.config, args.target)
        comparison = compare_executable(
            target,
            ExeCompareOptions(
                byte_sections=tuple(args.sections) if args.sections else (".text", ".rdata", ".data"),
                include_functions=args.functions,
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_executable_comparison(comparison))
    return 0


def run_report(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        options = SimilarityReportOptions(
            build=not args.no_build,
            canonical_aliases=extract_canonical_aliases(config),
            file_filter=args.file_filter,
            signature_overloads=extract_signature_overloads(config),
        )
        if target.kind == "dos16-omf":
            report = generate_omf_similarity_report(config, args.config, target, options)
        elif target.kind == "dos16-tpu":
            report = generate_tpu_similarity_report(config, args.config, target, options)
        else:
            report = generate_similarity_report(target, options)
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_similarity_report(report))
    return 0


def run_globals(args) -> int:
    try:
        config, target = load_project_target(args.config, args.target)
        summary = audit_globals(
            config,
            target,
            GlobalsAuditOptions(
                globals_source=args.globals_source,
                globals_header=args.globals_header,
                code_globals_header=args.code_globals_header,
                define_headers=tuple(args.define_headers or ()),
                code_dir=args.code_dir,
                asm_dir=args.asm_dir,
                auto_complete=args.auto_complete,
                data_sections=tuple(args.data_sections or [".data"]),
                min_address=args.min_address,
                max_address=args.max_address,
                issue_kinds=tuple(args.issue_kinds or ()),
                max_issues=args.max_issues,
                max_auto_facts=args.max_auto_facts,
                auto_complete_max_function_bytes=args.auto_complete_max_function_bytes,
                include_code_globals=args.include_code_globals,
                include_symbolic=args.include_symbolic,
                include_auto_complete_data_args=args.include_auto_complete_data_args,
                no_auto_complete_this_calls=args.no_auto_complete_this_calls,
                no_auto_complete_global_effects=args.no_auto_complete_global_effects,
                no_address_warnings=args.no_address_warnings,
                show_auto_complete_reviewed=args.show_auto_complete_reviewed,
                no_source_order=args.no_source_order,
                source_order_all=args.source_order_all,
                check_rebuilt_layout=args.check_rebuilt_layout,
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_report(summary))
    if args.fail_on_issues and (summary.issues or summary.unreviewed_auto_complete_count):
        return 1
    if args.fail_on_warnings and summary.address_warnings:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="binary-comp")
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_calls_parser(subparsers)
    add_compare_parser(subparsers)
    add_exepack_unpack_parser(subparsers)
    add_export_asm_parser(subparsers)
    add_seh_parser(subparsers)
    add_data_parser(subparsers)
    add_exe_parser(subparsers)
    add_global_access_parser(subparsers)
    add_globals_parser(subparsers)
    add_mz_info_parser(subparsers)
    add_omf_compare_parser(subparsers)
    add_tpov_info_parser(subparsers)
    add_tpu_compare_parser(subparsers)
    add_tpu_info_parser(subparsers)
    add_tpu_scan_parser(subparsers)
    add_report_parser(subparsers)
    add_values_parser(subparsers)
    add_vtables_parser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
