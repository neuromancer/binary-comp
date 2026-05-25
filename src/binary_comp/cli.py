"""Command line interface for binary-comp."""

from __future__ import annotations

import argparse
import sys

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
)
from binary_comp.analyzers.global_access import (
    GlobalAccessOptions,
    check_global_accesses,
    format_global_access_summary,
)
from binary_comp.analyzers.globals import GlobalsAuditOptions, audit_globals, format_report
from binary_comp.analyzers.report import (
    SimilarityReportOptions,
    format_similarity_report,
    generate_similarity_report,
)
from binary_comp.analyzers.values import ValuesOptions, check_values, format_summary, load_policy
from binary_comp.analyzers.vtables import VtableOptions, check_vtables, format_vtable_summary
from binary_comp.config import ConfigError, DEFAULT_CONFIG_PATH, load_project_target


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
    parser.set_defaults(handler=run_vtables)


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
    parser.add_argument("disassembled_code", help="Path to the Ghidra disassembly export for the function")
    parser.add_argument("--no-build", action="store_true", help="Use existing rebuilt binary and map")
    parser.set_defaults(handler=run_compare)


def add_report_parser(subparsers) -> None:
    parser = subparsers.add_parser("report", help="Generate a whole-project function similarity report")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Project config path (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", default="full", help="Target name from config (default: full)")
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
        _, target = load_project_target(args.config, args.target)
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
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_comparison(summary, verbose=args.verbose))
    return 0 if summary.mismatches == 0 else 1


def run_compare(args) -> int:
    try:
        _, target = load_project_target(args.config, args.target)
        comparison = FunctionComparer(target).compare(
            args.function_name,
            args.disassembled_code,
            build=not args.no_build,
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError, FunctionCompareError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_function_comparison(comparison))
    return 0


def run_report(args) -> int:
    try:
        _, target = load_project_target(args.config, args.target)
        report = generate_similarity_report(
            target,
            SimilarityReportOptions(build=not args.no_build),
        )
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
    add_data_parser(subparsers)
    add_global_access_parser(subparsers)
    add_globals_parser(subparsers)
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
