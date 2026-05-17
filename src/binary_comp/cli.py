"""Command line interface for binary-comp."""

from __future__ import annotations

import argparse
import sys

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
from binary_comp.analyzers.values import ValuesOptions, check_values, format_summary, load_policy
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
    parser.set_defaults(handler=run_values)


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
    parser.set_defaults(handler=run_data)


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
            ),
        )
    except (ConfigError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_summary(summary, min_similarity=args.min_similarity))
    return 0


def run_data(args) -> int:
    try:
        _, target = load_project_target(args.config, args.target)
        globals_source = require_globals_source(args.globals_source or target.globals_source)
        if args.find_missing:
            summary = find_missing_globals(target.original_exe, globals_source, section_name=args.section)
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
        )
    except (ConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(format_comparison(summary, verbose=args.verbose))
    return 0 if summary.mismatches == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="binary-comp")
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_data_parser(subparsers)
    add_values_parser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
