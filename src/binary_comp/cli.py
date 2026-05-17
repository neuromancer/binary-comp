"""Command line interface for binary-comp."""

from __future__ import annotations

import argparse
import sys

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="binary-comp")
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_values_parser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
