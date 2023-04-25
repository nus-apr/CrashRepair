# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import sys
import traceback

from .scenario import Scenario

DESCRIPTION = "crashrepair: automated repair of C/C++ security bugs"


def do_repair(args: argparse.Namespace) -> None:
    scenario = Scenario.for_file(args.filename, skip_fuzzing=args.no_fuzzing)
    scenario.should_terminate_early = args.should_terminate_early
    scenario.time_limit_minutes_validation = args.time_limit_minutes_validation
    scenario.time_limit_minutes_analysis = args.time_limit_minutes_analysis
    if args.time_limit_seconds_test:
        scenario.time_limit_seconds_single_test = args.time_limit_seconds_test
    if args.patch_limit:
        scenario.acceptable_patch_limit = args.patch_limit
    scenario.repair()


def do_analyze(args: argparse.Namespace) -> None:
    scenario = Scenario.for_file(args.filename)
    scenario.time_limit_minutes_analysis = args.time_limit_minutes
    scenario.analyze()


def do_fuzz(args: argparse.Namespace) -> None:
    scenario = Scenario.for_file(args.filename)
    scenario.fuzz()


def do_lint(args: argparse.Namespace) -> None:
    scenario = Scenario.for_file(args.filename)
    if not scenario.lint(fix=args.fix):
        print(f"FAIL: bad fix localization for scenario: {scenario.directory}")
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(DESCRIPTION)
    subparsers = parser.add_subparsers()

    parser_repair = subparsers.add_parser(
        "repair",
        help="performs end-to-end repair of a given bug scenario",
    )
    parser_repair.add_argument(
        "filename",
        help="the path to the bug.json file for the bug scenario",
    )
    parser_repair.add_argument(
        "--patch-limit",
        type=int,
        help="enforces a limit on the maximum number of acceptable patches",
    )
    parser_repair.add_argument(
        "--time-limit-minutes-analysis",
        type=int,
        help="enforces a limit on the maximum number of minutes required by the analysis",
        default=60,
    )
    parser_repair.add_argument(
        "--time-limit-minutes-validation",
        type=int,
        help="enforces a limit on the maximum number of minutes that are spent on validating candidate patches",
        required=False,
    )
    parser_repair.add_argument(
        "--time-limit-seconds-test",
        type=int,
        help="enforces a limit on the maximum number of seconds spent executing a single test",
        required=False,
    )
    parser_repair.add_argument(
        "--stop-early",
        help="stops generating patches after an acceptable patch has been found",
        dest="should_terminate_early",
        action="store_true",
    )
    parser_repair.add_argument(
        "--no-fuzzing",
        help="disables the use of fuzzing",
        dest="no_fuzzing",
        action="store_true",
    )
    parser_repair.set_defaults(func=do_repair)

    parser_analyze = subparsers.add_parser(
        "analyze",
        help="analyzes a given bug scenario and produces an annotated fix localization",
    )
    parser_analyze.add_argument(
        "filename",
        help="the path to the bug.json file for the bug scenario",
    )
    parser_analyze.add_argument(
        "--time-limit-minutes",
        type=int,
        help="enforces a limit on the maximum number of minutes required by the analysis",
        default=60,
    )
    parser_analyze.set_defaults(func=do_analyze)

    parser_fuzz = subparsers.add_parser(
        "fuzz",
        help="fuzzes a given bug scenario",
    )
    parser_fuzz.add_argument(
        "filename",
        help="the path to the bug.json file for the bug scenario",
    )
    parser_fuzz.set_defaults(func=do_fuzz)

    parser_lint = subparsers.add_parser(
        "lint",
        help="lints the localization.json for a given bug scenario",
    )
    parser_lint.add_argument(
        "--fix",
        help="attempts to automatically fix any issues with the fix localization",
        action="store_true",
    )
    parser_lint.add_argument(
        "filename",
        help="the path to the bug.json file for the bug scenario",
    )
    parser_lint.set_defaults(func=do_lint)

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if "func" in args:
            args.func(args)
    except KeyboardInterrupt:
        print("Received keyboard interrupt. Terminating...")
    except SystemExit:
        print("Shutting down...")
    except Exception as error:
        print(f"ERROR: {error}")
        print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
