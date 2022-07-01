# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import os
import sys
import typing as t

from loguru import logger

DESCRIPTION = "automatically repair security vulnerabilities in C/C++"


def do_validate(args: argparse.Namespace) -> None:
    scenario = BugScenario.for_directory_or_bug_file(args.directory_or_filename)
    if scenario.validate():
        sys.exit(0)
    else:
        sys.exit(1)


def do_map(args: argparse.Namespace) -> None:
    scenario = BugScenario.for_directory_or_bug_file(args.directory_or_filename)
    scenario.map_ir_to_source()


def do_mutate(args: argparse.Namespace) -> None:
    scenario = BugScenario.for_directory_or_bug_file(args.directory_or_filename)
    scenario.should_validate_localization = args.should_validate_localization
    scenario.generate_bitcode()
    scenario.mutate(
        localization_filename=args.localization_path,
    )


def do_analysis(args: argparse.Namespace) -> None:
    scenario = BugScenario.for_directory_or_bug_file(args.directory_or_filename)
    scenario.analyze(debug=args.debug)


def do_repair(args: argparse.Namespace) -> None:
    scenario = BugScenario.for_directory_or_bug_file(args.directory_or_filename)
    scenario.should_terminate_early = args.should_terminate_early
    scenario.should_validate_localization = args.should_validate_localization
    if not args.compute_deps:
        scenario.should_compute_dependencies = False
    scenario.repair(debug=args.debug)


def do_trace(args: argparse.Namespace) -> None:
    scenario = BugScenario.for_directory_or_bug_file(args.directory_or_filename)
    scenario.generate_trace()


def do_dump_ast(args: argparse.Namespace) -> None:
    scenario = BugScenario.for_directory_or_bug_file(args.directory_or_filename)
    scenario.obtain_ast_dump(args.filename)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(DESCRIPTION)
    subparsers = parser.add_subparsers()

    parser_dump_ast = subparsers.add_parser(
        "dump-ast",
        help="dumps the AST for a given source file",
    )
    parser_dump_ast.add_argument(
        "directory_or_filename",
        help="the path to the directory or bug.json for a repair scenario",
    )
    parser_dump_ast.add_argument(
        "filename",
        help="the path to the source file whose AST should be dumped",
    )
    parser_dump_ast.set_defaults(func=do_dump_ast)

    parser_repair = subparsers.add_parser(
        "repair",
        help="attempts to repair the given program",
    )
    parser_repair.add_argument(
        "directory_or_filename",
        help="the path to the directory or bug.json for a repair scenario",
    )
    parser_repair.add_argument(
        "--debug",
        help="enables debugging mode",
        action="store_true",
    )
    parser_repair.add_argument(
        "--no-deps",
        help="disables dependency calculation",
        dest="compute_deps",
        action="store_false",
    )
    parser_repair.add_argument(
        "--stop-early",
        help="stops generating patches after an acceptable patch has been found",
        dest="should_terminate_early",
        action="store_true",
    )
    parser_repair.add_argument(
        "--no-validation",
        help="disables validation of the fix localization for the purposes of repair",
        dest="should_validate_localization",
        action="store_false",
    )
    parser_repair.set_defaults(func=do_repair)

    parser_analysis = subparsers.add_parser(
        "analyze",
        help="analyses to produce repair constraints"
    )
    parser_analysis.add_argument(
        "--debug",
        help="enables debugging mode",
        action="store_true",
    )
    parser_analysis.add_argument(
        "directory_or_filename",
        help="the path to the directory or bug.json for a repair scenario",
    )
    parser_analysis.set_defaults(func=do_analysis)

    parser_mutate = subparsers.add_parser(
        "mutate",
        help="mutates the LLVM IR for the program",
    )
    parser_mutate.add_argument(
        "directory_or_filename",
        help="the path to the directory or bug.json for a repair scenario",
    )
    parser_mutate.add_argument(
        "--localization",
        dest="localization_path",
        help="an optional path to a handcrafted annotated fix localization that should be used during repair",
        required=False,
    )
    parser_mutate.add_argument(
        "--no-validation",
        help="disables validation of the fix localization for the purposes of repair",
        dest="should_validate_localization",
        action="store_false",
    )
    parser_mutate.set_defaults(func=do_mutate)

    parser_mapping = subparsers.add_parser(
        "map",
        help="produces an LLVM IR to source code mapping for the program",
    )
    parser_mapping.add_argument(
        "directory_or_filename",
        help="the path to the directory or bug.json for a repair scenario",
    )
    parser_mapping.set_defaults(func=do_map)

    parser_validate = subparsers.add_parser(
        "validate",
        help="attempts to find an acceptable repair using a super-mutated binary",
    )
    parser_validate.add_argument(
        "directory_or_filename",
        help="the path to the directory or bug.json for a repair scenario",
    )
    parser_validate.set_defaults(func=do_validate)

    parser_trace = subparsers.add_parser(
        "trace",
        help="produces trace from the instrumented binary",
    )
    parser_trace.add_argument(
        "directory_or_filename",
        help="the path to the directory or bug.json for a repair scenario",
    )
    parser_trace.set_defaults(func=do_trace)

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
        msg = "ERROR: {}".format(error)
        print(msg)
        raise error


if __name__ == "__main__":
    main()
