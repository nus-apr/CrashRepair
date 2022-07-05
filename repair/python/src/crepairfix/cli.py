# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import os
import sys
import typing as t

from loguru import logger

from .scenario import BugScenario

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
        help="the fix localization file that should be used to generate mutations",
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
