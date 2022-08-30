# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse

from .scenario import Scenario

DESCRIPTION = "crashrepair: automated repair of C/C++ security bugs"


def do_repair(args: argparse.Namespace) -> None:
    scenario = Scenario.for_file(args.filename)
    scenario.should_terminate_early = args.should_terminate_early
    scenario.skip_fuzzing = args.skip_fuzzing
    scenario.repair()


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
        raise error


if __name__ == "__main__":
    main()
