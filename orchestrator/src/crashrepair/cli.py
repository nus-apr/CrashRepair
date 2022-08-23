# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse

from .scenario import Scenario

DESCRIPTION = "crashrepair: automated repair of C/C++ security bugs"


def do_repair(args: argparse.Namespace) -> None:
    scenario = Scenario.for_file(args.filename)
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
