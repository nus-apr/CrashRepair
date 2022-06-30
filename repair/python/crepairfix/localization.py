# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import typing as t

import attr


@attr.s(slots=True, frozen=True)
class FixLocation:
    """Represents an LLVM IR location at which a fix may be performed."""
    instruction_id = attr.ib(type=int)
    implicit = attr.ib(type=bool)
    filename = attr.ib(type=str)
    line = attr.ib(type=int)
    column = attr.ib(type=int)

    @classmethod
    def from_dict(cls, dict_: t.Dict[str, t.Any]) -> "FixLocation":
        instruction_id = dict_["instruction"]["id"]
        implicit = dict_["implicit"]
        filename = dict_["source-location"]["filename"]
        line = dict_["source-location"]["line"]
        column = dict_["source-location"]["column"]
        return FixLocation(
            instruction_id=instruction_id,
            implicit=implicit,
            filename=filename,
            line=line,
            column=column,
        )


@attr.s(slots=True, frozen=True)
class FixLocalization(t.Mapping[int, FixLocation]):
    _instruction_to_location = attr.ib(type=dict)

    @classmethod
    def from_dict(cls, dict_: t.Sequence[t.Dict[str, t.Any]]) -> "FixLocalization":
        locations = [FixLocation.from_dict(loc) for loc in dict_]
        instruction_to_location = {
            location.instruction_id: location for location in locations
        }
        return FixLocalization(instruction_to_location)

    @classmethod
    def load(cls, filename: str) -> "FixLocalization":
        with open(filename, "r") as fh:
            return cls.from_dict(json.load(fh))

    def __getitem__(self, instruction_id: int) -> "FixLocation":
        return self._instruction_to_location[instruction_id]

    def __len__(self) -> int:
        return len(self._instruction_to_location)

    def __iter__(self) -> t.Iterator[int]:
        yield from self._instruction_to_location
