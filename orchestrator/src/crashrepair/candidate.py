# -*- coding: utf-8 -*-
from __future__ import annotations

import typing as t

import attrs


@attrs.define(auto_attribs=True, slots=True)
class PatchCandidate:
    id_: int
    # FIXME use sourcelocation package!
    location: str
    diff: str

    @classmethod
    def from_dict(cls, dict_: t.Dict[str, t.Any]) -> PatchCandidate:
        return PatchCandidate(
            id_=dict_["id"],
            location=dict_["location"],
            diff=dict_["diff"],
        )

    @property
    def filename(self) -> str:
        """The name of the source file to which this patch is applied."""
        raise NotImplementedError
