# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import typing as t
from subprocess import DEVNULL

import attrs


@attrs.define(auto_attribs=True, slots=True)
class PatchCandidate:
    id_: int
    # FIXME use sourcelocation package!
    location: str
    diff: str

    @classmethod
    def load_all(cls, filename: str) -> t.Collection[PatchCandidate]:
        """Loads a set of patch candidates from disk."""
        with open(filename, "r") as fh:
            jsn = json.load(fh)
        return [cls.from_dict(candidate_dict) for candidate_dict in jsn]

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

    def write(self, filename: str) -> str:
        """Writes the patch encoded to a unified diff text file."""
        # TODO inject file information at the top of the diff
        raise NotImplementedError

    def apply(self) -> None:
        """Applies this patch to the program."""
        _, patch_filename = tempfile.mkstemp(suffix=".diff")
        command = f"patch -u {self.filename} {patch_filename}"
        try:
            subprocess.check_call(
                command,
                stdin=DEVNULL,
                stdout=DEVNULL,
                stderr=DEVNULL,
            )
        finally:
            os.remove(patch_filename)

    def revert(self) -> None:
        """Reverts the changes introduced by this patch."""
        raise NotImplementedError
