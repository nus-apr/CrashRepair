# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import typing as t
from datetime import datetime
from subprocess import DEVNULL

import attrs
from loguru import logger

from .location import Location


@attrs.define(auto_attribs=True, slots=True)
class PatchCandidate:
    id_: int
    location: Location
    diff: str

    @classmethod
    def load_all(cls, filename: str) -> t.Collection[PatchCandidate]:
        """Loads a set of patch candidates from disk."""
        with open(filename, "r") as fh:
            jsn = json.load(fh)
        candidates = [cls.from_dict(candidate_dict) for candidate_dict in jsn]
        # exclude any patches with an empty diff (workaround to #15)
        candidates = [candidate for candidate in candidates if candidate.diff]
        return candidates

    @classmethod
    def from_dict(cls, dict_: t.Dict[str, t.Any]) -> PatchCandidate:
        return PatchCandidate(
            id_=dict_["id"],
            location=Location.from_string(dict_["location"]),
            diff=dict_["diff"],
        )

    @property
    def filename(self) -> str:
        """The name of the source file to which this patch is applied."""
        return self.location.filename

    def write(self, filename: str) -> None:
        """Writes the patch encoded to a unified diff text file."""
        directory = os.path.dirname(filename)
        os.makedirs(directory, exist_ok=True)

        modification_time_string = datetime.now().isoformat()
        header_from_line = f"--- {self.filename} {modification_time_string}\n"
        header_to_line = f"+++ {self.filename} {modification_time_string}\n"

        with open(filename, "w") as fh:
            fh.write(header_from_line)
            fh.write(header_to_line)
            fh.write(self.diff)

    def apply(self) -> None:
        """Applies this patch to the program."""
        logger.trace("applying candidate patch...")
        _, patch_filename = tempfile.mkstemp(suffix=".diff")
        self.write(patch_filename)
        command = f"patch -u {self.filename} {patch_filename}"
        try:
            subprocess.check_call(
                command,
                stdin=DEVNULL,
                stdout=DEVNULL,
                stderr=DEVNULL,
                shell=True,
            )
        finally:
            os.remove(patch_filename)
        logger.trace("applied candidate patch")

    def revert(self) -> None:
        """Reverts the changes introduced by this patch."""
        logger.trace("reverting candidate patch...")
        _, patch_filename = tempfile.mkstemp(suffix=".diff")
        self.write(patch_filename)
        command = f"patch -R -u {self.filename} {patch_filename}"
        try:
            subprocess.check_call(
                command,
                stdin=DEVNULL,
                stdout=DEVNULL,
                stderr=DEVNULL,
                shell=True,
            )
        finally:
            os.remove(patch_filename)
        logger.trace("reverted candidate patch")
