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

if t.TYPE_CHECKING:
    from .test import Test, TestOutcome


@attrs.define(auto_attribs=True, slots=True)
class PatchEvaluation:
    patch_id: int
    is_repair: bool
    compiles: bool
    compile_time_seconds: float
    test_time_seconds: t.Optional[float] = attrs.field(default=None)
    tests_passed: t.Collection[Test] = attrs.field(factory=list)
    tests_failed: t.Collection[Test] = attrs.field(factory=list)
    test_outcomes: t.Collection[TestOutcome] = attrs.field(factory=list)

    @classmethod
    def failed_to_compile(
        cls,
        candidate: PatchCandidate,
        time_taken: float,
    ) -> PatchEvaluation:
        return PatchEvaluation(
            patch_id=candidate.id_,
            is_repair=False,
            compiles=False,
            compile_time_seconds=time_taken,
        )

    @classmethod
    def failed_tests(
        cls,
        candidate: PatchCandidate,
        compile_time_seconds: float,
        test_time_seconds: float,
        tests_passed: t.Collection[Test],
        tests_failed: t.Collection[Test],
        test_outcomes: t.Collection[TestOutcome],
    ) -> PatchEvaluation:
        return PatchEvaluation(
            patch_id=candidate.id_,
            is_repair=False,
            compiles=True,
            compile_time_seconds=compile_time_seconds,
            test_time_seconds=test_time_seconds,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            test_outcomes=test_outcomes,
        )

    @classmethod
    def repair_found(
        cls,
        candidate: PatchCandidate,
        compile_time_seconds: float,
        test_time_seconds: float,
        tests_passed: t.Collection[Test],
        test_outcomes: t.Collection[TestOutcome],
    ) -> PatchEvaluation:
        return PatchEvaluation(
            patch_id=candidate.id_,
            is_repair=True,
            compiles=True,
            compile_time_seconds=compile_time_seconds,
            test_time_seconds=test_time_seconds,
            tests_passed=tests_passed,
            test_outcomes=test_outcomes,
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        total_time_seconds = self.compile_time_seconds + (self.test_time_seconds or 0)
        return {
            "patch-id": self.patch_id,
            "is-repair": self.is_repair,
            "compiles": self.compiles,
            "time-taken-seconds": {
                "total": total_time_seconds,
                "compile": self.compile_time_seconds,
                "tests": self.test_time_seconds,
            },
            "tests": {
                "executed": len(self.tests_passed) + len(self.tests_failed),
                "passed": len(self.tests_passed),
                "failed": len(self.tests_failed),
                "outcomes": [outcome.to_dict() for outcome in self.test_outcomes],
            },
        }

    def __bool__(self) -> bool:
        return self.is_repair


@attrs.define(auto_attribs=True, slots=True)
class PatchCandidate:
    id_: int
    location: Location
    diff: str

    @classmethod
    def rank(
        cls,
        candidates: t.Collection[PatchCandidate],
        localization_filename: str,
    ) -> t.Sequence[PatchCandidate]:
        """Sorts a list of patches by their estimated likelihood of correctness."""
        location_to_crash_distance: t.Dict[str, int] = {}
        with open(localization_filename, "r") as fh:
            localization = json.load(fh)
        for entry in localization:
            location = entry["location"]
            distance = entry["distance"]
            if location in location_to_crash_distance:
                logger.warning(f"found duplicate fix location: {location}")
            else:
                location_to_crash_distance[location] = distance

        def score(candidate: PatchCandidate) -> float:
            distance = location_to_crash_distance[str(candidate.location)]
            return float(distance)

        # for now, we simply rank based on crash distance
        return sorted(candidates, key=score)

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

    def to_dict(self) -> t.Dict[str, t.Any]:
        return {
            "id": self.id_,
            "location": str(self.location),
            "diff": self.diff,
        }

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
