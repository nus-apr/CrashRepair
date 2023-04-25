# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import typing as t

import attrs

from .exceptions import CrashRepairException

if t.TYPE_CHECKING:
    from .candidate import PatchEvaluation
    from .test import Test


def compute_disk_usage_in_bytes(directory: str) -> int:
    usage = 0
    for prefix, _subdirs, files in os.walk(directory):
        usage += os.path.getsize(prefix)
        usage += sum(os.path.getsize(os.path.join(prefix, file)) for file in files)
    return usage


@attrs.define(slots=True, auto_attribs=True)
class GenerationReport:
    duration_seconds: float
    candidates_json: t.List[t.Dict[str, t.Any]]

    @classmethod
    def build(
        cls,
        duration_seconds: float,
        candidates_filename: str,
    ) -> GenerationReport:
        with open(candidates_filename, "r") as fh:
            candidates_json = json.load(fh)

        return GenerationReport(
            duration_seconds=duration_seconds,
            candidates_json=candidates_json,
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "summary": {
                "duration-minutes": duration_minutes,
                "num-candidates": len(self.candidates_json),
            },
            "candidates": self.candidates_json,
        }
        return output


@attrs.define(slots=True, auto_attribs=True)
class ValidationReport:
    duration_seconds: float
    evaluations: t.List[PatchEvaluation]

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        num_evaluations = len(self.evaluations)
        num_compilation_failures = sum(1 for evaluation in self.evaluations if not evaluation.compiles)
        repairs_found = sum(1 for evaluation in self.evaluations if evaluation.is_repair)
        duration_tests_minutes = sum(evaluation.test_time_seconds or 0 for evaluation in self.evaluations) / 60
        duration_compilation_minutes = sum(evaluation.compile_time_seconds or 0 for evaluation in self.evaluations) / 60
        output: t.Dict[str, t.Any] = {
            "summary": {
                "duration-minutes": {
                    "overall": duration_minutes,
                    "tests": duration_tests_minutes,
                    "compilation": duration_compilation_minutes,
                },
                "num-patches-evaluated": num_evaluations,
                "num-repairs-found": repairs_found,
                "num-compilation-failures": num_compilation_failures,
            },
            "evaluations": [
                evaluation.to_dict() for evaluation in self.evaluations
            ],
            "repairs": [
                evaluation.patch_id for evaluation in self.evaluations if evaluation.is_repair
            ],
        }
        return output


@attrs.define(slots=True, auto_attribs=True)
class FuzzerReport:
    num_tests_total: int
    num_tests_passing: int
    num_tests_crashing: int
    duration_seconds: float = attrs.field(default=0)

    @classmethod
    def build(
        cls,
        fuzzer_tests: t.Sequence[Test],
        duration_seconds: float,
    ) -> FuzzerReport:
        num_tests_total = len(fuzzer_tests)
        num_tests_passing = sum(
            1 for test in fuzzer_tests if test.expected_stdout is not None
        )
        num_tests_crashing = num_tests_total - num_tests_passing
        return FuzzerReport(
            duration_seconds=duration_seconds,
            num_tests_total=num_tests_total,
            num_tests_crashing=num_tests_crashing,
            num_tests_passing=num_tests_passing,
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "summary": {
                "duration-minutes": duration_minutes,
                "num-tests": {
                    "total": self.num_tests_total,
                    "passing": self.num_tests_passing,
                    "crashing": self.num_tests_crashing,
                }
            },
        }
        return output


@attrs.define(slots=True, auto_attribs=True)
class AnalysisReport:
    duration_seconds: float
    fix_locations_json: t.List[t.Dict[str, t.Any]]
    linter_errors_json: t.List[t.Dict[str, t.Any]]
    disk_usage_megabytes: float

    @classmethod
    def build(
        cls,
        duration_seconds: float,
        analysis_directory: str,
        localization_filename: str,
        linter_filename: str,
    ) -> AnalysisReport:
        with open(localization_filename, "r") as fh:
            fix_locations_json = json.load(fh)

        with open(linter_filename, "r") as fh:
            linter_errors_json = json.load(fh)
            linter_errors_json = linter_errors_json["errors"]

        disk_usage_bytes = compute_disk_usage_in_bytes(analysis_directory)
        disk_usage_megabytes = disk_usage_bytes / 1000000

        return AnalysisReport(
            duration_seconds=duration_seconds,
            fix_locations_json=fix_locations_json,
            linter_errors_json=linter_errors_json,
            disk_usage_megabytes=disk_usage_megabytes,
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "summary": {
                "duration-minutes": duration_minutes,
                "num-fix-locations": len(self.fix_locations_json),
                "num-linter-errors": len(self.linter_errors_json),
                "disk-usage-megabytes": self.disk_usage_megabytes,
            },
            "fix-locations": self.fix_locations_json,
            "linter-errors": self.linter_errors_json,
        }
        return output


@attrs.define(slots=True, auto_attribs=True)
class Report:
    analysis: t.Optional[AnalysisReport] = attrs.field(default=None)
    fuzzer: t.Optional[FuzzerReport] = attrs.field(default=None)
    generation: t.Optional[GenerationReport] = attrs.field(default=None)
    validation: t.Optional[ValidationReport] = attrs.field(default=None)
    error: t.Optional[CrashRepairException] = attrs.field(default=None)
    duration_seconds: float = attrs.field(default=0)

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "duration-minutes": duration_minutes,
        }
        if self.analysis:
            output["analysis"] = self.analysis.to_dict()
        if self.fuzzer:
            output["fuzzer"] = self.fuzzer.to_dict()
        if self.generation:
            output["generation"] = self.generation.to_dict()
        if self.validation:
            output["validation"] = self.validation.to_dict()
        if self.error:
            output["error"] = self.error.to_dict()
        return output

    def save(self, filename: str) -> None:
        """Writes this report to a given location on disk."""
        with open(filename, "w") as fh:
            json.dump(self.to_dict(), fh, indent=2)
