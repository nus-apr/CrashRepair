# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import typing as t

import attrs

from .exceptions import CrashRepairException

if t.TYPE_CHECKING:
    from .candidate import PatchEvaluation


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
    duration_seconds: float = attrs.field(default=0)

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "summary": {
                "duration-minutes": duration_minutes,
            },
        }
        return output


@attrs.define(slots=True, auto_attribs=True)
class AnalysisReport:
    duration_seconds: float
    fix_locations_json: t.List[t.Dict[str, t.Any]]
    linter_errors_json: t.List[t.Dict[str, t.Any]]

    @classmethod
    def build(
        cls,
        duration_seconds: float,
        localization_filename: str,
        linter_filename: str,
    ) -> AnalysisReport:
        with open(localization_filename, "r") as fh:
            fix_locations_json = json.load(fh)

        with open(linter_filename, "r") as fh:
            linter_errors_json = json.load(fh)
            linter_errors_json = linter_errors_json["errors"]

        return AnalysisReport(
            duration_seconds=duration_seconds,
            fix_locations_json=fix_locations_json,
            linter_errors_json=linter_errors_json,
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "summary": {
                "duration-minutes": duration_minutes,
                "num-fix-locations": len(self.fix_locations_json),
                "num-linter-errors": len(self.linter_errors_json),
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
