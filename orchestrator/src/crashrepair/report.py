# -*- coding: utf-8 -*-
import json
import typing as t

import attrs

from .exceptions import CrashRepairException


@attrs.define(slots=True, auto_attribs=True)
class GenerationReport:
    duration_seconds: float = attrs.field(default=0)

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "duration-minutes": duration_minutes,
        }
        return output


@attrs.define(slots=True, auto_attribs=True)
class ValidationReport:
    duration_seconds: float = attrs.field(default=0)

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "duration-minutes": duration_minutes,
        }
        return output


@attrs.define(slots=True, auto_attribs=True)
class FuzzerReport:
    duration_seconds: float = attrs.field(default=0)

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "duration-minutes": duration_minutes,
        }
        return output


@attrs.define(slots=True, auto_attribs=True)
class AnalysisReport:
    duration_seconds: float = attrs.field(default=0)

    def to_dict(self) -> t.Dict[str, t.Any]:
        duration_minutes = self.duration_seconds / 60
        output: t.Dict[str, t.Any] = {
            "duration-minutes": duration_minutes,
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
