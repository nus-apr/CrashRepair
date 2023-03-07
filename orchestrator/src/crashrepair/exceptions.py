# -*- coding: utf-8 -*-
import abc
import typing as t

import attr as _attr


class CrashRepairException(Exception):
    """Used by all exceptions that are raised by the tool."""
    @abc.abstractmethod
    def to_dict(self) -> t.Dict[str, t.Any]:
        ...


@_attr.s(frozen=True, auto_exc=True, auto_attribs=True)
class AnalyzerCrashed(CrashRepairException):
    """Used to indicate that the analysis failed to produce a localization file.

    Attributes
    ----------
    tail: str
        Contains the last N lines of the output produced by the analyzer tool.
    """
    tail: str

    def __str__(self) -> str:
        return "analysis failed: no localization file was produced"

    def to_dict(self) -> t.Dict[str, t.Any]:
        return {
            "kind": "analyzer-crash",
            "tail": self.tail,
        }


@_attr.s(frozen=True, auto_exc=True, auto_attribs=True)
class AnalyzerTimedOut(CrashRepairException):
    """Used to indicate that the analysis failed to produce a localization file within a given timeout.

    Attributes
    ----------
    time_limit_minutes: int
        The timeout that was exceeded by the analysis, given in minutes.
    tail: str
        Contains the last N lines of the output produced by the analyzer tool.
    """
    time_limit_minutes: int
    tail: str

    def __str__(self) -> str:
        return (
            "analysis failed: no localization file was produced within timeout window "
            f"({self.time_limit_minutes} minutes)"
        )

    def to_dict(self) -> t.Dict[str, t.Any]:
        return {
            "kind": "analyzer-timeout",
            "time-limit-minutes": self.time_limit_minutes,
            "tail": self.tail,
        }
