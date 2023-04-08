# -*- coding: utf-8 -*-
from __future__ import annotations

import enum
import os
import subprocess
import typing as t

import attrs

from loguru import logger

from .shell import Shell
from .stopwatch import Stopwatch


class TestFailureReason(enum.Enum):
    """The reason why a test failed."""
    TIMEOUT = "timeout"
    BAD_OUTPUT = "bad-output"
    BAD_EXIT_CODE = "bad-exit-code"
    DECODE_ERROR = "decode-error"
    UNKNOWN = "unknown"


@attrs.define(auto_attribs=True, slots=True)
class TestOutcome:
    name: str
    successful: bool
    duration: float
    return_code: t.Optional[int] = attrs.field(default=None)
    failure_reason: t.Optional[TestFailureReason] = attrs.field(default=None)

    def __bool__(self) -> bool:
        return self.successful

    def to_dict(self) -> t.Dict[str, t.Any]:
        output: t.Dict[str, t.Any] = {}
        output["successful"] = self.successful
        output["return-code"] = self.return_code
        output["duration"] = self.duration
        if self.failure_reason:
            output["failure-reason"] = self.failure_reason.value
        return output


@attrs.define(auto_attribs=True, slots=True)
class Test:
    name: str
    command: str
    expected_exit_code: int
    cwd: str = attrs.field(repr=False)
    _shell: Shell = attrs.field(repr=False)
    bad_output: t.Optional[str] = attrs.field(default=None)
    asan_options: t.Optional[str] = attrs.field(default=None)
    ubsan_options: t.Optional[str] = attrs.field(default=None)

    def run(self, timeout_seconds: int, *, halt_on_error: bool = True) -> TestOutcome:
        """Runs this test and returns :code:`True` if it passes."""
        capture_output = self.bad_output is not None
        env: t.Dict[str, str] = {}
        timer = Stopwatch()

        if self.asan_options:
            asan_options = self.asan_options
        else:
            asan_options = f"detect_odr_violation=0:detect_leaks=0:halt_on_error={'true' if halt_on_error else 'false'}"  # noqa: E501
        env["ASAN_OPTIONS"] = asan_options

        if self.ubsan_options:
            env["UBSAN_OPTIONS"] = self.ubsan_options

        if "LD_LIBRARY_PATH_ORIG" in os.environ:
            env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH_ORIG"]

        try:
            timer.start()
            raw_test_outcome = self._shell(
                self.command,
                cwd=self.cwd,
                env=env,
                check_returncode=False,
                timeout_seconds=timeout_seconds,
                capture_output=capture_output,
            )
            timer.stop()
        except subprocess.TimeoutExpired:
            logger.debug("test failed: timeout")
            return TestOutcome(
                name=self.name,
                successful=False,
                duration=timer.duration,
                failure_reason=TestFailureReason.TIMEOUT,
            )
        except UnicodeDecodeError:
            logger.debug("test failed: unable to decode output")
            return TestOutcome(
                name=self.name,
                successful=False,
                duration=timer.duration,
                failure_reason=TestFailureReason.DECODE_ERROR,
            )

        actual_returncode = raw_test_outcome.returncode

        if self.bad_output:
            stdout = raw_test_outcome.stdout or ""
            stderr = raw_test_outcome.stderr or ""
            logger.debug(f"test output [stdout]: {stdout}")
            logger.debug(f"test output [stderr]: {stderr}")

            if self.bad_output in stdout:
                logger.debug(f"test failed: stdout contains bad output substring ({self.bad_output})")
                return TestOutcome(
                    name=self.name,
                    successful=False,
                    duration=timer.duration,
                    return_code=actual_returncode,
                    failure_reason=TestFailureReason.BAD_OUTPUT,
                )
            if self.bad_output in stderr:
                logger.debug(f"test failed: stderr contains bad output substring ({self.bad_output})")
                return TestOutcome(
                    name=self.name,
                    successful=False,
                    duration=timer.duration,
                    return_code=actual_returncode,
                    failure_reason=TestFailureReason.BAD_OUTPUT,
                )

        if actual_returncode != self.expected_exit_code:
            logger.debug(
                f"test failed: unexpected exit code (actual: {actual_returncode},"
                f" expected: {self.expected_exit_code})",
            )
            return TestOutcome(
                name=self.name,
                successful=False,
                duration=timer.duration,
                return_code=actual_returncode,
                failure_reason=TestFailureReason.BAD_EXIT_CODE,
            )

        return TestOutcome(
            name=self.name,
            successful=True,
            duration=timer.duration,
            return_code=actual_returncode,
        )
