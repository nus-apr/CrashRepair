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

SANITIZER_ERROR_STRINGS = (
    "AddressSanitizer",
    "runtime error",
)


class TestFailureReason(enum.Enum):
    """The reason why a test failed."""
    TIMEOUT = "timeout"
    BAD_OUTPUT = "bad-output"
    INCORRECT_STDOUT = "incorrect-stdout"
    BAD_EXIT_CODE = "bad-exit-code"
    DECODE_ERROR = "decode-error"
    UNKNOWN = "unknown"


@attrs.define(auto_attribs=True, slots=True)
class RawTestOutcome:
    duration: float
    stdout: t.Optional[str] = attrs.field(default=None)
    stderr: t.Optional[str] = attrs.field(default=None)
    return_code: t.Optional[int] = attrs.field(default=None)
    failure: t.Optional[TestFailureReason] = attrs.field(default=None)

    def contains_sanitizer_error(self) -> bool:
        """Returns true if the output contains a sanitizer error."""
        return any(
            self.contains_bad_output(error_string)
            for error_string in SANITIZER_ERROR_STRINGS
        )

    def stdout_contains_bad_output(self, bad_output: str) -> bool:
        """Returns true if the stdout contains a given taboo string."""
        stdout = self.stdout or ""
        return bad_output in stdout

    def stderr_contains_bad_output(self, bad_output: str) -> bool:
        """Returns true if the stderr contains a given taboo string."""
        stderr = self.stderr or ""
        return bad_output in stderr

    def contains_bad_output(self, bad_output: str) -> bool:
        """Returns true if the output contains a given taboo string."""
        if self.stdout_contains_bad_output(bad_output):
            return True
        return self.stderr_contains_bad_output(bad_output)


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
    cwd: str = attrs.field(repr=False)
    _shell: Shell = attrs.field(repr=False)
    expected_exit_code: t.Optional[int] = attrs.field(default=None)
    expected_stdout: t.Optional[str] = attrs.field(default=None)
    bad_output: t.Optional[str] = attrs.field(default=None)
    asan_options: t.Optional[str] = attrs.field(default=None)
    ubsan_options: t.Optional[str] = attrs.field(default=None)

    def raw_execute(
        self,
        timeout_seconds: int,
        *,
        halt_on_error: bool = True,
    ) -> RawTestOutcome:
        """Returns the raw output of executing this test."""
        failure: t.Optional[TestFailureReason] = None
        return_code: t.Optional[int] = None
        stdout: t.Optional[str] = None
        stderr: t.Optional[str] = None

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
            raw_outcome = self._shell(
                self.command,
                cwd=self.cwd,
                env=env,
                timeout_seconds=timeout_seconds,
                check_returncode=False,
                capture_output=True,
            )
            timer.stop()
        except subprocess.TimeoutExpired:
            failure = TestFailureReason.TIMEOUT
        except UnicodeDecodeError:
            failure = TestFailureReason.DECODE_ERROR
        else:
            stdout = raw_outcome.stdout
            stderr = raw_outcome.stderr
            return_code = raw_outcome.returncode

        return RawTestOutcome(
            duration=timer.duration,
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            failure=failure,
        )

    def run(self, timeout_seconds: int, *, halt_on_error: bool = True) -> TestOutcome:
        """Runs this test and returns :code:`True` if it passes."""
        raw_outcome = self.raw_execute(
            timeout_seconds=timeout_seconds,
            halt_on_error=halt_on_error,
        )

        if raw_outcome.failure is TestFailureReason.TIMEOUT:
            logger.debug(f"test failed: timeout ({timeout_seconds}s)")

        if raw_outcome.failure is TestFailureReason.DECODE_ERROR:
            logger.debug("test failed: decode error")

        # bad output in stdout/stderr?
        if self.bad_output:
            if raw_outcome.stdout_contains_bad_output(self.bad_output):
                logger.debug(f"test failed: stdout contains bad output substring ({self.bad_output})")
                raw_outcome.failure = raw_outcome.failure or TestFailureReason.BAD_OUTPUT

            if raw_outcome.stderr_contains_bad_output(self.bad_output):
                logger.debug(f"test failed: stderr contains bad output substring ({self.bad_output})")
                raw_outcome.failure = raw_outcome.failure or TestFailureReason.BAD_OUTPUT

        # unexpected stdout?
        if self.expected_stdout is not None:
            actual_stdout = raw_outcome.stdout
            if actual_stdout != self.expected_stdout:
                logger.debug(
                    f"test failed: unexpected stdout (actual: {actual_stdout},"
                    f" expected: {self.expected_stdout})",
                )
                raw_outcome.failure = raw_outcome.failure or TestFailureReason.INCORRECT_STDOUT

        # unexpected exit code?
        if self.expected_exit_code is not None and int(self.expected_exit_code) in [0, 1]:
            actual_returncode = raw_outcome.return_code
            if actual_returncode != self.expected_exit_code:
                logger.debug(
                    f"test failed: unexpected exit code (actual: {actual_returncode},"
                    f" expected: {self.expected_exit_code})",
                )
                raw_outcome.failure = raw_outcome.failure or TestFailureReason.BAD_EXIT_CODE

        return TestOutcome(
            name=self.name,
            successful=(raw_outcome.failure is None),
            duration=raw_outcome.duration,
            return_code=raw_outcome.return_code,
            failure_reason=raw_outcome.failure,
        )
