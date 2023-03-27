# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import subprocess
import typing as t

import attrs

from loguru import logger

from .shell import Shell


@attrs.define(auto_attribs=True, slots=True)
class Test:
    name: str
    command: str
    expected_exit_code: int
    cwd: str = attrs.field(repr=False)
    _shell: Shell = attrs.field(repr=False)
    bad_output: t.Optional[str] = attrs.field(default=None)

    def run(self, timeout_seconds: int, *, halt_on_error: bool = True) -> bool:
        """Runs this test and returns :code:`True` if it passes."""
        capture_output = self.bad_output is not None
        env: t.Dict[str, str] = {}
        env["ASAN_OPTIONS"] = f"detect_leaks=0:halt_on_error={'true' if halt_on_error else 'false'}"

        if "LD_LIBRARY_PATH_ORIG" in os.environ:
            env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH_ORIG"]

        try:
            raw_test_outcome = self._shell(
                self.command,
                cwd=self.cwd,
                env=env,
                check_returncode=False,
                timeout_seconds=timeout_seconds,
                capture_output=capture_output,
            )
        except subprocess.TimeoutExpired:
            return False
        except UnicodeDecodeError:
            logger.debug("test failed: unable to decode output")
            return False

        if self.bad_output:
            stdout = raw_test_outcome.stdout or ""
            stderr = raw_test_outcome.stderr or ""
            logger.debug(f"test output [stdout]: {stdout}")
            logger.debug(f"test output [stderr]: {stderr}")

            if self.bad_output in stdout:
                logger.debug(f"test failed: stdout contains bad output substring ({self.bad_output})")
                return False
            if self.bad_output in stderr:
                logger.debug(f"test failed: stderr contains bad output substring ({self.bad_output})")
                return False

        if raw_test_outcome.returncode != self.expected_exit_code:
            logger.debug(
                f"test failed: unexpected exit code (actual: {raw_test_outcome.returncode},"
                f" expected: {self.expected_exit_code})")
            return False

        return True
