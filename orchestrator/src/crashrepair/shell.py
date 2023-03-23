# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import subprocess
import typing as t

import attrs

from loguru import logger


@attrs.define(auto_attribs=True)
class Shell:
    cwd: str

    def __call__(
        self,
        command: str,
        env: t.Optional[t.Mapping[str, str]] = None,
        cwd: t.Optional[str] = None,
        check_returncode: bool = True,
        capture_output: bool = False,
        timeout_seconds: t.Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        if not env:
            env = {}

        if not cwd:
            cwd = self.cwd

        additional_args: t.Dict[str, t.Any] = {}
        if capture_output:
            additional_args["stdout"] = subprocess.PIPE
            additional_args["stderr"] = subprocess.PIPE
            additional_args["universal_newlines"] = "\n"

        logger.debug(f"executing: {command}")
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            timeout=timeout_seconds,
            env={
                **os.environ,
                **env,
                "REPAIR_TOOL": "crashrepair",
            },
            **additional_args,
        )

        if check_returncode:
            result.check_returncode()

        return result
