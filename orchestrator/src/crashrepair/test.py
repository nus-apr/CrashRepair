# -*- coding: utf-8 -*-
from __future__ import annotations

import attrs

from .shell import Shell


@attrs.define(auto_attribs=True, slots=True)
class Test:
    name: str
    command: str
    expected_exit_code: int
    cwd: str = attrs.field(repr=False)
    _shell: Shell = attrs.field(repr=False)

    def run(self) -> bool:
        """Runs this test and returns :code:`True` if it passes."""
        raw_test_outcome = self._shell(self.command, cwd=self.cwd)
        return raw_test_outcome.returncode == self.expected_exit_code
