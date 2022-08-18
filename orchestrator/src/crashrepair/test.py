# -*- coding: utf-8 -*-
from __future__ import annotations

import attrs


@attrs.define(auto_attribs=True, slots=True)
class Test:
    command: str
    cwd: str = attrs.field(repr=False)

    def run(self) -> bool:
        """Runs this test and returns :code:`True` if it passes."""
        raise NotImplementedError
