# -*- coding: utf-8 -*-
from __future__ import annotations

import attrs


@attrs.define(auto_attribs=True, slots=True)
class Location:
    filename: str
    line: int
    column: int

    @classmethod
    def from_string(cls, string_: str) -> Location:
        parts = string_.split(":")
        assert len(parts) == 3
        filename = parts[0]
        line = int(parts[1])
        column = int(parts[2])
        return Location(
            filename=filename,
            line=line,
            column=column,
        )

    def __str__(self) -> str:
        return f"{self.filename}:{self.line}:{self.column}"
