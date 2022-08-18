# -*- coding: utf-8 -*-
from __future__ import annotations

import configparser
import os

import attrs


@attrs.define(auto_attribs=True, slots=True)
class FuzzerConfig:
    filename: str
    _command_template: str

    @classmethod
    def load(cls, filename: str) -> FuzzerConfig:
        config = configparser.ConfigParser()
        config.read(filename)
        config_sections = config.sections()
        assert len(config_sections) == 1
        bug_config = config[config_sections[0]]

        command_template: str = bug_config["trace_cmd"].replace("***", "{filename}")
        command_template = command_template.replace(";", " ")

        return FuzzerConfig(
            filename=filename,
            command_template=command_template,
        )

    def command_for_input(self, filename: str) -> str:
        assert os.path.isabs(filename)
        return self._command_template.format(filename=filename)
