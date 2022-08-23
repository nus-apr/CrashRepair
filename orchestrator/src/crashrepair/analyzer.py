# -*- coding: utf-8 -*-
"""
Provides an interface for interacting with the CrashRepair program analyzer.
"""
from __future__ import annotations

import contextlib
import os
import tempfile
import typing as t

import attrs

from loguru import logger

if t.TYPE_CHECKING:
    from .scenario import Scenario

# FIXME what are test_input_list and poc_list? how are lists delimited?
_CONFIG_TEMPLATE = """
dir_exp:{project_directory}
tag_id:{bug_name}
src_directory:{source_directory}
binary_path:{binary_path}
config_command:CC=crepair-cc CXX=crepair-cxx {prebuild_command}
build_command:make CC=crepair-cc CXX=crepair-cxx {build_command}
test_input_list:-D $POC
poc_list:$script_dir/../tests/1.bin
klee_flags:--link-llvm-lib=/CrashRepair/lib/libcrepair_proxy.bca
"""


@attrs.define(auto_attribs=True)
class Analyzer:
    scenario: Scenario

    @classmethod
    def for_scenario(cls, scenario: Scenario) -> Analyzer:
        return Analyzer(scenario)

    @contextlib.contextmanager
    def _generate_config(self) -> t.Iterator[str]:
        """Generates a temporary configuration file for the analyzer."""
        scenario = self.scenario

        def write_config_to_file(filename: str) -> None:
            contents = _CONFIG_TEMPLATE.format(
                project_directory=scenario.directory,
                bug_name=scenario.name,
                source_directory=scenario.source_directory,
                binary_path=scenario.binary_path,
                prebuild_command=scenario.prebuild_command,
                build_command=scenario.build_command,
            )
            with open(filename, "w") as fh:
                fh.write(contents)

        try:
            _, filename = tempfile.mkstemp()
            write_config_to_file(filename)
            yield filename
        finally:
            if os.path.exists(filename):
                os.remove(filename)

    # TODO how can we specify to where the analyzer should write its output?
    def run(self) -> None:
        with self._generate_config() as config_filename:
            logger.debug(f"wrote analyzer config file to: {config_filename}")
            raise NotImplementedError
