# -*- coding: utf-8 -*-
"""
Provides an interface for interacting with the CrashRepair program analyzer.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
import typing as t

import attrs

from loguru import logger

from .exceptions import (
    AnalyzerCrashed,
    AnalyzerTimedOut,
)

if t.TYPE_CHECKING:
    from .scenario import Scenario

PATH_ANALYZER = "crepair"

_CONFIG_TEMPLATE = """
dir_exp:{project_directory}
tag_id:{tag_id}
src_directory:{source_directory}
binary_path:{binary_path}
config_command:CC=crepair-cc CXX=crepair-cxx {prebuild_flags} {prebuild_command}
build_command:CC=crepair-cc CXX=crepair-cxx CFLAGS="-g -O0 -static ${{CFLAGS:-}}" CXXFLAGS="-g -O0 -static ${{CXXFLAGS:-}}" LDFLAGS="-g -O0 -static ${{LDFLAGS:-}}" {build_command}
test_input_list:{crashing_input}
{poc_list}
klee_flags:--link-llvm-lib=/CrashRepair/lib/libcrepair_proxy.bca {extra_klee_flags}
"""  # noqa: E501


@attrs.define(auto_attribs=True)
class Analyzer:
    scenario: Scenario
    timeout_minutes: int

    @classmethod
    def for_scenario(cls, scenario: Scenario, timeout_minutes: int) -> Analyzer:
        return Analyzer(scenario, timeout_minutes)

    @contextlib.contextmanager
    def _generate_config(self) -> t.Iterator[str]:
        """Generates a temporary configuration file for the analyzer."""
        scenario = self.scenario

        prebuild_flags = (
            "CFLAGS=\"-g -O0 -static ${{CFLAGS:-}}\" "
            "CXXFLAGS=\"-g -O0 -static ${{CXXFLAGS:-}}\" "
            "LDFLAGS=\"-g -O0 -static ${{LDFLAGS:-}}\""
        )

        # this is a bit of an unfortunate project-specific workaround
        # for this particular scenario in libarchive, we can't pass the flags above to configure
        if scenario.name == "CVE-2016-5844":
            prebuild_flags = ""

        def write_config_to_file(filename: str) -> None:
            poc_list = f"poc_list:{scenario.crashing_input}" if scenario.crashing_input else ""
            contents = _CONFIG_TEMPLATE.format(
                project_directory=scenario.directory,
                prebuild_flags=prebuild_flags,
                tag_id=scenario.tag_id,
                source_directory=scenario.source_directory,
                binary_path=scenario.binary_path,
                prebuild_command=scenario.prebuild_command,
                build_command=scenario.build_command,
                crashing_input=scenario.crashing_command,
                # FIXME it isn't clear how this works when positional arguments are used
                poc_list=poc_list,
                extra_klee_flags=scenario.additional_klee_flags,
            )
            logger.debug(f"generated analyzer config:\n{contents}")
            with open(filename, "w") as fh:
                fh.write(contents)

        try:
            _, filename = tempfile.mkstemp()
            write_config_to_file(filename)
            yield filename
        finally:
            if os.path.exists(filename):
                os.remove(filename)

    def run(self, write_to: str) -> None:
        """Runs the analysis and writes its results to a given output directory.

        Raises
        ------
        AnalyzerCrashed
            If no localization file is produced by the analyzer.
        """
        shell = self.scenario.shell

        # destroy any existing contents of the analyzer output directory
        output_directory = f"/CrashRepair/output/{self.scenario.tag_id}"
        localization_filename = os.path.join(output_directory, "localization.json")

        logger.info(f"running analysis with timeout: {self.timeout_minutes} minutes")

        with self._generate_config() as config_filename:
            timeout_seconds = self.timeout_minutes * 60
            logger.debug(f"wrote analyzer config file to: {config_filename}")
            command = f"{PATH_ANALYZER} --conf={config_filename}"
            try:
                shell(
                    command,
                    cwd=self.scenario.directory,
                    check_returncode=False,
                    timeout_seconds=timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                raise AnalyzerTimedOut(self.timeout_minutes, "TODO: grab tail of analysis output")

        # ensure that the results exist!
        # FIXME grab the tail of the output from the analysis command line
        if not os.path.exists(localization_filename):
            raise AnalyzerCrashed("TODO: grab tail of analysis output")

        if not os.path.exists(write_to):
            logger.warning(f"analysis output directory does not exist [{write_to}]: creating...")

        # FIXME since the analysis results can be pretty big, we should move rather than copy
        # copy across the analysis results
        shutil.copytree(output_directory, write_to)
        shutil.rmtree(output_directory, ignore_errors=True)
