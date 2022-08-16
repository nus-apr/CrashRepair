# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import typing as t

import attrs

from loguru import logger

CRASHREPAIRFIX_PATH = "/opt/crashrepair/bin/crashrepairfix"


@attrs.define(slots=True, auto_attribs=True)
class Scenario:
    """Provides access to the program under repair.

    Attributes
    ----------
    directory: str
        The absolute path of the bug scenario directory
    source_directory: str
        The absolute path of the source directory for this bug scenario
    compile_commands_path: str
        The absolute path of the compile commands for this bug scenario
    binary_path: str
        The absolute path of the binary under repair for this scenario
    should_terminate_early: bool
        Flag used to control whether the repair process should stop when the first
        acceptable patch has been found, or, alternatively, if it should continue
        finding all acceptable patches for the given bug.
    analysis_directory: str
        The absolute path of the directory that holds the results of the analysis.
    patches_directory: str
        The absolute path of the directory that holds validated patches.
    clean_command: str
        The command that should be used to clean the build space.
    prebuild_command: str
        The command that should be used prior to building the program (e.g., configure).
    build_command: str
        The command that should be used to build the program.
    """
    directory: str
    source_directory: str
    binary_path: str
    clean_command: str
    prebuild_command: str
    build_command: str
    should_terminate_early: bool = attrs.field(default=True)

    @property
    def compile_commands_path(self) -> str:
        return os.path.join(self.source_directory, "compile_commands.json")

    @property
    def analysis_directory(self) -> str:
        return os.path.join(self.directory, "analysis")

    @property
    def fuzzer_directory(self) -> str:
        return os.path.join(self.directory, "fuzzer")

    @property
    def patches_directory(self) -> str:
        return os.path.join(self.directory, "patches")

    @property
    def localization_path(self) -> str:
        return os.path.join(self.analysis_directory, "localization.json")

    @property
    def patch_candidates_path(self) -> str:
        return os.path.join(self.directory, "candidates.json")

    def analysis_results_exist(self) -> bool:
        """Determines whether the results of the analysis exist."""
        return os.path.exists(self.analysis_directory)

    def fuzzer_outputs_exist(self) -> bool:
        """Determines whether the outputs of the fuzzer exist."""
        return os.path.exists(self.fuzzer_directory)

    def candidate_repairs_exist(self) -> bool:
        """Determines whether a set of candidate repairs exists."""
        return os.path.exists(self.patch_candidates_path)

    @classmethod
    def build(
        cls,
        filename: str,
        source_directory: str,
        binary_path: str,
        clean_command: str,
        prebuild_command: str,
        build_command: str,
    ) -> Scenario:
        directory = os.path.dirname(filename)
        directory = os.path.abspath(directory)

        if not os.path.isabs(source_directory):
            source_directory = os.path.join(directory, source_directory)

        if not os.path.isabs(binary_path):
            binary_path = os.path.join(directory, binary_path)

        scenario = Scenario(
            directory=directory,
            source_directory=source_directory,
            binary_path=binary_path,
            clean_command=clean_command,
            prebuild_command=prebuild_command,
            build_command=build_command,
        )
        logger.info(f"loaded bug scenario: {scenario}")
        return scenario

    @classmethod
    def for_file(cls, filename: str) -> Scenario:
        if not os.path.exists(filename):
            raise ValueError(f"bug file not found: {filename}")

        with open(filename, "r") as fh:
            bug_dict = json.load(fh)

        try:
            binary_path = bug_dict["binary"]
            source_directory = bug_dict["source-directory"]
            build_dict = bug_dict["build"]
            build_commands = build_dict["commands"]
            clean_command = build_commands["clean"]
            prebuild_command = build_commands["prebuild"]
            build_command = build_commands["build"]
        except KeyError as exc:
            raise ValueError(f"missing field in bug.json: {exc}")

        return Scenario.build(
            filename=filename,
            binary_path=binary_path,
            source_directory=source_directory,
            clean_command=clean_command,
            prebuild_command=prebuild_command,
            build_command=build_command,
        )

    @classmethod
    def for_directory(cls, directory: str) -> Scenario:
        if not os.path.isdir(directory):
            raise ValueError("bug directory does not exist [{directory}]")

        filename = os.path.join(directory, "bug.json")
        return cls.for_file(filename)

    @classmethod
    def for_directory_or_file(cls, directory_or_filename: str) -> Scenario:
        if os.path.isdir(directory_or_filename):
            return cls.for_directory(directory_or_filename)
        else:
            return cls.for_file(directory_or_filename)

    def shell(
        self,
        command: str,
        env: t.Optional[t.Mapping[str, str]] = None,
        cwd: t.Optional[str] = None,
        check_returncode: bool = True,
        capture_output: bool = False,
    ) -> subprocess.CompletedProcess:
        if not env:
            env = {}

        if not cwd:
            cwd = self.directory

        additional_args: t.Dict[str, t.Any] = {}
        if capture_output:
            additional_args["stdout"] = subprocess.PIPE
            additional_args["universal_newlines"] = "\n"

        logger.debug(f"executing: {command}")
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
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

    def rebuild(
        self,
        *,
        env: t.Optional[t.Dict[str, str]] = None,
    ) -> None:
        """Performs a clean rebuild of the program under test."""
        if not env:
            env = {}

        # if CC/CXX aren't specified, use LLVM/Clang 11
        default_env = {
            "CC": "/opt/llvm11/bin/clang",
            "CXX": "/opt/llvm11/bin/clang++",
        }
        env = {**default_env, **env}

        self.shell(self.clean_command, cwd=self.source_directory)
        self.shell(self.prebuild_command, env=env, cwd=self.source_directory)
        self.shell(f"bear {self.build_command}", env=env, cwd=self.source_directory)

    def analyze(self) -> None:
        """Analyzes the underlying cause of the bug and generates repair hints."""
        if self.analysis_results_exist():
            logger.info(f"skipping analysis: results already exist [{self.analysis_directory}]")
            return

        raise NotImplementedError

    def fuzz(self) -> None:
        """Generates additional test cases via concentrated fuzzing."""
        if self.fuzzer_outputs_exist():
            logger.info(f"skipping fuzzing: outputs already exist [{self.fuzzer_directory}]")
            return

        # TODO generate config file based on bug.json contents
        # - rand_seed={fuzzer_seed}
        # - store_all_inputs=False
        # - combination_num={max_fuzzing_combinations}

        # Questions:
        # - What is the global timeout vs. local timeout?
        # - What is mutate_range?
        # - What is crash_tag and how is it used?
        # - What other formats are used by poc_fmt?
        # - Is there a facility to replaying individual fuzzer-generated inputs?

        # Example:
        #
        #   [bugzilla_2611]
        #   trace_cmd=/benchmarks/libtiff/bugzilla_2611/source/tools/tiffmedian;***;foo2
        #   crash_cmd=/benchmarks/libtiff/bugzilla_2611/source/tools/tiffmedian;***;foo1
        #   bin_path=/benchmarks/libtiff/bugzilla_2611/source/tools/tiffmedian
        #   poc=/benchmarks/libtiff/bugzilla_2611/exploit
        #   poc_fmt=bfile
        #   mutate_range=default
        #   folder=/benchmarks/libtiff/bugzilla_2611
        #   crash_tag=runtime;tif_ojpeg.c:816
        #   global_timeout=300
        #   local_timeout=300
        #   rand_seed=3
        #   store_all_inputs=True
        #
        # TODO build the program for fuzzing
        self.rebuild()

        # TODO run the fuzzer (and block until completion for now)

        # TODO construct reproducible test cases from concentrated inputs
        # ./fuzzer/concentrated_inputs/...
        raise NotImplementedError

    def generate(self) -> None:
        """Generates candidate patches using the analysis results."""
        assert self.analysis_results_exist()

        # generate a compile_commands.json file
        self.rebuild()
        assert os.path.exists(self.compile_commands_path)

        command = " ".join((
            CRASHREPAIRFIX_PATH,
            "--output-to",
            self.patch_candidates_path,
            # FIXME replace with --analysis-directory
            "--localization-filename",
            self.localization_path,
            "-p",
            self.compile_commands_path,
            "-extra-arg=-I/opt/llvm11/lib/clang/11.1.0/include/",
        ))
        self.shell(command, cwd=self.source_directory)
        assert os.path.exists(self.patch_candidates_path)

    def validate(self) -> None:
        """Validates candidate patches."""
        assert self.candidate_repairs_exist()

        # TODO run both the proof of exploit and the fuzzer-generated tests

        # TODO load candidates from file

        raise NotImplementedError

    def repair(self) -> None:
        """Performs end-to-end repair of this bug scenario."""
        # NOTE these two steps could be performed in parallel
        self.fuzz()
        self.analyze()
        self.generate()
        self.validate()
