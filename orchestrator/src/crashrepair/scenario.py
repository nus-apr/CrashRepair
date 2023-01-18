# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import typing as t

import attrs

from loguru import logger

from .analyzer import Analyzer
from .candidate import PatchCandidate
from .fuzzer import FuzzerConfig
from .shell import Shell
from .test import Test

# TODO allow these to be customized via environment variables
CRASHREPAIRFIX_PATH = "/opt/crashrepair/bin/crashrepairfix"
CRASHREPAIRLINT_PATH = "/opt/crashrepair/bin/crashrepairlint"
FUZZER_PATH = "/opt/fuzzer/code/fuzz"

# _FUZZER_CONFIG_TEMPLATE = """
# [{scenario_name}]
# bin_path={binary_path}
# folder={directory}
# global_timeout={global_timeout}
# local_timeout={local_timeout}
# mutate_range=default
# store_all_inputs=False
# rand_seed={fuzz_seed}
# combination_num={max_fuzzing_combinations}
# trace_cmd=TODO
# crash_cmd=TODO
# poc={poc}
# poc_fmt={poc_fmt}
# """


@attrs.define(slots=True, auto_attribs=True)
class Scenario:
    """Provides access to the program under repair.

    Attributes
    ----------
    subject: str
        The name of the subject program
    name: str
        The name of the bug scenario
    directory: str
        The absolute path of the bug scenario directory
    build_directory: str
        The absolute path of the build directory for this bug scenario
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
    crashing_command: str
        The command that should be used to trigger the program to crash.
    crashing_input: t.Optional[str]
        The optional path to the file that causes the binary to crash, if relevant.
    expected_exit_code_for_crashing_input: int
        The exit code that _should_ be produced by the program when the crashing input is provided (i.e., the oracle).
    fuzz_seed: int
        The RNG seed that should be used during fuzzing.
    """
    subject: str
    name: str
    directory: str
    build_directory: str
    source_directory: str
    binary_path: str
    clean_command: str
    prebuild_command: str
    build_command: str
    crashing_command: str
    crashing_input: t.Optional[str]
    shell: Shell
    crash_test: Test
    additional_klee_flags: str = attrs.field(default="")
    expected_exit_code_for_crashing_input: int = attrs.field(default=0)
    should_terminate_early: bool = attrs.field(default=True)
    skip_fuzzing: bool = attrs.field(default=False)
    fuzzer_tests: t.List[Test] = attrs.field(factory=list)
    fuzz_seed: int = attrs.field(default=0)

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

    # TODO rename config.ini to fuzzer.ini to make its purpose clear
    @property
    def fuzzer_config_path(self) -> str:
        return os.path.join(self.directory, "config.ini")

    @property
    def localization_path(self) -> str:
        return os.path.join(self.analysis_directory, "localization.json")

    @property
    def linter_report_path(self) -> str:
        return os.path.join(self.directory, "linter-summary.json")

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
        subject: str,
        name: str,
        build_directory: str,
        source_directory: str,
        binary_path: str,
        clean_command: str,
        prebuild_command: str,
        build_command: str,
        crashing_command: str,
        crashing_input: t.Optional[str],
        expected_exit_code_for_crashing_input: int,
        skip_fuzzing: bool,
        additional_klee_flags: str,
        fuzz_seed: int = 0,
    ) -> Scenario:
        directory = os.path.dirname(filename)
        directory = os.path.abspath(directory)

        if not os.path.isabs(build_directory):
            build_directory = os.path.join(directory, build_directory)

        if not os.path.isabs(source_directory):
            source_directory = os.path.join(directory, source_directory)

        if not os.path.isabs(binary_path):
            binary_path = os.path.join(directory, binary_path)

        shell = Shell(cwd=directory)

        full_crash_command = f"{binary_path} {crashing_command}"
        if crashing_input:
            full_crash_command = full_crash_command.replace("$POC", crashing_input)

        crash_test = Test(
            name="crash",
            command=full_crash_command,
            expected_exit_code=expected_exit_code_for_crashing_input,
            cwd=directory,
            shell=shell,
        )

        scenario = Scenario(
            subject=subject,
            name=name,
            directory=directory,
            build_directory=build_directory,
            source_directory=source_directory,
            binary_path=binary_path,
            clean_command=clean_command,
            prebuild_command=prebuild_command,
            build_command=build_command,
            crashing_command=crashing_command,
            crashing_input=crashing_input,
            shell=shell,
            crash_test=crash_test,
            skip_fuzzing=skip_fuzzing,
            additional_klee_flags=additional_klee_flags,
            fuzz_seed=fuzz_seed,
        )
        logger.info(f"loaded bug scenario: {scenario}")
        return scenario

    @classmethod
    def for_file(
        cls,
        filename: str,
        *,
        skip_fuzzing: bool = False,
        fuzz_seed: int = 0,
    ) -> Scenario:
        if not os.path.exists(filename):
            raise ValueError(f"bug file not found: {filename}")

        with open(filename, "r") as fh:
            bug_dict = json.load(fh)

        try:
            project_dict = bug_dict["project"]
            subject = project_dict["name"]
            name = bug_dict["name"]
            binary_path = bug_dict["binary"]
            source_directory = bug_dict["source-directory"]
            build_dict = bug_dict["build"]
            build_directory = build_dict["directory"]
            build_commands = build_dict["commands"]
            clean_command = build_commands["clean"]
            prebuild_command = build_commands["prebuild"]
            build_command = build_commands["build"]

            crash_dict = bug_dict["crash"]
            crashing_command = crash_dict["command"]
            crashing_input = crash_dict.get("input")
            additional_klee_flags = crash_dict.get("extra-klee-flags", "")
            expected_exit_code_for_crashing_input = crash_dict.get("expected-exit-code", 0)
        except KeyError as exc:
            raise ValueError(f"missing field in bug.json: {exc}")

        return Scenario.build(
            filename=filename,
            subject=subject,
            name=name,
            binary_path=binary_path,
            build_directory=build_directory,
            source_directory=source_directory,
            clean_command=clean_command,
            prebuild_command=prebuild_command,
            build_command=build_command,
            crashing_command=crashing_command,
            crashing_input=crashing_input,
            skip_fuzzing=skip_fuzzing,
            additional_klee_flags=additional_klee_flags,
            expected_exit_code_for_crashing_input=expected_exit_code_for_crashing_input,
            fuzz_seed=fuzz_seed,
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

        self.shell(self.clean_command, cwd=self.build_directory)
        self.shell(self.prebuild_command, env=env, cwd=self.build_directory)
        self.shell(f"bear {self.build_command}", env=env, cwd=self.build_directory)

    def analyze(self) -> None:
        """Analyzes the underlying cause of the bug and generates repair hints."""
        if self.analysis_results_exist():
            logger.info(f"skipping analysis: results already exist [{self.analysis_directory}]")
            return

        self.shell(self.clean_command, cwd=self.build_directory)

        analyzer = Analyzer.for_scenario(self)
        analyzer.run(write_to=self.analysis_directory)

    def fuzz(self) -> None:
        """Generates additional test cases via concentrated fuzzing."""
        if self.skip_fuzzing:
            logger.info("skipping fuzzing: disabled by request")
            return

        # NOTE for now, use the provided config file
        assert os.path.exists(self.fuzzer_config_path)

        # TODO generate config file based on bug.json contents

        if self.fuzzer_outputs_exist():
            logger.info(f"skipping fuzzing: outputs already exist [{self.fuzzer_directory}]")
        else:
            # TODO build the program for fuzzing
            # NOTE for now, we can use build-for-fuzzer, but going forward, we can
            # generate the appropriate build call here (and save the need to write another script for each scenario!)
            self.rebuild()
            command = " ".join((
                FUZZER_PATH,
                "--config_file",
                self.fuzzer_config_path,
                "--tag",
                self.name,
            ))
            self.shell(command, cwd=self.directory)

        # construct reproducible test cases from concentrated inputs
        # FIXME all of these tests should pass on the original program (optionally verify this assumption)
        fuzzer_config = FuzzerConfig.load(self.fuzzer_config_path)
        fuzzer_tests_directory = os.path.join(self.fuzzer_directory, "concentrated_inputs")
        self.fuzzer_tests = []
        for fuzzer_test_filename in os.listdir(fuzzer_tests_directory):
            fuzzer_test_command = fuzzer_config.command_for_input(fuzzer_test_filename)
            fuzzer_test_name = f"fuzzer-{os.path.basename(fuzzer_test_filename)}"
            fuzzer_test = Test(
                name=fuzzer_test_name,
                command=fuzzer_test_command,
                cwd=self.directory,
                shell=self.shell,
                # FIXME the expected exit code should be the same as the original program!
                expected_exit_code=0,
            )
            self.fuzzer_tests.append(fuzzer_test)

    def _determine_implicated_files(self) -> t.Set[str]:
        """Determines the set of source files that are implicated by the fix localization."""
        implicated_files: t.Set[str] = set()
        with open(self.localization_path, "r") as fh:
            localization: t.List[t.Dict[str, t.Any]] = json.load(fh)
            for entry in localization:
                if entry.get("ignore", False):
                    continue
                filename = entry["location"].split(":")[0]
                implicated_files.add(filename)
        return implicated_files

    def generate(self) -> None:
        """Generates candidate patches using the analysis results."""
        assert self.analysis_results_exist()

        # generate a compile_commands.json file
        self.rebuild()
        assert os.path.exists(self.compile_commands_path)

        # extract a list of implicated source files
        implicated_files = self._determine_implicated_files()
        logger.info(f"generating candidate repairs in implicated files: {implicated_files}")

        command = " ".join((
            CRASHREPAIRFIX_PATH,
            "--output-to",
            self.patch_candidates_path,
            # FIXME replace with --analysis-directory
            "--localization-filename",
            self.localization_path,
            "-p",
            self.compile_commands_path,
            " ".join(implicated_files),
            "-extra-arg=-I/opt/llvm11/lib/clang/11.1.0/include/",
        ))
        self.shell(command, cwd=self.source_directory)
        assert os.path.exists(self.patch_candidates_path)

    def validate(self) -> None:
        """Validates candidate patches."""
        assert self.candidate_repairs_exist()

        candidates = PatchCandidate.load_all(self.patch_candidates_path)

        # TODO apply ranking of candidate patches prior to evaluation

        # TODO add resource limits

        # TODO evaluate candidates in parallel via worker queue
        # note that doing so will require us to create copies of the scenario directory
        for candidate in candidates:
            if self.evaluate(candidate):
                logger.info(f"saving successful patch #{candidate.id_}...")
                patch_filename = f"{candidate.id_}.diff"
                patch_filename = os.path.join(self.patches_directory, patch_filename)
                candidate.write(patch_filename)

                if self.should_terminate_early:
                    logger.info("stopping search: patch was found")
                    return

    def evaluate(self, candidate: PatchCandidate) -> bool:
        """Evaluates a candidate repair and returns :code:`True` if it passes all tests."""
        logger.info(f"evaluating candidate patch #{candidate.id_}:\n{candidate.diff}")
        try:
            candidate.apply()
            # TODO enable the appropriate sanitizers
            try:
                self.rebuild()
            except subprocess.CalledProcessError:
                logger.info(f"candidate patch #{candidate.id_} failed to compile")
                return False

            # run both the proof of exploit and the fuzzer-generated tests
            all_tests: t.Sequence[Test] = [self.crash_test] + self.fuzzer_tests
            for test in all_tests:
                logger.debug(f"testing candidate #{candidate.id_} against test #{test.name}...")
                if test.run():
                    logger.info(f"candidate #{candidate.id_} passes test #{test.name}")
                else:
                    logger.info(f"candidate #{candidate.id_} fails test #{test.name}")
                    return False

            logger.info(f"repair found! candidate #{candidate.id_} passes all tests")

        finally:
            candidate.revert()

        return True

    def repair(self) -> None:
        """Performs end-to-end repair of this bug scenario."""
        # NOTE these two steps could be performed in parallel
        self.fuzz()
        self.analyze()
        self.generate()
        self.validate()

    def lint(self) -> bool:
        """Lints the fix localization for this bug scenario.

        Returns
        -------
        bool
            :code:`True` if OK; :code:`False` if bad.
        """
        self.analyze()

        implicated_files = self._determine_implicated_files()
        command = " ".join((
            CRASHREPAIRLINT_PATH,
            "--output-to",
            self.linter_report_path,
            "--localization-filename",
            self.localization_path,
            "-p",
            self.compile_commands_path,
            " ".join(implicated_files),
            "-extra-arg=-I/opt/llvm11/lib/clang/11.1.0/include/",
        ))
        outcome = self.shell(command, cwd=self.source_directory, check_returncode=False)
        assert os.path.exists(self.linter_report_path)
        return outcome.returncode == 0
