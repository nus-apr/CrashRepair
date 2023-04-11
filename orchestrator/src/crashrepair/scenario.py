# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import typing as t

import attrs

from loguru import logger

from .analyzer import Analyzer
from .candidate import PatchCandidate, PatchEvaluation
from .exceptions import CrashRepairException
from .fuzzer import Fuzzer, FuzzerConfig
from .report import (
    AnalysisReport,
    FuzzerReport,
    GenerationReport,
    Report,
    ValidationReport,
)
from .shell import Shell
from .stopwatch import Stopwatch
from .test import Test, TestOutcome

# TODO allow these to be customized via environment variables
CRASHREPAIRFIX_PATH = "/opt/crashrepair/bin/crashrepairfix"
CRASHREPAIRLINT_PATH = "/opt/crashrepair/bin/crashrepairlint"
CREPAIR_LIB_PATH = "/CrashRepair/lib"
CREPAIR_RUNTIME_HEADER_PATH = "/CrashRepair/lib/crepair_runtime.h"
KLEE_LIB_PATH = "/klee/build/lib"


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
    fuzzer: t.Optional[Fuzzer]
        The fuzzer, if any, that should be used to generate additional test cases.
    time_limit_seconds_single_test: int
        The maximum number of seconds that the test is allowed to run before being considered a timeout.
    time_limit_minutes_analysis: int
        The maximum number of minutes that the analysis can run before being considered a timeout.
    sanitizer_flags: str
        Additional CFLAGS/CXXFLAGS that should be used to enable the relevant sanitizers.
    halt_on_error: bool
        If :code:`True`, instructs the sanitizer to halt the program upon failure.
        Otherwise, the program will continue to run where possible.
    rebuild_for_validation: bool
        Forces the orchestrator to rebuild the project from scratch before beginning validation.
    asan_options: t.Optional[str]
        Optional, custom ASAN options that should be used when validating patches.
    ubsan_options: t.Optional[str]
        Optional, custom UBSAN options that should be used when validating patches.
    use_ghost_functions: bool
        Inject the necessary compilation options to allow support for ghost functions during validation.
        Should only be used when ASAN is enabled and must not be used during analysis.
    acceptable_patch_limit: t.Optional[int]
        The maximum number of acceptable patches that should be found before the repair process is halted.
    """
    subject: str
    name: str
    directory: str
    build_directory: str
    source_directory: str
    tag_id: str
    binary_path: str
    clean_command: str
    prebuild_command: str
    build_command: str
    crashing_command: str
    crashing_input: t.Optional[str]
    shell: Shell
    crash_test: Test
    sanitizer_flags: str = attrs.field(default="")
    additional_klee_flags: str = attrs.field(default="")
    expected_exit_code_for_crashing_input: int = attrs.field(default=0)
    should_terminate_early: bool = attrs.field(default=True)
    fuzzer_tests: t.List[Test] = attrs.field(factory=list)
    fuzzer: t.Optional[Fuzzer] = attrs.field(default=None)
    time_limit_minutes_validation: t.Optional[int] = attrs.field(default=None)
    time_limit_seconds_single_test: int = attrs.field(default=30)
    time_limit_minutes_analysis: int = attrs.field(default=3600)
    halt_on_error: bool = attrs.field(default=True)
    rebuild_for_validation: bool = attrs.field(default=False)
    asan_options: t.Optional[str] = attrs.field(default=None)
    ubsan_options: t.Optional[str] = attrs.field(default=None)
    use_ghost_functions: bool = attrs.field(default=False)
    acceptable_patch_limit: t.Optional[int] = attrs.field(default=None)

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

    def candidate_repairs_exist(self) -> bool:
        """Determines whether a set of candidate repairs exists."""
        return os.path.exists(self.patch_candidates_path)

    @classmethod
    def build(
        cls,
        filename: str,
        subject: str,
        name: str,
        tag_id: str,
        build_directory: str,
        source_directory: str,
        binary_path: str,
        clean_command: str,
        prebuild_command: str,
        build_command: str,
        crashing_command: str,
        crashing_input: t.Optional[str],
        expected_exit_code_for_crashing_input: int,
        additional_klee_flags: str,
        sanitizer_flags: str,
        fuzzer_config: t.Optional[FuzzerConfig] = None,
        bad_output: t.Optional[str] = None,
        rebuild_for_validation: bool = False,
        halt_on_error: bool = True,
        ubsan_options: t.Optional[str] = None,
        asan_options: t.Optional[str] = None,
        use_ghost_functions: bool = False,
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
            bad_output=bad_output,
            asan_options=asan_options,
            ubsan_options=ubsan_options,
        )

        scenario = Scenario(
            subject=subject,
            name=name,
            tag_id=tag_id,
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
            additional_klee_flags=additional_klee_flags,
            sanitizer_flags=sanitizer_flags,
            rebuild_for_validation=rebuild_for_validation,
            halt_on_error=halt_on_error,
            ubsan_options=ubsan_options,
            asan_options=asan_options,
            use_ghost_functions=use_ghost_functions,
        )

        if fuzzer_config:
            scenario.fuzzer = fuzzer_config.build(scenario)

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

        fuzzer_config: t.Optional[FuzzerConfig] = None

        try:
            project_dict = bug_dict["project"]
            subject = project_dict["name"]
            name = bug_dict["name"]
            tag_id = f"{subject}_{name}"
            binary_path = bug_dict["binary"]
            source_directory = bug_dict["source-directory"]
            build_dict = bug_dict["build"]
            build_directory = build_dict["directory"]
            build_commands = build_dict["commands"]
            clean_command = build_commands["clean"]
            prebuild_command = build_commands["prebuild"]
            build_command = build_commands["build"]
            sanitizer_flags = build_dict.get("sanitizerflags", "")
            rebuild_for_validation = build_dict.get("rebuild-for-validation", False)
            use_ghost_functions = build_dict.get("use-ghost-functions", False)

            crash_dict = bug_dict["crash"]
            crashing_command = crash_dict["command"]
            halt_on_error = crash_dict.get("halt-on-error", True)
            crashing_input = crash_dict.get("input")
            bad_output = crash_dict.get("bad_output")
            asan_options = crash_dict.get("asan-options")
            ubsan_options = crash_dict.get("ubsan-options")
            additional_klee_flags = crash_dict.get("extra-klee-flags", "")
            expected_exit_code_for_crashing_input = crash_dict.get("expected-exit-code", 0)
        except KeyError as exc:
            raise ValueError(f"missing field in bug.json: {exc}")

        if "fuzzer" in bug_dict and not skip_fuzzing:
            fuzzer_config = FuzzerConfig.from_dict(bug_dict["fuzzer"])

        return Scenario.build(
            filename=filename,
            subject=subject,
            name=name,
            tag_id=tag_id,
            binary_path=binary_path,
            build_directory=build_directory,
            source_directory=source_directory,
            clean_command=clean_command,
            prebuild_command=prebuild_command,
            build_command=build_command,
            crashing_command=crashing_command,
            crashing_input=crashing_input,
            additional_klee_flags=additional_klee_flags,
            expected_exit_code_for_crashing_input=expected_exit_code_for_crashing_input,
            sanitizer_flags=sanitizer_flags,
            rebuild_for_validation=rebuild_for_validation,
            fuzzer_config=fuzzer_config,
            bad_output=bad_output,
            halt_on_error=halt_on_error,
            ubsan_options=ubsan_options,
            asan_options=asan_options,
            use_ghost_functions=use_ghost_functions,
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
        clean: bool = True,
        prebuild: bool = False,
        record_compile_commands: bool = True,
        use_sanitizers: bool = True,
    ) -> None:
        """Performs a clean rebuild of the program under test."""
        if not env:
            env = {}

        logger.debug(f"original environment: {os.environ}")

        generic_cflags = "-g -O0 -Wno-error"
        klee_cflags = f"-L{KLEE_LIB_PATH} -lkleeRuntest"
        crepair_cflags = (
            f"-I{CREPAIR_LIB_PATH} "
            f"-L{CREPAIR_LIB_PATH} "
            "-lcrepair_runtime -lcrepair_proxy"
        )
        cflags = f"{generic_cflags} {klee_cflags} {crepair_cflags}"

        if self.use_ghost_functions:
            ghost_flags = "-lcrepair_ghost"
            logger.debug(f"injecting ghost function into CFLAGS during build: {ghost_flags}")
            cflags = f"{cflags} {ghost_flags}"

        if use_sanitizers:
            cflags = f"{cflags} {self.sanitizer_flags}"

        # if CC/CXX aren't specified, use LLVM/Clang 11
        default_env = {
            "INJECT_CFLAGS": cflags,
            "INJECT_CXXFLAGS": cflags,
            "INJECT_LDFLAGS": cflags,
        }
        if "LD_LIBRARY_PATH_ORIG" in os.environ:
            default_env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH_ORIG"]
        env = {**default_env, **env}

        logger.debug(f"using environment: {env}")

        if clean:
            self.shell(self.clean_command, cwd=self.build_directory, check_returncode=False)

        if prebuild:
            self.shell(self.prebuild_command, env=env, cwd=self.build_directory)

        build_command = self.build_command
        if record_compile_commands:
            build_command = f"bear {build_command}"
        self.shell(build_command, env=env, cwd=self.build_directory)

    def analyze(self) -> None:
        """Analyzes the underlying cause of the bug and generates repair hints."""
        if self.analysis_results_exist():
            logger.info(f"skipping analysis: results already exist [{self.analysis_directory}]")
            return

        analyzer = Analyzer.for_scenario(
            self,
            timeout_minutes=self.time_limit_minutes_analysis,
        )
        analyzer.run(write_to=self.analysis_directory)

    def fuzz(self) -> None:
        """Generates additional test cases via concentrated fuzzing."""
        if not self.fuzzer:
            logger.info("skipping fuzzing: fuzzer disabled")
            return

        # FIXME all of these tests should pass on the original program (optionally verify this assumption)
        self.fuzzer_tests = list(self.fuzzer.fuzz())

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
        # self.rebuild()
        # assumes that bear has produced a compilation database previously
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
        self.shell(command, cwd=self.source_directory, check_returncode=False)
        assert os.path.exists(self.patch_candidates_path)

    def validate(self) -> ValidationReport:
        """Validates candidate patches."""
        assert self.candidate_repairs_exist()

        logger.info(
            "beginning candidate patch evaluation with time limit: "
            f"{self.time_limit_minutes_validation} minutes",
        )

        time_limit_seconds: t.Optional[int] = None
        if self.time_limit_minutes_validation:
            time_limit_seconds = self.time_limit_minutes_validation * 60

        timer = Stopwatch()
        timer.start()
        candidates = PatchCandidate.load_all(self.patch_candidates_path)
        candidates = PatchCandidate.rank(candidates, self.localization_path)
        evaluations: t.List[PatchEvaluation] = []
        num_repairs_found = 0

        # rebuild the whole project once before using incremental builds for each patch
        # don't bother rebuilding if we don't use additional sanitizer flags
        should_rebuild = self.sanitizer_flags or self.rebuild_for_validation
        should_rebuild = should_rebuild or not os.path.exists(self.compile_commands_path)
        if should_rebuild:
            self.rebuild(record_compile_commands=False)

        for candidate in candidates:
            if time_limit_seconds and timer.duration >= time_limit_seconds:
                logger.info("reached candidate patch evaluation time limit")
                break

            if self.acceptable_patch_limit and num_repairs_found >= self.acceptable_patch_limit:
                logger.info(f"reached acceptable patch limit ({self.acceptable_patch_limit})")
                break

            outcome = self.evaluate(candidate)
            evaluations.append(outcome)
            if outcome:
                logger.info(f"saving successful patch #{candidate.id_}...")
                num_repairs_found += 1
                patch_filename = f"{candidate.id_}.diff"
                patch_filename = os.path.join(self.patches_directory, patch_filename)
                candidate.write(patch_filename)

                if self.should_terminate_early:
                    logger.info("stopping search: patch was found")
                    break

        return ValidationReport(
            duration_seconds=timer.duration,
            evaluations=evaluations,
        )

    def evaluate(self, candidate: PatchCandidate) -> PatchEvaluation:
        """Evaluates a candidate repair and returns :code:`True` if it passes all tests."""
        logger.info(f"evaluating candidate patch #{candidate.id_}:\n{candidate.diff}")
        try:
            timer_compile = Stopwatch()
            timer_compile.start()
            candidate.apply()

            try:
                self.rebuild(prebuild=False, clean=False, record_compile_commands=False)
            except subprocess.CalledProcessError:
                logger.info(f"candidate patch #{candidate.id_} failed to compile")
                return PatchEvaluation.failed_to_compile(candidate, timer_compile.duration)
            timer_compile.stop()

            # run both the proof of exploit and the fuzzer-generated tests
            timer_tests = Stopwatch()
            timer_tests.start()
            all_tests: t.Sequence[Test] = [self.crash_test] + self.fuzzer_tests
            tests_passed: t.List[Test] = []
            tests_failed: t.List[Test] = []
            test_outcomes: t.List[TestOutcome] = []
            for test in all_tests:
                logger.debug(f"testing candidate #{candidate.id_} against test #{test.name}...")
                outcome = test.run(self.time_limit_seconds_single_test, halt_on_error=self.halt_on_error)
                test_outcomes.append(outcome)
                if outcome:
                    logger.info(f"candidate #{candidate.id_} passes test #{test.name}")
                    tests_passed.append(test)
                else:
                    logger.info(f"candidate #{candidate.id_} fails test #{test.name}")
                    tests_failed.append(test)
                    return PatchEvaluation.failed_tests(
                        candidate=candidate,
                        compile_time_seconds=timer_compile.duration,
                        test_time_seconds=timer_tests.duration,
                        test_outcomes=test_outcomes,
                        tests_passed=tests_passed,
                        tests_failed=tests_failed,
                    )

            timer_tests.stop()
            logger.info(f"repair found! candidate #{candidate.id_} passes all tests")

        finally:
            candidate.revert()

        return PatchEvaluation.repair_found(
            candidate=candidate,
            compile_time_seconds=timer_compile.duration,
            test_time_seconds=timer_tests.duration,
            test_outcomes=test_outcomes,
            tests_passed=tests_passed,
        )

    def repair(self) -> None:
        """Performs end-to-end repair of this bug scenario."""
        report = Report()
        report_filename = os.path.join(self.directory, "report.json")
        timer_overall = Stopwatch()
        timer_overall.start()
        try:
            with Stopwatch() as timer_fuzz:  # noqa: F841
                self.fuzz()
                report.fuzzer = FuzzerReport(
                    duration_seconds=timer_fuzz.duration,
                )

            with Stopwatch() as timer_analyze:
                self.analyze()
                self.lint(fix=True)
                report.analysis = AnalysisReport.build(
                    duration_seconds=timer_analyze.duration,
                    analysis_directory=self.analysis_directory,
                    localization_filename=self.localization_path,
                    linter_filename=self.linter_report_path,
                )

            with Stopwatch() as timer_generate:
                self.generate()
                report.generation = GenerationReport.build(
                    duration_seconds=timer_generate.duration,
                    candidates_filename=self.patch_candidates_path,
                )

            report.validation = self.validate()

        except CrashRepairException as error:
            report.error = error
            print(f"FATAL ERROR: {error}")
        finally:
            report.duration_seconds = timer_overall.duration
            report.save(report_filename)

    def lint(self, fix: bool) -> bool:
        """Lints the fix localization for this bug scenario.

        Arguments
        ---------
        fix: bool
            Attempts to automatically fix any issues with the fix localization if :code:`True`

        Returns
        -------
        bool
            :code:`True` if OK; :code:`False` if bad.
        """
        self.analyze()

        # ensure that compile_commands.json exists
        if not os.path.exists(self.compile_commands_path):
            self.rebuild(record_compile_commands=True)

        fix_flag = "--fix" if fix else ""
        implicated_files = self._determine_implicated_files()
        command = " ".join((
            CRASHREPAIRLINT_PATH,
            fix_flag,
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
