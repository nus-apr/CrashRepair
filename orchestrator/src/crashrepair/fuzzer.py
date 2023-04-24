# -*- coding: utf-8 -*-
from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import typing as t

import attrs
from loguru import logger

from .test import Test

if t.TYPE_CHECKING:
    from .scenario import Scenario

FUZZER_PATH = "/opt/fuzzer/code/fuzz"

_FUZZER_CONFIG_TEMPLATE = """
[{scenario_name}]
bin_path={binary_path}
folder={directory}
global_timeout={global_timeout}
local_timeout={local_timeout}
mutate_range={mutate_range}
crash_tag={crash_tag}
store_all_inputs={store_all_inputs}
rand_seed={fuzz_seed}
combination_num={max_combinations}
trace_cmd={trace_cmd}
crash_cmd={crash_cmd}
poc={poc}
poc_fmt={poc_fmt}
process_max_number={num_workers}
"""


@attrs.define(auto_attribs=True, slots=True)
class FuzzerConfig:
    crash_command_template: t.Sequence[str]
    crash_tag: str
    poc_format: t.Sequence[str]
    poc_values: t.Sequence[t.Union[str, int, float]]
    trace_command_template: t.Sequence[str]
    store_all_inputs: bool
    max_combinations: int = attrs.field(default=1)
    mutate_range: str = attrs.field(default="default")
    seed: int = attrs.field(default=0)
    timeout_global: int = attrs.field(default=300)
    timeout_local: int = attrs.field(default=300)
    num_workers: int = attrs.field(default=8)

    @classmethod
    def from_dict(cls, dict_: t.Dict[str, t.Any]) -> FuzzerConfig:
        config = FuzzerConfig(
            crash_tag=dict_["crash-tag"],
            crash_command_template=dict_["proof-of-crash"]["commands"]["crash"],
            trace_command_template=dict_["proof-of-crash"]["commands"]["trace"],
            poc_format=dict_["proof-of-crash"]["format"],
            poc_values=dict_["proof-of-crash"]["values"],
            store_all_inputs=dict_.get("store-all-inputs", False),
        )
        if "max-combinations" in dict_:
            config.max_combinations = dict_["max-combinations"]
        if "seed" in dict_:
            config.seed = dict_["seed"]
        timeout_dict = dict_.get("timeout", {})
        if "local" in timeout_dict:
            config.timeout_local = timeout_dict["local"]
        if "global" in timeout_dict:
            config.timeout_global = timeout_dict["global"]
        if "mutate-range" in dict_:
            config.mutate_range = dict_["mutate-range"]
        if "num-workers" in dict_:
            config.num_workers = dict_["num-workers"]
        return config

    def build(self, scenario: Scenario) -> Fuzzer:
        return Fuzzer(self, scenario)


@attrs.define(auto_attribs=True, slots=True)
class Fuzzer:
    config: FuzzerConfig
    scenario: Scenario

    @property
    def tests_directory(self) -> str:
        """Returns the absolute path of the generated tests directory."""
        return os.path.join(self.scenario.directory, "concentrated_inputs")

    def _generate_config_file_contents(self) -> str:
        config = self.config
        poc = ";".join(str(v) for v in config.poc_values)
        poc_fmt = ";".join(config.poc_format)
        trace_command = ";".join(config.trace_command_template)
        crash_command = ";".join(config.crash_command_template)
        store_all_inputs = "True" if config.store_all_inputs else "False"
        return _FUZZER_CONFIG_TEMPLATE.format(
            store_all_inputs=store_all_inputs,
            binary_path=self.scenario.binary_path,
            crash_cmd=crash_command,
            crash_tag=config.crash_tag,
            directory=self.scenario.directory,
            fuzz_seed=config.seed,
            global_timeout=config.timeout_global,
            local_timeout=config.timeout_local,
            max_combinations=config.max_combinations,
            mutate_range=config.mutate_range,
            num_workers=config.num_workers,
            poc=poc,
            poc_fmt=poc_fmt,
            scenario_name=self.scenario.tag_id,
            trace_cmd=trace_command,
        )

    @contextlib.contextmanager
    def _generate_config_file(self) -> t.Iterator[str]:
        _, filename = tempfile.mkstemp(suffix="crashrepair.fuzzer.", prefix=".cfg", text=True)
        contents = self._generate_config_file_contents()
        logger.debug(f"fuzzer configuration:\n{contents}")
        try:
            with open(filename, "w") as fh:
                fh.write(contents)
            yield filename
        finally:
            os.remove(filename)

    def _input_to_test_command(self, filename: str) -> str:
        # TODO this doesn't support commands with positional arguments
        template = self.config.trace_command_template
        return " ".join(part.replace("***", filename) for part in template)

    def _load_raw_input(self, filename: str) -> Test:
        """Creates a test case with no oracle from a given input file."""
        command = self._input_to_test_command(filename)
        name = f"fuzzer-{os.path.basename(filename)}"
        return Test(
            name=name,
            command=command,
            cwd=self.scenario.directory,
            shell=self.scenario.shell,
            asan_options=self.scenario.asan_options,
            ubsan_options=self.scenario.ubsan_options,
        )

    def _input_to_test_case(self, filename: str) -> t.Optional[Test]:
        """Attempts to create a usable test case from a given input file."""
        proof_of_crash = self.scenario.crash_test
        bad_output = proof_of_crash.bad_output
        assert bad_output is not None

        test = self._load_raw_input(filename)
        halt_on_error = self.scenario.halt_on_error
        time_limit = self.scenario.time_limit_seconds_single_test

        logger.debug(f"processing fuzzer generated test: {test.name}")
        raw_outcome = test.raw_execute(
            timeout_seconds=time_limit,
            halt_on_error=halt_on_error,
        )

        # does the generated input behave like the original crash?
        if raw_outcome.contains_bad_output(bad_output):
            logger.debug(f"created additional crashing test: {test.name}")
            test.bad_output = bad_output
            test.expected_exit_code = proof_of_crash.expected_exit_code
            return test

        # does the sanitizer report an error other than the one that we expect?
        # if so, we discard this test since we can't reliably use it as an oracle
        # for the original crash
        if raw_outcome.contains_sanitizer_error():
            logger.debug(f"discarded fuzzer generated test [contains a different error]: {test.name}")
            return None

        # otherwise, we attempt to treat the generated input as a passing test
        # and ensure that the patched program retains its original behavior
        logger.debug(f"creating additional passing test: {test.name}")
        test.expected_exit_code = raw_outcome.return_code

        # ensure that the stdout is deterministic
        num_repeats = 1
        expected_stdout = raw_outcome.stdout
        for _ in range(num_repeats):
            repeat_test_outcome = test.raw_execute(
                timeout_seconds=time_limit,
                halt_on_error=halt_on_error,
            )
            if repeat_test_outcome.stdout != expected_stdout:
                logger.debug(
                    f"fuzzer generated test has nondeterministic output -- ignoring stdout [test: {test.name}]",
                )
                expected_stdout = None
                break

        if expected_stdout:
            logger.debug(f"fuzzer generated test has deterministic stdout [test: {test.name}]")
            test.expected_stdout = expected_stdout

        logger.debug(f"created additional passing test: {test.name}")
        return test

    def _load_tests(self) -> t.Sequence[Test]:
        """Loads all of the usable tests that were generated by the fuzzer."""
        tests: t.List[Test] = []
        for filename in os.listdir(self.tests_directory):
            maybe_test = self._input_to_test_case(filename)
            if maybe_test:
                tests.append(maybe_test)
        return tests

    def fuzz(self, *, force: bool = False) -> t.Sequence[Test]:
        # don't bother running the fuzzer if we don't have a means of checking
        # the output for a particular crash
        if not self.scenario.crash_test.bad_output:
            logger.info("skipping fuzzing: crashing test has no bad_output defined")
            return []

        # the fuzzer requires that the output directory exists
        os.makedirs(self.tests_directory, exist_ok=True)

        env: t.Dict[str, str] = {}
        if "LD_LIBRARY_PATH_ORIG" in os.environ:
            env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH_ORIG"]

        # only bother rebuilding if we have additional sanitizer flags
        # if self.scenario.sanitizer_flags:
        self.scenario.rebuild(use_sanitizers=True)

        # are there any generated tests?
        if os.listdir(self.tests_directory):
            logger.info(f"skipping fuzzing: outputs already exist [{self.tests_directory}]")
            return self._load_tests()

        # invoke the fuzzer
        with self._generate_config_file() as config_filename:
            command = " ".join((
                FUZZER_PATH,
                "--config_file",
                config_filename,
                "--tag",
                self.scenario.tag_id,
            ))
            self.scenario.shell(command, cwd=self.scenario.directory, env=env)

        # if we store all inputs, copy across those inputs into the test directory
        fuzzer_directory = os.path.join(self.scenario.directory, "fuzzer")
        all_inputs_directory = os.path.join(fuzzer_directory, "all_inputs")
        concentrated_inputs_directory = os.path.join(fuzzer_directory, "concentrated_inputs")

        if self.config.store_all_inputs:
            shutil.copytree(all_inputs_directory, self.tests_directory, dirs_exist_ok=True)
        else:
            shutil.copytree(concentrated_inputs_directory, self.tests_directory, dirs_exist_ok=True)

        # how many tests did we generate?
        num_generated_tests = len(os.listdir(self.tests_directory))
        logger.info(f"fuzzer generated: {num_generated_tests} tests")

        return self._load_tests()
