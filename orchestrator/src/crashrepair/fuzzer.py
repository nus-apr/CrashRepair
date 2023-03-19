# -*- coding: utf-8 -*-
from __future__ import annotations

import contextlib
import os
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
store_all_inputs=False
rand_seed={fuzz_seed}
combination_num={max_combinations}
trace_cmd={trace_cmd}
crash_cmd={crash_cmd}
poc={poc}
poc_fmt={poc_fmt}
"""


@attrs.define(auto_attribs=True, slots=True)
class FuzzerConfig:
    crash_command_template: t.Sequence[str]
    crash_tag: str
    poc_format: t.Sequence[str]
    poc_values: t.Sequence[t.Union[str, int, float]]
    trace_command_template: t.Sequence[str]
    max_combinations: int = attrs.field(default=3)
    mutate_range: str = attrs.field(default="default")
    seed: int = attrs.field(default=0)
    timeout_global: int = attrs.field(default=300)
    timeout_local: int = attrs.field(default=300)

    @classmethod
    def from_dict(cls, dict_: t.Dict[str, t.Any]) -> FuzzerConfig:
        config = FuzzerConfig(
            crash_tag=dict_["crash-tag"],
            crash_command_template=dict_["proof-of-crash"]["commands"]["crash"],
            trace_command_template=dict_["proof-of-crash"]["commands"]["trace"],
            poc_format=dict_["proof-of-crash"]["format"],
            poc_values=dict_["proof-of-crash"]["values"],
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
        return _FUZZER_CONFIG_TEMPLATE.format(
            binary_path=self.scenario.binary_path,
            crash_cmd=crash_command,
            crash_tag=config.crash_tag,
            directory=self.scenario.directory,
            fuzz_seed=config.seed,
            global_timeout=config.timeout_global,
            local_timeout=config.timeout_local,
            max_combinations=config.max_combinations,
            mutate_range=config.mutate_range,
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

    def _load_test_from_file(self, filename: str) -> Test:
        command = " ".join(part.replace("***", filename) for part in self.config.trace_command_template)
        name = f"fuzzer-{os.path.basename(filename)}"
        return Test(
            name=name,
            command=command,
            cwd=self.scenario.directory,
            shell=self.scenario.shell,
            # FIXME the expected exit code should be the same as the original program!
            expected_exit_code=0,
        )

    def _load_tests(self) -> t.Sequence[Test]:
        return [self._load_test_from_file(filename) for filename in os.listdir(self.tests_directory)]

    def fuzz(self, *, force: bool = False) -> t.Sequence[Test]:
        # the fuzzer requires that the output directory exists
        os.makedirs(self.tests_directory, exist_ok=True)

        # are there any generated tests?
        if os.listdir(self.tests_directory):
            logger.info(f"skipping fuzzing: outputs already exist [{self.tests_directory}]")
            return self._load_tests()

        # TODO build the program for fuzzing
        # NOTE for now, we can use build-for-fuzzer, but going forward, we can
        # generate the appropriate build call here (and save the need to write another script for each scenario!)
        self.scenario.rebuild()

        # invoke the fuzzer
        with self._generate_config_file() as config_filename:
            command = " ".join((
                FUZZER_PATH,
                "--config_file",
                config_filename,
                "--tag",
                self.scenario.tag_id,
            ))
            self.scenario.shell(command, cwd=self.scenario.directory)

        # how many tests did we generate?
        num_generated_tests = len(os.listdir(self.tests_directory))
        logger.info(f"fuzzer generated: {num_generated_tests} tests")

        return self._load_tests()
