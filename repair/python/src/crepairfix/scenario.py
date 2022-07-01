# -*- coding: utf-8 -*-
from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import tempfile
import typing as t

import attr
from loguru import logger

from .localization import FixLocalization
from .mutation import Mutation

# TODO allow these to be set via command-line
PATH_CC = "/opt/llvm11/bin/clang"
PATH_LLC = "/opt/llvm11/bin/llc"
PATH_LLVM_COMPILER = "/opt/llvm11/bin"
PATH_LLVM_LINK = "/opt/llvm11/bin/llvm-link"
PATH_LLVM_DIS = "/opt/llvm11/bin/llvm-dis"
PATH_OPT = "/opt/llvm11/bin/opt"

# TODO this is a nasty temporary workaround
PATH_LLVMTOSOURCE = "/opt/hifix/build/src/llvmtosource/libllvm2source.so"
PATH_LLVMREPAIR = "/opt/hifix/build/src/llvm-repair/libllvmrepair.so"


@attr.s(slots=True)
class BugScenario:
    """Provides access to the program under repair.

    Attributes
    ----------
    directory: str
        The path of the bug scenario directory
    subject: str
        The name of the subject being repaired (e.g., libtiff)
    bug_id: str
        The unique identifier for the bug (e.g., cve_2016_10092)
    binary_path: str
        The path of the binary under repair for this scenario, relative to
        the source directory for this scenario.
    linker_options: str
        Additional options that should be passed to the linker when building
        the instrumented binary.
    should_validate_localization: bool
        Flag used to control whether the produced fix localization should be
        validated to ensure that it satisfies the requirements of repair.
    should_terminate_early: bool
        Flag used to control whether the repair process should stop when the first
        acceptable patch has been found, or, alternatively, if it should continue
        finding all acceptable patches for the given bug.
    should_validate_lifted_patches: bool
        Flag used to control whether patches that are validated via the LLVM
        supermutant should also be validated at the source level.
    _source_filename_to_ast: t.Dict[str, ClangAST]
        A map from source files, given by their path relative to the source directory,
        and the corresponding AST for those source files.
    _fix_localization: FixLocalization
        The cached fix localization for this bug scenario.
    """
    directory = attr.ib(type=str)
    subject = attr.ib(type=str)
    bug_id = attr.ib(type=str)
    binary_path = attr.ib(type=str)
    linker_options = attr.ib(type=str)
    should_compute_dependencies = attr.ib(type=bool, default=True)
    should_compute_repair = attr.ib(type=bool, default=True)
    should_validate_localization = attr.ib(type=bool, default=True)
    should_terminate_early = attr.ib(type=bool, default=False)
    should_validate_lifted_patches = attr.ib(type=bool, default=True)
    _source_filename_to_ast = attr.ib(type=dict, factory=dict)
    _fix_localization = attr.ib(type=FixLocalization, default=None)

    @classmethod
    def for_bug_file(cls, bug_filename: str) -> "BugScenario":
        if not os.path.exists(bug_filename):
            msg = "bug.json not found in directory [{}]".format(directory)
            raise ValueError(msg)

        with open(bug_filename, "r") as f:
            bug_dict = json.load(f)

        try:
            subject = bug_dict["subject"]
            bug_id = bug_dict["name"]
            binary_path = bug_dict["binary"]
            options_dict = bug_dict.get("options", {})
            linker_options = options_dict.get("hifix", {}).get("linker-options", "")
        except KeyError as exc:
            msg = "missing field in bug.json: {}".format(exc)
            raise ValueError(msg)

        # ensure that directory is an absolute path
        directory = os.path.dirname(bug_filename)
        directory = os.path.abspath(directory)

        scenario = BugScenario(
            directory=directory,
            subject=subject,
            bug_id=bug_id,
            binary_path=binary_path,
            linker_options=linker_options,
        )
        logger.info("loaded bug scenario: {}".format(scenario))
        return scenario

    @classmethod
    def for_directory(cls, directory: str) -> "BugScenario":
        if not os.path.isdir(directory):
            msg = "bug directory does not exist [{}]".format(directory)
            raise ValueError(msg)

        bug_filename = os.path.join(directory, "bug.json")
        return cls.for_bug_file(bug_filename)

    @classmethod
    def for_directory_or_bug_file(cls, directory_or_filename: str) -> "BugScenario":
        if os.path.isdir(directory_or_filename):
            return cls.for_directory(directory_or_filename)
        else:
            return cls.for_bug_file(directory_or_filename)

    @property
    def binary_name(self) -> str:
        """The base name of the binary for the program under repair."""
        return os.path.basename(self.binary_path)

    @property
    def ir_source_mapping_path(self) -> str:
        """The absolute path of the IR->source mapping file for the program under repair."""
        return os.path.join(self.directory, "source-mapping.json")

    @property
    def instrumented_binary_path(self) -> str:
        """The absolute path of the instrumented binary for the program under repair."""
        return os.path.join(self.directory, self.binary_name + "-inst")

    @property
    def mutated_binary_path(self) -> str:
        """The absolute path of the mutated binary for the program under repair."""
        return os.path.join(self.directory, self.binary_name + "-mutated")

    @property
    def bitcode_path(self) -> str:
        """The absolute path of the uninstrumented bitcode for the program under repair."""
        return os.path.join(self.directory, self.binary_name + ".bc")

    @property
    def localization_path(self) -> str:
        """The absolute path of the annotated fix localization for the program under repair."""
        return os.path.join(self.directory, "localization.json")

    @property
    def mutation_index_path(self) -> str:
        """The absolute path of the mutation index for the super-mutated binary."""
        return os.path.join(self.directory, "mutations.json")

    @property
    def mutated_bitcode_path(self) -> str:
        """The absolute path of the mutated bitcode for the program under repair."""
        return os.path.join(self.directory, self.binary_name + ".mutated.bc")

    @property
    def mutated_object_path(self) -> str:
        """The absolute path of the mutated object for the program under repair."""
        return os.path.join(self.directory, self.binary_name + ".mutated.o")

    @property
    def instrumented_bitcode_path(self) -> str:
        """The absolute path of the instrumented bitcode for the program under repair."""
        return os.path.join(self.directory, self.binary_name + "-inst.bc")

    @property
    def trace_path(self) -> str:
        """The absolute path of the trace path for the program under repair."""
        return os.path.join(self.directory, self.binary_name + ".bbt")

    @property
    def test_path(self) -> str:
        """The absolute path of the single test for the program under repair."""
        return os.path.join(self.directory, "test")

    @property
    def ast_dumps_path(self) -> str:
        """The absolute path of the AST dumps directory for the program under repair."""
        return os.path.join(self.directory, "asts")

    @property
    def patches_path(self) -> str:
        """The absolute path of the source-level patches directory for the program under repair."""
        return os.path.join(self.directory, "patches")

    @property
    def failed_patches_path(self) -> str:
        """The absolute path of the directory containing patches that failed when lifted to source."""
        return os.path.join(self.directory, ".failed-patches")

    @property
    def source_path(self) -> str:
        """The absolute path of the source code directory for the program under repair."""
        return os.path.join(self.directory, "source")

    @property
    def input_spec_path(self) -> t.Optional[str]:
        """The absolute path for the input specification for the program under repair"""
        path = os.path.join(self.directory, "input.json")
        if not os.path.exists(path):
            logger.warning("no input specification file provided for this bug scenario")
            return None

        logger.info("using input specification file: {}".format(path))
        return path

    @property
    def fix_localization(self) -> FixLocalization:
        """Loads and returns the fix localization for the program under repair."""
        # is it already cached?
        if self._fix_localization:
            return self._fix_localization

        # if not, let's cache it
        filename = self.localization_path
        logger.info("loading fix localization")
        if not os.path.exists(filename):
            raise ValueError("unable to load localization: has not been computed")

        self._fix_localization = FixLocalization.load(filename)
        logger.info("loaded fix localization: {}".format(self._fix_localization))
        return self._fix_localization

    def obtain_implicated_asts(self) -> None:
        """Obtains ASTs dumps for all files implicated by the fix localization."""
        logger.info("obtaining implicated ASTs")
        localization_path = self.localization_path
        if not os.path.exists(localization_path):
            raise ValueError("localization file must exist to obtain implicated ASTs")

        with open(localization_path, "r") as fh:
            localization_dict = json.load(fh)

        implicated_files = set(
            entry["source-location"]["filename"] for entry in localization_dict
        )
        logger.info("- found implicated source files: {}".format(", ".join(implicated_files)))

        for filename in implicated_files:
            self.obtain_ast_dump(os.path.join(self.source_path, filename))

        logger.info("obtained all implicated ASTs")

    def obtain_ast_dump(self, abs_filename: str) -> None:
        """Obtains the AST dump for a given source file and saves it to the AST dumps directory."""
        if not os.path.isabs(abs_filename):
            raise ValueError("source file must be given as an absolute path to obtain an AST dump")

        # determine where to store the AST dump
        rel_filename = os.path.relpath(abs_filename, self.source_path)
        ast_dump_filename = os.path.join(self.ast_dumps_path, rel_filename)
        ast_dump_filename += ".ast.json"

        # don't bother recreating an existing AST dump
        if os.path.exists(ast_dump_filename):
            logger.debug("AST dump for file already exists: {}".format(ast_dump_filename))
            # load and store the AST
            self._source_filename_to_ast[rel_filename] = ClangAST.load(
                    ast_filename=ast_dump_filename,
                    source_filename=abs_filename,
            )
            logger.info("stored AST for source file in memory: {}".format(rel_filename))
            return

        # use clang to obtain an AST dump
        command = " ".join([
            PATH_CC,
            "-Xclang",
            "-ast-dump=json",
            "-fsyntax-only",
            abs_filename,
        ])
        outcome = self.shell(command, capture_output=True)
        json_txt = outcome.stdout

        # create the directory that the AST dump will be dropped into
        ast_dump_directory = os.path.dirname(ast_dump_filename)
        os.makedirs(ast_dump_directory, exist_ok=True)

        with open(ast_dump_filename, "w") as fh:
            fh.write(json_txt)

        logger.info("saved AST for source file: {}".format(rel_filename))

        # load and store the AST
        self._source_filename_to_ast[rel_filename] = ClangAST.load(
            ast_filename=ast_dump_filename,
            source_filename=abs_filename,
        )
        logger.info("stored AST for source file in memory: {}".format(rel_filename))

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

        additional_args = {}
        if capture_output:
            additional_args["stdout"] = subprocess.PIPE
            additional_args["universal_newlines"] = "\n"

        logger.debug("executing: %s", command)
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            env={
                **os.environ,
                **env,
                "REPAIR_TOOL": "hifix",
            },
            **additional_args,
        )

        if check_returncode:
            result.check_returncode()

        return result

    def build_with_llvm(self) -> None:
        # TODO locate wllvm binary (/opt/wllvm/bin)
        check_call = functools.partial(
            self.shell,
            env={
                "CC": "wllvm",
                "CXX": "wllvm++",
                "LLVM_COMPILER": "clang",
                "LLVM_COMPILER_PATH": PATH_LLVM_COMPILER,
                "CFLAGS": "-g -O0",
                "CXXFLAGS": "-g -O0 -fsanitize=address",
            },
        )

        logger.info("prebuilding project")
        check_call("./prebuild")
        logger.info("finished prebuilding project")

        logger.info("building project")
        check_call("./build")
        logger.info("finished building project")

    def generate_bitcode(self, disassemble: bool = True) -> str:
        """Generate the uninstrumented bitcode file for this scenario."""
        bitcode_path = self.bitcode_path

        if os.path.exists(bitcode_path):
            logger.debug("skipping generation of bitcode: already exists")
            return bitcode_path

        self.build_with_llvm()

        # NOTE we may want to produce .bc for an archive instead of a binary
        command = "extract-bc -o {} -l {} {}"
        command = command.format(
            bitcode_path,
            PATH_LLVM_LINK,
            os.path.join("source", self.binary_path),
        )
        logger.info(
            "generating bitcode file: %s [command: %s]",
            bitcode_path,
            command,
        )
        self.shell(command)

        # we also need to run the split-calls pass on the bitcode
        command = " ".join((
            PATH_OPT,
            "-load",
            PATH_SPLITCALLS,
            "-o",
            bitcode_path,
            "-splitcall",
            bitcode_path,
        ))
        self.shell(command)

        logger.info("generated bitcode file: {}".format(bitcode_path))

        # optionally, disassemble the bitcode
        if disassemble:
            command = " ".join((
                PATH_LLVM_DIS,
                bitcode_path,
            ))
            self.shell(command)

        return bitcode_path

    def build_instrumented_binary(self) -> str:
        """Generates an instrumented binary for this bug scenario."""
        instrumented_binary_path = self.instrumented_binary_path

        if os.path.exists(instrumented_binary_path):
            logger.debug("skipping building of instrumented binary: already exists")
            return instrumented_binary_path

        trace_path = self.trace_path
        bitcode_path = self.bitcode_path
        instrumented_bc_path = self.instrumented_bitcode_path
        path_instrumented_object = bitcode_path[:-3] + "-inst.o"

        logger.info("generating instrumented binary [%s]", instrumented_binary_path)
        self.generate_bitcode()

        # instrument the bitcode
        logger.info("generating instrumented bitcode [%s]", instrumented_bc_path)
        command = '{} -load "{}" -tracer --trace-file="{}" "{}" -o "{}"'
        command = command.format(PATH_OPT, PATH_LIBTRACER, trace_path, bitcode_path, instrumented_bc_path)
        self.shell(command)

        # compile the binary
        logger.info("compiling instrumented object [%s]", path_instrumented_object)
        command = '{} --filetype=obj -o "{}" "{}"'
        command = command.format(PATH_LLC, path_instrumented_object, instrumented_bc_path)
        self.shell(command)

        # link the binary
        logger.info("linking instrumented binary [%s]", path_instrumented_object)
        command = '{} -o "{}" "{}" "{}" {}'
        command = command.format(
            PATH_CC,
            instrumented_binary_path,
            path_instrumented_object,
            PATH_RUNTIME_O,
            self.linker_options,
        )
        self.shell(command)

        logger.info("generated instrumented binary [%s]", instrumented_binary_path)
        return instrumented_binary_path

    def generate_trace(self) -> None:
        """
        Uses the test case and an instrumented binary for this bug scenario to generate a
        program trace for subsequent analysis and repair.
        """
        trace_path = self.trace_path

        if os.path.exists(trace_path):
            logger.debug("skipping building of trace file: already exists")
            return trace_path

        test_path = self.test_path
        instrumented_binary_path = self.instrumented_binary_path
        logger.info("generating trace file: %s", trace_path)

        if os.path.exists(trace_path):
            logger.info("removing existing trace file: %s", trace_path)
            os.remove(trace_path)
            logger.info("removed existing trace file: %s", trace_path)

        self.build_instrumented_binary()

        # run the test case on the instrumented binary
        logger.info("executing test on instrumented binary [%s]", instrumented_binary_path)
        command = '{} {}'.format(test_path, instrumented_binary_path)
        self.shell(command, check_returncode=False)
        logger.info("generated trace file")

    def analyze(self, debug: bool = False) -> None:
        # NOTE we run the analysis on the instrumented bitcode
        self.generate_bitcode()
        self.generate_trace()
        trace_path = self.trace_path
        bitcode_path = self.bitcode_path
        input_spec_path = self.input_spec_path

        command_parts = [
            PATH_OPT,
            "-load",
            PATH_LLVMTOSOURCE,
            "-load",
            PATH_HIFIX,
            "-hifix",
            "-trace",
            trace_path,
            bitcode_path,
            "-depend={}".format('true' if self.should_compute_dependencies else 'false'),
            "-repair={}".format('true' if self.should_compute_repair else 'false'),
            "-o=/dev/null",
        ]

        if input_spec_path is not None:
            command_parts += ["-inputspec={}".format(input_spec_path)]

        if debug:
            command_parts += ["-debug"]

        command = " ".join(command_parts)
        self.shell(command)

    def mutate(
        self,
        disassemble: bool = True,
        localization_filename: t.Optional[str] = None
    ) -> None:
        bitcode_path = self.bitcode_path

        mutated_bitcode_path = self.mutated_bitcode_path
        mutated_object_path = self.mutated_object_path
        mutated_binary_path = self.mutated_binary_path

        if not localization_filename:
            localization_filename = self.localization_path

        command = " ".join((
            PATH_OPT,
            "-load",
            PATH_LLVMTOSOURCE,
            "-load",
            PATH_HIFIX,
            "-load",
            PATH_LLVMREPAIR,
            "-llvmrepair",
            bitcode_path,
            "-localization-filename",
            localization_filename,
            "-validate-localization={}".format('true' if self.should_validate_localization else 'false'),
            "-mutated-filename",
            mutated_bitcode_path,
            "-o={}".format(mutated_bitcode_path),
        ))
        self.shell(command)

        # for the sake of better understanding the mutations, we also
        # disassemble the mutated bitcode
        if disassemble:
            command = " ".join((
                PATH_LLVM_DIS,
                mutated_bitcode_path,
            ))
            self.shell(command)

        # compile to an object file
        command = " ".join((
            PATH_LLC,
            "--filetype=obj",
            "-o",
            mutated_object_path,
            mutated_bitcode_path,
        ))
        self.shell(command)

        # compile the mutated binary
        command = " ".join((
            PATH_CC,
            "-o",
            mutated_binary_path,
            mutated_object_path,
            self.linker_options,
        ))
        self.shell(command)

    def map_ir_to_source(self) -> None:
        self.generate_bitcode()
        command = " ".join((
            PATH_OPT,
            "-load",
            PATH_LLVMTOSOURCE,
            "-load",
            PATH_HIFIX,
            "-llvm2source",
            "-mapping-filename",
            self.ir_source_mapping_path,
            self.bitcode_path,
        ))
        self.shell(command)

    def validate_mutation_via_llvm(self, mutation: Mutation) -> bool:
        """Determines whether a given mutation fixes the vulnerability at the LLVM level.

        Returns
        -------
        True if the vulnerability is fixed, or false if not.
        """
        # compute the command to run the exploit on the mutated binary
        command = '{} {}'.format(self.test_path, self.mutated_binary_path)

        # compute the environment variables that should be used to activate this mutation
        env = mutation.env()

        # use the exit status of the test script to determine if the program was repaired
        return self.shell(command, env=env, check_returncode=False).returncode == 0

    def validate_mutation_via_source(self, mutation: Mutation) -> bool:
        # find the corresponding fix location and AST
        fix_location = self.fix_localization[mutation.instruction_id]
        ast = self._source_filename_to_ast[fix_location.filename]

        # FIXME generate patch via temp file
        with tempfile.TemporaryDirectory() as variant_directory:
            os.rmdir(variant_directory)
            shutil.copytree(self.directory, variant_directory)
            patch_filename = os.path.join(variant_directory, "patch.diff")
            buggy_filename = os.path.join(
                variant_directory,
                "source",
                fix_location.filename,
            )
            mutation.diff(ast, fix_location, patch_filename)

            # apply
            command = " ".join([
                "patch",
                buggy_filename,
                patch_filename,
            ])
            try:
                self.shell(
                    command,
                    cwd=variant_directory,
                )
            except subprocess.CalledProcessError:
                logger.info("failed to lift mutation to source: patch command failed")
                return False

            # rebuild
            try:
               self.shell(
                    "./build",
                    env={
                        "CC": "wllvm",
                        "CXX": "wllvm++",
                        "LLVM_COMPILER": "clang",
                        "LLVM_COMPILER_PATH": PATH_LLVM_COMPILER,
                        "CFLAGS": "-g -O0",
                        "CXXFLAGS": "-g -O0",
                    },
                    cwd=variant_directory,
                )
            except subprocess.CalledProcessError:
                logger.info("failed to lift mutation to source: build command failed")
                return False

            # test
            try:
               self.shell("./test", cwd=variant_directory)
            except subprocess.CalledProcessError:
                logger.info("failed to lift mutation to source: test command failed")
                return False

        return True

    def validate_mutation(self, mutation: Mutation) -> bool:
        # FIXME copypasta code; this needs a bit of refactoring
        # find the corresponding fix location and AST
        fix_location = self.fix_localization[mutation.instruction_id]
        ast = self._source_filename_to_ast[fix_location.filename]

        if not self.validate_mutation_via_llvm(mutation):
            return False

        if self.should_validate_lifted_patches:
            if not self.validate_mutation_via_source(mutation):
                # ensure that the failed patches directory exists
                os.makedirs(self.failed_patches_path, exist_ok=True)

                failed_patch_filename = "i{}_m{}.diff".format(
                    mutation.instruction_id,
                    mutation.mutant_id,
                )
                failed_patch_filename = os.path.join(
                    self.failed_patches_path,
                    failed_patch_filename,
                )
                mutation.diff(ast, fix_location, failed_patch_filename)
                return False

        return True

    def find_acceptable_mutations(self) -> t.Iterator[Mutation]:
        """Returns a stream of mutations that fix the underlying bug."""
        for mutation in Mutation.load_all(self.mutation_index_path):
            if self.validate_mutation(mutation):
                yield mutation

    def validate(self) -> None:
        """Validates the generated mutations and creates source-level patches."""
        found_patch = False
        for mutation in self.find_acceptable_mutations():
            print("FOUND AN ACCEPTABLE REPAIR: {}".format(mutation))
            found_patch = True
            self.create_patch(mutation)

            # if we only need to generate a single acceptable patch, let's terminate early
            if self.should_terminate_early:
                print("TERMINATING EARLY: ACCEPTABLE PATCH WAS FOUND")
                return

        print("FINISHED EVALUATING ALL PLAUSIBLE MUTATIONS")

        if not found_patch:
            print("NO ACCEPTABLE REPAIR WAS FOUND")

    def create_patch(self, mutation: Mutation) -> None:
        """Creates a patch file for a given mutation."""
        logger.info("creating source-level patch file for mutation: {}".format(mutation))

        # ensure that the patch directory exists
        patch_dir = self.patches_path
        os.makedirs(patch_dir, exist_ok=True)

        patch_filename = "i{}_m{}.diff".format(mutation.instruction_id, mutation.mutant_id)
        patch_filename = os.path.join(patch_dir, patch_filename)

        # find the corresponding fix location and AST
        fix_location = self.fix_localization[mutation.instruction_id]
        ast = self._source_filename_to_ast[fix_location.filename]

        # generate and store the patch
        mutation.diff(ast, fix_location, patch_filename)
        logger.info("saved patch for mutation [{}] to file: {}".format(mutation, patch_filename))

    def repair(self, debug: bool = False) -> None:
        self.analyze(debug)
        # FIXME why would we be calling repair and not actually computing the repair?
        if self.should_compute_repair:
            self.obtain_implicated_asts()
            self.mutate()
            self.validate()

