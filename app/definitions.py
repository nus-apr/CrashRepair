#! /usr/bin/env python3
# -*- coding: utf-8 -*-
import os

# ------------------- Directories --------------------

DIRECTORY_ROOT = "/".join(os.path.realpath(__file__).split("/")[:-2])
DIRECTORY_LIB = DIRECTORY_ROOT + "/lib"
DIRECTORY_LOG = ""
DIRECTORY_LOG_BASE = DIRECTORY_ROOT + "/logs"
DIRECTORY_TESTS = DIRECTORY_ROOT + "/tests"
DIRECTORY_OUTPUT_BASE = DIRECTORY_ROOT + "/output"
DIRECTORY_COMPONENTS = DIRECTORY_ROOT + "/components"
DIRECTORY_OUTPUT = ""
DIRECTORY_TMP = DIRECTORY_ROOT + "/tmp"
DIRECTORY_BACKUP = DIRECTORY_ROOT + "/backup"
DIRECTORY_TOOLS = DIRECTORY_ROOT + "/tools"
DIRECTORY_DATA = DIRECTORY_ROOT + "/data"

# ------------------- Files --------------------

FILE_MAIN_LOG = ""
FILE_ERROR_LOG = DIRECTORY_LOG_BASE + "/log-error"
FILE_LAST_LOG = DIRECTORY_LOG_BASE + "/log-latest"
FILE_MAKE_LOG = DIRECTORY_LOG_BASE + "/log-make"
FILE_CRASH_LOG = DIRECTORY_LOG_BASE + "/log-crash"
FILE_COMMAND_LOG = DIRECTORY_LOG_BASE + "/log-command"
FILE_LOCALIZE_LOG = DIRECTORY_LOG_BASE + "/log-localize"
FILE_EXCEPTION_LOG = DIRECTORY_LOG_BASE + "/log-exception"
FILE_STANDARD_FUNCTION_LIST = DIRECTORY_DATA + "/standard-function-list"
FILE_STANDARD_MACRO_LIST = DIRECTORY_DATA + "/standard-macro-list"
FILE_PATCH_SET = ""
FILE_PATCH_RANK_MATRIX = ""
FILE_PATCH_RANK_INDEX = ""
FILE_LOCALIZATION_INFO = ""
FILE_ANALYSIS_INFO = ""


# ------------------- Configuration --------------------
CONF_DIR_EXPERIMENT = "dir_exp:"
CONF_PATH_SPECIFICATION = "spec_path:"
CONF_POC_LIST = "poc_list:"
CONF_COMMAND_CONFIG = "config_command:"
CONF_COMMAND_BUILD = "build_command:"
CONF_BINARY_PATH = "binary_path:"
CONF_GENERAL_COMP_LIST = "general_comp_list:"
CONF_CUSTOM_COMP_LIST = "custom_comp_list:"
CONF_DEPTH_VALUE = "depth:"
CONF_DIR_SRC = "src_directory:"
CONF_LOC_BUG = "loc_bug:"
CONF_LOC_PATCH = "loc_patch:"
CONF_LOW_BOUND = "low_bound:"
CONF_MAX_BOUND = "max_bound:"
CONF_GEN_SEARCH_LIMIT = "gen_limit:"
CONF_MAX_FORK = "max-fork:"
CONF_TAG_ID = "tag_id:"
CONF_STATIC = "static:"
CONF_FLAG_ASAN = "flag_asan:"
CONF_FLAGS_C = "flag_c:"
CONF_FLAGS_CXX = "flag_cxx:"
CONF_SELECTION_STRATEGY = "select_strategy:"
CONF_DISTANCE_METRIC = "dist_metric:"
CONF_PATCH_TYPE = "patch_type:"
CONF_BUILD_FLAGS = "build_flags:"
CONF_KLEE_FLAGS = "klee_flags:"
CONF_OPERATION_MODE = "mode:"
CONF_ITERATION_LIMIT = "iterations:"
CONF_STACK_SIZE = "stack_size:"
CONF_MASK_ARG = "mask_arg:"
CONF_IS_CPP = "is_cpp:"
CONF_IS_CRASH = "is_crash:"
CONF_TIMEOUT_SAT = "timeout_sat:"
CONF_TIMEOUT_CONCOLIC_RUN = "timeout_concolic:"
CONF_TIMEOUT_CONCRETE_RUN = "timeout_concrete:"
CONF_RANK_LIMIT = "rank_limit:"
CONF_TEST_INPUT_DIR = "test_input_dir:"
CONF_TEST_OUTPUT_DIR = "test_output_dir:"
CONF_TEST_INPUT_FILE = "test_input_file:"
CONF_TEST_OUTPUT_FILE = "test_output_file:"
CONF_TEST_INPUT_LIST = "test_input_list:"
CONF_TEST_OUTPUT_LIST = "test_output_list:"
CONF_TEST_BINARY_CONFIG_FILE = "test_binary_config_file:"
CONF_SEED_BINARY_CONFIG_FILE = "seed_binary_config_file:"
CONF_TEST_SUITE_CONFIG = "path_test_suite:"
CONF_SEED_SUITE_CONFIG = "path_seed_suite:"
CONF_TEST_SUITE_ID_LIST = "list_test_id:"
CONF_SEED_SUITE_ID_LIST = "list_seed_id:"
CONF_MAX_FLIPPINGS = "max_flippings:"

CONF_SEED_FILE = "seed_file:"
CONF_SEED_DIR = "seed_dir:"
CONF_SEED_LIST = "seed_list:"
CONF_GEN_SPECIAL_PATH = "gen_special_path:"
CONF_PRESERVE_BC = "preserve_bc:"
CONF_GENERALIZED_SEED_INPUT = "generalize_seed_input:"
CONF_GENERALIZED_TEST_INPUT = "generalize_test_input:"

# ----------------- KEY DEFINITIONS -------------------

KEY_DURATION_TOTAL = 'run-time'
KEY_DURATION_BOOTSTRAP = 'bootstrap'
KEY_DURATION_BUILD = "build"
KEY_DURATION_INITIALIZATION = 'initialization'
KEY_DURATION_ANALYSIS = 'analyze'
KEY_DURATION_CONCOLIC = 'concolic'
KEY_DURATION_CONCRETE = 'concrete'
KEY_DURATION_LOCALIZATION = 'localization'
KEY_DURATION_REPAIR = "repair"


# ---------------- ARGUMENTS ---------------------------
ARG_CONF_FILE = "--conf="
ARG_DEBUG = "--debug"
ARG_DISABLE_DISTANCE_CAL = "--dist-cal="
ARG_DIST_METRIC = "--dist-metric="
ARG_SELECTION_METHOD = "--selection="
ARG_OPERATION_MODE = "--mode="
ARG_PATCH_TYPE = "--patch-type="
ARG_REFINE_METHOD = "--refine-method="
ARG_SKIP_BUILD = "--skip-build"
ARG_SKIP_GENERATION = "--skip-gen"
ARG_SKIP_TEST = "--skip-test"
ARG_REDUCE_METHOD = "--reduce-method="
ARG_COMP_ALL = "--all-comps"
ARG_CEGIS_TIME_SPLIT = "--cegis-time-split="
ARG_TIME_DURATION = "--time-duration="
ARG_RANK_LIMIT = "--top-n="
ARG_ITERATION_COUNT = "--iterations="
ARG_COLLECT_STAT = "--stat"
ARG_LOW_BOUND = "--low-bound="
ARG_MAX_BOUND = "--max-bound="
ARG_ONLY_GEN = "--only-gen"
ARG_ONLY_TEST = "--only-test"
ARG_TEST_SUITE_ID_LIST = "--test-id-list="
ARG_SEED_SUITE_ID_LIST = "--seed-id-list="
ARG_PRESERVE_BC = "--preserve-bc"
ARG_USE_CACHE = "--use-cache"
ARG_CORE_LIMIT = "--cpus"
ARG_SYNTHESIZE_EXPR = "--synthesize-expr"


# ----------------- TOOLS --------------------------------
TOOL_VECGEN = "third-party/deckard/cvecgen_fail "
TOOL_VECGEN_ORIG = "third-party/deckard/cvecgen "

PATCH_COMMAND = "patchweave-patch"
PATCH_SIZE = "1000"
DIFF_COMMAND = "crochet-diff "
DIFF_SIZE = "1000"
SYNTAX_CHECK_COMMAND = "clang-check "
STYLE_FORMAT_COMMAND = "clang-format -style=LLVM "

crash_word_list = ["abort", "core dumped", "crashed", "exception"]
error_word_list = ["runtime error", "buffer-overflow", "unsigned integer overflow"]

CRASH_TYPE_DIV_ZERO = 1
CRASH_TYPE_INT_MUL_OVERFLOW = 2
CRASH_TYPE_INT_ADD_OVERFLOW = 3
CRASH_TYPE_INT_SUB_OVERFLOW = 4
CRASH_TYPE_MEMORY_READ_OVERFLOW = 5
CRASH_TYPE_SHIFT_OVERFLOW = 6
CRASH_TYPE_MEMSET_ERROR = 7
CRASH_TYPE_MEMCPY_ERROR = 8
CRASH_TYPE_ASSERTION_ERROR = 9
CRASH_TYPE_MEMORY_WRITE_OVERFLOW = 10
CRASH_TYPE_MEMORY_READ_NULL = 11
CRASH_TYPE_MEMORY_WRITE_NULL = 12
CRASH_TYPE_MEMMOVE_ERROR = 13
CRASH_TYPE_CAST_OVERFLOW = 14
CRASH_TYPE_KLEE_CHECK_MEMORY = 15


CRASH_TYPE_MESSAGE = {
    CRASH_TYPE_DIV_ZERO: "division by zero",
    CRASH_TYPE_INT_MUL_OVERFLOW: "integer multiplication overflow",
    CRASH_TYPE_INT_ADD_OVERFLOW:  "integer addition overflow",
    CRASH_TYPE_INT_SUB_OVERFLOW: "integer subtraction overflow",
    CRASH_TYPE_SHIFT_OVERFLOW: "overflow on shift operation",
    CRASH_TYPE_MEMORY_READ_OVERFLOW: "memory read overflow",
    CRASH_TYPE_MEMORY_WRITE_OVERFLOW: "memory write overflow",
    CRASH_TYPE_KLEE_CHECK_MEMORY: "check memory access error",
    CRASH_TYPE_MEMSET_ERROR: "memset error",
    CRASH_TYPE_MEMCPY_ERROR: "memcpy error",
    CRASH_TYPE_MEMMOVE_ERROR: "memmove error",
    CRASH_TYPE_ASSERTION_ERROR: "assertion error",
    CRASH_TYPE_MEMORY_READ_NULL: "memory read from null pointer",
    CRASH_TYPE_MEMORY_WRITE_NULL: "memory write to null pointer",
    CRASH_TYPE_CAST_OVERFLOW: "overflow on cast operation"
}

INTEGER_TYPES = ["int", "short", "long", "size_t", "unsigned long", "unsigned int", "unsigned short",
                 "uint_fast8_t", "uint_fast8_t","uint_fast32_t", "uint_fast16_t", "unsigned char",
                 "uint8", "uint16", "uint32", "UI8", "UI16"]



