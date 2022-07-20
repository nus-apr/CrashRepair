import logging
from typing import Union
import time
import os
import app.generator
from app import emitter, values, reader, utilities, definitions, generator, oracle, parallel, \
    extractor, distance, configuration


logger = logging.getLogger(__name__)

list_path_explored = list()
list_path_detected = list()
list_path_infeasible = list()
list_path_inprogress = list()
count_discovered = 0


def run_concolic_execution(program, argument_list, second_var_list, print_output=False, klee_out_dir=None):
    """
    This function will execute the program in concolic mode using the generated ktest file
        program: the absolute path of the bitcode of the program
        argument_list : a list containing each argument in the order that should be fed to the program
        second_var_list: a list of tuples where a tuple is (var identifier, var size, var value)
    """
    logger.info("running concolic execution")

    global File_Log_Path
    current_dir = os.getcwd()
    directory_path = "/".join(str(program).split("/")[:-1])
    emitter.debug("changing directory:" + directory_path)
    project_path = values.CONF_DIR_SRC
    os.chdir(directory_path)
    binary_name = str(program).split("/")[-1]
    input_argument = ""
    # argument_list = str(argument_str).split(" ")
    for argument in argument_list:
        index = list(argument_list).index(argument)
        if "$POC" in argument:
            file_path = values.FILE_POC_GEN
            # if "_" in argument:
            #     file_index = "_".join(str(argument).split("_")[1:])
            #     file_path = values.LIST_TEST_FILES[file_index]
            # else:
            #     file_path = values.CONF_PATH_POC
            #     if values.FILE_POC_GEN:
            #         file_path = values.FILE_POC_GEN
            #     elif values.FILE_POC_SEED:
            #         file_path = values.FILE_POC_SEED
            concrete_file = open(file_path, 'rb')
            bit_size = os.fstat(concrete_file.fileno()).st_size
            input_argument += " A --sym-files 1 " + str(bit_size) + " "
        elif str(index) in values.CONF_MASK_ARG:
            input_argument += " " + argument
        else:
            input_argument += " --sym-arg " + str(len(str(argument)))
    ktest_path, return_code = generator.generate_ktest(argument_list, second_var_list)
    ktest_log_file = "/tmp/ktest.log"
    ktest_command = "ktest-tool " + ktest_path + " > " + ktest_log_file
    utilities.execute_command(ktest_command)
    bit_length_list = reader.read_bit_length(ktest_log_file)
    if values.LIST_BIT_LENGTH:
        for var in bit_length_list:
            if var in values.LIST_BIT_LENGTH:
                if values.LIST_BIT_LENGTH[var] < bit_length_list[var]:
                    values.LIST_BIT_LENGTH[var] = bit_length_list[var]
            else:
                values.LIST_BIT_LENGTH[var] = bit_length_list[var]
    else:
        values.LIST_BIT_LENGTH = bit_length_list
    emitter.normal("\texecuting klee in concolic mode")
    # hit_location_flag = " "
    runtime_lib_path = definitions.DIRECTORY_LIB + "/libcrepair_runtime.bca"
    # if values.CONF_DISTANCE_METRIC == "control-loc":
    hit_location_flag = "--hit-locations " + values.CONF_LOC_BUG + "," + values.CONF_LOC_PATCH
    if values.CONF_LOC_LIST_CRASH:
        crash_locations = ', '.join(['{}'.format(loc) for loc in values.CONF_LOC_LIST_CRASH])
        hit_location_flag += "," + crash_locations + " "
    else:
        hit_location_flag += " "
    ppc_log_flag = ""
    if values.DEFAULT_DISTANCE_METRIC != values.OPTIONS_DIST_METRIC[2]:
        ppc_log_flag = "--log-ppc "

    klee_command = "timeout " + str(values.DEFAULT_TIMEOUT_KLEE_CONCOLIC) + " "
    if klee_out_dir:
        klee_command += "klee --output-dir=" + str(klee_out_dir) + " "
        values.KLEE_LAST_DIR = klee_out_dir
    else:
        klee_command += "klee "
    klee_command += "--posix-runtime " \
                    "--libc=uclibc " \
                    "--write-smt2s " \
                    "-allow-seed-extension " \
                    "-named-seed-matching " \
                    "--log-trace " \
                    + "--external-calls=all " \
                    + "--link-llvm-lib={0} " .format(runtime_lib_path) \
                    + "--max-time={0} ".format(values.DEFAULT_TIMEOUT_KLEE_CONCOLIC) \
                    + "{0}".format(ppc_log_flag) \
                    + "{0}".format(hit_location_flag) \
                    + "--max-forks {0} ".format(values.DEFAULT_MAX_FORK) \
                    + values.CONF_KLEE_FLAGS + " " \
                    + "--seed-out={0} ".format(ktest_path) \
                    + "{0} ".format(binary_name) \
                    + input_argument
    if not print_output:
        klee_command += " > " + File_Log_Path + " 2>&1 "
    return_code = utilities.execute_command(klee_command)
    emitter.debug("changing directory:" + current_dir)
    os.chdir(current_dir)

    # collect artifacts
    ppc_log_path = klee_out_dir + "/ppc.log"
    trace_log_path = klee_out_dir + "/trace.log"
    if values.DEFAULT_DISTANCE_METRIC != values.OPTIONS_DIST_METRIC[2]:
        ppc_list, path_formula = reader.collect_symbolic_path(ppc_log_path, project_path)
        values.LIST_PPC = values.LIST_PPC = ppc_list
        values.LAST_PPC_FORMULA = path_formula
        values.PREFIX_PPC_STR = reader.collect_symbolic_path_prefix(ppc_log_path, project_path)
    else:
        values.LAST_PPC_FORMULA = extractor.extract_largest_path_condition(klee_out_dir)
        if values.LAST_PPC_FORMULA:
            ppc_list = generator.generate_ppc_from_formula(values.LAST_PPC_FORMULA)
            values.LIST_PPC = values.LIST_PPC + ppc_list
        # else:
        #     values.LIST_PPC = []
    values.PREFIX_PPC_FORMULA = generator.generate_formula(values.PREFIX_PPC_STR)
    values.LIST_TRACE = reader.collect_trace(trace_log_path, project_path)
    if oracle.is_loc_in_trace(values.CONF_LOC_BUG) and oracle.is_loc_in_trace(values.CONF_LOC_PATCH):
        if values.DEFAULT_DISTANCE_METRIC != values.OPTIONS_DIST_METRIC[2]:
            values.NEGATED_PPC_FORMULA = generator.generate_path_for_negation()
        else:
            if values.LAST_PPC_FORMULA:
                values.NEGATED_PPC_FORMULA = generator.generate_negated_path(values.LAST_PPC_FORMULA)
    else:
        values.NEGATED_PPC_FORMULA = None
    return return_code

#
# def run_symbolic_execution(program, argument_list, print_output=False):
#     """
#     This function will execute the program in symbolic mode using the initial test case
#         program: the absolute path of the bitcode of the program
#         argument_list : a list containing each argument in the order that should be fed to the program
#     """
#     logger.info("running symbolic execution")
#
#     global File_Log_Path
#     current_dir = os.getcwd()
#     directory_path = "/".join(str(program).split("/")[:-1])
#     emitter.debug("changing directory:" + directory_path)
#     project_path = values.CONF_PATH_PROJECT
#     os.chdir(directory_path)
#     binary_name = str(program).split("/")[-1]
#     emitter.normal("\texecuting klee in concolic mode")
#     runtime_lib_path = definitions.DIRECTORY_LIB + "/libcrepair_runtime.bca"
#     input_argument = ""
#     for argument in argument_list:
#         if "$POC" in argument:
#             argument = values.CONF_PATH_POC
#         input_argument += " " + str(argument)
#
#     klee_command = "/klee/build-origin/bin/klee " \
#                    "--posix-runtime " \
#                    "--libc=uclibc " \
#                    "--write-smt2s " \
#                    "--search=dfs " \
#                    "-no-exit-on-error " \
#                    + "--external-calls=all " \
#                    + "--link-llvm-lib={0} " .format(runtime_lib_path) \
#                    + "--max-time={0} ".format(values.DEFAULT_TIMEOUT_KLEE_CEGIS) \
#                    + "--max-forks {0} ".format(values.DEFAULT_MAX_FORK_CEGIS) \
#                    + values.CONF_KLEE_FLAGS + " " \
#                    + "{0} ".format(binary_name) \
#                    + input_argument
#
#     if not print_output:
#         klee_command += " > " + File_Log_Path + " 2>&1 "
#     return_code = utilities.execute_command(klee_command)
#     emitter.debug("changing directory:" + current_dir)
#     os.chdir(current_dir)
#     return return_code


def run_concrete_execution(program, argument_list, print_output=False, klee_out_dir=None):
    """
    This function will execute the program in concrete mode using the concrete inputs
        program: the absolute path of the bitcode of the program
        argument_list : a list containing each argument in the order that should be fed to the program
        second_var_list: a list of tuples where a tuple is (var identifier, var size, var value)
    """
    logger.info("running concolic execution")
    emitter.normal("\texecuting klee in concrete mode")
    global File_Log_Path
    current_dir = os.getcwd()
    directory_path = "/".join(str(program).split("/")[:-1])
    emitter.debug("changing directory:" + directory_path)
    os.chdir(directory_path)
    binary_name = str(program).split("/")[-1]
    project_path = values.CONF_DIR_SRC
    input_argument = ""
    runtime_lib_path = definitions.DIRECTORY_LIB + "/libcrepair_runtime.bca"
    for argument in argument_list:
        if "$POC" in argument:
            argument = values.FILE_POC_GEN
        #     if "_" in argument:
        #         file_index = "_".join(str(argument).split("_")[1:])
        #         argument = values.LIST_TEST_FILES[file_index]
        #     else:
        #         argument = values.CONF_PATH_POC
        #         if values.FILE_POC_GEN:
        #             argument = values.FILE_POC_GEN
        input_argument += " " + str(argument)
    if klee_out_dir:
        klee_command = "klee --output-dir=" + str(klee_out_dir) + " "
        values.KLEE_LAST_DIR = klee_out_dir
    else:
        klee_command = "klee "
    hit_location_flag = values.CONF_LOC_BUG + "," + values.CONF_LOC_PATCH

    klee_command += "--posix-runtime " \
                    "--libc=uclibc " \
                    "--search=dfs " \
                    "--write-smt2s " \
                    "--external-calls=all " \
                    "--log-trace " \
                    "--max-forks {0} ".format(values.DEFAULT_MAX_FORK) \
                    + values.CONF_KLEE_FLAGS + " " \
                    + "--max-time={0} ".format(values.DEFAULT_TIMEOUT_KLEE_CONCRETE) \
                    + " --hit-locations {0} ".format(hit_location_flag) \
                    + "--link-llvm-lib={0} ".format(runtime_lib_path) \
                    + "{0} ".format(binary_name) \
                    + input_argument

    if not print_output:
        klee_command += " > " + File_Log_Path + " 2>&1 "
    return_code = utilities.execute_command(klee_command)
    emitter.debug("changing directory:" + current_dir)
    os.chdir(current_dir)
    trace_log_path = klee_out_dir + "/trace.log"
    values.LIST_TRACE = reader.collect_trace(trace_log_path, project_path)
    return return_code


