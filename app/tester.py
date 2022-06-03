import os
import app.configuration
import app.utilities
from app import emitter, logger, definitions, values, builder, repair, \
    configuration, reader, parallel, extractor,  generator
from app.concolic import run_concrete_execution, run_concolic_execution


def test():
    emitter.title("Initializing Program")
    test_input_list = values.LIST_TEST_INPUT
    second_var_list = list()
    output_dir_path = definitions.DIRECTORY_OUTPUT
    emitter.sub_title("Running Test-Suite")
    test_case_id = 0
    seed_id = 0
    count_seeds = len(values.LIST_SEED_INPUT)
    count_inputs = len(test_input_list)
    for argument_list in test_input_list[:count_inputs - count_seeds]:
        print_argument_list = app.configuration.extract_input_arg_list(argument_list)
        generalized_arg_list = []
        seed_file = None
        test_case_id = test_case_id + 1
        for arg in print_argument_list:
            if arg in (list(values.LIST_SEED_FILES.values()) + list(values.LIST_TEST_FILES.values())):
                generalized_arg_list.append("$POC")
                seed_file = arg
            else:
                generalized_arg_list.append(arg)

        emitter.sub_sub_title("Test Case #" + str(test_case_id))
        emitter.highlight("\tUsing Arguments: " + str(generalized_arg_list))
        emitter.highlight("\tUsing Input File: " + str(seed_file))
        emitter.debug("input list in test case:" + argument_list)
        argument_list = app.configuration.extract_input_arg_list(argument_list)
        klee_concrete_out_dir = output_dir_path + "/klee-out-concrete-" + str(test_case_id - 1)
        if values.LIST_TEST_BINARY:
            program_path = values.LIST_TEST_BINARY[test_case_id - 1]
            values.CONF_PATH_PROGRAM = program_path
        else:
            program_path = values.CONF_PATH_PROGRAM
        emitter.highlight("\tUsing Binary: " + str(program_path))

        extractor.extract_crash_information(program_path, argument_list, definitions.FILE_CRASH_LOG)

        extractor.extract_byte_code(program_path)
        if not os.path.isfile(program_path + ".bc"):
            app.utilities.error_exit("Unable to generate bytecode for " + program_path)

        exit_code = run_concrete_execution(program_path + ".bc", argument_list, True, klee_concrete_out_dir)
        assert exit_code == 0
        # set location of bug/crash
        values.IS_CRASH = False
        latest_crash_loc, crash_type = reader.collect_crash_point(values.get_file_message_log())
        # if oracle.is_loc_in_trace(values.CONF_LOC_PATCH):
        #     values.USEFUL_SEED_ID_LIST.append(test_case_id)
        if latest_crash_loc:
            values.IS_CRASH = True
            emitter.information("\t\t\t[info] identified a crash location: " + str(latest_crash_loc))
            if latest_crash_loc not in values.CONF_LOC_LIST_CRASH:
                values.CONF_LOC_LIST_CRASH.append(latest_crash_loc)

        if crash_type == definitions.CRASH_TYPE_DIV_ZERO:
            emitter.information("\t\t\t[info] identified crash type: divide by zero")

        klee_concolic_out_dir = output_dir_path + "/klee-out-concolic-" + str(test_case_id - 1)
        generalized_arg_list = []
        poc_path = None
        for arg in argument_list:
            if str(argument_list.index(arg)) in values.CONF_MASK_ARG:
                generalized_arg_list.append(arg)
            elif arg in (list(values.LIST_SEED_FILES.values()) + list(values.LIST_TEST_FILES.values())):
                poc_path = arg
                values.FILE_POC_SEED = arg
                values.FILE_POC_GEN = arg
                generalized_arg_list.append("$POC")
            else:
                generalized_arg_list.append(arg)
        seed_id = seed_id + 1

        emitter.highlight("\tUsing Arguments: " + str(generalized_arg_list))
        emitter.highlight("\tUsing Input File: " + str(poc_path))
        if values.LIST_TEST_BINARY:
            program_path = values.LIST_TEST_BINARY[seed_id - 1]
            values.CONF_PATH_PROGRAM = program_path
        else:
            program_path = values.CONF_PATH_PROGRAM
        extractor.extract_byte_code(program_path)
        if not os.path.isfile(program_path + ".bc"):
            app.utilities.error_exit("Unable to generate bytecode for " + program_path)

        values.ARGUMENT_LIST = generalized_arg_list
        _, second_var_list = generator.generate_angelic_val(klee_concrete_out_dir, generalized_arg_list, poc_path)
        exit_code = run_concolic_execution(program_path + ".bc", generalized_arg_list, second_var_list, True,
                                           klee_concolic_out_dir)
        # assert exit_code == 0

