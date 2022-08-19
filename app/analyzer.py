from ast import Or
import collections
import os
from typing import OrderedDict
import app.configuration
import app.utilities
from app import emitter, utilities, definitions, values, builder, \
    reader, extractor,  generator, instrumentor, klee

def analyze():
    emitter.title("Analyzing Program")
    test_input_list = values.LIST_TEST_INPUT
    second_var_list = list()
    cfc_info = dict()
    output_dir_path = definitions.DIRECTORY_OUTPUT
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
        emitter.sub_title("Test Case #" + str(test_case_id))
        emitter.highlight("\tUsing Arguments: " + str(generalized_arg_list))
        emitter.highlight("\tUsing Input File: " + str(seed_file))
        emitter.debug("input list in test case:" + argument_list)
        argument_list = app.configuration.extract_input_arg_list(argument_list)

        emitter.sub_sub_title("Running Sanitized Analysis")
        if not values.CONF_SKIP_BUILD:
            builder.build_normal()
            if values.CONF_PATH_PROGRAM:
                assert os.path.isfile(values.CONF_PATH_PROGRAM)
                assert os.path.getsize(values.CONF_PATH_PROGRAM) > 0
        klee_concrete_out_dir = output_dir_path + "/klee-out-concrete-" + str(test_case_id - 1)
        if values.LIST_TEST_BINARY:
            program_path = values.LIST_TEST_BINARY[test_case_id - 1]
            values.CONF_PATH_PROGRAM = program_path
        else:
            program_path = values.CONF_PATH_PROGRAM
        emitter.highlight("\tUsing Binary: " + str(program_path))

        # c_src_file, var_list, cfc = extractor.extract_sanitizer_information(program_path, argument_list, definitions.FILE_CRASH_LOG)
        extractor.extract_byte_code(program_path)
        if not os.path.isfile(program_path + ".bc"):
            app.utilities.error_exit("Unable to generate bytecode for " + program_path)
        exit_code = klee.run_concrete_execution(program_path + ".bc", argument_list, True, klee_concrete_out_dir)
        assert exit_code == 0
        # set location of bug/crash
        values.IS_CRASH = False
        taint_log_path = klee_concrete_out_dir + "/taint.log"

        # Retrieve concrete values from the taint.log file.
        taint_values_concrete = reader.read_taint_values(taint_log_path)

        c_src_file, var_list, cfc = extractor.extract_crash_information(program_path, argument_list, values.get_file_message_log())
        cfc_info["file"] = c_src_file
        cfc_info["var-list"] = var_list
        cfc_info["expr"] = cfc
        latest_crash_loc, crash_type = reader.collect_crash_point(values.get_file_message_log())
        cfc_info["loc"] = latest_crash_loc
        cfc_info["type"] = crash_type
        # if oracle.is_loc_in_trace(values.CONF_LOC_PATCH):
        #     values.USEFUL_SEED_ID_LIST.append(test_case_id)
        if latest_crash_loc:
            values.IS_CRASH = True
            if latest_crash_loc not in values.CONF_LOC_LIST_CRASH:
                values.CONF_LOC_LIST_CRASH.append(latest_crash_loc)

        if crash_type == definitions.CRASH_TYPE_DIV_ZERO:
            emitter.information("\t\t\t[info] identified crash type: divide by zero")

        emitter.sub_sub_title("Running Concolic Analysis")
        instrumentor.instrument_klee_var_expr(c_src_file, var_list)
        builder.build_normal()
        utilities.restore_file(c_src_file, c_src_file + ".bk")
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
        exit_code = klee.run_concolic_execution(program_path + ".bc", generalized_arg_list, second_var_list, True,
                                           klee_concolic_out_dir)
        # assert exit_code == 0
        expr_trace_log = klee_concolic_out_dir + "/expr.log"
        var_info = reader.read_symbolic_expressions(expr_trace_log)

        memory_track_log = klee_concolic_out_dir + "/memory.log"
        values.MEMORY_TRACK = reader.read_memory_values(memory_track_log)
        input_byte_list = []
        updated_var_info = collections.OrderedDict()
        for var_name in var_info:
            sym_expr_list = var_info[var_name]["expr_list"]
            var_type = var_info[var_name]["data_type"]
            updated_var_info[var_name] = var_info[var_name]
            if var_type == "pointer":
                if len(sym_expr_list) > 1 :
                    emitter.error("More than one value for pointer")
                if crash_type == definitions.CRASH_TYPE_MEMORY_OVERFLOW:
                    symbolic_ptr = sym_expr_list[0].split(" ")[1]
                    sizeof_expr_list = values.MEMORY_TRACK[symbolic_ptr]
                    sizeof_name = "sizeof {}".format(var_name)
                    updated_var_info[sizeof_name] = {
                        "expr_list": sizeof_expr_list,
                        "data_type": "integer"
                    }

        for var_name in updated_var_info:
            tainted_byte_list = []
            sym_expr_list = updated_var_info[var_name]["expr_list"]
            for sym_expr in sym_expr_list:
                var_sym_expr_code = generator.generate_z3_code_for_var(sym_expr, var_name)
                tainted_byte_list = extractor.extract_input_bytes_used(var_sym_expr_code)
                # if not tainted_byte_list and not input_byte_list and len(sym_expr) > 16:
                #     tainted_byte_list = [sym_expr.strip().split(" ")[1]]
                #     break
            tainted_byte_list = list(set(tainted_byte_list))
            input_byte_list = input_byte_list + tainted_byte_list
            tainted_bytes = sorted([str(i) for i in tainted_byte_list])
            emitter.highlight("\t\t[info] Symbolic Mapping: {} -> [{}]".format(var_name, ",".join(tainted_bytes)))

        input_byte_list = list(set(input_byte_list))
        cfc_info["var-info"] = updated_var_info
        emitter.sub_sub_title("Running Taint Analysis")
        builder.build_normal()
        extractor.extract_byte_code(program_path)

        if not os.path.isfile(program_path + ".bc"):
            app.utilities.error_exit("Unable to generate bytecode for " + program_path)
        values.ARGUMENT_LIST = generalized_arg_list
        klee_taint_out_dir = output_dir_path + "/klee-out-taint-" + str(test_case_id - 1)
        exit_code = klee.run_concolic_execution(program_path + ".bc", generalized_arg_list, second_var_list, True,
                                           klee_taint_out_dir)

        taint_log_path = klee_taint_out_dir + "/taint.log"

        # Retrieve symbolic expressions from taint.log of concolic run.
        taint_map_symbolic = reader.read_tainted_expressions(taint_log_path)

        return input_byte_list, taint_map_symbolic, cfc_info, taint_values_concrete
