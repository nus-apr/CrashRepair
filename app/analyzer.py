from ast import Or
import collections
import time
import os
import re
import app.configuration
import app.utilities
from app import emitter, utilities, definitions, values, builder, \
    reader, extractor,  generator, instrumentor, klee


def get_concrete_values(arguments_str, output_dir_path, test_case_id, program_path):
    emitter.sub_sub_title("Running Concrete Execution")
    print_argument_list = app.configuration.extract_input_arg_list(arguments_str)
    argument_list = app.configuration.extract_input_arg_list(arguments_str)
    generalized_arg_list = []
    seed_file = None
    for arg in print_argument_list:
        if arg in (list(values.LIST_SEED_FILES.values()) + list(values.LIST_TEST_FILES.values())):
            generalized_arg_list.append("$POC")
            seed_file = arg
        else:
            generalized_arg_list.append(arg)
    emitter.highlight("\tUsing Arguments: " + str(generalized_arg_list))
    emitter.highlight("\tUsing Input File: " + str(seed_file))
    emitter.debug("input list in test case:" + arguments_str)
    if not values.CONF_SKIP_BUILD and not values.DEFAULT_USE_CACHE:
        builder.build_normal()
        if values.CONF_PATH_PROGRAM:
            assert os.path.isfile(values.CONF_PATH_PROGRAM)
            assert os.path.getsize(values.CONF_PATH_PROGRAM) > 0
    klee_concrete_out_dir = output_dir_path + "/klee-out-concrete-" + str(test_case_id - 1)
    emitter.highlight("\tUsing Binary: " + str(program_path))


    extractor.extract_byte_code(program_path)
    if not os.path.isfile(program_path + ".bc"):
        app.utilities.error_exit("Unable to generate bytecode for " + program_path)
    exit_code = klee.run_concrete_execution(program_path + ".bc", argument_list, True, klee_concrete_out_dir)
    assert exit_code == 0

    if not values.IS_CRASH:
        emitter.warning("\t\t[note]: the program did not crash")
        exit(0)

    # set location of bug/crash
    values.IS_CRASH = False
    c_type, c_file, c_line, c_column, _ = reader.collect_klee_crash_info(values.get_file_message_log())
    concrete_crash = ":".join([str(c_type), c_file, str(c_line), str(c_column)])
    crash_loc = ":".join([c_file, str(c_line)])
    taint_log_path = klee_concrete_out_dir + "/taint.log"

    # Retrieve concrete values from the taint.log file.
    taint_values_concrete, trace_list_concrete = reader.read_tainted_expressions(taint_log_path, crash_loc)
    values.TRACE_CONCRETE = trace_list_concrete
    values.VALUE_TRACK_CONCRETE = taint_values_concrete
    state_value_map = reader.read_state_values(taint_log_path)
    memory_track_log = klee_concrete_out_dir + "/memory.log"
    values.MEMORY_TRACK_CONCRETE = reader.read_memory_values(memory_track_log)
    pointer_track_log = klee_concrete_out_dir + "/pointer.log"
    values.POINTER_TRACK_CONCRETE = reader.read_pointer_values(pointer_track_log)
    return taint_values_concrete, state_value_map, concrete_crash


def get_tainted_values(arguments_str, program_path, output_dir_path, test_case_id):
    emitter.sub_sub_title("Running Concolic Execution")
    argument_list = app.configuration.extract_input_arg_list(arguments_str)
    generalized_arg_list = []
    second_var_list = list()
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

    emitter.highlight("\tUsing Arguments: " + str(generalized_arg_list))
    emitter.highlight("\tUsing Input File: " + str(poc_path))
    if not values.DEFAULT_USE_CACHE:
        builder.build_normal()
    extractor.extract_byte_code(program_path)
    if not os.path.isfile(program_path + ".bc"):
        app.utilities.error_exit("Unable to generate bytecode for " + program_path)

    if not os.path.isfile(program_path + ".bc"):
        app.utilities.error_exit("Unable to generate bytecode for " + program_path)
    values.ARGUMENT_LIST = generalized_arg_list
    klee_taint_out_dir = output_dir_path + "/klee-out-taint-" + str(test_case_id - 1)
    exit_code = klee.run_concolic_execution(program_path + ".bc",
                                            generalized_arg_list,
                                            second_var_list,
                                            True,
                                            klee_taint_out_dir)
    c_type, c_file, c_line, c_column, _ = reader.collect_klee_crash_info(values.get_file_message_log())
    concolic_crash = None
    if c_type is None:
        return None, concolic_crash
    concolic_crash = ":".join([str(c_type), c_file, str(c_line), str(c_column)])
    crash_loc = ":".join([c_file, str(c_line)])
    taint_log_path = klee_taint_out_dir + "/taint.log"
    # Retrieve symbolic expressions from taint.log of concolic run.
    taint_values_symbolic, trace_symbolic = reader.read_tainted_expressions(taint_log_path, crash_loc)
    values.TRACE_SYMBOLIC = trace_symbolic
    values.VALUE_TRACK_SYMBOLIC = taint_values_symbolic
    memory_track_log = klee_taint_out_dir + "/memory.log"
    values.MEMORY_TRACK_SYMBOLIC = reader.read_memory_values(memory_track_log)
    pointer_track_log = klee_taint_out_dir + "/pointer.log"
    values.POINTER_TRACK_SYMBOLIC = reader.read_pointer_values(pointer_track_log)
    return taint_values_symbolic, concolic_crash


def get_crash_values(argument_list, program_path):
    crash_info = dict()
    var_info = dict()
    var_loc_map = dict()
    c_src_file, var_list, cfc, \
        c_func_name, c_loc, c_type = extractor.extract_crash_information(program_path,
                                                                         argument_list,
                                                                         values.get_file_message_log())
    crash_info["file"] = c_src_file
    crash_info["var-list"] = var_list
    crash_info["expr"] = cfc
    crash_info["loc"] = c_loc
    crash_info["type"] = c_type
    crash_info["function"] = c_func_name

    for v in var_list:
        v_name, v_line, v_col, v_type, v_ref = v
        v_info = dict()
        static_size = None
        if v_type in definitions.INTEGER_TYPES:
            data_type = "integer"
        elif "*" in v_type or "[" in v_type:
            static_size = v_type.split("[")[-1].split("]")[0]
            data_type = "pointer"
        elif v_type in ["double", "float"]:
            data_type = "double"
        else:
            data_type = None
        v_info["data_type"] = data_type
        v_info["static_size"] = static_size
        v_info["expr_list"] = []
        var_info[v_name] = v_info
        v_loc = "{}:{}:{}".format(c_src_file, v_line, v_col)
        if any( t in v_name for t in ["size ", "base "]):
            search_ex = re.search(r'pointer, (.*?)\)\)', v_name)
            v_name = search_ex.group(1)
            #v_name = v_name.split(" ")[-1].replace(")", "")
        var_loc_map[v_loc] = v_name

    crash_info["var-info"] = var_info
    crash_info["var-loc"] = var_loc_map
    crash_type_msg = definitions.CRASH_TYPE_MESSAGE[c_type]
    emitter.information("\t\t\t[info] identified crash type: {}".format(crash_type_msg))
    return crash_info


def extract_value_list(value_map, crash_info):
    var_loc_map = crash_info["var-loc"]
    var_info = crash_info["var-info"]
    value_info = dict()
    for loc_info in value_map:
        c_file, line, col, adr = loc_info.split(":")
        expr_list = value_map[loc_info]
        loc = "{}:{}:{}".format(c_file, line, col)
        if loc in var_loc_map:
            var_name = var_loc_map[loc]
            var_type = None
            if var_name in var_info:
                var_type = var_info[var_name]["data_type"]
                if var_name not in value_info:
                    value_info[var_name] = {
                                "expr_list": [],
                                "loc": loc,
                                "data_type": var_type,
                                "static_size": var_info[var_name]["static_size"]
                            }

            for expr in expr_list:
                data_type, expr = expr.split(":")
                if data_type == var_type and var_name in value_info:
                    value_info[var_name]["expr_list"] = [expr]
                if data_type == "pointer":
                    size_expr = "(size  @var(pointer, {}))".format(var_name)
                    base_expr = "(base  @var(pointer, {}))".format(var_name)
                    diff_expr = "(diff  @var(pointer, {}))".format(var_name)
                    if size_expr in var_info:
                        value_info[size_expr] = {
                            "expr_list": [],
                            "loc": loc_info,
                            "data_type": "integer",
                            "meta_data": expr,
                            "static_size": var_info[size_expr]["static_size"]
                        }

                    if base_expr in var_info:
                       value_info[base_expr] = {
                           "expr_list": [],
                           "loc": loc_info,
                           "data_type": "pointer",
                           "meta_data": expr
                       }
                    if diff_expr in var_info:
                       value_info[diff_expr] = {
                           "expr_list": [],
                           "loc": loc_info,
                           "data_type": "integer",
                           "meta_data": expr
                       }
            if crash_info["type"] == definitions.CRASH_TYPE_ASSERTION_ERROR:
                break
    return value_info

def get_concrete_pointer(symbolic_ptr):
    pointer_tokens = symbolic_ptr.split(" ")
    if "bvadd" in pointer_tokens[0]:
        concrete_ptr = re.search(r'bvadd  \(_ bv(.*?) 64\) ', symbolic_ptr).group(1)
    else:
        concrete_ptr = pointer_tokens[1].replace("bv", "")
    return concrete_ptr


def get_base_address(symbolic_ptr, memory_track, pointer_track):
    concrete_ptr = get_concrete_pointer(symbolic_ptr)
    if str(concrete_ptr).isnumeric():
        concrete_ptr = int(concrete_ptr)
    base_address = None
    if concrete_ptr in memory_track:
        base_address = int(concrete_ptr)
    else:
        ref_address = None
        current_ptr = symbolic_ptr
        count_pointers = len(pointer_track)
        iteration = 0
        while base_address is None:
            iteration = iteration + 1
            if current_ptr not in pointer_track:
                break
            pointer_info = pointer_track[current_ptr]
            sym_address = pointer_info["base"]
            if "A-data" in sym_address or "arg" in sym_address:
                ref_address = int(sym_address.split(" ")[3].replace("bv", ""))
            else:
                ref_address = int(sym_address.split(" ")[1].replace("bv", ""))
            if ref_address in memory_track:
                base_address = ref_address
            else:
                current_ptr = sym_address
            if iteration == count_pointers:
                break

        if not base_address and ref_address:
            for address in memory_track:
                alloc_info = memory_track[address]
                alloc_range = range(int(address), int(address) + int(alloc_info["con_size"]) + 1)
                if int(ref_address) in alloc_range:
                    base_address = address
    return base_address

def get_size_pointer(base_address, memory_track, static_size):
    size_expr_list = []
    concrete_value = None
    if base_address in memory_track:
        alloc_info = memory_track[base_address]
        sym_size_expr = alloc_info["sym_size"]
        concrete_value = alloc_info["con_size"]
        if "A-data" in sym_size_expr or "arg" in sym_size_expr:
            size_expr_list = [sym_size_expr]
        elif static_size and str(static_size).isnumeric():
            size_expr_list = {"width": "1", "con_size": static_size}
            concrete_value = static_size
        else:
            sym_size_val = sym_size_expr.split(" ")[1].replace("bv", "")
            size_expr_list = {"width": alloc_info["width"], "con_size": sym_size_val}
    return size_expr_list, concrete_value


def pointer_analysis(var_info, memory_track,
                     pointer_track, taint_memory_list):
    updated_var_info = dict()
    for var_name in var_info:
        var_type = var_info[var_name]["data_type"]
        updated_var_info[var_name] = var_info[var_name]
        if "size " in var_name:
            symbolic_ptr = var_info[var_name]["meta_data"]
            static_size = var_info[var_name]["static_size"]
            base_address = get_base_address(symbolic_ptr, memory_track, pointer_track)
            meta_ptr = get_concrete_pointer(symbolic_ptr)
            if not base_address:
                symbolic_ptr = list(pointer_track.keys())[-1]
                base_address = get_base_address(symbolic_ptr, memory_track, pointer_track)
            size_expr_list, concrete_value = get_size_pointer(base_address, memory_track, static_size)
            if symbolic_ptr not in taint_memory_list:
                meta_ptr = get_base_address(f"(_ bv{meta_ptr} 64)", memory_track, pointer_track)
            updated_var_info[var_name] = {
                "expr_list": size_expr_list,
                "data_type": "integer",
                "concrete_value": concrete_value,
                "meta_data": f"bv{meta_ptr}"
            }

        elif "base " in var_name:
            symbolic_ptr = var_info[var_name]["meta_data"]
            meta_ptr = get_concrete_pointer(symbolic_ptr)
            base_address = get_base_address(symbolic_ptr, memory_track, pointer_track)
            if not base_address:
                symbolic_ptr = list(pointer_track.keys())[-1]
                base_address = get_base_address(symbolic_ptr, memory_track, pointer_track)
            if symbolic_ptr not in taint_memory_list:
                meta_ptr = get_base_address(f"(_ bv{meta_ptr} 64)", memory_track, pointer_track)
            updated_var_info[var_name] = {
                "expr_list": [f"(_ bv{base_address} 64)"],
                "data_type": "pointer",
                "meta_data": f"bv{meta_ptr}"
            }


        elif var_type == "pointer":
            symbolic_ptr = var_info[var_name]["expr_list"][0]
            base_address = get_base_address(symbolic_ptr, memory_track, pointer_track)
            if symbolic_ptr not in list(pointer_track.keys()) or \
                symbolic_ptr not in taint_memory_list:
                if base_address:
                    symbolic_ptr = f"(_ bv{base_address} 64)"
                else:
                    symbolic_ptr = list(pointer_track.keys())[-1]
            updated_var_info[var_name] = {
                "expr_list": [symbolic_ptr],
                "data_type": "pointer"
            }
    return updated_var_info


def identify_sources(var_info):
    taint_byte_list = []
    taint_memory_list = []
    for var_name in var_info:
        sym_expr_list = var_info[var_name]["expr_list"]
        var_type = var_info[var_name]["data_type"]
        byte_list = []
        if isinstance(sym_expr_list, list):
            for sym_expr in sym_expr_list:
                var_sym_expr_code = generator.generate_z3_code_for_var(sym_expr, var_name)
                byte_list = extractor.extract_input_bytes_used(var_sym_expr_code)
        byte_list = list(set(byte_list))
        taint_byte_list = taint_byte_list + byte_list
        taint_sources = sorted([str(i) for i in byte_list])
        if var_type == "pointer":
            memory_list = []
            if "size " in var_name or "base " in var_name:
                memory_list.append(var_info[var_name]["meta_data"])
            else:
                value_list = var_info[var_name]["expr_list"]
                for expr in value_list:
                    memory_address = get_concrete_pointer(expr)
                    memory_list.append(f"bv{memory_address}")
            memory_list = list(set(memory_list))
            taint_memory_list = taint_memory_list + memory_list
            tainted_addresses = sorted([str(i) for i in memory_list])
            taint_sources = taint_sources + tainted_addresses
            emitter.highlight("\t\t[info] Symbolic Mapping: {} -> [{}]".format(var_name, ",".join(taint_sources)))
        else:
            emitter.highlight("\t\t[info] Symbolic Mapping: {} -> [{}]".format(var_name, ",".join(taint_sources)))

    taint_byte_list = list(set(taint_byte_list))
    taint_memory_list = list(set(taint_memory_list))
    return taint_byte_list, taint_memory_list


def analyze():
    emitter.title("Analyzing Program")
    test_input_list = values.LIST_TEST_INPUT
    output_dir_path = definitions.DIRECTORY_OUTPUT
    test_case_id = 0
    count_seeds = len(values.LIST_SEED_INPUT)
    count_inputs = len(test_input_list)
    for argument_list in test_input_list[:count_inputs - count_seeds]:
        test_case_id = test_case_id + 1
        emitter.sub_title("Test Case #" + str(test_case_id))
        if values.LIST_TEST_BINARY:
            program_path = values.LIST_TEST_BINARY[test_case_id - 1]
            values.CONF_PATH_PROGRAM = program_path
        else:
            program_path = values.CONF_PATH_PROGRAM

        concrete_start = time.time()
        taint_values_concrete, state_values, concrete_crash = get_concrete_values(argument_list,
                                                                                  output_dir_path,
                                                                                  test_case_id,
                                                                                  program_path)
        concrete_end = time.time()
        values.TIME_CONCRETE_ANALYSIS = format((concrete_end - concrete_start) / 60, '.3f')
        crash_info = get_crash_values(argument_list, program_path)
        crash_var_concrete_info = extract_value_list(taint_values_concrete, crash_info)
        taint_memory_addresses = []
        for taint_loc in taint_values_concrete:
            if values.CONF_DIR_SRC not in taint_loc:
                continue
            expr_list = taint_values_concrete[taint_loc]
            if expr_list and "pointer" in expr_list[0]:
                for symbolic_ptr in expr_list:
                    if symbolic_ptr not in taint_memory_addresses:
                        taint_memory_addresses.append(symbolic_ptr.replace("pointer:", ""))
        con_var_info = pointer_analysis(crash_var_concrete_info,
                                        values.MEMORY_TRACK_CONCRETE,
                                        values.POINTER_TRACK_CONCRETE,
                                        taint_memory_addresses)

        concolic_start = time.time()
        taint_values_symbolic, concolic_crash = get_tainted_values(argument_list,
                                                                   program_path,
                                                                   output_dir_path,
                                                                   test_case_id)


        concolic_end = time.time()
        values.TIME_CONCOLIC_ANALYSIS = format((concolic_end - concolic_start) / 60, '.3f')

        var_info = con_var_info
        value_map = taint_values_concrete
        if concolic_crash == concrete_crash:
            taint_memory_addresses = []
            for taint_loc in taint_values_symbolic:
                if values.CONF_DIR_SRC not in taint_loc:
                    continue
                expr_list = taint_values_symbolic[taint_loc]
                if expr_list and "pointer" in expr_list[0]:
                    for symbolic_ptr in expr_list:
                        if symbolic_ptr not in taint_memory_addresses:
                            taint_memory_addresses.append(symbolic_ptr.replace("pointer:", ""))

            crash_var_symbolic_info = extract_value_list(taint_values_symbolic, crash_info)
            sym_var_info = pointer_analysis(crash_var_symbolic_info,
                                            values.MEMORY_TRACK_SYMBOLIC,
                                            values.POINTER_TRACK_SYMBOLIC,
                                            taint_memory_addresses
                                            )
            if sym_var_info:
                var_info = sym_var_info
                value_map = taint_values_symbolic
        else:
            emitter.warning("\t[warning] taint analysis failed, using concrete values")
        crash_info["var-info"] = var_info
        byte_source_list, memory_source_list = identify_sources(var_info)
        return byte_source_list, memory_source_list, value_map, crash_info, state_values
