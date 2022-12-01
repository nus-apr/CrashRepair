#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import operator
import collections
from app import emitter, oracle, definitions, generator, extractor, values, writer, solver, \
    utilities, logger, parallel, converter, constraints
import ctypes
import copy


global_candidate_mapping = collections.OrderedDict()
arithmetic_op = ["+", "-", "*", "/", "%"]
comparison_op = ["==", "!=", ">", ">=", "<", "<="]
symbol_op = arithmetic_op + comparison_op


def generate_fix_locations(marked_byte_list, taint_memory_list, taint_symbolic, cfc_info):
    emitter.sub_title("Generating Fix Locations")
    logger.track_localization("generating fix locations\n")
    fix_locations = dict()
    is_taint_influenced = len(marked_byte_list) > 0 or len(taint_memory_list) > 0
    loc_to_byte_map, source_mapping = parallel.generate_loc_to_bytes(taint_symbolic,
                                                                     is_taint_influenced)
    logger.track_localization("found {} source files".format(len(source_mapping)))
    logger.track_localization("found {} source locations".format(len(taint_symbolic)))
    emitter.highlight("\t\t[info] found " + str(len(source_mapping)) + " source files")
    logger.track_localization("generating tainted function list")
    tainted_function_list = collections.OrderedDict()
    func_count = 0
    for source_path in source_mapping:
        tainted_loc_list = source_mapping[source_path]
        source_dir = values.CONF_DIR_EXPERIMENT + "/src/"
        source_dir = source_dir.replace("//", "/")
        if source_dir not in source_path:
            continue
        ast_tree = extractor.extract_ast_json(source_path)
        function_node_list = extractor.extract_function_node_list(ast_tree)
        for func_name, func_node in function_node_list.items():
            func_range = func_node["range"]
            f_line_range = extractor.extract_line_range(source_path, func_range)
            for loc in tainted_loc_list:
                line, col = loc
                if int(line) in f_line_range:
                    if source_path not in tainted_function_list:
                        tainted_function_list[source_path] = dict()
                    if func_name not in tainted_function_list[source_path]:
                        func_count = func_count + 1
                        tainted_function_list[source_path][func_name] = list()
                    tainted_function_list[source_path][func_name].append(loc)

    logger.track_localization("found {} executed functions".format(func_count))
    emitter.highlight("\t\t[info] found " + str(func_count) + " executed functions")
    logger.track_localization("filtering tainted locations for fix")
    for source_path in tainted_function_list:
        if not is_taint_influenced and source_path != cfc_info["file"]:
            continue
        function_list = tainted_function_list[source_path]
        for func_name in function_list:
            if not is_taint_influenced and func_name != cfc_info["function"]:
                    continue
            func_loc_list = function_list[func_name]
            observed_tainted_bytes = set()
            for loc in sorted(func_loc_list):
                source_loc = source_path + ":" + ":".join(loc)
                if not is_taint_influenced:
                    fix_locations[source_loc] = func_name
                else:
                    observed_tainted_bytes.update(loc_to_byte_map[source_loc])
                    if not observed_tainted_bytes:
                        continue
                    if set(marked_byte_list) <= set(observed_tainted_bytes):
                        fix_locations[source_loc] = func_name
    logger.track_localization("found {} fix locations".format(len(fix_locations)))
    logger.track_localization("sorting fix location based on trace")
    sorted_fix_locations = []
    cached_list = []
    emitter.normal("\tgenerating possible fix locations")
    for taint_info in taint_symbolic.keys():
        src_file, line, col, inst_addr = taint_info.split(":")
        taint_loc = ":".join([src_file, line, col])
        if taint_loc in fix_locations and taint_loc not in cached_list:
            sorted_fix_locations.append((fix_locations[taint_loc], taint_loc))
            emitter.highlight("\t\t[fix-loc] {}, {}".format(fix_locations[taint_loc],taint_loc))
            cached_list.append(taint_loc)
    logger.track_localization("found {} unique fix locations".format(len(sorted_fix_locations)))
    return sorted_fix_locations


def get_candidate_map_for_func(function_name, taint_symbolic, src_file, function_ast, cfc_var_info_list):
    global global_candidate_mapping
    if function_name in global_candidate_mapping:
        return global_candidate_mapping[function_name]
    function_range = function_ast["range"]
    func_line_range = extractor.extract_line_range(src_file, function_range)

    var_info_list = extractor.extract_var_list(function_ast, src_file)
    expr_info_list = extractor.extract_expression_list(function_ast, src_file)
    expr_taint_list = collections.OrderedDict()
    logger.track_localization("generating candidate map for function {} in {}".format(function_name, src_file))
    logger.track_localization("CFC VAR LIST: {}".format(cfc_var_info_list))
    logger.track_localization("VAR LIST: {}".format(var_info_list))
    logger.track_localization("EXPR LIST: {}".format(expr_info_list))

    for taint_info in taint_symbolic:
        c_file, line, col, inst_add = taint_info.split(":")
        taint_expr_list = taint_symbolic[taint_info]
        if src_file != c_file:
            continue
        if int(line) not in func_line_range:
            continue
        for expr_info in (var_info_list+expr_info_list):
            e_str, e_line, e_col, e_type, dec_or_ref = expr_info
            if int(e_line) == int(line) and int(col) == int(e_col):
            # if int(e_line) == int(line) and int(col) in range(int(e_col), int(e_col) + len(e_str)):
                # print(var_name, v_line, v_col, line, col, range(int(v_col), int(v_col) + len(var_name)))
                var_info_index = (e_str, e_line, e_col, inst_add)
                if var_info_index not in expr_taint_list:
                    filtered_taint_list = []
                    data_type = None
                    for taint_expr in taint_expr_list:
                        data_type, taint_expr = taint_expr.split(":")
                        if data_type == "integer" and e_type not in definitions.INTEGER_TYPES:
                            continue
                        if data_type == "pointer" and "*" not in e_type and "[" not in e_type:
                            continue
                        if data_type == "double" and e_type != "double":
                            continue
                        filtered_taint_list.append(taint_expr)
                    expr_taint_list[var_info_index] = {
                        "expr_list": filtered_taint_list,
                        "data_type": data_type,
                        "is_dec": dec_or_ref == "dec"
                    }
    # print(var_taint_list)
    logger.track_localization("VAR TAINT LIST: {}".format(expr_taint_list))
    candidate_mapping = collections.OrderedDict()
    for crash_var_name in cfc_var_info_list:
        crash_var_type = cfc_var_info_list[crash_var_name]['data_type']
        crash_var_expr_list = cfc_var_info_list[crash_var_name]['expr_list']
        if "sizeof " in crash_var_name:
            crash_var_expr_list = ["(_ {} 64)".format(crash_var_expr_list["size"])]
        for crash_var_expr in crash_var_expr_list:
            found_mapping = False
            subset_var_list = list()
            crash_var_sym_expr_code = generator.generate_z3_code_for_var(crash_var_expr, crash_var_name)
            crash_var_input_byte_list = extractor.extract_input_bytes_used(crash_var_sym_expr_code)
            for expr_taint_info in expr_taint_list:
                expr_str, e_line, e_col, e_addr = expr_taint_info
                var_expr_list = expr_taint_list[expr_taint_info]["expr_list"]
                e_type = expr_taint_list[expr_taint_info]["data_type"]
                is_exp_dec = expr_taint_list[expr_taint_info]["is_dec"]
                if e_type != crash_var_type:
                    # print("SKIP", crash_var_name, var_name, crash_var_type, v_type)
                    logger.track_localization("SKIP {} with {}".format((crash_var_name, crash_var_type),
                                                                       (expr_str, e_type, e_line, e_col, )))
                    continue
                # print("MATCH", crash_var_name, var_name, crash_var_type, v_type)
                logger.track_localization("MATCH {} with {}".format((crash_var_name, crash_var_type),
                                                                   (expr_str, e_type, e_line, e_col)))
                for var_expr in var_expr_list:
                    var_sym_expr_code = generator.generate_z3_code_for_var(var_expr, expr_str)
                    var_input_byte_list = extractor.extract_input_bytes_used(var_sym_expr_code)
                    if not var_input_byte_list and not crash_var_input_byte_list:
                        if crash_var_type == "pointer" and e_type == "pointer":
                            if var_expr in crash_var_expr_list:
                                if crash_var_name not in candidate_mapping:
                                    candidate_mapping[crash_var_name] = set()
                                logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                                logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                                logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                                candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                        elif oracle.is_expr_list_match(crash_var_expr_list, var_expr_list):
                            if crash_var_name not in candidate_mapping:
                                candidate_mapping[crash_var_name] = set()
                            logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                            logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                            logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                            candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                        else:
                            crash_var_expr_list = cfc_var_info_list[crash_var_name]['expr_list']
                            if "width" in crash_var_expr_list:
                                crash_size_bits = int(crash_var_expr_list["size"].replace("bv", ""))
                                crash_size_width = int(crash_var_expr_list["width"])
                                crash_size_bytes = int(crash_size_bits / 4)
                                if crash_size_width > 0:
                                    crash_size_bytes = int(crash_size_bits/crash_size_width)
                                var_size_bytes = 0
                                if "bv" in var_expr:
                                    var_size_bytes = int(var_expr.split(" ")[1].replace("bv", ""))
                                if crash_var_name not in candidate_mapping:
                                    candidate_mapping[crash_var_name] = set()
                                if var_size_bytes == crash_size_bytes:
                                    candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                                else:
                                    candidate_mapping[crash_var_name].add((str(crash_size_bytes), e_line, e_col, e_addr, is_exp_dec))
                                logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                                logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                                logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                    elif var_input_byte_list == crash_var_input_byte_list:
                        z3_eq_code = generator.generate_z3_code_for_equivalence(var_sym_expr_code,
                                                                                crash_var_sym_expr_code)
                        if oracle.is_satisfiable(z3_eq_code):
                            found_mapping = True
                            if crash_var_name not in candidate_mapping:
                                candidate_mapping[crash_var_name] = set()
                            logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                            logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                            logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                            candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                        else:
                            z3_offset_code = generator.generate_z3_code_for_offset(var_sym_expr_code,
                                                                                   crash_var_sym_expr_code)
                            if oracle.is_satisfiable(z3_offset_code):
                                found_mapping = True
                                offset = solver.get_offset(z3_offset_code)
                                if len(str(offset)) > 16:
                                    number = offset & 0xFFFFFFFF
                                    offset = ctypes.c_long(number).value
                                if offset < 1000:
                                    mapping = "({} - {})".format(expr_str, offset)
                                    if crash_var_name not in candidate_mapping:
                                        candidate_mapping[crash_var_name] = set()
                                    logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                                    logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                                    logger.track_localization("{}->[{}]".format(mapping, var_expr_list))
                                    candidate_mapping[crash_var_name].add((mapping, e_line, e_col, e_addr, is_exp_dec))
                    elif set(var_input_byte_list) <= set(crash_var_input_byte_list):
                        subset_var_list.append((expr_str, var_expr))
            # if not found_mapping and subset_var_list:
            #     sub_expr_mapping = localize_sub_expr(crash_var_expr, subset_var_list)
    global_candidate_mapping[function_name] = candidate_mapping
    return candidate_mapping


def localize_cfc(taint_loc, cfc_info, taint_symbolic):
    localized_cfc = None
    candidate_constraints = list()
    candidate_locations = set()
    src_file, taint_line, taint_col = taint_loc.split(":")
    crash_loc = cfc_info["loc"]
    cfc_expr = cfc_info["expr"]
    cfc_var_info_list = cfc_info["var-info"]
    # cfc_expr.resolve_sizeof(cfc_var_info_list)
    cfc_expr_str = cfc_expr.to_string()
    func_name, function_ast = extractor.extract_func_ast(src_file, taint_line)
    candidate_mapping = get_candidate_map_for_func(func_name, taint_symbolic, src_file,
                                                   function_ast, cfc_var_info_list)

    cfc_tokens = cfc_expr.get_symbol_list()
    cfc_token_mappings = []
    for c_t_lookup in cfc_tokens:
        if c_t_lookup in candidate_mapping:
            cfc_token_mappings.append((c_t_lookup, len(candidate_mapping[c_t_lookup])))
    sorted_cfc_tokens = sorted(cfc_token_mappings, key=lambda x:x[1])
    sorted_cfc_tokens = [x[0] for x in sorted_cfc_tokens]
    logger.track_localization("CFC Tokens {}".format(sorted_cfc_tokens))
    logger.track_localization("Candidate Map {}".format(candidate_mapping))
    for c_t_lookup in sorted_cfc_tokens:
        if c_t_lookup in candidate_mapping:
            candidate_list = candidate_mapping[c_t_lookup]
            for candidate in candidate_list:
                c_mapping, c_line, c_col, _, is_dec = candidate
                if int(c_line) > int(taint_line):
                    continue
                if int(c_line) == int(taint_line) and is_dec:
                    continue
                if int(c_line) == int(taint_line) and int(c_col) > int(taint_col):
                    continue
                candidate_locations.add((int(c_line), int(c_col)))
                candidate_locations.add((int(taint_line), int(taint_col)))
    sorted_candidate_locations = sorted(candidate_locations, key=operator.itemgetter(0, 1))
    logger.track_localization("Sorted Locations {}".format(sorted_candidate_locations))
    for candidate_loc in sorted_candidate_locations:
        localized_tokens = collections.OrderedDict()
        used_candidates = list()
        candidate_line, candidate_col = candidate_loc
        for c_t_lookup in sorted_cfc_tokens:
            if c_t_lookup in symbol_op or str(c_t_lookup).isnumeric():
                continue
            if c_t_lookup in candidate_mapping:
                c_t_map = candidate_mapping[c_t_lookup]
                selected_expr = None
                selected_line = 0
                selected_col = 0
                for mapping in c_t_map:
                    m_expr, m_line, m_col, _, is_dec = mapping
                    if m_line > candidate_line:
                        continue
                    if selected_line > m_line:
                        continue
                    if m_line == candidate_line and is_dec:
                        continue
                    selected_expr = m_expr
                    if selected_expr in used_candidates:
                        continue
                    selected_col = m_col
                    selected_line = m_line
                    if selected_expr:
                        if c_t_lookup in localized_tokens:
                            current_mapping = localized_tokens[c_t_lookup]
                            if current_mapping != c_t_lookup:
                                if len(current_mapping) > len(selected_expr):
                                    localized_tokens[c_t_lookup] = selected_expr
                                    used_candidates.append(selected_expr)
                        else:
                            localized_tokens[c_t_lookup] = selected_expr
                            used_candidates.append(selected_expr)
        logger.track_localization("Localized Tokens {}".format(localized_tokens))
        if len(localized_tokens.keys()) == len(sorted_cfc_tokens):
            localized_cfc = copy.deepcopy(cfc_expr)
            localized_cfc.update_symbols(localized_tokens)
            candidate_constraints.append((localized_cfc, candidate_line, candidate_col))

    # identify potential expression replacements
    expression_string_list = extractor.extract_expression_string_list(function_ast, src_file)
    updated_candidate_constraints = list()
    for candidate_constraint in candidate_constraints:
        candidate_cfc, candidate_line, candidate_col = candidate_constraint
        candidate_loc = (candidate_line, candidate_col)
        if candidate_loc in expression_string_list:
            expression_str = expression_string_list[candidate_loc]
            cfc_rhs_str = candidate_cfc.get_r_expr().to_expression()
            cfc_lhs_str = candidate_cfc.get_l_expr().to_expression()
            # print("CANDIDATE", candidate_loc)
            # print(cfc_lhs_str)
            # print(cfc_rhs_str)
            # print(expression_str)
            if "sizeof " not in cfc_lhs_str:
                if oracle.is_expression_equal(cfc_lhs_str, expression_str):
                    # print("MATCH LHS", localized_cfc.to_string(), expression_str)
                    result_symbol = constraints.make_constraint_symbol(expression_str, "RESULT_INT")
                    result_expr = constraints.make_symbolic_expression(result_symbol)
                    candidate_cfc.set_l_expr(result_expr)
                    updated_candidate_constraints.append((candidate_cfc, candidate_line, candidate_col))
                    continue
            if "sizeof " not in cfc_rhs_str:
                if oracle.is_expression_equal(cfc_rhs_str, expression_str):
                    # print("MATCH RHS", localized_cfc.to_string(), expression_str)
                    result_symbol = constraints.make_constraint_symbol(expression_str, "RESULT_INT")
                    result_expr = constraints.make_symbolic_expression(result_symbol)
                    candidate_cfc.set_r_expr(result_expr)
                    updated_candidate_constraints.append((candidate_cfc, candidate_line, candidate_col))
                    continue
        updated_candidate_constraints.append(candidate_constraint)
    return candidate_constraints


def localize_state_info(fix_loc, taint_concrete):
    """
        Extracts for the given fix location the corresponding variable values, which are
        in the scope and tracked by the taint analysis.
    """
    src_file, fix_line, fix_col = fix_loc.split(":")
    func_name, function_ast = extractor.extract_func_ast(src_file, fix_line)
    func_line_range = extractor.extract_line_range(src_file, function_ast["range"])
    var_info_list = extractor.extract_var_list(function_ast, src_file)
    state_info_list_values = dict()
    taint_info_listed_occurences = taint_concrete[fix_loc]
    for occurence in range(len(taint_info_listed_occurences)):
        taint_info_list = taint_info_listed_occurences[occurence]
        state_info_list_values[occurence] = dict()
        for taint_loc, taint_value in taint_info_list.items():
            c_file, taint_line, taint_col, inst_addr = taint_loc.split(":")
            if src_file != c_file:
                continue
            if int(taint_line) not in func_line_range:
                continue
            if int(taint_line) > int(fix_line):
                continue
            for var_info in var_info_list:
                var_name, v_line, v_col, v_type, _ = var_info
                if "argv" in var_name:
                    continue
                if int(v_col) == int(taint_col) and int(v_line) == int(taint_line):
                    # Remove previous values for the same variable at a different line.
                    outdated_entries = [(var_name_a, v_line_a, v_col_a, var_type_a) for (var_name_a, v_line_a, v_col_a, var_type_a) in state_info_list_values[occurence].keys() if var_name_a == var_name and var_type_a == v_type and v_line_a != v_line]
                    for entry in outdated_entries:
                        del state_info_list_values[occurence][entry]

                    # Create index.
                    var_type, var_value = taint_value.split(":")
                    var_info_index = (var_name, v_line, v_col, var_type)

                    # We only want to to keep the last value for variable at a specific location (line+column).
                    # However, we can have multiple instructions mapped to one variable, hence, we need to filter.
                    if var_info_index in state_info_list_values[occurence]:
                        other_state_info = state_info_list_values[occurence][var_info_index]
                        if int(other_state_info["inst_addr"]) >= int(inst_addr):
                            continue

                    state_info_list_values[occurence][var_info_index] = {
                        "inst_addr": inst_addr,
                        "values": var_value
                    }
    return state_info_list_values


def fix_localization(taint_byte_list, taint_memory_list, taint_symbolic, cfc_info, taint_concrete):
    emitter.title("Fix Localization")
    tainted_fix_locations = generate_fix_locations(taint_byte_list, taint_memory_list, taint_symbolic, cfc_info)
    definitions.FILE_LOCALIZATION_INFO = definitions.DIRECTORY_OUTPUT + "/localization.json"
    localization_list = list()
    localized_loc_list = list()
    emitter.sub_title("Localizing Constraints")
    for func_name, tainted_fix_loc in tainted_fix_locations:
        src_file = tainted_fix_loc.split(":")[0]
        logger.track_localization("[taint-loc] {}:{}".format(func_name, tainted_fix_loc))
        candidate_constraints = localize_cfc(tainted_fix_loc, cfc_info, taint_symbolic)
        logger.track_localization("[constraints] {}".format(candidate_constraints))
        for candidate_info in candidate_constraints:
            localization_obj = collections.OrderedDict()
            localized_cfc, localized_line, localized_col = candidate_info
            localized_loc = ":".join([src_file, str(localized_line), str(localized_col)])
            if localized_loc in localized_loc_list:
                continue
            localized_loc_list.append(localized_loc)
            # location is not precise with assignments, hence avoid localization if location is not in taint map
            if localized_loc not in taint_concrete:
                continue
            state_info_list_values = localize_state_info(localized_loc, taint_concrete)
            emitter.sub_sub_title("[fix-loc] {}".format(localized_loc))
            localization_obj["location"] = localized_loc
            localization_obj["constraint"] = localized_cfc.to_string()
            # localization_obj["constraint-ast"] = localized_cfc.to_json()
            emitter.highlight("\t[constraint] {}".format(localized_cfc.to_string()))

            fieldnames = []
            rows = []
            variables = []
            for occurence in state_info_list_values:
                row = dict()
                for var_info, var_content in state_info_list_values[occurence].items():
                    var_name, line, col, var_type = var_info
                    var_value = var_content["values"]
                    inst_addr = int(var_content["inst_addr"])

                    var_meta_data = {
                        "name": var_name,
                        "line": line,
                        "column": col,
                        "instruction-address": inst_addr,
                        "type": var_type
                    }

                    if var_meta_data not in variables:
                        variables.append(var_meta_data)
                    
                    if var_type == "pointer":
                        var_id = var_name
                    else:
                        var_id = "*" + var_name

                    if var_id not in fieldnames:
                        fieldnames.append(var_id)

                    row[var_id] = var_value
                rows.append(row)
            # Fill in missing values
            for row in rows:
                for var_id in fieldnames:
                    if var_id not in row:
                        row[var_id] = "none"
            localization_obj["variables"] = variables
            values_directory = os.path.join(definitions.DIRECTORY_OUTPUT, "values")
            rel_output_filename = f"{localized_loc.replace('/', '#')}.csv"
            abs_output_filepath = os.path.join(values_directory, rel_output_filename)
            writer.write_as_csv(fieldnames, rows, abs_output_filepath)
            localization_obj["values-file"] = rel_output_filename

            localization_list.append(localization_obj)
    if not localization_list:
        emitter.error("Unable to Localize a Crash Free Constraint")
        utilities.error_exit("Analysis Failed")
    writer.write_as_json(localization_list, definitions.FILE_LOCALIZATION_INFO)
    emitter.success("\n\tlocalization information saved at {}".format(definitions.FILE_LOCALIZATION_INFO))
    emitter.success("\n\tstate values saved at {}{}".format(definitions.DIRECTORY_OUTPUT, '/values/'))
