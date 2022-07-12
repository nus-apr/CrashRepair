#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import collections
from app import emitter, oracle, definitions, generator, extractor, values, writer, solver, constraints
import ctypes
import copy


global_candidate_mapping = collections.OrderedDict()
arithmetic_op = ["+", "-", "*", "/", "%"]
comparison_op = ["==", "!=", ">", ">=", "<", "<="]
symbol_op = arithmetic_op + comparison_op


def generate_fix_locations(marked_byte_list, taint_map):
    emitter.sub_title("Generating Fix Locations")
    fix_locations = dict()
    loc_to_byte_map = collections.OrderedDict()
    for taint_info in taint_map:
        src_file, line, col, inst_addr = taint_info.split(":")
        taint_loc = ":".join([src_file, line, col])
        taint_expr_list = taint_map[taint_info]['symbolic-list']
        for taint_value in taint_expr_list:
            sym_expr_code = generator.generate_z3_code_for_var(taint_value, "TAINT")
            tainted_bytes = extractor.extract_input_bytes_used(sym_expr_code)
            if not tainted_bytes and len(taint_value) > 16:
                tainted_bytes = [taint_value.split(" ")[1]]
            if taint_loc not in loc_to_byte_map:
                loc_to_byte_map[taint_loc] = set()
            loc_to_byte_map[taint_loc].update(set(tainted_bytes))
    source_mapping = collections.OrderedDict()
    for taint_loc in taint_map:
        source_path, line_number, col_number, _ = taint_loc.split(":")
        if source_path not in source_mapping:
            source_mapping[source_path] = set()
        source_mapping[source_path].add((line_number, col_number))
    tainted_function_list = collections.OrderedDict()
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
                        tainted_function_list[source_path][func_name] = list()
                    tainted_function_list[source_path][func_name].append(loc)

    for source_path in tainted_function_list:
        function_list = tainted_function_list[source_path]
        for func_name in function_list:
            func_loc_list = function_list[func_name]
            for loc in sorted(func_loc_list):
                source_loc = source_path + ":" + ":".join(loc)
                observed_tainted_bytes = loc_to_byte_map[source_loc]
                if not observed_tainted_bytes:
                    continue
                if set(marked_byte_list) <= set(observed_tainted_bytes):
                    fix_locations[source_loc] = func_name
                    break
    sorted_fix_locations = []
    cached_list = []
    for taint_info in taint_map.keys():
        src_file, line, col, inst_addr = taint_info.split(":")
        taint_loc = ":".join([src_file, line, col])
        if taint_loc in fix_locations and taint_loc not in cached_list:
            sorted_fix_locations.append((fix_locations[taint_loc], taint_loc))
            cached_list.append(taint_loc)
    return sorted_fix_locations


def get_candidate_map_for_func(function_name, taint_map, src_file, function_ast, cfc_var_info_list):
    global global_candidate_mapping
    if function_name in global_candidate_mapping:
        return global_candidate_mapping[function_name]
    function_range = function_ast["range"]
    func_line_range = extractor.extract_line_range(src_file, function_range)
    var_info_list = extractor.extract_var_list(function_ast, src_file)
    var_taint_list = collections.OrderedDict()
    for taint_info in taint_map:
        c_file, line, col, inst_add = taint_info.split(":")
        taint_expr_list = taint_map[taint_info]['symbolic-list']
        if src_file != c_file:
            continue
        if int(line) not in func_line_range:
            continue
        for var_info in var_info_list:
            var_name, v_line, v_col, v_type = var_info
            if int(v_col) == int(col) and int(v_line) == int(line):
                var_info_index = (var_name, v_line, v_col, inst_add)
                if var_info_index not in var_taint_list:
                    var_taint_list[var_info_index] = taint_expr_list
    candidate_mapping = collections.OrderedDict()
    for crash_var_name in cfc_var_info_list:
        crash_var_expr_list = cfc_var_info_list[crash_var_name]['expr_list']
        for crash_var_expr in crash_var_expr_list:
            found_mapping = False
            subset_var_list = list()
            crash_var_sym_expr_code = generator.generate_z3_code_for_var(crash_var_expr, crash_var_name)
            crash_var_input_byte_list = extractor.extract_input_bytes_used(crash_var_sym_expr_code)
            for var_taint_info in var_taint_list:
                var_name, v_line, v_col, v_addr = var_taint_info
                var_expr_list = var_taint_list[var_taint_info]
                for var_expr in var_expr_list:
                    var_sym_expr_code = generator.generate_z3_code_for_var(var_expr, var_name)
                    var_input_byte_list = extractor.extract_input_bytes_used(var_sym_expr_code)
                    if not var_input_byte_list and not crash_var_input_byte_list:
                        if crash_var_expr_list == var_expr_list:
                            if crash_var_name not in candidate_mapping:
                                candidate_mapping[crash_var_name] = set()
                            candidate_mapping[crash_var_name].add((var_name, v_line, v_col, v_addr))
                    if var_input_byte_list == crash_var_input_byte_list:
                        z3_eq_code = generator.generate_z3_code_for_equivalence(var_sym_expr_code,
                                                                                crash_var_sym_expr_code)
                        if oracle.is_satisfiable(z3_eq_code):
                            found_mapping = True
                            if crash_var_name not in candidate_mapping:
                                candidate_mapping[crash_var_name] = set()
                            candidate_mapping[crash_var_name].add((var_name, v_line, v_col, v_addr))
                        else:
                            z3_offset_code = generator.generate_z3_code_for_offset(var_sym_expr_code,
                                                                                   crash_var_sym_expr_code)
                            if oracle.is_satisfiable(z3_offset_code):
                                found_mapping = True
                                offset = solver.get_offset(z3_offset_code)
                                if len(str(offset)) > 16:
                                    number = offset & 0xFFFFFFFF
                                    offset = ctypes.c_long(number).value
                                mapping = "({} - {})".format(var_name, offset)
                                if crash_var_name not in candidate_mapping:
                                    candidate_mapping[crash_var_name] = set()
                                candidate_mapping[crash_var_name].add((mapping, v_line, v_col, v_addr))
                    elif set(var_input_byte_list) <= set(crash_var_input_byte_list):
                        subset_var_list.append((var_name, var_expr))
            # if not found_mapping and subset_var_list:
            #     sub_expr_mapping = localize_sub_expr(crash_var_expr, subset_var_list)

    global_candidate_mapping[function_name] = candidate_mapping
    return candidate_mapping


def localize_cfc(taint_loc, cfc_info, taint_map):
    localized_cfc = None
    candidate_constraints = list()
    candidate_locations = list()
    src_file, taint_line, taint_col = taint_loc.split(":")
    crash_loc = cfc_info["loc"]
    cfc_expr = cfc_info["expr"]
    # cfc_expr_str = cfc_expr.to_string()
    cfc_var_info_list = cfc_info["var-info"]
    func_name, function_ast = extractor.extract_func_ast(src_file, taint_line)
    candidate_mapping = get_candidate_map_for_func(func_name, taint_map, src_file,
                                                   function_ast, cfc_var_info_list)
    cfc_tokens = cfc_expr.get_symbol_list()
    for c_t in cfc_tokens:
        c_t_lookup = c_t.replace("(", "").replace(")", "")
        if c_t_lookup in candidate_mapping:
            candidate_list = candidate_mapping[c_t_lookup]
            for candidate in candidate_list:
                c_mapping, c_line, c_col, _ = candidate
                if int(c_line) < int(taint_line):
                    continue
                if int(c_line) == int(taint_line) and int(c_col) < int(taint_col):
                    continue
                candidate_locations.append((c_line, c_col))

    for candidate_loc in candidate_locations:
        localized_tokens = dict()
        candidate_line, candidate_col = candidate_loc
        for c_t in cfc_tokens:
            c_t_lookup = c_t.replace("(", "").replace(")", "")
            if c_t_lookup in symbol_op or str(c_t_lookup).isnumeric():
                continue
            if c_t_lookup in candidate_mapping:
                c_t_map = candidate_mapping[c_t_lookup]
                selected_expr = None
                selected_line = 0
                selected_col = 0
                for mapping in c_t_map:
                    m_expr, m_line, m_col, _ = mapping
                    if m_line > candidate_line or (m_line == candidate_line
                                                   and m_col > candidate_col):
                        continue
                    if selected_line > m_line or (selected_line == m_line
                                                   and selected_col > m_col):
                        continue
                    selected_expr = m_expr
                    selected_col = m_col
                    selected_line = m_line

                if selected_expr:
                    localized_tokens[c_t_lookup] = selected_expr
            else:
                localized_tokens = dict()
                break
        if localized_tokens:
            localized_cfc = copy.deepcopy(cfc_expr)
            localized_cfc.update_symbols(localized_tokens)
            candidate_constraints.append((localized_cfc, candidate_line, candidate_col))
    return candidate_constraints


def localize_state_info(fix_loc, taint_map):
    state_info_list = dict()
    src_file, fix_line, fix_col = fix_loc.split(":")
    func_name, function_ast = extractor.extract_func_ast(src_file, fix_line)
    func_line_range = extractor.extract_line_range(src_file, function_ast["range"])
    var_info_list = extractor.extract_var_list(function_ast, src_file)
    for taint_info in taint_map:
        c_file, taint_line, taint_col, inst_add = taint_info.split(":")
        taint_value_list = taint_map[taint_info]['concrete-list']

        if src_file != c_file:
            continue
        if int(taint_line) not in func_line_range:
            continue
        if int(taint_line) > int(fix_line):
            continue

        for var_info in var_info_list:
            var_name, v_line, v_col, v_type = var_info
            if "argv" in var_name:
                continue
            if int(v_col) == int(taint_col) and int(v_line) == int(taint_line):
                var_info_index = (var_name, v_line, v_col, inst_add)
                if var_info_index not in state_info_list:
                    state_info_list[var_info_index] = taint_value_list
    return state_info_list


def fix_localization(input_byte_list, taint_map, cfc_info):
    emitter.title("Fix Localization")
    tainted_fix_locations = generate_fix_locations(input_byte_list, taint_map)
    for taint_loc in tainted_fix_locations:
        emitter.highlight("\t[taint-loc] {}".format(taint_loc))
    definitions.FILE_LOCALIZATION_INFO = definitions.DIRECTORY_OUTPUT + "/localization.json"
    localization_list = list()
    for func_name, tainted_fix_loc in tainted_fix_locations:
        src_file = tainted_fix_loc.split(":")[0]
        candidate_constraints = localize_cfc(tainted_fix_loc, cfc_info, taint_map)
        for candidate_info in candidate_constraints:
            localization_obj = dict()
            localized_cfc, localized_line, localized_col = candidate_info
            localized_loc = ":".join([src_file, str(localized_line), str(localized_col)])
            state_info = localize_state_info(localized_loc, taint_map)
            emitter.sub_sub_title("[fix-loc] {}".format(localized_loc))
            localization_obj["fix-location"] = localized_loc
            localization_obj["constraint"] = localized_cfc.to_json()
            localization_obj["state"] = list()
            emitter.highlight("\t[constraint] {}".format(localized_cfc.to_string()))
            emitter.highlight("\t[state information]:")
            emitter.highlight("\t" + "="*60)
            for state in state_info:
                state_obj = dict()
                var_name, line, col, inst_addr = state
                value_list = state_info[state]
                state_obj["variable-name"] = var_name
                state_obj["source-location"] = ":".join([src_file, str(line), str(col)])
                state_obj["instruction-address"] = int(inst_addr)
                state_obj["value-list"] = value_list
                print_list = [str(x) for x in value_list[:5]]
                localization_obj["state"].append(state_obj)
                state_str = "[var-name] : {0:20}".format(var_name)
                state_str += " [var-loc] {0:4},{0:4}".format(line, col)
                state_str += " [instruction-address]: {0:4}".format(inst_addr)
                state_str += " [values]: {0:20}".format(",".join(print_list))
                emitter.information("\t\t{ " + state_str + " }")
            localization_list.append(localization_obj)
    writer.write_as_json(localization_list, definitions.FILE_LOCALIZATION_INFO)
    emitter.success("\n\tlocalization information saved at {}".format(definitions.FILE_LOCALIZATION_INFO))

