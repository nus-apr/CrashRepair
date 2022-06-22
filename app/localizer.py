#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import collections
from app import emitter, oracle, definitions, generator, extractor, values, writer


def generate_fix_locations(input_byte_list, taint_map):
    emitter.sub_title("Generating Fix Locations")
    fix_locations = dict()
    line_to_byte_map = collections.OrderedDict()
    for taint_info in taint_map:
        src_file, line, col, inst_addr = taint_info.split(":")
        taint_loc = ":".join([src_file, line])
        taint_expr_list = taint_map[taint_info]['symbolic-list']
        for taint_value in taint_expr_list:
            sym_expr_code = generator.generate_z3_code_for_var(taint_value, "TAINT")
            tainted_bytes = extractor.extract_input_bytes_used(sym_expr_code)
            if not tainted_bytes and len(taint_value) > 16:
                tainted_bytes = [taint_value.split(" ")[1]]
            if taint_loc not in line_to_byte_map:
                line_to_byte_map[taint_loc] = set()
            line_to_byte_map[taint_loc].update(set(tainted_bytes))
    source_mapping = collections.OrderedDict()
    for taint_loc in taint_map:
        source_path, line_number, _, _ = taint_loc.split(":")
        if source_path not in source_mapping:
            source_mapping[source_path] = set()
        source_mapping[source_path].add(line_number)
    tainted_function_list = collections.OrderedDict()
    for source_path in source_mapping:
        tainted_line_list = source_mapping[source_path]
        source_dir = values.CONF_DIR_EXPERIMENT + "/src/"
        ast_tree = extractor.extract_ast_json(source_path)
        function_node_list = extractor.extract_function_node_list(ast_tree)
        for func_name, func_node in function_node_list.items():
            func_range = range(func_node["start line"], func_node["end line"])
            for line in tainted_line_list:
                if int(line) in func_range:
                    if source_path not in tainted_function_list:
                        tainted_function_list[source_path] = dict()
                    if func_name not in tainted_function_list[source_path]:
                        tainted_function_list[source_path][func_name] = list()
                    tainted_function_list[source_path][func_name].append(line)

    for source_path in tainted_function_list:
        function_list = tainted_function_list[source_path]
        for func_name in function_list:
            func_line_list = function_list[func_name]
            for line in sorted(func_line_list):
                source_line = source_path + ":" + str(line)
                observed_tainted_bytes = line_to_byte_map[source_line]
                if not observed_tainted_bytes:
                    continue
                if set(input_byte_list) <= set(observed_tainted_bytes):
                    fix_locations[source_line] = func_name
                    break
    sorted_fix_locations = []
    cached_list = []
    for taint_info in taint_map.keys():
        src_file, line, col, inst_addr = taint_info.split(":")
        taint_loc = ":".join([src_file, line])
        if taint_loc in fix_locations and taint_loc not in cached_list:
            sorted_fix_locations.append((fix_locations[taint_loc], taint_loc))
            cached_list.append(taint_loc)
    return sorted_fix_locations


def localize_cfc(fix_loc, cfc_info, taint_map):
    localized_cfc = None
    taint_info_at_loc = dict()
    src_file, line = fix_loc.split(":")
    crash_loc = cfc_info["loc"]
    cfc_expr = cfc_info["expr"]
    cfc_var_info_list = cfc_info["var-info"]
    if crash_loc == fix_loc:
        return cfc_expr, line
    func_name, function_ast = extractor.extract_func_ast(src_file, line)
    function_range = range(function_ast["start line"], function_ast["end line"])
    var_info_list = extractor.extract_var_list(function_ast)
    var_taint_list = dict()
    for taint_info in taint_map:
        c_file, line, col, inst_add = taint_info.split(":")
        taint_expr_list = taint_map[taint_info]['symbolic-list']
        if src_file != c_file:
            continue
        if int(line) not in function_range:
            continue
        for var_info in var_info_list:
            var_name, v_line, v_col, v_type = var_info
            if int(v_col) == int(col) and int(v_line) == int(line):
                var_info_index = (var_name, v_line, v_col)
                if var_info_index not in var_taint_list:
                    var_taint_list[var_info_index] = taint_expr_list
    candidate_var_list = dict()
    for crash_var_name in cfc_var_info_list:
        crash_var_expr_list = cfc_var_info_list[crash_var_name]['expr_list']
        for crash_var_expr in crash_var_expr_list:
            crash_var_sym_expr_code = generator.generate_z3_code_for_var(crash_var_expr, crash_var_name)
            crash_var_input_byte_list = extractor.extract_input_bytes_used(crash_var_sym_expr_code)
            for var_taint_info in var_taint_list:
                var_name, v_line, v_col = var_taint_info
                var_expr_list = var_taint_list[var_taint_info]
                for var_expr in var_expr_list:
                    var_sym_expr_code = generator.generate_z3_code_for_var(var_expr, var_name)
                    var_input_byte_list = extractor.extract_input_bytes_used(var_sym_expr_code)
                    if var_input_byte_list == crash_var_input_byte_list:
                        z3_eq_code = generator.generate_z3_code_for_equivalence(var_sym_expr_code,
                                                                                crash_var_sym_expr_code)
                        if oracle.is_var_expr_equal(z3_eq_code):
                            if crash_var_name not in candidate_var_list:
                                candidate_var_list[crash_var_name] = set()
                            candidate_var_list[crash_var_name].add((var_name, v_line))

    cfc_tokens = cfc_expr.split(" ")
    localized_tokens = []
    possible_line = 0
    for c_t in cfc_tokens:
        c_t_lookup = c_t.replace("(", "").replace(")", "")
        if c_t_lookup in candidate_var_list:
            candidate_list = candidate_var_list[c_t_lookup]
            candidate_var, candidate_line = list(candidate_list)[0]
            localized_tokens.append(c_t.replace(c_t_lookup, candidate_var))
            if possible_line < candidate_line:
                possible_line = candidate_line
        else:
            localized_tokens.append(c_t)
    if possible_line > 0:
        localized_cfc = " ".join(localized_tokens)
    return localized_cfc, possible_line


def localize_state_info(fix_loc, taint_map):
    state_info_list = dict()
    src_file, line = fix_loc.split(":")
    func_name, function_ast = extractor.extract_func_ast(src_file, line)
    function_range = range(function_ast["start line"], function_ast["end line"])
    var_info_list = extractor.extract_var_list(function_ast)
    for taint_info in taint_map:
        c_file, line, col, inst_add = taint_info.split(":")
        taint_value_list = taint_map[taint_info]['concrete-list']
        if src_file != c_file:
            continue
        if int(line) not in function_range:
            continue
        for var_info in var_info_list:
            var_name, v_line, v_col, v_type = var_info
            if "argv" in var_name:
                continue
            if int(v_col) == int(col) and int(v_line) == int(line):
                var_info_index = (var_name, v_line, v_col, inst_add)
                if var_info_index not in state_info_list:
                    state_info_list[var_info_index] = taint_value_list
    return state_info_list


def fix_localization(input_byte_list, taint_map, cfc_info):
    emitter.title("Fix Localization")
    fix_locations = generate_fix_locations(input_byte_list, taint_map)
    definitions.FILE_LOCALIZATION_INFO = definitions.DIRECTORY_OUTPUT + "/localization.json"
    localization_list = list()
    for func_name, fix_loc in fix_locations:
        localization_obj = dict()
        emitter.sub_sub_title("[fix-loc] {}()".format(func_name))
        localized_cfc, localized_line = localize_cfc(fix_loc, cfc_info, taint_map)
        src_file, line = fix_loc.split(":")
        localized_loc = src_file + ":" + str(localized_line)
        state_info = localize_state_info(fix_loc, taint_map)
        localization_obj["source-location"] = localized_loc
        localization_obj["constraint"] = localized_cfc
        localization_obj["state"] = list()
        emitter.highlight("\t[cfc-loc] {}".format(localized_loc))
        emitter.highlight("\t[cfc-expr] {}".format(localized_cfc))
        emitter.highlight("\t[state information]:")
        emitter.highlight("\t" + "="*100)
        for state in state_info:
            state_obj = dict()
            var_name, line, col, inst_addr = state
            value_list = state_info[state]
            state_obj["variable-name"] = var_name
            state_obj["source-location"] = ":".join([src_file, str(line), str(col)])
            state_obj["instruction-address"] = inst_addr
            state_obj["value-list"] = ",".join(value_list)
            localization_obj["state"].append(state_obj)
            emitter.highlight("\t\t[var-name] {}".format(var_name))
            emitter.highlight("\t\t[var-loc] {}:{}".format(line, col))
            emitter.highlight("\t\t[instruction-address] {}".format(inst_addr))
            emitter.highlight("\t\t[values] {}".format(",".join(value_list[:5])))
            if state != list(state_info.keys())[-1]:
                emitter.highlight("\t\t" + "-"*50)
        localization_list.append(localization_obj)
    writer.write_as_json(localization_list, definitions.FILE_LOCALIZATION_INFO)
    emitter.success("\n\tlocalization information saved at {}".format(definitions.FILE_LOCALIZATION_INFO))
