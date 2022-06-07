#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import os
import collections
from app import emitter, reader, utilities, generator, extractor, values


def fix_localization(input_byte_list, taint_log_path):
    emitter.normal("\tcomputing fix locations")
    fix_locations = []
    line_to_byte_map = collections.OrderedDict()
    taint_map = reader.read_taint_values(taint_log_path)
    for taint_loc in taint_map:
        taint_value_list = taint_map[taint_loc]
        for taint_value in taint_value_list:
            sym_expr_code = generator.generate_z3_code_for_var(taint_value, "TAINT")
            input_bytes = extractor.extract_input_bytes_used(sym_expr_code)
            if taint_loc not in line_to_byte_map:
                line_to_byte_map[taint_loc] = set()
            line_to_byte_map[taint_loc].update(set(input_bytes))

    source_mapping = collections.OrderedDict()
    for taint_loc in taint_map:
        source_path, line_number = taint_loc.split(":")
        if source_path not in source_mapping:
            source_mapping[source_path] = set()
        source_mapping[source_path].add(line_number)

    tainted_function_list = collections.OrderedDict()
    for source_path in source_mapping:
        tainted_line_list = source_mapping[source_path]
        source_dir = values.CONF_PATH_PROJECT + "/src/"
        ast_tree = extractor.extract_ast_json(source_dir, source_path)
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
                    fix_locations.append(source_line)
                    break
    sorted_fix_locations = []
    for loc in taint_map.keys():
        if loc in fix_locations:
            sorted_fix_locations.append(loc)
    for fix_loc in sorted_fix_locations:
        emitter.highlight("\t\t[fix-loc] {}".format(fix_loc))