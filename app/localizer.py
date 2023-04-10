#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import operator
import collections
from app import emitter, oracle, definitions, generator, extractor, values, writer, solver, \
    utilities, logger, parallel, converter, constraints
import copy
from itertools import chain, combinations, product


global_candidate_mapping = collections.OrderedDict()
arithmetic_op = ["+", "-", "*", "/", "%"]
comparison_op = ["==", "!=", ">", ">=", "<", "<="]
symbol_op = arithmetic_op + comparison_op


def generate_fix_locations(marked_byte_list, taint_memory_list, taint_symbolic, cfc_info):
    emitter.sub_title("Generating Fix Locations")
    logger.track_localization("generating fix locations\n")
    fix_locations = dict()
    taint_analysis_summary = dict()
    if taint_memory_list:
        taint_sources = taint_memory_list
    else:
        taint_sources = marked_byte_list
    is_taint_influenced = len(taint_sources) > 0
    taint_source_loc_map, taint_sink_loc_list = parallel.generate_taint_sink_info(taint_symbolic,
                                                                                  taint_memory_list,
                                                                                  is_taint_influenced)
    logger.track_localization("found {} source files".format(len(taint_sink_loc_list)))
    logger.track_localization("found {} source locations".format(len(taint_symbolic)))
    emitter.highlight("\t\t[info] found " + str(len(taint_sink_loc_list)) + " source files")
    logger.track_localization("generating tainted function list")
    taint_analysis_summary["analyzed-file-count"] = len(taint_sink_loc_list)
    taint_analysis_summary["analyzed-taint-loc-count"] = len(taint_source_loc_map)
    taint_analysis_summary["taint-instr-count"] = len(taint_symbolic)
    tainted_function_list = collections.OrderedDict()
    func_count = 0
    for source_path in taint_sink_loc_list:
        tainted_loc_list = taint_sink_loc_list[source_path]
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
    taint_analysis_summary["analyzed-func-count"] = func_count
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
                elif source_loc in taint_source_loc_map:
                    observed_tainted_bytes.update(taint_source_loc_map[source_loc])
                    if not observed_tainted_bytes:
                        continue
                    if set(taint_sources) <= set(observed_tainted_bytes):
                        fix_locations[source_loc] = func_name
    logger.track_localization("found {} fix locations".format(len(fix_locations)))
    logger.track_localization("sorting fix location based on trace")
    sorted_fix_locations = [(cfc_info["function"], cfc_info["loc"])]
    cached_list = []
    emitter.normal("\tgenerating possible fix locations")
    for taint_info in reversed(taint_symbolic.keys()):
        src_file, line, col, inst_addr = taint_info.split(":")
        taint_loc = ":".join([src_file, line, col])
        if taint_loc in fix_locations and taint_loc not in cached_list:
            sorted_fix_locations.append((fix_locations[taint_loc], taint_loc))
            emitter.highlight("\t\t[fix-loc] {}, {}".format(fix_locations[taint_loc],taint_loc))
            cached_list.append(taint_loc)
    logger.track_localization("found {} unique fix locations".format(len(sorted_fix_locations)))
    unique_fix_files = []
    unique_fix_functons = []
    unique_fix_lines = []
    for function_name, loc in sorted_fix_locations:
        src_file = loc.split(":")[0]
        src_line = loc.split(":")[1]
        fix_line = f"{src_file}:{src_line}"
        if src_file not in unique_fix_files:
            unique_fix_files.append(src_file)
        if fix_line not in unique_fix_lines:
            unique_fix_lines.append(fix_line)
        if function_name not in unique_fix_functons:
            unique_fix_functons.append(function_name)

    taint_analysis_summary["fix-loc-count"] = len(fix_locations)
    taint_analysis_summary["fix-line-count"] = len(unique_fix_lines)
    taint_analysis_summary["fix-func-count"] = len(unique_fix_functons)
    taint_analysis_summary["fix-file-count"] = len(unique_fix_files)
    taint_analysis_summary["fix-file-list"] = unique_fix_files
    taint_analysis_summary["fix-func-list"] = unique_fix_functons
    taint_analysis_summary["fix-line-list"] = unique_fix_lines
    taint_analysis_summary["fix-loc-list"] = list(fix_locations.keys())
    writer.write_as_json(taint_analysis_summary, definitions.DIRECTORY_OUTPUT + "/taint-analysis-summary.json")
    return sorted_fix_locations


def get_candidate_map_for_func(function_name, taint_symbolic, taint_concrete, src_file, function_ast, cfc_var_info_list):
    global global_candidate_mapping
    if function_name in global_candidate_mapping:
        return global_candidate_mapping[function_name]
    function_range = function_ast["range"]
    func_line_range = extractor.extract_line_range(src_file, function_range)

    var_info_list = extractor.extract_ast_var_list(function_ast, src_file)
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
            # e-col indicates the index of the parameter argument, not the column number in the source
            if dec_or_ref == "param" and int(e_line) == int(line) and int(e_col) == int(col):
                var_info_index = (e_str, e_line, e_col, 0)
                if var_info_index not in expr_taint_list:
                    filtered_taint_list = []
                    arg_type = None
                    if e_type in definitions.INTEGER_TYPES:
                        arg_type = "integer"
                    elif "*" in e_type or "[" in e_type:
                        arg_type = "pointer"
                    elif e_type in ["double", "float"]:
                        arg_type = "double"
                    for taint_expr in taint_expr_list:
                        data_type, taint_expr = taint_expr.split(":")
                        if data_type != "argument":
                            continue
                        filtered_taint_list.append(taint_expr)
                    expr_taint_list[var_info_index] = {
                        "expr_list": filtered_taint_list,
                        "data_type": arg_type,
                        "is_dec": True
                    }
            elif int(e_line) == int(line) and int(col) == int(e_col):
            # if int(e_line) == int(line) and int(col) in range(int(e_col), int(e_col) + len(e_str)):
                # print(var_name, v_line, v_col, line, col, range(int(v_col), int(v_col) + len(var_name)))
                var_info_index = (e_str, e_line, e_col, int(inst_add))
                if var_info_index not in expr_taint_list:
                    filtered_taint_list = []
                    data_type = None
                    for taint_expr in taint_expr_list:
                        data_type, taint_expr = taint_expr.split(":")
                        if data_type == "integer" and e_type not in definitions.INTEGER_TYPES:
                            continue
                        if data_type == "pointer" and "*" not in e_type and "[" not in e_type:
                            continue
                        if data_type in ["double", "float"] and e_type not in ["double", "float"]:
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
        if ("size " in crash_var_name) and \
                "con_size" in crash_var_expr_list:
            crash_var_expr_list = ["(_ bv{} 64)".format(crash_var_expr_list["con_size"])]
        crash_var_input_byte_list = []
        subset_expr_list = list()
        for crash_var_expr in crash_var_expr_list:
            found_mapping = False
            crash_var_sym_expr_code = generator.generate_z3_code_for_var(crash_var_expr, crash_var_name)
            crash_var_input_byte_list = extractor.extract_input_bytes_used(crash_var_sym_expr_code)
            for expr_taint_info in expr_taint_list:
                expr_str, e_line, e_col, e_addr = expr_taint_info
                var_expr_list = expr_taint_list[expr_taint_info]["expr_list"]
                var_expr_list = var_expr_list[-values.DEFAULT_EXPR_COMPARE_LIMIT:]
                e_type = expr_taint_list[expr_taint_info]["data_type"]
                is_exp_dec = expr_taint_list[expr_taint_info]["is_dec"]
                if e_type != crash_var_type:
                    # print("SKIP", expr_str, var_name, crash_var_type, e_type)
                    logger.track_localization("SKIP {} with {}".format((crash_var_name, crash_var_type),
                                                                       (expr_str, e_type, e_line, e_col, )))
                    continue
                # print("MATCH", expr_str, var_name, crash_var_type, e_type)
                logger.track_localization("MATCH {} with {}".format((crash_var_name, crash_var_type),
                                                                   (expr_str, e_type, e_line, e_col)))
                for var_expr in var_expr_list:
                    var_sym_expr_code = generator.generate_z3_code_for_var(var_expr, expr_str)
                    var_input_byte_list = extractor.extract_input_bytes_used(var_sym_expr_code)
                    if not var_input_byte_list and not crash_var_input_byte_list:
                        logger.track_localization("NO TAINT SOURCES FOR {} and {}".format(crash_var_name, expr_str))
                        if not expr_str or expr_str.strip() in ["()"]:
                            continue
                        if crash_var_type == "pointer" and e_type == "pointer" and "base " not in crash_var_name:
                            if var_expr in crash_var_expr_list:
                                if crash_var_name not in candidate_mapping:
                                    candidate_mapping[crash_var_name] = set()
                                expr_str = constraints.transform_increment_decrement(expr_str)
                                logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                                logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                                logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                                candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                        elif oracle.is_expr_list_match(crash_var_expr_list, var_expr_list) and crash_var_name == expr_str:
                            if crash_var_name not in candidate_mapping:
                                candidate_mapping[crash_var_name] = set()
                            logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                            logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                            logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                            candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                        elif var_expr == crash_var_expr and crash_var_name == expr_str:
                            if crash_var_name not in candidate_mapping:
                                candidate_mapping[crash_var_name] = set()
                            expr_str = constraints.transform_increment_decrement(expr_str)
                            logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                            logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                            logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                            candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                        elif var_expr == crash_var_expr and (expr_str == "++" + crash_var_name or
                                                             expr_str == "--" + crash_var_name or
                                                             expr_str == crash_var_name + "++" or
                                                             expr_str == crash_var_name + "--"):
                            if crash_var_name not in candidate_mapping:
                                candidate_mapping[crash_var_name] = set()
                            logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                            logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                            logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                            candidate_mapping[crash_var_name].add((crash_var_name, e_line, e_col, e_addr, is_exp_dec))
                        elif any(token in crash_var_name for token in ["base ", "size "]) and "bv" in var_expr:
                            if var_expr == crash_var_expr:
                                if crash_var_name not in candidate_mapping:
                                    candidate_mapping[crash_var_name] = set()
                                logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                                logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                                logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                                candidate_mapping[crash_var_name].add(
                                    (expr_str, e_line, e_col, e_addr, is_exp_dec))
                        else:
                            crash_var_expr_list = cfc_var_info_list[crash_var_name]['expr_list']
                            if "width" in crash_var_expr_list:
                                crash_size_bits = int(crash_var_expr_list["con_size"].replace("bv", ""))
                                crash_size_width = int(crash_var_expr_list["width"])
                                crash_size_bytes = int(crash_size_bits / 4)
                                if crash_size_width > 0:
                                    crash_size_bytes = int(crash_size_bits/crash_size_width)
                                var_size_bytes = 0
                                if "bv" in var_expr and "A-data" not in var_expr:
                                    var_size_bytes = int(var_expr.split(" ")[1].replace("bv", ""))

                                if var_size_bytes == crash_size_bytes and len(var_expr_list) == 1:
                                    if crash_var_name not in candidate_mapping:
                                        candidate_mapping[crash_var_name] = set()
                                    candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                                else:
                                    continue
                                    # candidate_mapping[crash_var_name].add((str(crash_size_bytes), e_line, e_col, e_addr, is_exp_dec))
                                logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                                logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                                logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))

                    elif var_input_byte_list == crash_var_input_byte_list:
                        logger.track_localization("Matching Source for {} and {}".format(crash_var_name, expr_str))
                        if oracle.is_equivalent(var_sym_expr_code, crash_var_sym_expr_code):
                            found_mapping = True
                            if crash_var_name not in candidate_mapping:
                                candidate_mapping[crash_var_name] = set()
                            logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                            logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                            logger.track_localization("{}->[{}]".format(expr_str, var_expr_list))
                            candidate_mapping[crash_var_name].add((expr_str, e_line, e_col, e_addr, is_exp_dec))
                        else:

                            constant_mapping = synthesize_constant_factor(var_sym_expr_code,
                                                                         crash_var_sym_expr_code,
                                                                         expr_str)
                            if constant_mapping is None:
                                constant_mapping = synthesize_constant_divisor(var_sym_expr_code,
                                                                               crash_var_sym_expr_code,
                                                                               expr_str)

                            if constant_mapping is None:
                                constant_mapping = synthesize_constant_offset(var_sym_expr_code,
                                                                              crash_var_sym_expr_code,
                                                                              expr_str)
                            if constant_mapping:
                                if crash_var_name not in candidate_mapping:
                                    candidate_mapping[crash_var_name] = set()
                                logger.track_localization("MAPPING {} with {}".format(crash_var_name, expr_str))
                                logger.track_localization("{}->[{}]".format(crash_var_name, crash_var_expr_list))
                                logger.track_localization("{}->[{}]".format(constant_mapping, var_expr_list))
                                candidate_mapping[crash_var_name].add((constant_mapping, e_line, e_col, e_addr, is_exp_dec))

                    elif var_input_byte_list and set(var_input_byte_list) <= set(crash_var_input_byte_list):
                        logger.track_localization("Subset Match for {} and {}: {} <= {}".format(crash_var_name, expr_str, var_input_byte_list, crash_var_input_byte_list))
                        subset_expr_list.append((expr_str, var_expr, e_line, e_col, e_addr, is_exp_dec, var_input_byte_list))

        if values.DEFAULT_SYNTHESIZE_SUBSET_EXPR and crash_var_name not in candidate_mapping:
            if subset_expr_list:
                unique_byte_list = set()
                for subset_var in subset_expr_list:
                    _, _, _, _, _, _, byte_list = subset_var
                    unique_byte_list.update(byte_list)
                if unique_byte_list == set(crash_var_input_byte_list):
                    subset_mapping = synthesize_subset_expr(crash_var_name,
                                                            crash_var_expr_list[0],
                                                            crash_var_input_byte_list,
                                                            subset_expr_list)
                    candidate_mapping.update(subset_mapping)
    for crash_var_name in candidate_mapping:
        edit_distance_index = list()
        candidate_list = candidate_mapping[crash_var_name]
        index = 0
        for candidate_info in candidate_list:
            constant_mapping, _, _, _, _ = candidate_info
            edit_distance = solver.levenshtein_distance(crash_var_name, constant_mapping)
            edit_distance_index.append((index, edit_distance))
            index = index + 1
        ranked_index_list = sorted(edit_distance_index, key=lambda x:x[1])
        ranked_candidate_list = list()
        for index in ranked_index_list:
            ranked_candidate_list.append(list(candidate_list)[index[0]])
        candidate_mapping[crash_var_name] = ranked_candidate_list

    global_candidate_mapping[function_name] = candidate_mapping
    return candidate_mapping


def synthesize_subset_expr(ref_var, ref_expr, ref_byte_list, expr_list):
    emitter.debug("\t\tPossible Synthesis (not implemented)")
    emitter.debug("\t\tLogical Var Name:{}".format(ref_var))
    emitter.debug("\t\tSymbolic Expr:{}".format(ref_expr))
    expr_info = dict()
    expr_loc_list = []
    candidate_mapping = dict()
    for expr in expr_list:
        expr_str, var_expr, e_line, e_col, e_addr, is_exp_dec, var_input_byte_list = expr
        expr_loc_list.append((e_line, e_col, e_addr))
        expr_info[(e_line, e_col, e_addr)] = (var_expr, expr_str, var_input_byte_list)
        emitter.debug("\t\t\tProgram Expr:{}".format(expr_str))
        emitter.debug("\t\t\tSymbolic Expr:{}".format(var_expr))

    combination_depth = 3
    l1 = list(combinations(reversed(expr_loc_list), 2))
    l2 = []
    l3 = []
    # if len(expr_loc_list) > 3:
    #     l2 = list(combinations(expr_loc_list, 3))
    # if len(expr_loc_list) > 4:
    #     l3 = list(combinations(expr_loc_list, 4))
    combination_list = l1 + l2 + l3
    latest_expr_loc = None
    latest_expr_addr = 0
    for combination in combination_list:
        program_expr_list = []
        symbolic_expr_list = []
        combination_byte_list = []
        num_expr = len(combination)
        for expr_loc in combination:
            expr_addr = expr_loc[2]
            if latest_expr_addr < int(expr_addr):
                latest_expr_addr = int(expr_addr)
                latest_expr_loc = expr_loc
            expr_loc_info = expr_info[expr_loc]
            combination_byte_list = combination_byte_list + expr_loc_info[2]
            if expr_loc_info[1] in program_expr_list:
                break
            program_expr_list.append(expr_loc_info[1])
            symbolic_expr_list.append(expr_loc_info[0])
        if len(program_expr_list) == num_expr:
            if set(ref_byte_list) == set(combination_byte_list):
                synthesized_expr = synthesize_sub_expr_mul(symbolic_expr_list, ref_expr, program_expr_list)
                if not synthesized_expr:
                    synthesized_expr = synthesize_sub_expr_add(symbolic_expr_list, ref_expr, program_expr_list)
                if synthesized_expr:
                    if ref_var not in candidate_mapping:
                        candidate_mapping[ref_var] = set()
                    logger.track_localization("MAPPING {} with {}".format(ref_var, ref_expr))
                    logger.track_localization("{}->[{}]".format(ref_var, ref_byte_list))
                    logger.track_localization("{}->[{}]".format(synthesized_expr, combination_byte_list))
                    candidate_mapping[ref_var].add((synthesized_expr,
                                                    latest_expr_loc[0],
                                                    latest_expr_loc[1],
                                                    latest_expr_loc[2],
                                                    False))
                    break
    return candidate_mapping

def synthesize_sub_expr_mul(symbolic_expr_list, ref_expr, prog_expr_list):
    z3_code = generator.generate_z3_code_for_combination_mul(symbolic_expr_list, ref_expr)
    mapping_str = ""
    if oracle.is_satisfiable(z3_code):
        for expr in prog_expr_list:
            if mapping_str:
                mapping_str = mapping_str + " * ({})".format(expr)
            else:
                mapping_str = "({})".format(expr)
    return mapping_str

def synthesize_sub_expr_add(symbolic_expr_list, ref_expr, prog_expr_list):
    z3_code = generator.generate_z3_code_for_combination_add(symbolic_expr_list, ref_expr)
    mapping_str = ""
    if oracle.is_satisfiable(z3_code):
        for expr in prog_expr_list:
            if mapping_str:
                mapping_str = mapping_str + " + ({})".format(expr)
            else:
                mapping_str = "({})".format(expr)
    return mapping_str


def synthesize_constant_divisor(var_sym_expr_code, crash_var_sym_expr_code, expr_str):
    z3_factor_code_b, bit_size = generator.generate_z3_code_for_factor(var_sym_expr_code,
                                                                       crash_var_sym_expr_code)
    mapping = None
    offset = None
    if oracle.is_satisfiable(z3_factor_code_b):
        offset = solver.get_offset(z3_factor_code_b, bit_size)
    if offset:
        if 1 < offset < 1000:
            mapping = "({} / {})".format(expr_str, offset)
    return mapping

def synthesize_constant_factor(var_sym_expr_code, crash_var_sym_expr_code, expr_str):
    z3_factor_code_b, bit_size = generator.generate_z3_code_for_factor(crash_var_sym_expr_code,
                                                                       var_sym_expr_code)
    mapping = None
    offset = None
    if oracle.is_satisfiable(z3_factor_code_b):
        offset = solver.get_offset(z3_factor_code_b, bit_size)
    if offset:
        if 1 < offset < 1000:
            mapping = "({} * {})".format(expr_str, offset)
    return mapping

def synthesize_constant_offset(var_sym_expr_code, crash_var_sym_expr_code, expr_str):
    z3_offset_code, bit_size = generator.generate_z3_code_for_offset(var_sym_expr_code,
                                                                     crash_var_sym_expr_code)
    mapping = None
    if oracle.is_satisfiable(z3_offset_code):
        offset = solver.get_offset(z3_offset_code, bit_size)
        if offset:
            if offset > 0:
                mapping = "({} - {})".format(expr_str, offset)
            else:
                mapping = "({} + {})".format(expr_str, abs(offset))
    return mapping


def localize_cfc(taint_loc_str, cfc_info, taint_symbolic, taint_concrete):
    localized_cfc = None
    candidate_constraints = list()
    candidate_locations = set()
    src_file, taint_line, taint_col = taint_loc_str.strip().split(":")
    crash_loc = cfc_info["loc"]
    cfc_expr = cfc_info["expr"]
    cfc_var_info_list = cfc_info["var-info"]
    # cfc_expr.resolve_size(cfc_var_info_list)
    cfc_expr_str = cfc_expr.to_string()
    if not os.path.isfile(src_file):
        emitter.warning("\t\t[warning] source file not found for ast lookup {}".format(src_file))
        return []
    func_name, function_ast = extractor.extract_func_ast(src_file, taint_line)
    call_node_list = extractor.extract_call_node_list(function_ast)
    taint_src_loc = (src_file, int(taint_line), int(taint_col))
    if oracle.is_top_assertion(taint_src_loc, call_node_list) or \
            oracle.is_loc_member_access(taint_src_loc, function_ast):
        return []

    candidate_mapping = get_candidate_map_for_func(func_name, taint_symbolic, taint_concrete, src_file,
                                                   function_ast, cfc_var_info_list)

    cfc_tokens = cfc_expr.get_symbol_list()
    injected_cfc_tokens = []
    for cfc_token in cfc_tokens:
        if "size " in cfc_token:
            symbol_ptr = re.search(r'pointer, (.*)\)\)', cfc_token).group(1)
            base_var = f"(base  @var(pointer, {symbol_ptr}))"
            if base_var not in cfc_tokens:
                injected_cfc_tokens.append(base_var)
        injected_cfc_tokens.append(cfc_token)
    cfc_tokens = injected_cfc_tokens
    logger.track_localization("CFC Tokens {}".format(cfc_tokens))
    cfc_token_mappings = []
    for c_t_lookup in cfc_tokens:
        if any(token in c_t_lookup for token in ["size ", "base "]):
            cfc_token_mappings.append((c_t_lookup, 100))
        elif c_t_lookup in candidate_mapping:
            cfc_token_mappings.append((c_t_lookup, len(candidate_mapping[c_t_lookup])))
    sorted_cfc_tokens = sorted(cfc_token_mappings, key=lambda x:x[1])
    sorted_cfc_tokens = [x[0] for x in sorted_cfc_tokens]
    logger.track_localization("Sorted CFC Tokens {}".format(sorted_cfc_tokens))
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
                # if int(c_line) == int(taint_line) and int(c_col) > int(taint_col):
                #     continue
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
                sorted_mapping = sorted(c_t_map, key=lambda x:(x[3], -len(x[0]), 1 - int(x[4])), reverse=True)
                for mapping in sorted_mapping:
                    m_expr, m_line, m_col, _, is_dec = mapping
                    if m_line > candidate_line:
                        continue
                    if selected_line > m_line:
                        continue
                    if m_line == candidate_line:
                        continue
                    selected_expr = m_expr
                    if selected_expr in used_candidates:
                        continue
                    selected_col = m_col
                    selected_line = m_line
                    if selected_expr:
                        if c_t_lookup in localized_tokens:
                            # favors non-array access
                            mapped_expr = localized_tokens[c_t_lookup]
                            if "(" in mapped_expr and "(" not in selected_expr:
                                localized_tokens[c_t_lookup] = selected_expr
                            if "[" in mapped_expr and "[" not in selected_expr:
                                localized_tokens[c_t_lookup] = selected_expr
                        if c_t_lookup not in localized_tokens:
                            localized_tokens[c_t_lookup] = selected_expr
                            used_candidates.append(selected_expr)


        for c_t_lookup in sorted_cfc_tokens:
            if c_t_lookup in localized_tokens:
                continue
            if "size " in c_t_lookup:
                ptr_name = re.search(r'pointer, (.*)\)\)', c_t_lookup).group(1)
                base_ptr = f"(base  @var(pointer, {ptr_name}))"
                mapped_ptr = None
                if base_ptr in localized_tokens:
                    mapped_ptr = localized_tokens[base_ptr]
                elif ptr_name in localized_tokens:
                    mapped_ptr = localized_tokens[ptr_name]
                if mapped_ptr:
                    if "malloc(" in mapped_ptr:
                        malloc_size = re.search(r'malloc\((.*?)\)', mapped_ptr).group(1)
                        localized_tokens[c_t_lookup] = malloc_size
                    elif "malloc (" in mapped_ptr:
                        malloc_size = re.search(r'malloc \((.*?)\)', mapped_ptr).group(1)
                        localized_tokens[c_t_lookup] = malloc_size
                    else:
                        localized_tokens[c_t_lookup] = f"crepair_size({mapped_ptr})"

            if "base " in c_t_lookup:
                ptr_name = re.search(r'pointer, (.*)\)\)', c_t_lookup).group(1)
                if "malloc(" in ptr_name or "malloc (" in ptr_name:
                    continue
                if ptr_name in localized_tokens:
                    mapped_ptr = localized_tokens[ptr_name]
                    localized_tokens[c_t_lookup] = f"crepair_base({mapped_ptr})"


        cfc_tokens = cfc_expr.get_symbol_list()
        logger.track_localization("Localized Tokens {}".format(localized_tokens))
        if all(token in localized_tokens for token in cfc_tokens):
            localized_cfc = copy.deepcopy(cfc_expr)
            localized_cfc.update_symbols(localized_tokens)
            candidate_constraints.append((localized_cfc, candidate_line, candidate_col))


    # identify potential expression replacements
    expression_string_list = extractor.extract_expression_string_list(function_ast, src_file)
    updated_candidate_constraints = list()
    for candidate_constraint in candidate_constraints:
        candidate_cfc, candidate_line, candidate_col = candidate_constraint
        candidate_loc = (candidate_line, candidate_col)
        if oracle.is_loc_match(candidate_loc, taint_src_loc):
            if candidate_loc in expression_string_list:
                expression_str, data_type = expression_string_list[candidate_loc]
                updated_cfc = update_result_nodes(candidate_cfc, expression_str, data_type)
                if updated_cfc:
                    updated_candidate_constraints.append((updated_cfc, candidate_line, candidate_col))
                    continue
        updated_candidate_constraints.append(candidate_constraint)

    # update top-level fix locations
    stmt_node_list = extractor.extract_stmt_nodes(function_ast, black_list=["CompoundStmt"])
    assignment_op_list = ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|="]
    binary_op_list = extractor.extract_binaryop_node_list(function_ast, src_file, assignment_op_list)
    initialization_list = extractor.extract_var_decl_node_list(function_ast)
    assignment_node_list = binary_op_list + initialization_list
    assignment_list = dict()
    for assign_node in assignment_node_list:
        node_type = assign_node["kind"]
        if node_type == "VarDecl":
            if "inner" not in assign_node:
                continue
            left_side = assign_node['inner'][0]
            if "inner" in left_side and len(left_side["inner"]) > 0:
                right_side =  left_side['inner'][0]
                begin_loc = extractor.extract_loc(src_file, assign_node["loc"])
                _, line_number, col_number = begin_loc
                dec_loc = (int(line_number), int(col_number))
                rhs_ast_loc = right_side["range"]["begin"]
                rhs_begin_col = extractor.extract_col_range(rhs_ast_loc)[0]
                rhs_loc = (int(line_number), int(rhs_begin_col))
                assignment_list[dec_loc] = rhs_loc

            else:
                continue

        else:
            left_side = assign_node['inner'][0]
            right_side = assign_node['inner'][1]
            op_code = assign_node['opcode']
            begin_loc = extractor.extract_loc(src_file, assign_node["range"]["begin"])
            data_type = extractor.extract_data_type(left_side)
            _, line_number, col_number = begin_loc
            if src_file not in values.SOURCE_LINE_MAP:
                with open(src_file, "r") as s_file:
                    values.SOURCE_LINE_MAP[src_file] = s_file.readlines()
            source_line = values.SOURCE_LINE_MAP[src_file][line_number - 1]
            if op_code not in source_line:
                continue
            op_position = source_line.index(op_code, col_number - 1) + 1
            op_loc = (int(line_number), int(op_position))
            rhs_ast_loc = right_side["range"]["begin"]
            rhs_begin_col = extractor.extract_col_range(rhs_ast_loc)[0]
            rhs_loc = (int(line_number), int(rhs_begin_col))
            assignment_list[op_loc] = rhs_loc


    fix_loc_updated_candidate_constraints = list()
    top_level_node_list = stmt_node_list + assignment_node_list + call_node_list


    for candidate_constraint in updated_candidate_constraints:
        candidate_cfc, candidate_line, candidate_col = candidate_constraint
        candidate_loc = (src_file, candidate_line, candidate_col)
        top_level_line = 0
        top_level_col = 0
        is_declaration = False
        for top_node in top_level_node_list:
            loc_range = top_node["range"]
            node_type = top_node["kind"]
            if node_type == "CaseStmt":
                continue
            if oracle.is_loc_in_range(candidate_loc, loc_range):
                if node_type == "DeclStmt":
                    top_level_line = extractor.extract_line_range(src_file, loc_range)[0]
                    top_level_col = extractor.extract_col_range(loc_range["begin"])[0]
                    is_declaration = True
                    break
                if node_type == "CallExpr":
                    func_ref_node = top_node["inner"][0]
                    func_ref_name = func_ref_node["inner"][0]["referencedDecl"]["name"]
                    if func_ref_name in ["assert", "__assert_fail"]:
                        top_level_line = -1
                        break
                top_node_line = extractor.extract_line_range(src_file, loc_range)[0]
                top_node_col = extractor.extract_col_range(loc_range["begin"])[0]
                if top_node_line > top_level_line:
                    top_level_line = top_node_line
                    top_level_col = 0
                if top_node_line == top_level_line and top_node_col > top_level_col:
                    top_level_col = top_node_col
        top_level_loc = (top_level_line, top_level_col)
        taint_loc = (int(taint_line), int(taint_col))
        if top_level_line == -1:
            emitter.warning(f"[warning] skipping assertion for top-level statement for {crash_loc}")
            continue
        if top_level_line == 0 and top_level_col == 0:
            emitter.warning(f"[warning] did not find top-level for {crash_loc}")
            continue
        if "@result" in candidate_cfc.to_string():
            # if not is_declaration:
            #     fix_loc_updated_candidate_constraints.append((candidate_cfc, top_level_loc, taint_loc))
            if taint_loc in assignment_list:
                shifted_loc = assignment_list[taint_loc]
                fix_loc_updated_candidate_constraints.append((candidate_cfc, shifted_loc, taint_loc))
            else:
                fix_loc_updated_candidate_constraints.append((candidate_cfc, taint_loc, taint_loc))
        else:
            fix_loc_updated_candidate_constraints.append((candidate_cfc, top_level_loc, taint_loc))

    return fix_loc_updated_candidate_constraints

def update_result_nodes(cfc, expr_str, data_type):
    if cfc.is_leaf():
        return None
    cfc_rhs_str = ""
    cfc_lhs_str = ""
    updated_cfc = None
    if cfc.get_r_expr():
        cfc_rhs_str = cfc.get_r_expr().to_expression()

    if cfc.get_l_expr():
        cfc_lhs_str = cfc.get_l_expr().to_expression()

    if not any (op in cfc_lhs_str for op in ["size ", "base "]):
        if oracle.is_expression_equal(cfc_lhs_str, expr_str):
            # print("MATCH LHS", cfc.to_string(), expr_str)
            result_symbol = constraints.make_constraint_symbol(expr_str, data_type)
            result_expr = constraints.make_symbolic_expression(result_symbol)
            cfc.set_l_expr(result_expr)
            updated_cfc =  cfc
        elif expr_str in cfc_lhs_str:
            cfc_lhs = update_result_nodes(cfc.get_l_expr(), expr_str, data_type)
            if cfc_lhs:
                cfc.set_l_expr(cfc_lhs)
                updated_cfc = cfc
    if updated_cfc is not None:
        cfc = updated_cfc
    if not any (op in cfc_rhs_str for op in ["size ", "base "]):
        if oracle.is_expression_equal(cfc_rhs_str, expr_str):
            # print("MATCH RHS", cfc.to_string(), expr_str)
            result_symbol = constraints.make_constraint_symbol(expr_str, data_type)
            result_expr = constraints.make_symbolic_expression(result_symbol)
            cfc.set_r_expr(result_expr)
            updated_cfc =  cfc
        elif expr_str in cfc_rhs_str:
            cfc_rhs = update_result_nodes(cfc.get_r_expr(), expr_str, data_type)
            if cfc_rhs:
                cfc.set_r_expr(cfc_rhs)
                updated_cfc =  cfc
    return updated_cfc


def localize_state_info(fix_loc, taint_concrete):
    """
        Extracts for the given fix location the corresponding variable values, which are
        in the scope and tracked by the taint analysis.
    """
    src_file, fix_line, fix_col = fix_loc.split(":")
    func_name, function_ast = extractor.extract_func_ast(src_file, fix_line)
    func_line_range = extractor.extract_line_range(src_file, function_ast["range"])
    var_info_list = extractor.extract_ast_var_list(function_ast, src_file)

    logger.information(f"computed variable list: {var_info_list}")

    state_info_list_values = dict()
    if fix_loc not in taint_concrete:
        return state_info_list_values
    taint_info_listed_occurences = taint_concrete[fix_loc]
    for occurence in range(len(taint_info_listed_occurences)):
        taint_info_list = taint_info_listed_occurences[occurence]
        logger.information(f"taint occurrences [{occurence}]: {taint_info_list}")
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
                var_name, v_line, v_col, v_type, v_kind = var_info
                if "argv" in var_name:
                    continue
                if int(v_col) == int(taint_col) and int(v_line) == int(taint_line):
                    # Remove previous values for the same variable at a different line.
                    outdated_entries = [(var_name_a, v_line_a, v_col_a, var_type_a) for (var_name_a, v_line_a, v_col_a, var_type_a) in state_info_list_values[occurence].keys() if var_name_a == var_name and var_type_a == v_type and v_line_a != v_line]
                    for entry in outdated_entries:
                        del state_info_list_values[occurence][entry]

                    # Create index.
                    var_type, var_value = taint_value.split(":")

                    # Determine the expression, if any, that is necessary to obtain the underlying value of a pointer
                    if v_kind == "dec" and var_type == "integer":
                        num_asterixes = v_type.split(" ")[-1].count("*")
                        dereference_prefix = "*" * num_asterixes
                        var_name = f"{dereference_prefix}{var_name}"

                    if var_type == "argument":
                        if v_type in definitions.INTEGER_TYPES:
                            var_type = "integer"
                        elif "*" in v_type or "[" in v_type:
                            var_type = "pointer"
                        elif v_type in ["double", "float"]:
                            var_type = "double"

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

    logger.information(f"computed state info values: {state_info_list_values}")
    return state_info_list_values


def fix_localization(taint_byte_list, taint_memory_list, taint_symbolic, cfc_info, taint_concrete):
    emitter.title("Fix Localization")
    tainted_fix_locations = generate_fix_locations(taint_byte_list, taint_memory_list, taint_symbolic, cfc_info)
    definitions.FILE_LOCALIZATION_INFO = definitions.DIRECTORY_OUTPUT + "/localization.json"
    localization_list = list()
    localized_loc_list = list()
    trace_list = []
    for taint_loc in reversed(values.TRACE_CONCRETE):
        if taint_loc not in trace_list:
            trace_list.append(taint_loc)

    emitter.sub_title("Localizing Constraints")
    loc_limit = values.DEFAULT_MAX_FIX_LOCATIONS
    for func_name, tainted_fix_loc in tainted_fix_locations[:loc_limit]:
        src_file = tainted_fix_loc.split(":")[0]
        logger.track_localization("[taint-loc] {}:{}".format(func_name, tainted_fix_loc))
        candidate_constraints = localize_cfc(tainted_fix_loc, cfc_info, taint_symbolic, taint_concrete)
        logger.track_localization("[constraints] {}".format(candidate_constraints))
        for candidate_info in candidate_constraints:
            localization_obj = collections.OrderedDict()
            localized_cfc, localized_loc, taint_loc = candidate_info
            localized_line, localized_col = localized_loc
            taint_line, taint_col = taint_loc
            taint_src_loc = f"{src_file}:{taint_line}"
            localized_src_loc = f"{src_file}:{localized_line}"

            if localized_src_loc in trace_list:
                distance = trace_list.index(localized_src_loc) + 1
            elif taint_src_loc in trace_list:
                distance = trace_list.index(taint_src_loc) + 1 + (int(taint_line) - int(localized_line))
            else:
                distance = 0
                emitter.warning("\t\t[warning] location not found in taint trace {}".format(taint_src_loc))

            localized_loc_str = ":".join([src_file, str(localized_line), str(localized_col)])
            if localized_loc_str in localized_loc_list:
                continue
            localized_loc_list.append(localized_loc_str)

            # location is not precise with assignments, hence avoid localization if location is not in taint map
            if localized_loc_str not in taint_concrete:
                taint_loc_str = ":".join([src_file, str(taint_line), str(taint_col)])
                state_info_list_values = localize_state_info(taint_loc_str, taint_concrete)
            else:
                state_info_list_values = localize_state_info(localized_loc_str, taint_concrete)

            emitter.sub_sub_title("[fix-loc] {}".format(localized_loc_str))
            localization_obj["location"] = localized_loc_str
            localization_obj["distance"] = distance
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
                        "type": var_type,
                    }

                    logger.information(f"generated var metadata: {var_meta_data}")

                    if var_meta_data not in variables:
                        variables.append(var_meta_data)

                    var_id = var_name

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
            rel_output_filename = f"{localized_loc_str.replace('/', '#')}.csv"
            abs_output_filepath = os.path.join(values_directory, rel_output_filename)
            writer.write_as_csv(fieldnames, rows, abs_output_filepath)
            localization_obj["values-file"] = rel_output_filename

            localization_list.append(localization_obj)
    if not localization_list:
        utilities.normal_exit("Unable to Localize a Crash Free Constraint")
    values.COUNT_FIX_LOC = len(localization_list)
    writer.write_as_json(localization_list, definitions.FILE_LOCALIZATION_INFO)
    emitter.success("\n\tlocalization information saved at {}".format(definitions.FILE_LOCALIZATION_INFO))
    emitter.success("\n\tstate values saved at {}{}".format(definitions.DIRECTORY_OUTPUT, '/values/'))
