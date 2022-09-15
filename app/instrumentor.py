#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import os
import collections
from app import emitter, reader, utilities


def instrument_klee_var_expr(source_path, var_list):
    emitter.normal("\tinstrumenting source code")
    is_error_on_exit = True
    insert_code = dict()
    instrument_code = ""
    for variable, line_number, col, data_type, _ in var_list:
        print_code = "klee_print_expr(\"[var-expr] " + variable + "\", " + variable + ");\n"
        type_print_code = "klee_print_stmt(\"[var-type]: " + variable + ":" + data_type + "\");\n"
        print_code = print_code + type_print_code
        line_number = line_number - 1
        if line_number in insert_code.keys():
            insert_code[line_number] = insert_code[line_number] + print_code
        else:
            insert_code[line_number] = print_code

    sorted_insert_code = collections.OrderedDict(sorted(insert_code.items(), reverse=True))
    utilities.backup_file(source_path, source_path + ".bk")
    ast_json_file = source_path + ".ast"
    ast_tree = reader.read_ast_tree(ast_json_file)
    if os.path.exists(source_path):
        with open(source_path, 'r') as source_file:
            content = source_file.readlines()
            for insert_line in sorted_insert_code:
                instrument_code = sorted_insert_code[insert_line]
                # print(instrument_code, insert_line)
                # if Values.PATH_B not in source_path:
                #     if Oracle.is_loc_on_stack(source_path, function_name, insert_line, stack_info):
                #         instrument_code += "exit(1);\n"
                #         is_error_on_exit = False
                existing_line = content[insert_line-1]
                content[insert_line-1] = existing_line + instrument_code

    with open(source_path, 'w') as source_file:
        source_file.writelines(content)
    ret_code = 1
    while ret_code != 0:
        syntax_fix_command = "clang-tidy --fix-errors " + source_path
        # print(syntax_fix_command)
        utilities.execute_command(syntax_fix_command)
        syntax_check_command = "clang-tidy " + source_path
        # print(syntax_check_command)
        ret_code = int(utilities.execute_command(syntax_check_command))
    return is_error_on_exit

