import re
from six.moves import cStringIO
from pysmt.shortcuts import And
import os
import json
from app import emitter, utilities, reader, values, converter
from pathlib import Path
from pysmt.smtlib.parser import SmtLibParser



def extract_var_relationship(var_expr_map):
    # preserve user-input : program variable relationship
    # include program variable names for program specification
    parser = SmtLibParser()
    relationship = None
    for expr_map in var_expr_map:
        prog_var_name, prog_var_expr = expr_map[0]
        angelic_var_name, angelic_var_expr = expr_map[1]
        prog_dependent_var_list = set(re.findall("\(select (.+?) \(_ ", prog_var_expr))
        angelic_dependent_var_list = set(re.findall("\(select (.+?) \(_ ", angelic_var_expr))
        dependent_var_list = set(list(prog_dependent_var_list) + list(angelic_dependent_var_list))

        str_script = "(set-logic QF_AUFBV )\n"
        str_script += "(declare-fun " + prog_var_name + " () (Array (_ BitVec 32) (_ BitVec 8) ) )\n"
        for var_d in dependent_var_list:
            str_script += "(declare-fun " + var_d + " () (Array (_ BitVec 32) (_ BitVec 8) ) )\n"
        str_script += "(assert (= " + prog_var_expr + " " + angelic_var_expr + " ))\n"
        str_script += "(assert (= " + prog_var_name + " " + angelic_var_name + " ))\n"
        str_script += "(exit)\n"
        script = parser.get_script(cStringIO(str_script))
        formula = script.get_last_formula()
        if not relationship:
            relationship = formula
        else:
            relationship = And(relationship, formula)
    return relationship


def extract_bit_vector(expression_str):
    bit_vector = dict()
    if "[" in expression_str:
        token_list = expression_str.split("[")
        token_list.remove(token_list[0])
        for token in token_list:
            if ".." in token:
                continue
            index_str, value_str = token.split(" := ")
            index = int(index_str.split("_")[0])
            value = int(value_str.split("_")[0])
            bit_vector[index] = value
    return bit_vector


def extract_byte_code(binary_path):
    if not utilities.values.CONF_PRESERVE_BC:
        emitter.normal("\textracting bytecode")
        directory_path = "/".join(binary_path.split("/")[:-1])
        binary_name = binary_path.split("/")[-1]
        extract_command = "cd " + directory_path + ";"
        extract_command += "extract-bc " + binary_name
        utilities.execute_command(extract_command)


def extract_formula_from_file(spec_file_path):
    spec_dir_path = "/".join(spec_file_path.split("/")[:-1])
    spec_file_name = spec_file_path.split("/")[-1]
    current_dir = os.getcwd()
    os.chdir(spec_dir_path)
    # emitter.normal("\textracting program specification")
    smt_parser = SmtLibParser()
    assertion_formula = None
    with Path(spec_file_name).open() as f:
        script = smt_parser.get_script(f)
        assertion_formula = script.get_last_formula()
    os.chdir(current_dir)
    return assertion_formula


def extract_input_list(model):
    input_list = dict()
    for var_name in model:
        if "rvalue!" in str(var_name) and "_" not in str(var_name):
            byte_list = model[var_name]
            input_list[str(var_name)] = utilities.get_signed_value(byte_list)
    is_multi_dimension = False
    if len(input_list) > 1:
        is_multi_dimension = True
    return input_list, is_multi_dimension


def extract_parameter_list(model):
    parameter_list = dict()
    for var_name in model:
        if "const_" in str(var_name):
            byte_list = model[var_name]
            parameter_list[str(var_name)] = utilities.get_signed_value(byte_list)
    is_multi_dimension = False
    if len(parameter_list) > 1:
        is_multi_dimension = True
    return parameter_list, is_multi_dimension


def extract_largest_path_condition(dir_path):
    largest_path_condition = None
    pc_formula_len = 0
    emitter.normal("\textracting largest symbolic path")
    file_list = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
    for file_name in file_list:
        if ".smt2" in file_name:
            file_path = os.path.join(dir_path, file_name)
            path_condition = extract_formula_from_file(file_path)
            if ".err" in file_name:
                largest_path_condition = path_condition
                break
            pc_formula_str = str(path_condition.serialize())
            if len(pc_formula_str) > pc_formula_len:
                pc_formula_len = len(pc_formula_str)
                largest_path_condition = path_condition
    return largest_path_condition


def extract_child_expressions(patch_tree):
    (cid, semantics), children = patch_tree
    child_list = list()
    if "right" not in patch_tree:
        child_list = [patch_tree]
    else:
        right_child = children['right']
        left_child = children['left']
        if cid in ["logical-or", "logical-and"]:
            right_list = extract_child_expressions(right_child)
            left_list = extract_child_expressions(left_child)
            child_list = right_list + left_list
        else:
            child_list = [patch_tree]
    return child_list


def extract_crash_information(binary_path, argument_list, log_path):
    emitter.normal("\textracting crash information")
    binary_input = " ".join(argument_list)
    test_command = "LD_LIBRARY_PATH=\"/CrashRepair/lib/;/klee/build/lib\" "
    test_command += "{} {} > {} 2>&1".format(binary_path, binary_input, log_path)
    utilities.execute_command(test_command, False)
    c_loc, c_type, c_address, c_func_name = reader.collect_exploit_output(log_path)
    emitter.normal("\textracting source ast")
    ast_diff_bin = "/CrashRepair/bin/ast-diff"
    src_dir = values.CONF_PATH_PROJECT + "/src/"
    src_path = src_dir + c_loc.split(":")[0]
    ast_file_path = src_path + ".ast"
    generate_ast_command = "cd {} && {} -ast-dump-json {} > {}".format(src_dir, ast_diff_bin, src_path, ast_file_path)
    utilities.execute_command(generate_ast_command)
    ast_tree = reader.read_ast_tree(ast_file_path)
    function_node_list = extract_function_node_list(ast_tree)
    if not c_func_name:
        _, line_num, _ = c_loc.split(":")
        for func_name, func_node in function_node_list.items():
            func_line_range = range(func_node["start line"], func_node["end line"])
            if int(line_num) in func_line_range:
                c_func_name = func_name
                break
    crash_func_ast = function_node_list[c_func_name]
    cfc = extract_crash_free_constraint(crash_func_ast, c_type, c_loc)

    emitter.highlight("\t\t[info] crash type: {}".format(c_type))
    emitter.highlight("\t\t[info] crash location: {}".format(c_loc))
    emitter.highlight("\t\t[info] crash function: {}".format(c_func_name))
    emitter.highlight("\t\t[info] crash address: {}".format(c_address))
    emitter.highlight("\t\t[info] crash free constraint: {}".format(cfc))



def extract_crash_free_constraint(func_ast, crash_type, crash_loc):
    cfc = None
    src_file, line_num, column_num = crash_loc.split(":")
    if crash_type == "division by zero":
        binaryop_list = extract_binaryop_node_list(func_ast, ["/"])
        div_op_ast = None
        for binaryop in binaryop_list.values():
            if int(line_num) == binaryop["start line"]:
                col_range = range(binaryop["start column"], binaryop["end column"])
                if int(column_num) in col_range:
                    div_op_ast = binaryop
                    break
        if div_op_ast is None:
            emitter.error("\t[error] unable to find division operator")
            utilities.error_exit("Unable to generate crash free constraint")
        divisor_ast = div_op_ast["children"][1]
        cfc = converter.convert_node_to_str(divisor_ast) + " != 0"
    elif crash_type == "signed integer overflow":
        binaryop_list = extract_binaryop_node_list(func_ast, ["*", "+", "-"])
        crash_op_str = None
        crash_op_ast = None
        for binary_op_str, binary_op_ast in binaryop_list.items():
            if int(line_num) == binary_op_ast["start line"]:
                col_range = range(binary_op_ast["start column"], binary_op_ast["end column"])
                if int(column_num) in col_range:
                    crash_op_ast = binary_op_ast
                    crash_op_str = binary_op_str
                    break
        if crash_op_ast is None:
            emitter.error("\t[error] unable to find binary operator for {}".format(crash_type))
            utilities.error_exit("Unable to generate crash free constraint")
        op_a_ast = crash_op_ast["children"][0]
        op_b_ast = crash_op_ast["children"][1]
        op_a_str = converter.convert_node_to_str(op_a_ast)
        op_b_str = converter.convert_node_to_str(op_b_ast)
        crash_op_converter = {"*": "/", "+": "-", "-": "+"}
        cfc = "{} <= INT_MAX {} {}".format(op_a_str, crash_op_converter[crash_op_str], op_b_str)
    else:
        emitter.error("\t[error] unknown crash type")
        utilities.error_exit("Unable to generate crash free constraint")
    return cfc

def extract_child_id_list(ast_node):
    id_list = list()
    for child_node in ast_node['children']:
        child_id = int(child_node['id'])
        id_list.append(child_id)
        grand_child_list = extract_child_id_list(child_node)
        if grand_child_list:
            id_list = id_list + grand_child_list
    if id_list:
        id_list = list(set(id_list))
    return id_list


def extract_call_node_list(ast_node):
    call_expr_list = list()
    node_type = str(ast_node["type"])
    if node_type == "CallExpr":
        call_expr_list.append(ast_node)
    else:
        if len(ast_node['children']) > 0:
            for child_node in ast_node['children']:
                child_call_list = extract_call_node_list(child_node)
                call_expr_list = call_expr_list + child_call_list
    return call_expr_list


def extract_label_node_list(ast_node):
    label_stmt_list = dict()
    node_type = str(ast_node["type"])
    if node_type == "LabelStmt":
        node_value = ast_node['value']
        label_stmt_list[node_value] = ast_node
    else:
        if len(ast_node['children']) > 0:
            for child_node in ast_node['children']:
                child_label_list = extract_label_node_list(child_node)
                label_stmt_list.update(child_label_list)
    return label_stmt_list


def extract_goto_node_list(ast_node):
    goto_stmt_list = list()
    node_type = str(ast_node["type"])
    if node_type == "GotoStmt":
        goto_stmt_list.append(ast_node)
    else:
        if len(ast_node['children']) > 0:
            for child_node in ast_node['children']:
                child_goto_list = extract_goto_node_list(child_node)
                goto_stmt_list = goto_stmt_list + child_goto_list
    return goto_stmt_list


def extract_function_node_list(ast_node):
    function_node_list = dict()
    for child_node in ast_node['children']:
        node_type = str(child_node["type"])
        if node_type in ["FunctionDecl"]:
            identifier = str(child_node['identifier'])
            function_node_list[identifier] = child_node
    return function_node_list


def extract_reference_node_list(ast_node):
    ref_node_list = list()
    node_type = str(ast_node["type"])
    if node_type in ["Macro", "DeclRefExpr", "MemberExpr", "GotoStmt"]:
        ref_node_list.append(ast_node)

    if len(ast_node['children']) > 0:
        for child_node in ast_node['children']:
            child_ref_list = extract_reference_node_list(child_node)
            ref_node_list = ref_node_list + child_ref_list
    return ref_node_list


def extract_initialization_node_list(ast_node, ref_node):
    init_node_list = list()
    node_type = str(ast_node["type"])
    if node_type == "BinaryOperator":
        node_value = str(ast_node['value'])
        if node_value == "=":
            assign_node = ast_node['children'][0]
            if assign_node['type'] == "DeclRefExpr":
                if assign_node['value'] == ref_node['identifier']:
                    init_node_list.append(ast_node)
    else:
        if len(ast_node['children']) > 0:
            for child_node in ast_node['children']:
                child_init_list = extract_initialization_node_list(child_node, ref_node)
                init_node_list = init_node_list + child_init_list
    return init_node_list


def extract_decl_list(ast_node, ref_type=None):
    dec_list = list()
    node_type = str(ast_node["type"])
    if ref_type:
        if node_type == ref_type:
            identifier = str(ast_node['identifier'])
            dec_list.append(identifier)
    else:
        if node_type in ["FunctionDecl", "VarDecl", "ParmVarDecl", "RecordDecl"]:
            identifier = str(ast_node['identifier'])
            dec_list.append(identifier)

    if len(ast_node['children']) > 0:
        for child_node in ast_node['children']:
            child_dec_list = extract_decl_list(child_node, ref_type)
            dec_list = dec_list + child_dec_list
    return list(set(dec_list))


def extract_decl_node_list(ast_node, ref_type=None):
    dec_list = dict()
    if not ast_node:
        return dec_list
    node_type = str(ast_node["type"])
    if ref_type:
        if node_type == ref_type:
            identifier = str(ast_node['identifier'])
            dec_list[identifier] = ast_node
    else:
        if node_type in ["FunctionDecl", "VarDecl", "ParmVarDecl", "RecordDecl"]:
            identifier = str(ast_node['identifier'])
            dec_list[identifier] = ast_node

    if len(ast_node['children']) > 0:
        for child_node in ast_node['children']:
            child_dec_list = extract_decl_node_list(child_node, ref_type)
            dec_list.update(child_dec_list)
    return dec_list


def extract_decl_node_list_global(ast_tree):
    dec_list = dict()
    if not ast_tree:
        return dec_list
    if len(ast_tree['children']) > 0:
        for child_node in ast_tree['children']:
            child_node_type = child_node['type']
            if child_node_type in ["FunctionDecl", "VarDecl", "ParmVarDecl"]:
                identifier = str(child_node['identifier'])
                dec_list[identifier] = child_node
    return dec_list


def extract_enum_node_list(ast_tree):
    dec_list = dict()
    node_type = str(ast_tree["type"])
    if node_type in ["EnumConstantDecl"]:
        identifier = str(ast_tree['identifier'])
        dec_list[identifier] = ast_tree

    if len(ast_tree['children']) > 0:
        for child_node in ast_tree['children']:
            child_dec_list = extract_enum_node_list(child_node)
            dec_list.update(child_dec_list)
    return dec_list


def extract_global_var_node_list(ast_tree):
    dec_list = list()
    for ast_node in ast_tree:
        node_type = str(ast_node["type"])
        if node_type in ["VarDecl"]:
            dec_list.append(ast_node)
    return dec_list


def extract_data_type_list(ast_node):
    data_type_list = list()
    node_type = str(ast_node["type"])
    if "data_type" in ast_node.keys():
        data_type = str(ast_node['data_type'])
        data_type_list.append(data_type)
    if len(ast_node['children']) > 0:
        for child_node in ast_node['children']:
            child_data_type_list = extract_data_type_list(child_node)
            data_type_list = data_type_list + child_data_type_list
    return list(set(data_type_list))


def extract_typedef_node_list(ast_node):
    typedef_node_list = dict()
    node_type = str(ast_node["type"])
    if node_type in ["TypedefDecl", "RecordDecl"]:
        identifier = str(ast_node['identifier'])
        typedef_node_list[identifier] = ast_node

    if len(ast_node['children']) > 0:
        for child_node in ast_node['children']:
            child_typedef_node_list = extract_typedef_node_list(child_node)
            typedef_node_list.update(child_typedef_node_list)
    return typedef_node_list


def extract_typeloc_node_list(ast_node):
    typeloc_node_list = dict()
    node_type = str(ast_node["type"])
    if node_type in ["TypeLoc"]:
        identifier = str(ast_node['value'])
        typeloc_node_list[identifier] = ast_node

    if len(ast_node['children']) > 0:
        for child_node in ast_node['children']:
            child_typeloc_node_list = extract_typeloc_node_list(child_node)
            # print(child_typeloc_node_list)
            typeloc_node_list.update(child_typeloc_node_list)
    return typeloc_node_list


def extract_binaryop_node_list(ast_node, filter_list=None):
    binaryop_node_list = dict()
    node_type = str(ast_node["type"])
    if node_type in ["BinaryOperator"]:
        identifier = str(ast_node['value'])
        if filter_list:
            if identifier in filter_list:
                binaryop_node_list[identifier] = ast_node
        else:
            binaryop_node_list[identifier] = ast_node

    if len(ast_node['children']) > 0:
        for child_node in ast_node['children']:
            child_binaryop_node_list = extract_binaryop_node_list(child_node, filter_list)
            binaryop_node_list.update(child_binaryop_node_list)
    return binaryop_node_list


def extract_unaryop_node_list(ast_node):
    unaryop_node_list = dict()
    node_type = str(ast_node["type"])
    if node_type in ["UnaryOperator"]:
        identifier = str(ast_node['value'])
        unaryop_node_list[identifier] = ast_node

    if len(ast_node['children']) > 0:
        for child_node in ast_node['children']:
            child_unaryop_node_list = extract_binaryop_node_list(child_node)
            unaryop_node_list.update(child_unaryop_node_list)
    return unaryop_node_list

