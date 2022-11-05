import re
from six.moves import cStringIO
from pysmt.shortcuts import And
import os
from sympy import sympify
from app import emitter, utilities, reader, values, converter, generator, \
    definitions, constraints, oracle
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


def extract_func_ast(src_path, line_number):
    ast_tree = extract_ast_json(src_path)
    function_node_list = extract_function_node_list(ast_tree)
    c_func_name = None
    for func_name, func_node in function_node_list.items():
        func_range = func_node["range"]
        func_line_range = extract_line_range(src_path, func_range)
        if int(line_number) in func_line_range:
            c_func_name = func_name
            # if c_func_name:
            #     emitter.warning("\t\t[warning] two functions were found for same line number")
    if not function_node_list:
        utilities.error_exit("Could not generate function list for AST of {}".format(src_path))
    if c_func_name is None:
        utilities.error_exit("A function could not be found for line {} in file {}".format(src_path, line_number))
    if c_func_name not in  function_node_list:
        utilities.error_exit("Function {} could not be found in file {}".format(c_func_name, line_number))
    crash_func_ast = function_node_list[c_func_name]
    return c_func_name, crash_func_ast


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
    (cid, semantics), inner = patch_tree
    child_list = list()
    if "right" not in patch_tree:
        child_list = [patch_tree]
    else:
        right_child = inner['right']
        left_child = inner['left']
        if cid in ["logical-or", "logical-and"]:
            right_list = extract_child_expressions(right_child)
            left_list = extract_child_expressions(left_child)
            child_list = right_list + left_list
        else:
            child_list = [patch_tree]
    return child_list

def extract_ast_json(source_file_path):
    ast_file_path = source_file_path + ".ast"
    if values.DEFAULT_USE_CACHE:
        if os.path.isfile(ast_file_path):
            ast_tree = reader.read_ast_tree(ast_file_path)
            return ast_tree
    source_dir = "/".join(source_file_path.split("/")[:-1])
    diff_command = "clang-10 "
    if values.COMPILE_COMMANDS:
        if source_file_path in values.COMPILE_COMMANDS:
            include_dir_list = values.COMPILE_COMMANDS[source_file_path]
            for path in include_dir_list:
                diff_command += " -I{} ".format(path)
    diff_command += " -Xclang -ast-dump=json -fsyntax-only"

    generate_ast_command = "cd {} && {}  {} > {}".format(source_dir, diff_command, source_file_path,
                                                                       ast_file_path)
    utilities.execute_command(generate_ast_command)
    ast_tree = reader.read_ast_tree(ast_file_path)
    return ast_tree


def extract_source_loc_from_stack(log_file):
    source_loc = None
    with open(log_file, "r") as log_file:
        log_lines = log_file.readlines()
        is_stack = False
        crash_libc_func = None
        for line in log_lines:
            if is_stack:
                if crash_libc_func is None:
                    crash_libc_func = line.split(" in ")[-1].split(" ")[0]
                else:
                    bug_loc = line.split(" ")[-1]
                    if "klee-uclibc" not in bug_loc:
                        source_loc = bug_loc
                        break
            if "Stack" in line:
                is_stack = True
    return source_loc

def extract_crash_information(binary_path, argument_list, klee_log_path):
    emitter.normal("\textracting crash information")
    binary_input = " ".join(argument_list)
    c_type, c_file, c_line, c_column, c_address = reader.collect_klee_crash_info(klee_log_path)
    if "klee-uclibc" in c_file:
        klee_out_dir = Path(klee_log_path).parent.absolute()
        klee_file_list = [f for f in os.listdir(klee_out_dir) if os.path.isfile(os.path.join(klee_out_dir, f))]
        err_file = None
        for filename in klee_file_list:
            if ".err" in filename:
                err_file = filename
                break
        source_loc = extract_source_loc_from_stack(os.path.join(klee_out_dir, err_file))
        c_file, c_line = source_loc.split(":")
        c_column = "-1"
        c_address = "-1"
    # ast_tree = extract_ast_json(c_file)
    # function_node_list = extract_function_node_list(ast_tree)
    c_func_name, crash_func_ast = extract_func_ast(c_file, c_line)
    c_loc = ":".join([c_file, c_line, c_column])
    cfc, var_list = extract_crash_free_constraint(crash_func_ast, c_type, c_loc)
    var_name_list = sorted([x[0] for x in var_list])
    c_details = ""
    if c_type == definitions.CRASH_TYPE_DIV_ZERO:
        c_details = "division by zero"
    elif c_type == definitions.CRASH_TYPE_INT_MUL_OVERFLOW:
        c_details = "integer multiplication overflow"
    elif c_type == definitions.CRASH_TYPE_INT_ADD_OVERFLOW:
        c_details = "integer addition overflow"
    elif c_type == definitions.CRASH_TYPE_INT_SUB_OVERFLOW:
        c_details = "integer subtraction overflow"
    elif c_type == definitions.CRASH_TYPE_SHIFT_OVERFLOW:
        c_details = "overflow on shift operation"
    elif c_type == definitions.CRASH_TYPE_MEMORY_OVERFLOW:
        c_details = "memory overflow"
    elif c_type == definitions.CRASH_TYPE_MEMSET_ERROR:
        c_details = "memset error"
    elif c_type == definitions.CRASH_TYPE_MEMCPY_ERROR:
        c_details = "memcpy error"
    elif c_type == definitions.CRASH_TYPE_ASSERTION_ERROR:
        c_details = "assertion error"
    else:
        c_details = "unknown"
    emitter.highlight("\t\t[info] crash type: {}".format(c_details))
    emitter.highlight("\t\t[info] crash location: {}".format(c_loc))
    emitter.highlight("\t\t[info] crash function: {}".format(c_func_name))
    emitter.highlight("\t\t[info] crash address: {}".format(c_address))
    emitter.highlight("\t\t[info] crash free constraint: {}".format(cfc.to_string()))
    emitter.highlight("\t\t[info] crash inducing variables: {}".format(", ".join(var_name_list)))
    return c_file, var_list, cfc, c_func_name


def extract_sanitizer_information(binary_path, argument_list, log_path):
    emitter.normal("\textracting crash information")
    binary_input = " ".join(argument_list)
    test_command = "LD_LIBRARY_PATH=\"/CrashRepair/lib/;/klee/build/lib\" "
    test_command += "{} {} > {} 2>&1".format(binary_path, binary_input, log_path)
    utilities.execute_command(test_command, False)
    c_loc, c_type, c_address, c_func_name = reader.collect_exploit_output(log_path)
    src_dir = values.CONF_DIR_EXPERIMENT + "/src/"
    src_path = c_loc.split(":")[0]
    ast_tree = extract_ast_json(src_path)
    function_node_list = extract_function_node_list(ast_tree)
    if not c_func_name:
        _, line_num, _ = c_loc.split(":")
        for func_name, func_node in function_node_list.items():
            func_line_range = range(func_node["start line"], func_node["end line"])
            if int(line_num) in func_line_range:
                c_func_name = func_name
                break
    crash_func_ast = function_node_list[c_func_name]
    cfc, var_list = extract_crash_free_constraint(crash_func_ast, c_type, c_loc)
    var_name_list = [x[0] for x in var_list]
    emitter.highlight("\t\t[info] crash type: {}".format(c_type))
    emitter.highlight("\t\t[info] crash location: {}".format(c_loc))
    emitter.highlight("\t\t[info] crash function: {}".format(c_func_name))
    emitter.highlight("\t\t[info] crash address: {}".format(c_address))
    emitter.highlight("\t\t[info] crash free constraint: {}".format(cfc.to_string()))
    emitter.highlight("\t\t[info] crash inducing variables: {}".format(",".join(var_name_list)))
    return src_path, var_list, cfc


def extract_var_dec_list(ast_node, file_path):
    var_list = list()
    child_count = 0
    if not ast_node:
        return var_list
    if "inner" in ast_node:
        child_count = len(ast_node['inner'])
    node_type = ast_node["kind"]
    if node_type in ["ParmVarDecl"]:
        var_name = str(ast_node["name"])
        var_type = extract_data_type(ast_node)
        begin_loc = extract_loc(file_path, ast_node["range"]["begin"])
        _, line_number, column_number = begin_loc
        var_list.append((var_name, line_number, column_number, var_type, "dec"))
        return var_list

    if node_type in ["VarDecl"]:
        var_name = str(ast_node["name"])
        var_type = extract_data_type(ast_node)
        begin_loc = extract_loc(file_path, ast_node["loc"])
        _, line_number, column_number = begin_loc
        var_list.append((var_name, line_number, column_number, var_type, "dec"))
        return var_list
    if child_count:
        for child_node in ast_node['inner']:
            var_list = var_list + list(set(extract_var_dec_list(child_node, file_path)))
    return list(set(var_list))


def extract_var_ref_list(ast_node, file_path):
    var_list = list()
    child_count = 0
    if not ast_node:
        return var_list
    node_type = ast_node["kind"]
    if node_type == "ImplicitCastExpr":
        ast_node = ast_node["inner"][0]
        node_type = ast_node["kind"]
    if "inner" in ast_node:
        child_count = len(ast_node['inner'])
    if not ast_node:
        return var_list

    if node_type in ["ReturnStmt"]:
        if child_count == 0:
            return var_list
    if node_type in ["BinaryOperator", "CompoundAssignOperator"]:
        left_side = ast_node['inner'][0]
        right_side = ast_node['inner'][1]
        right_var_list = extract_var_ref_list(right_side, file_path)
        left_var_list = extract_var_ref_list(left_side, file_path)
        operands_var_list = right_var_list + left_var_list
        op_code = ast_node['opcode']
        if op_code in ["=", "+=", "-=", "*=", "/="]:
            begin_loc = extract_loc(file_path, ast_node["range"]["begin"])
            data_type = extract_data_type(left_side)
            _, line_number, col_number = begin_loc
            if file_path not in values.SOURCE_LINE_MAP:
                with open(file_path, "r") as s_file:
                    values.SOURCE_LINE_MAP[file_path] = s_file.readlines()
            source_line = values.SOURCE_LINE_MAP[file_path][line_number - 1]
            if op_code not in source_line:
                return var_list
            op_position = source_line.index(op_code, col_number-1) + 1
            assignment_var_name = converter.convert_node_to_str(left_side)
            # print("ADD", (str(assignment_var_name), line_number, op_position, data_type))
            var_list.append((str(assignment_var_name), line_number, op_position, data_type, "ref"))
        for var_name, line_number, col_number, var_type, _ in operands_var_list:
            var_list.append((str(var_name), line_number, col_number, str(var_type), "ref"))
        return var_list
    if node_type == "UnaryOperator":
        node_value = ast_node['opcode']
        child_node = ast_node['inner'][0]
        child_var_list = extract_var_ref_list(child_node, file_path)
        for var_name, line_number, col_number, var_type, _ in child_var_list:
            if node_value == "&":
                var_name = "&" + str(var_name)
            var_list.append((var_name, line_number, col_number, var_type, "ref"))
        return var_list
    if node_type == "DeclRefExpr":
        begin_loc = extract_loc(file_path, ast_node["range"]["begin"])
        _, line_number, col_number = begin_loc
        if "referencedDecl" in ast_node.keys():
            ref_type = str(ast_node['referencedDecl']['kind'])
            if ref_type == "FunctionDecl":
                return var_list
        var_name = str(ast_node['referencedDecl']['name'])
        # print(ast_node)
        if 'type' in ast_node.keys():
            var_type = str(ast_node['type']['qualType'])
        else:
            var_type = "macro"
        var_list.append((var_name, line_number, col_number, var_type, "ref"))
    if node_type == "ArraySubscriptExpr":
        var_name, var_type, auxilary_list = converter.convert_array_subscript(ast_node)
        begin_loc = extract_loc(file_path, ast_node["range"]["begin"])
        _, line_number, col_number = begin_loc
        var_list.append((str(var_name), line_number, col_number, var_type, "ref"))
        for aux_var_name, aux_var_type in auxilary_list:
            var_list.append((str(aux_var_name), line_number, col_number, aux_var_type, "ref"))
        return var_list
    if node_type in ["MemberExpr"]:
        var_name, var_type, auxilary_list = converter.convert_member_expr(ast_node)
        begin_loc = extract_loc(file_path, ast_node["range"]["begin"])
        _, line_number, column_number = begin_loc
        var_list.append((str(var_name), line_number, column_number, var_type, "ref"))
        for aux_var_name, aux_var_type in auxilary_list:
            var_list.append((str(aux_var_name), line_number, column_number, aux_var_type, "ref"))
        return var_list
    if node_type in ["ForStmt", "WhileStmt"]:
        body_node = ast_node['inner'][child_count - 1]
        begin_loc = extract_loc(file_path, ast_node["range"]["begin"])
        _, line_number, column_number = begin_loc
        for i in range(0, child_count - 1):
            condition_node = ast_node['inner'][i]
            condition_node_var_list = extract_var_ref_list(condition_node, file_path)
            for var_name, line_number, col_number, var_type, _ in condition_node_var_list:
                var_list.append((str(var_name), line_number, col_number, var_type, "ref"))
        var_list = var_list + extract_var_ref_list(body_node, file_path)
        return var_list
    # if node_type in ["CaseStmt"]:
    #     return var_list
    if node_type in ["IfStmt"]:
        condition_node = ast_node['inner'][0]
        body_node = ast_node['inner'][1]
        condition_node_var_list = extract_var_ref_list(condition_node, file_path)
        for var_name, line_number, col_number, var_type, _ in condition_node_var_list:
            var_list.append((str(var_name), line_number, col_number, var_type, "ref"))
        var_list = var_list + extract_var_ref_list(body_node, file_path)
        return var_list
    if node_type in ["SwitchStmt"]:
        condition_node = ast_node['inner'][0]
        body_node = ast_node['inner'][1]
        condition_node_var_list = extract_var_ref_list(condition_node, file_path)
        for var_name, line_number, col_number, var_type, _ in condition_node_var_list:
            var_list.append((str(var_name), line_number, col_number, var_type, "ref"))
        var_list = var_list + extract_var_ref_list(body_node, file_path)
        return var_list
    if child_count:
        for child_node in ast_node['inner']:
            var_list = var_list + list(set(extract_var_ref_list(child_node, file_path)))
    sorted_var_list = sorted(list(set(var_list)), key=lambda x:x[1], reverse=True)
    return sorted_var_list


def extract_var_list(ast_node, file_path):
    var_dec_list = extract_var_dec_list(ast_node, file_path)
    var_ref_list = extract_var_ref_list(ast_node, file_path)
    variable_list = list(set(var_ref_list + var_dec_list))
    if 'inner' in ast_node:
        for child_node in ast_node['inner']:
            child_var_dec_list = extract_var_dec_list(child_node, file_path)
            child_var_ref_list = extract_var_ref_list(child_node, file_path)
            variable_list = list(set(variable_list + child_var_ref_list + child_var_dec_list))
    sorted_var_list = sorted(list(set(variable_list)), key=lambda x: x[1], reverse=True)
    return sorted_var_list


def extract_crash_free_constraint(func_ast, crash_type, crash_loc_str):
    cfc = None
    var_list = []
    src_file, line_num, column_num = crash_loc_str.split(":")
    crash_loc = (src_file, int(line_num), int(column_num))
    if crash_type == definitions.CRASH_TYPE_DIV_ZERO :
        binaryop_list = extract_binaryop_node_list(func_ast, src_file, ["/", "%"])
        div_op_ast = None
        for op_ast in binaryop_list:
            if oracle.is_loc_in_range(crash_loc, op_ast["range"]):
                div_op_ast = op_ast
                break
        if div_op_ast is None:
            emitter.error("\t[error] unable to find division operator")
            utilities.error_exit("Unable to generate crash free constraint")
        divisor_ast = div_op_ast["inner"][1]
        var_list = extract_var_list(divisor_ast, src_file)
        cfc = constraints.generate_div_zero_constraint(divisor_ast)
    elif crash_type in [definitions.CRASH_TYPE_INT_MUL_OVERFLOW,
                        definitions.CRASH_TYPE_INT_ADD_OVERFLOW]:
        binaryop_list = extract_binaryop_node_list(func_ast, src_file, ["*", "+"])
        unaryop_list = extract_unaryop_node_list(func_ast, ["++"])
        crash_op_ast = None
        for op_ast in (binaryop_list + unaryop_list):
            if oracle.is_loc_in_range(crash_loc, op_ast["range"]):
                crash_op_ast = op_ast
                break
        if crash_op_ast is None:
            emitter.error("\t[error] unable to find binary operator for overflow")
            utilities.error_exit("Unable to generate crash free constraint")
        var_list = extract_var_list(crash_op_ast, src_file)
        cfc = constraints.generate_type_overflow_constraint(crash_op_ast)
    elif crash_type in [definitions.CRASH_TYPE_INT_SUB_OVERFLOW]:
        binaryop_list = extract_binaryop_node_list(func_ast, src_file, ["-"])
        unaryop_list = extract_unaryop_node_list(func_ast, ["--"])
        crash_op_ast = None
        for op_ast in (binaryop_list + unaryop_list):
            if oracle.is_loc_in_range(crash_loc, op_ast["range"]):
                crash_op_ast = op_ast
                break
        if crash_op_ast is None:
            emitter.error("\t[error] unable to find binary operator for underflow")
            utilities.error_exit("Unable to generate crash free constraint")
        var_list = extract_var_list(crash_op_ast, src_file)
        cfc = constraints.generate_type_underflow_constraint(crash_op_ast)
    elif crash_type == definitions.CRASH_TYPE_MEMORY_OVERFLOW:
        # check for memory write nodes if not found check for memory access nodes
        target_ast = None
        binaryop_list = extract_binaryop_node_list(func_ast, src_file, ["="])
        assign_op_ast = None
        for binary_op_ast in binaryop_list:
            if oracle.is_loc_in_range(crash_loc, binary_op_ast["range"]):
                assign_op_ast = binary_op_ast
                break
        deref_op_ast = None
        if not assign_op_ast:
            unaryop_list = extract_unaryop_node_list(func_ast, ["*"])
            for unary_op_ast in unaryop_list:
                if oracle.is_loc_in_range(crash_loc, unary_op_ast["range"]):
                    deref_op_ast = unary_op_ast
                    break
        array_access_node = None
        array_access_list = extract_array_subscript_node_list(func_ast)
        for reference_ast in array_access_list:
            if oracle.is_loc_in_range(crash_loc, reference_ast["range"]):
                array_access_node = reference_ast

        if array_access_node:
            target_ast = array_access_node
        elif assign_op_ast:
            target_ast = assign_op_ast["inner"][0]
        elif deref_op_ast:
            target_ast = deref_op_ast


        if target_ast is None:
            emitter.error("\t[error] unable to find memory access operator")
            utilities.error_exit("Unable to generate crash free constraint")
        var_list = extract_var_list(target_ast, src_file)
        for var_node in var_list:
            if "[" in var_node[0]:
                var_list.remove(var_node)
        cfc = constraints.generate_memory_overflow_constraint(target_ast)
    elif crash_type == definitions.CRASH_TYPE_SHIFT_OVERFLOW:
        binaryop_list = extract_binaryop_node_list(func_ast, src_file, ["<<", ">>"])
        crash_op_ast = None
        for binary_op_ast in binaryop_list:
            if oracle.is_loc_in_range(crash_loc, binary_op_ast["range"]):
                crash_op_ast = binary_op_ast
                break
        if crash_op_ast is None:
            emitter.error("\t[error] unable to find binary operator for shift overflow")
            utilities.error_exit("Unable to generate crash free constraint")
        var_list = extract_var_list(crash_op_ast, src_file)
        cfc = constraints.generate_shift_overflow_constraint(crash_op_ast)
    elif crash_type == definitions.CRASH_TYPE_MEMCPY_ERROR:
        call_node_list = extract_call_node_list(func_ast, None, ["memcpy"])
        crash_call_ast = None
        for call_ast in call_node_list:
            if oracle.is_loc_in_range(crash_loc, call_ast["range"]):
                crash_call_ast = call_ast
                break
        if crash_call_ast is None:
            emitter.error("\t[error] unable to find binary operator for memcpy error")
            utilities.error_exit("Unable to generate crash free constraint")
        var_list = extract_var_list(crash_call_ast, src_file)
        cfc = constraints.generate_memcpy_constraint(crash_call_ast)
    elif crash_type == definitions.CRASH_TYPE_MEMSET_ERROR:
        call_node_list = extract_call_node_list(func_ast, None, ["memset"])
        crash_call_ast = None
        for call_ast in call_node_list:
            if oracle.is_loc_in_range(crash_loc, call_ast["range"]):
                crash_call_ast = call_ast
                break
        if crash_call_ast is None:
            emitter.error("\t[error] unable to find binary operator for memset error")
            utilities.error_exit("Unable to generate crash free constraint")
        var_list = extract_var_list(crash_call_ast, src_file)
        cfc = constraints.generate_memset_constraint(crash_call_ast)
    elif crash_type == definitions.CRASH_TYPE_ASSERTION_ERROR:
        call_node_list = extract_call_node_list(func_ast, None, ["__assert_fail"])
        crash_call_ast = None
        for call_ast in call_node_list:
            if oracle.is_loc_in_range(crash_loc, call_ast["range"]):
                crash_call_ast = call_ast
                break
        if crash_call_ast is None:
            emitter.error("\t[error] unable to find binary operator for memset error")
            utilities.error_exit("Unable to generate crash free constraint")
        func_var_list = extract_var_ref_list(func_ast, src_file)
        cfc = constraints.generate_assertion_constraint(crash_call_ast, func_ast, src_file)
        cfc_var_list = cfc.get_symbol_list()
        assertion_var_list = dict()
        for var in func_var_list:
            name, row, col, _, _ = var
            _, c_line, c_col = crash_loc
            if name in cfc_var_list:
                if c_line >= row and name not in assertion_var_list:
                    assertion_var_list[name] = var
        var_list = assertion_var_list.values()

    else:
        emitter.error("\t[error] unknown crash type: {}".format(crash_type))
        utilities.error_exit("Unable to generate crash free constraint")
    return cfc, var_list


def extract_child_id_list(ast_node):
    id_list = list()
    for child_node in ast_node['inner']:
        child_id = int(child_node['id'])
        id_list.append(child_id)
        grand_child_list = extract_child_id_list(child_node)
        if grand_child_list:
            id_list = id_list + grand_child_list
    if id_list:
        id_list = list(set(id_list))
    return id_list


def extract_call_node_list(ast_node, black_list=None, white_list=None):
    call_expr_list = list()
    node_type = str(ast_node["kind"])
    if node_type == "CallExpr":
        func_ref_node = ast_node["inner"][0]
        func_ref_name = func_ref_node["inner"][0]["referencedDecl"]["name"]
        if black_list:
            if func_ref_name not in black_list:
                call_expr_list.append(ast_node)
        if white_list:
            if func_ref_name in white_list:
                call_expr_list.append(ast_node)
    else:
        if "inner" in ast_node and len(ast_node['inner']) > 0:
            for child_node in ast_node['inner']:
                child_call_list = extract_call_node_list(child_node, black_list, white_list)
                call_expr_list = call_expr_list + child_call_list
    return call_expr_list


def extract_label_node_list(ast_node):
    label_stmt_list = dict()
    node_type = str(ast_node["kind"])
    if node_type == "LabelStmt":
        node_value = ast_node['value']
        label_stmt_list[node_value] = ast_node
    else:
        if len(ast_node['inner']) > 0:
            for child_node in ast_node['inner']:
                child_label_list = extract_label_node_list(child_node)
                label_stmt_list.update(child_label_list)
    return label_stmt_list


def extract_goto_node_list(ast_node):
    goto_stmt_list = list()
    node_type = str(ast_node["kind"])
    if node_type == "GotoStmt":
        goto_stmt_list.append(ast_node)
    else:
        if len(ast_node['inner']) > 0:
            for child_node in ast_node['inner']:
                child_goto_list = extract_goto_node_list(child_node)
                goto_stmt_list = goto_stmt_list + child_goto_list
    return goto_stmt_list


def extract_function_node_list(ast_node):
    function_node_list = dict()
    for child_node in ast_node["inner"]:
        node_type = str(child_node["kind"])
        if node_type in ["FunctionDecl"]:
            identifier = str(child_node["name"])
            loc_info = child_node["loc"]
            if "includedFrom" in loc_info:
                continue
            if "spellingLoc" in loc_info:
                continue
            if "storageClass" in child_node:
                if child_node["storageClass"] == "extern":
                    continue
            function_node_list[identifier] = child_node
    return function_node_list


def extract_reference_node_list(ast_node):
    ref_node_list = list()
    if not ast_node:
        return ref_node_list
    node_type = str(ast_node["kind"])
    if node_type in ["Macro", "DeclRefExpr", "MemberExpr", "GotoStmt"]:
        ref_node_list.append(ast_node)

    if 'inner' in ast_node and len(ast_node['inner']) > 0:
        for child_node in ast_node['inner']:
            child_ref_list = extract_reference_node_list(child_node)
            ref_node_list = ref_node_list + child_ref_list
    return ref_node_list


def extract_initialization_node_list(ast_node):
    init_node_list = list()
    if not ast_node:
        return init_node_list
    node_type = str(ast_node["kind"])
    if node_type == "BinaryOperator":
        node_value = str(ast_node['opcode'])
        if node_value == "=":
            init_node_list.append(ast_node)
    elif node_type == "VarDecl":
        if "inner" in ast_node and len(ast_node['inner']) > 0:
            init_node_list.append(ast_node["inner"][0])
    else:
        if "inner" in ast_node and len(ast_node['inner']) > 0:
            for child_node in ast_node['inner']:
                child_init_list = extract_initialization_node_list(child_node)
                init_node_list = init_node_list + child_init_list
    return init_node_list


def extract_decl_list(ast_node, ref_type=None):
    dec_list = list()
    node_type = str(ast_node["kind"])
    if ref_type:
        if node_type == ref_type:
            identifier = str(ast_node["name"])
            dec_list.append(identifier)
    else:
        if node_type in ["FunctionDecl", "VarDecl", "ParmVarDecl", "RecordDecl"]:
            identifier = str(ast_node["name"])
            dec_list.append(identifier)

    if len(ast_node['inner']) > 0:
        for child_node in ast_node['inner']:
            child_dec_list = extract_decl_list(child_node, ref_type)
            dec_list = dec_list + child_dec_list
    return list(set(dec_list))


def extract_decl_node_list(ast_node, ref_type=None):
    dec_list = dict()
    if not ast_node:
        return dec_list
    node_type = str(ast_node["kind"])
    if ref_type:
        if node_type == ref_type:
            identifier = str(ast_node["name"])
            dec_list[identifier] = ast_node
    else:
        if node_type in ["FunctionDecl", "VarDecl", "ParmVarDecl", "RecordDecl"]:
            identifier = str(ast_node["name"])
            dec_list[identifier] = ast_node

    if len(ast_node['inner']) > 0:
        for child_node in ast_node['inner']:
            child_dec_list = extract_decl_node_list(child_node, ref_type)
            dec_list.update(child_dec_list)
    return dec_list


def extract_decl_node_list_global(ast_tree):
    dec_list = dict()
    if not ast_tree:
        return dec_list
    if len(ast_tree['inner']) > 0:
        for child_node in ast_tree['inner']:
            child_node_type = child_node["kind"]
            if child_node_type in ["FunctionDecl", "VarDecl", "ParmVarDecl"]:
                identifier = str(child_node["name"])
                dec_list[identifier] = child_node
    return dec_list


def extract_enum_node_list(ast_tree):
    dec_list = dict()
    node_type = str(ast_tree["kind"])
    if node_type in ["EnumConstantDecl"]:
        identifier = str(ast_tree["name"])
        dec_list[identifier] = ast_tree

    if len(ast_tree['inner']) > 0:
        for child_node in ast_tree['inner']:
            child_dec_list = extract_enum_node_list(child_node)
            dec_list.update(child_dec_list)
    return dec_list


def extract_global_var_node_list(ast_tree):
    dec_list = list()
    for ast_node in ast_tree:
        node_type = str(ast_node["kind"])
        if node_type in ["VarDecl"]:
            dec_list.append(ast_node)
    return dec_list


def extract_data_type_list(ast_node):
    data_type_list = list()
    node_type = str(ast_node["kind"])
    data_type = extract_data_type(ast_node)
    if data_type != "None":
        data_type_list.append(data_type)
    if len(ast_node['inner']) > 0:
        for child_node in ast_node['inner']:
            child_data_type_list = extract_data_type_list(child_node)
            data_type_list = data_type_list + child_data_type_list
    return list(set(data_type_list))


def extract_typedef_node_list(ast_node):
    typedef_node_list = dict()
    node_type = str(ast_node["kind"])
    if node_type in ["TypedefDecl", "RecordDecl"]:
        identifier = str(ast_node["name"])
        typedef_node_list[identifier] = ast_node

    if len(ast_node['inner']) > 0:
        for child_node in ast_node['inner']:
            child_typedef_node_list = extract_typedef_node_list(child_node)
            typedef_node_list.update(child_typedef_node_list)
    return typedef_node_list


def extract_typeloc_node_list(ast_node):
    typeloc_node_list = dict()
    node_type = str(ast_node["kind"])
    if node_type in ["TypeLoc"]:
        identifier = str(ast_node['value'])
        typeloc_node_list[identifier] = ast_node

    if len(ast_node['inner']) > 0:
        for child_node in ast_node['inner']:
            child_typeloc_node_list = extract_typeloc_node_list(child_node)
            # print(child_typeloc_node_list)
            typeloc_node_list.update(child_typeloc_node_list)
    return typeloc_node_list


def extract_binaryop_node_list(ast_node, file_path, white_list=None, black_list=None):
    binaryop_node_list = list()
    if not ast_node:
        return binaryop_node_list
    node_type = str(ast_node["kind"])
    if node_type in ["BinaryOperator"]:
        identifier = str(ast_node['opcode'])
        if white_list:
            if identifier in white_list:
                binaryop_node_list.append(ast_node)
        elif black_list:
            if identifier not in black_list:
                binaryop_node_list.append(ast_node)
        else:
            binaryop_node_list.append(ast_node)
    if "inner" in ast_node and len(ast_node['inner']) > 0:
        for child_node in ast_node['inner']:
            child_binaryop_node_list = extract_binaryop_node_list(child_node, file_path,
                                                                  white_list, black_list)
            binaryop_node_list = binaryop_node_list + child_binaryop_node_list
    return binaryop_node_list


def extract_array_subscript_node_list(ast_node):
    array_node_list = list()
    if not ast_node:
        return  array_node_list
    node_type = str(ast_node["kind"])
    if node_type in ["ArraySubscriptExpr"]:
        array_node_list.append(ast_node)
    if 'inner' in ast_node and len(ast_node['inner']) > 0:
            for child_node in ast_node['inner']:
                child_array_node_list = extract_array_subscript_node_list(child_node)
                array_node_list = array_node_list + child_array_node_list
    return array_node_list


def extract_unaryop_node_list(ast_node, filter_list=None):
    unaryop_node_list = list()
    if not ast_node:
        return unaryop_node_list
    node_type = str(ast_node["kind"])
    if node_type in ["UnaryOperator"]:
        identifier = str(ast_node['opcode'])
        if filter_list:
            if identifier in filter_list:
                unaryop_node_list.append(ast_node)
        else:
            unaryop_node_list.append(ast_node)

    if 'inner' in ast_node and  len(ast_node['inner']) > 0:
        for child_node in ast_node['inner']:
            child_unaryop_node_list = extract_unaryop_node_list(child_node, filter_list)
            unaryop_node_list = unaryop_node_list + child_unaryop_node_list
    return unaryop_node_list


def extract_keys_from_model(model):
    byte_list = list()
    k_list = ""
    for dec in model:
        if hasattr(model[dec], "num_entries"):
            k_list = model[dec].as_list()
            if dec.name() == "A-data":
                break
    for pair in k_list:
        if type(pair) == list:
            byte_list.append(int(str(pair[0])))
    return byte_list


def extract_input_bytes_used(sym_expr):
    input_byte_list = list()
    script_lines = str(sym_expr).split("\n")
    value_line = [x for x in script_lines if "assert" in x][0]
    if "select" in value_line:
        select_list = [x.group() for x in re.finditer(r'select (.*?)\)', value_line)]
        for sel_expr in select_list:
            symbolic_source = sel_expr.split(" ")[2]
            byte_index = sel_expr.split(" ")[4].replace("bv", "")
            input_byte_list.append("{}_{}".format(symbolic_source, byte_index))
            emitter.debug("\t\t\twarning: manual inspection of bytes")

    # print("input byte list")
    # print(input_byte_list)
    if input_byte_list:
        input_byte_list = sorted(input_byte_list)
    return input_byte_list


def extract_line(file_path, ast_loc_info):
    if "expansionLoc" in ast_loc_info:
        ast_loc_info = ast_loc_info["expansionLoc"]
    if "offset" not in ast_loc_info:
        return 0
    offset = int(ast_loc_info["offset"])
    if file_path not in values.AST_OFFSET_MAP:
        values.AST_OFFSET_MAP[file_path] = generator.generate_offset_to_line(file_path)
    offset_mapping = values.AST_OFFSET_MAP[file_path]
    return offset_mapping[offset]


def extract_line_range(file_path, ast_range):
    begin_loc = ast_range["begin"]
    end_loc = ast_range["end"]
    begin_line = extract_line(file_path,begin_loc)
    end_line = extract_line(file_path, end_loc)
    return range(begin_line, end_line+1)


def extract_col_range(ast_loc_info):
    begin_col = ast_loc_info["col"]
    end_col = begin_col + int(ast_loc_info["tokLen"])
    return range(begin_col, end_col+1)


def extract_loc(file_path, ast_loc_info, op_code = None):
    if "expansionLoc" in ast_loc_info:
        ast_loc_info = ast_loc_info["expansionLoc"]
    col_number = ast_loc_info["col"]
    line_number = extract_line(file_path, ast_loc_info)
    if op_code:
        if file_path not in values.SOURCE_LINE_MAP:
            with open(file_path, "r") as s_file:
                values.SOURCE_LINE_MAP[file_path] = s_file.readlines()
        source_line = values.SOURCE_LINE_MAP[file_path][line_number - 1]
        if source_line.find(op_code, col_number - 1) < 0:
            return None
        col_number = source_line.index(op_code, col_number-1) + 1
    return file_path, line_number, col_number

def extract_expression_list(ast_node, src_file):
    expression_list = list()
    array_access_list = extract_array_subscript_node_list(ast_node)
    binary_op_list = extract_binaryop_node_list(ast_node, src_file)
    initialize_op_list = extract_initialization_node_list(ast_node)
    unary_op_list = extract_unaryop_node_list(ast_node, src_file)
    for subscript_node in array_access_list:
        index_node = subscript_node["inner"][1]
        # expression_str = converter.convert_node_to_str(index_node)
        expression_loc = extract_loc(src_file, index_node["range"]["begin"])
        # data_type = index_node["type"]["qualType"]
        if expression_loc is None:
            continue
        # expression_list.append((expression_str, expression_loc[1], expression_loc[2], data_type, "ref"))

    for op_node in (binary_op_list + unary_op_list + initialize_op_list):
        op_code = None
        if "opcode" in op_node:
            op_code = op_node["opcode"]
            if op_code == "=":
                op_node = op_node["inner"][1]
                if "opcode" in op_node:
                    op_code = op_node["opcode"]
                else:
                    op_code = None
        if op_code in [">", ">=", "<", "<=", "==", "!="]:
            data_type = "bool"
        else:
            data_type = extract_data_type(op_node)
        expression_str = converter.convert_node_to_str(op_node)
        expression_loc = extract_loc(src_file, op_node["range"]["begin"], op_code)
        if expression_loc is None:
            continue
        expression_list.append((expression_str, expression_loc[1], expression_loc[2], data_type, "ref"))
    return list(set(expression_list))

def extract_expression_string_list(ast_node, src_file):
    expression_list = dict()
    binary_op_list = extract_binaryop_node_list(ast_node, src_file)
    array_access_list = extract_array_subscript_node_list(ast_node)
    initialize_op_list = extract_initialization_node_list(ast_node)
    unary_op_list = extract_unaryop_node_list(ast_node)
    for subscript_node in array_access_list:
        index_node = subscript_node["inner"][1]
        # expression_str = converter.convert_node_to_str(index_node)
        expression_loc = extract_loc(src_file, index_node["range"]["begin"])
        # data_type = index_node["type"]["qualType"]
        if expression_loc is None:
            continue
        expression_index = (expression_loc[1], expression_loc[2])
        # expression_list[expression_index] = expression_str
    for ast_node in (binary_op_list + unary_op_list + initialize_op_list):
        op_code = None
        if "opcode" in ast_node:
            op_code = ast_node["opcode"]
            if op_code == "=":
                ast_node = ast_node["inner"][1]
                if "opcode" in ast_node:
                    op_code = ast_node["opcode"]
                else:
                    op_code = None
        if op_code in [">", ">=", "<", "<=", "==", "!="]:
            continue
        expression_str = converter.convert_node_to_str(ast_node)
        loc_range = ast_node["range"]["begin"]
        if ast_node["kind"] == "BinaryOperator":
            loc_range = ast_node["inner"][0]["range"]["end"]
        expression_loc = extract_loc(src_file, loc_range, op_code)
        if expression_loc is None:
            continue
        expression_index = (expression_loc[1], expression_loc[2])
        expression_list[expression_index] = expression_str
    return expression_list

def extract_data_type(ast_node):
    data_type = "None"
    if "type" in ast_node:
        type_node = ast_node["type"]
        if "desugaredQualType" in type_node:
            data_type = type_node["desugaredQualType"]
        elif "qualType" in type_node:
            data_type = type_node["qualType"]
    return data_type
