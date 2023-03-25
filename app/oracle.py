import os
import signal
from app import definitions, values, emitter, extractor, logger, utilities, generator
from pysmt.shortcuts import is_sat, Not, And, is_unsat
from pysmt.smtlib.parser import SmtLibParser
from six.moves import cStringIO
import numpy as np
from sympy import sympify
from subprocess import Popen, PIPE


tautology_included = False
contradiction_included = False


def update_tautology_included(lock):
    global tautology_included
    res = False
    lock.acquire()
    if not tautology_included:
        tautology_included = True
        res = True
    lock.release()
    return res


def update_contradiction_included(lock):
    global contradiction_included
    res = False
    lock.acquire()
    if not contradiction_included:
        contradiction_included = True
        res = True
    lock.release()
    return res



import sys
if not sys.warnoptions:
    import warnings
    warnings.simplefilter("ignore")


def did_program_crash(program_output):
    if any(crash_word in str(program_output).lower() for crash_word in definitions.crash_word_list):
        return True
    return False


def any_runtime_error(program_output):
    if any(error_word in str(program_output).lower() for error_word in definitions.error_word_list):
        return True
    return False


def is_loc_on_stack(source_path, function_name, line_number, stack_info):
    # print(source_path, function_name, line_number)
    if source_path in stack_info.keys():
        # print(source_path)
        source_info = stack_info[source_path]
        if function_name in source_info.keys():
            # print(function_name)
            line_list = source_info[function_name]
            # print(line_list)
            if str(line_number) in line_list:
                # print(line_number)
                return True
    return False


def is_loc_on_sanitizer(source_path, line_number, suspicious_lines):
    # print(source_path, line_number)
    # print(suspicious_lines)
    source_loc = source_path + ":" + str(line_number)
    if source_loc in suspicious_lines.keys():
        return True
    return False


def is_loc_in_trace(source_loc):
    return source_loc in values.LIST_TRACE


def is_valid_range(check_range):
    lower_bound, upper_bound = check_range
    if lower_bound <= upper_bound:
        return True
    return False


def is_component_constant(patch_comp):
    (cid, semantics), children = patch_comp
    if "constant" in cid:
        return True
    return False


def is_same_children(patch_comp):
    (_, _), children = patch_comp
    right_child = children['right']
    left_child = children['left']
    (cid_right, _), _ = right_child
    (cid_left, _), _ = left_child
    if cid_left == cid_right:
        return True
    return False


def is_always_true(patch):
    program = patch[list(patch.keys())[0]]
    tree, _ = program
    (cid, semantics), children = tree
    if cid not in ["equal", "greater-or-equal", "less-or-equal"]:
        return False
    return is_same_children(tree)


def is_always_false(patch):
    program = patch[list(patch.keys())[0]]
    tree, _ = program
    (cid, semantics), children = tree
    if cid not in ["not-equal", "greater-than", "less-than"]:
        return False
    return is_same_children(tree)


def is_tree_duplicate(tree, lock):
    (cid, semantics), children = tree
    if len(children) == 2:
        right_child = children['right']
        left_child = children['left']

        if cid in ["less-than", "less-or-equal", "greater-than", "greater-or-equal", "equal", "not-equal", "addition", "division", "multiplication", "subtraction"]:
            is_right_constant = is_component_constant(right_child)
            is_left_constant = is_component_constant(left_child)
            if is_right_constant and is_left_constant:
                return True
            if is_same_children(tree):
                if is_left_constant or is_right_constant:
                    return True
                else:
                    if cid in ['not-equal', 'less-than', 'greater-than']:
                        return not update_contradiction_included(lock)
                    elif cid in ['equal', 'less-or-equal', 'greater-or-equal']:
                        return not update_tautology_included(lock)
                    elif cid in ['addition', 'division', 'subtraction', 'remainder']:
                        return True
                    # else:
                    #     return True

        if cid in ["logical-or", "logical-and", "less-than", "less-or-equal", "greater-than", "greater-or-equal", "equal", "not-equal", "addition", "division", "multiplication", "subtraction"]:
            is_right_redundant = is_tree_duplicate(right_child, lock)
            is_left_redundant = is_tree_duplicate(left_child, lock)
            if is_right_redundant or is_left_redundant:
                return True
    return False


def is_tree_logic_redundant(tree):
    (cid, semantics), children = tree
    if cid in ["addition", "division", "multiplication", "subtraction", "remainder"]:
        return False
    child_node_list = extractor.extract_child_expressions(tree)
    unique_child_node_list = []
    for child in child_node_list:
        if child not in unique_child_node_list:
            unique_child_node_list.append(child)
        else:
            return True
    return False


def is_patch_duplicate(patch, index, lock):
    program = patch[list(patch.keys())[0]]
    tree, _ = program
    result = is_tree_duplicate(tree, lock) or is_tree_logic_redundant(tree)
    return result, index


def is_expression_equal(str_a, str_b):
    token_list = [x for x in str(str_a + str_b).split(" ")]
    prohibited_tok_list = ["(", "&"]
    if any(t in prohibited_tok_list for t in token_list):
        return False
    try:
        expr_a = sympify(str_a.replace("[", "(").replace("]", ")").replace(".", "_").replace("->", "_"))
        expr_b = sympify(str_b.replace("[", "(").replace("]", ")").replace(".", "_").replace("->", "_"))
    except Exception as ex:
        logger.exception(ex, (str_a, str_b))
        return False
    return expr_a == expr_b

def is_equivalent(expr_a, expr_b):
    z3_eq_code = generator.generate_z3_code_for_equivalence(expr_a, expr_b)
    return not is_satisfiable(z3_eq_code)


def is_satisfiable(z3_code):
    parser = SmtLibParser()
    result = False
    try:
        script = parser.get_script(cStringIO(z3_code))
        formula = script.get_last_formula()
        result = is_sat(formula, solver_name="z3")
    except Exception as ex:
        emitter.debug("\t\t[warning] Z3 Exception in PYSM, Trying Z3 CLI")
        logger.information(z3_code)
        with open("/tmp/z3_cli_code", "w") as z3_file:
            z3_file.writelines(z3_code)
            z3_file.close()
        z3_cli_command = "timeout -k 1s 10s z3 /tmp/z3_cli_code > /tmp/z3_cli_output"
        utilities.execute_command(z3_cli_command)
        with open("/tmp/z3_cli_output", "r") as log_file:
            output_content = log_file.readlines()
            if output_content and "sat" == output_content[-1].strip():
                result = True
    return result


def ndim_grid(start,stop):
    # Set number of dimensions
    ndims = len(start)

    # List of ranges across all dimensions
    L = [np.arange(start[i],stop[i]) for i in range(ndims)]

    # Finally use meshgrid to form all combinations corresponding to all
    # dimensions and stack them as M x ndims array
    return np.hstack((np.meshgrid(*L))).swapaxes(0,1).reshape(ndims,-1).T


def is_top_assertion(src_loc, call_node_list):
    for call_node in call_node_list:
        loc_range = call_node["range"]
        if is_loc_in_range(src_loc, loc_range):
            node_type = call_node["kind"]
            if node_type == "CallExpr":
                func_ref_node = call_node["inner"][0]
                func_ref_name = func_ref_node["inner"][0]["referencedDecl"]["name"]
                if func_ref_name in ["assert", "__assert_fail"]:
                    return True
    return False

def is_loc_member_access(check_loc, function_ast):
    member_node_list = extractor.extract_member_node_list(function_ast)
    for member_node in member_node_list:
        ast_range = member_node["range"]
        file_path, c_line, c_col = check_loc
        line_range = extractor.extract_line_range(file_path, ast_range)
        expansion_col_range = extractor.extract_col_range(ast_range)
        check_range = range(expansion_col_range[1], expansion_col_range[-1])
        if int(c_line) in line_range:
            if int(c_col) in check_range:
                return True
    return False


def is_loc_in_range(check_loc, ast_range, is_arrow=False):
    file_path, c_line, c_col = check_loc
    # end_col = extractor.extract_loc(file_path, ast_range["end"])[2]
    # if "tokLen" in ast_range["end"]:
    #     end_col = end_col + int(ast_range["end"]["tokLen"])
    line_range = extractor.extract_line_range(file_path, ast_range)
    col_range = extractor.extract_col_range(ast_range)
    if int(c_line) in line_range:
        if int(c_line) == line_range.stop - 1:
            if int(c_col) in col_range:
                return True
            elif is_arrow and int(c_col) <= col_range.stop + 1:
                return True
        else:
            return True

    # if int(c_line) in line_range:
    #     if int(c_line) == line_range.stop - 1:
    #         if int(c_col) <= end_col:
    #             return True
    #         elif is_arrow:
    #             if int(c_col) <= end_col + 2:
    #                 return True
    #     else:
    #         return True
    return False


def is_loc_match(check_loc, ref_loc):
    if len(check_loc) == 2:
        c_line, c_col = check_loc
    else:
        _, c_line, c_col = check_loc

    if len(ref_loc) == 2:
        r_line, r_col = ref_loc
    else:
        _, r_line, r_col = ref_loc

    if int(c_line) == int(r_line) and int(c_col) == int(r_col):
       return True
    return False


def is_expr_list_match(expr_list_a, expr_list_b):
    if "width" in expr_list_a or "width" in expr_list_b:
        return False
    value_list_a = []
    value_list_b = []
    for expr_a in expr_list_a:
        value_a = expr_a
        if " " in expr_a:
            value_a = expr_a.split(" ")[1]
        value_list_a.append(value_a)
    for expr_b in expr_list_b:
        value_b = expr_b
        if " " in expr_b:
            value_b = expr_b.split(" ")[1]
        value_list_b.append(value_b)
    if value_list_a != value_list_b:
        return False
    return True
