#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import os
from app import utilities


def convert_cast_expr(ast_node, only_string=False):
    var_list = list()
    data_type = "None"
    if "type" in ast_node:
        data_type = str(ast_node["type"]["qualType"])
    param_node = ast_node["inner"][0]
    param_node_type = param_node["kind"]
    var_name = "(" + data_type + ") " + get_node_value(param_node)
    if only_string:
        return var_name
    return var_name, var_list

def convert_unaryexprortypetraitexpr_to_expr(ast_node, only_string=False):
    var_list = list()
    expr = "{}({})".format(ast_node["name"], ast_node["argType"]["qualType"])
    if only_string:
        return expr
    return expr, var_list


def convert_paren_node_to_expr(ast_node, only_string=False):
    var_name = ""
    var_list = list()
    value = ""
    child_node = ast_node["inner"][0]
    # print(child_node)
    child_node_type = child_node["kind"]
    value = get_node_value(child_node)
    var_name = "(" + value + ")"
    # print(var_name)
    if only_string:
        return var_name
    return var_name, list(set(var_list))


def convert_unary_node_to_expr(ast_node, only_string=False):
    var_name = ""
    var_list = list()
    # print(ast_node)
    child_node = ast_node["inner"][0]
    # print(left_child)
    child_value = ""
    child_type = str(child_node["kind"])
    if child_type in [ "IntegerLiteral"]:
        child_value = str(child_node['value'])
    elif child_type in ["DeclRefExpr"]:
        child_value = str(child_node['referencedDecl']['name'])
    elif child_type == "BinaryOperator":
        child_value = convert_binary_node_to_expr(child_node, True)
        # var_list = var_list + child_var_list
    elif child_type == "MemberExpr":
        child_value = convert_member_expr(child_node, True)
        # var_list = var_list + child_var_list
    elif child_type == "ParenExpr":
        child_value = convert_paren_node_to_expr(child_node, True)
        # var_list = var_list + child_var_list
    operation = str(ast_node['opcode'])
    # print(operation)
    var_name = operation + child_value
    if "isPostfix" in ast_node:
        if ast_node["isPostfix"] == "True":
            var_name = child_value + operation
    if only_string:
        return var_name
    return var_name, list(set(var_list))


def convert_conditional_op_to_expr(ast_node, only_string=False):
    var_name = ""
    condition_exp = convert_node_to_str(ast_node["inner"][0], True)
    true_node = ast_node["inner"][1]
    true_node_value = get_node_value(true_node)
    false_node = ast_node["inner"][2]
    false_node_value = get_node_value(false_node)
    var_name = condition_exp + " ? " + true_node_value + " : " + false_node_value
    return var_name


def get_node_value(ast_node):
    ast_value = ""
    if not ast_node:
        return ast_value
    ast_type = str(ast_node["kind"])
    if ast_type in ["DeclRefExpr"]:
        ast_value = str(ast_node['referencedDecl']['name'])
    elif ast_type in ["IntegerLiteral", "StringLiteral"]:
        ast_value = str(ast_node['value'])
    elif ast_type in ["ParmVarDecl", "RecordDecl", "VarDecl"]:
        ast_value = ast_node['identifier']
    elif ast_type in ["FieldDecl"]:
        ast_value = ast_node['qualified_identifier'].split("::")[0] + "." + ast_node['identifier']
    elif ast_type == "FunctionDecl":
        ast_value = ast_node['identifier'] + "("
    elif ast_type == "BinaryOperator":
        ast_value = convert_binary_node_to_expr(ast_node, True)
        # var_list = var_list + left_child_var_list
    elif ast_type == "ParenExpr":
        ast_value = convert_paren_node_to_expr(ast_node, True)
        # var_list = var_list + left_child_var_list
    elif ast_type == "ArraySubscriptExpr":
        ast_value = convert_array_subscript(ast_node, True)
    elif ast_type == "MemberExpr":
        ast_value = convert_member_expr(ast_node, True)
        # var_list = var_list + left_child_var_list
    elif ast_type in ["Macro", "LabelStmt", "TypeLoc", "GotoStmt"]:
        if "value" in ast_node:
            ast_value = ast_node['value']
    elif ast_type == "CStyleCastExpr":
        ast_value = convert_cast_expr(ast_node, True)
    elif ast_type == "CallExpr":
        ast_value = convert_call_expr(ast_node, True)
    elif ast_type == "UnaryExprOrTypeTraitExpr":
        ast_value = ""
    elif ast_type == "UnaryOperator":
        ast_value = convert_unary_node_to_expr(ast_node, True)
    elif ast_type == "ConditionalOperator":
        ast_value = convert_conditional_op_to_expr(ast_node, True)
    elif ast_type in ["PredefinedExpr", "ImplicitCastExpr"]:
        ast_value = get_node_value(ast_node["inner"][0])
    elif ast_type in ["CharacterLiteral", "CompoundLiteralExpr", "BinaryConditionalOperator"]:
        return None
    else:
        print(ast_type)
        print(ast_node)
        utilities.error_exit("Unhandled node type in convert ast node")
    return ast_value


def convert_binary_node_to_expr(ast_node, only_string=False):
    var_name = ""
    var_list = list()
    # print(ast_node)
    left_child = ast_node["inner"][0]
    # print(left_child)
    left_child_value = get_node_value(left_child)
    operation = str(ast_node['opcode'])
    # print(operation)
    right_child = ast_node["inner"][1]
    # print(right_child)
    right_child_value = get_node_value(right_child)
    var_name = left_child_value + " " + operation + " " + right_child_value
    if only_string:
        return var_name
    return var_name, list(set(var_list))


def convert_array_iterator(iterator_node, only_string=False):
    iterator_node_type = str(iterator_node["kind"])
    var_list = list()
    if iterator_node_type == "ImplicitCastExpr":
        iterator_node = iterator_node["inner"][0]
        iterator_node_type = str(iterator_node["kind"])
    var_type = iterator_node["type"]["qualType"]
    if iterator_node_type in ["VarDecl", "ParmVarDecl"]:
        iterator_name = str(iterator_node['identifier'])
        iterator_data_type = None
        if "data-type" in iterator_node:
            iterator_data_type = str(iterator_node["type"]["qualType"])
        var_list.append((iterator_name, iterator_data_type))
        var_name = "[" + iterator_name + "]"
    elif iterator_node_type in ["Macro"]:
        iterator_value = str(iterator_node['value'])
        var_name = "[" + iterator_value + "]"
    elif iterator_node_type == "DeclRefExpr":
        iterator_name = str(iterator_node['referencedDecl']['name'])
        iterator_data_type = None
        if "data-type" in iterator_node:
            iterator_data_type = str(iterator_node["type"]["qualType"])
        var_list.append((iterator_name, iterator_data_type))
        var_name = "[" + iterator_name + "]"
    elif iterator_node_type in ["IntegerLiteral"]:
        iterator_value = str(iterator_node['value'])
        var_name = "[" + iterator_value + "]"
    elif iterator_node_type in ["BinaryOperator"]:
        iterator_value = convert_binary_node_to_expr(iterator_node, True)
        var_name = "[" + iterator_value + "]"
    elif iterator_node_type in ["UnaryOperator"]:
        iterator_value = convert_unary_node_to_expr(iterator_node, True)
        var_name = "[" + iterator_value + "]"
    elif iterator_node_type in ["MemberExpr"]:
        iterator_value = convert_member_expr(iterator_node, True)
        var_name = "[" + iterator_value + "]"
    elif iterator_node_type == "ParenExpr":
        iterator_value = convert_paren_node_to_expr(iterator_node, True)
        var_name = "[" + iterator_value + "]"
    elif iterator_node_type == "CallExpr":
        iterator_value = convert_call_expr(iterator_node, True)
        var_name = "[" + iterator_value + "]"
    elif iterator_node_type == "ArraySubscriptExpr":
        iterator_value = convert_array_subscript(iterator_node, True)
        var_name = "[" + iterator_value + "]"
    elif iterator_node_type == "CStyleCastExpr":
        iterator_value = convert_cast_expr(iterator_node, True)
        var_name = "[" + iterator_value + "]"
    else:
        print(iterator_node)
        utilities.error_exit("Unknown iterator type for convert_array_iterator")
    if only_string:
        return var_name
    return var_name, var_type, var_list


def convert_array_subscript(ast_node, only_string=False):
    var_list = list()
    var_name = ""
    var_data_type = str(ast_node["type"]["qualType"])
    # print(ast_node)
    array_node = ast_node["inner"][0]
    array_type = str(array_node["kind"])
    if array_type == "ImplicitCastExpr":
        array_node = array_node["inner"][0]
        array_type = str(array_node["kind"])

    if array_type == "DeclRefExpr":
        array_name = str(array_node['referencedDecl']['name'])
        array_data_type = None
        if "type" in array_node.keys():
            array_data_type = str(array_node["type"]["qualType"])
        if array_data_type is None:
            var_data_type = "unknown"
        else:
            var_data_type = array_data_type.split("[")[0]
        iterator_node = ast_node["inner"][1]
        iterator_name, iterator_type, _ = convert_array_iterator(iterator_node)
        var_name = array_name + iterator_name
    elif array_type == "MemberExpr":
        # array_name = str(array_node['referencedDecl']['name'])
        # array_data_type = None
        if "type" in array_node.keys():
            array_data_type = str(array_node["type"]["qualType"])
        if len(ast_node["inner"]) > 1:
            iterator_node = ast_node["inner"][1]
            array_name = convert_member_expr(array_node, True)
            iterator_name, iterator_type, _ = convert_array_iterator(iterator_node)
            var_name = array_name + iterator_name
    elif array_type == "ParenExpr":
        array_name = convert_paren_node_to_expr(array_node, True)
        var_data_type = None
        if "type" in array_node.keys():
            var_data_type = str(array_node["type"]["qualType"])
        iterator_node = ast_node["inner"][1]
        iterator_name, iterator_type, _ = convert_array_iterator(iterator_node)
        var_name = array_name + iterator_name
    elif array_type == "Macro":
        var_data_type = None
        iterator_node = ast_node["inner"][1]
        array_name = str(array_node['value'])
        iterator_name, iterator_type, _ = convert_array_iterator(iterator_node)
        var_name = array_name + iterator_name
    elif array_type == "ArraySubscriptExpr":
        array_name = convert_array_subscript(array_node, True)
        iterator_node = ast_node["inner"][1]
        iterator_name, iterator_type, _ = convert_array_iterator(iterator_node)
        var_name = array_name + iterator_name
    else:
        print(array_type)
        print(array_node)
        print(ast_node)
        utilities.error_exit("Unknown data type for array_subscript")
    iterator_name = iterator_name.replace("[", "").replace("]", "")
    if not str(iterator_name).isnumeric():
        var_list.append((iterator_name, iterator_type))
    if only_string:
        return var_name
    return var_name, var_data_type, var_list


def convert_call_expr(ast_node, only_string=False):
    var_name = "()"
    function_name = ""
    operand_list = list()
    var_list = list()
    call_function_node = ast_node["inner"][0]
    call_function_node_type = str(call_function_node["kind"])
    if call_function_node_type == "ImplicitCastExpr":
        call_function_node = call_function_node["inner"][0]
        call_function_node_type = str(call_function_node["kind"])
    if "referencedDecl" in call_function_node:
        call_function_node_ref_type = str(call_function_node['referencedDecl']['kind'])
        operand_count = len(ast_node["inner"])
        if call_function_node_type == "DeclRefExpr" and call_function_node_ref_type == "FunctionDecl":
            function_name = str(call_function_node['referencedDecl']['name'])
        elif call_function_node_type == "DeclRefExpr" and call_function_node_ref_type == "VarDecl":
            function_name = str(call_function_node["type"]["qualType"])
            operand = str(call_function_node['value'])
            operand_list.append(operand)
            operand_count = 0
        else:
            print(ast_node)
            utilities.error_exit("unknown decl type in convert_call_expr")

        for i in range(1, operand_count):
            operand_node = ast_node["inner"][i]
            operand_node_type = str(operand_node["kind"])
            if operand_node_type == "CallExpr":
                operand_var_name = convert_call_expr(operand_node, True)
                operand_list.append(operand_var_name)
                # var_list = var_list + operand_var_list
            elif operand_node_type == "DeclRefExpr":
                operand_var_name = str(operand_node['value'])
                operand_list.append(operand_var_name)
            elif operand_node_type == "MemberExpr":
                operand_var_name = convert_member_expr(operand_node, True)
                operand_list.append(operand_var_name)
            elif operand_node_type == "Macro":
                operand_var_name = str(operand_node['value'])
                if "?" in operand_var_name:
                    continue
                operand_list.append(operand_var_name)
            elif operand_node_type == "IntegerLiteral":
                operand_var_name = str(operand_node['value'])
                operand_list.append(operand_var_name)
            else:
                operand_var_name = get_node_value(operand_node)
                operand_list.append(operand_var_name)

        var_name = function_name + "("
        for operand in operand_list:
            var_name += operand
            if operand != operand_list[-1]:
                var_name += ","

        var_name += ")"
        # print(var_name)
    if only_string:
        return var_name
    return var_name, list(set(var_list))


def convert_member_expr(ast_node, only_string=False):
   
    var_list = list()
    var_name = ""
    var_data_type = ""
    # print(ast_node)
    if 'name' in ast_node.keys():
        node_value = ast_node['name']
        var_name = str(node_value.split(":")[-1])
        # print(var_name)
        var_data_type = str(ast_node["type"]["qualType"])
        if "isArrow" in ast_node.keys():
            if ast_node["isArrow"] is False:
                var_name = "." + var_name
            else:
                var_name = "->" + var_name
        else:
            var_name = "->" + var_name
    child_node = ast_node["inner"][0]
    while child_node:
        child_node_type = child_node["kind"]
        if child_node_type == "ImplicitCastExpr":
            child_node = child_node["inner"][0]
            child_node_type = child_node["kind"]
        if child_node_type == "DeclRefExpr":
            var_name = str(child_node['referencedDecl']['name']) + var_name
        elif child_node_type == "ArraySubscriptExpr":
            # array_var_name, array_var_data_type, \
            # iterating_var_list = convert_array_subscript(child_node)
            # var_list = var_list + iterating_var_list
            # if var_name[:2] == "->":
            #     var_name = "." + var_name[2:]
            # var_name = array_var_name + var_name
            iterating_var_node = child_node["inner"][1]

            # iterating_var_name = iterating_var_node['value']
            # iterating_var_type = iterating_var_node["kind"]
            # iterating_var_data_type = iterating_var_node["type"]["qualType"]
            iterating_var_name = convert_array_iterator(iterating_var_node, True)

            # if var_data_type == "":
            #     var_data_type = iterating_var_data_type

            # var_list = var_list + iterating_var_list
            if var_name[:2] == "->":
                var_name = "." + var_name[2:]
            var_name = iterating_var_name + var_name
            # if iterating_var_type == "DeclRefExpr":
            #     iterating_var_ref_type = iterating_var_node['ref_type']
            #     if iterating_var_ref_type in ["VarDecl", "ParmVarDecl"]:
            #         var_list.append((iterating_var_name, iterating_var_data_type))
            #         if var_name[:2] == "->":
            #             var_name = "." + var_name[2:]
            #         var_name = "[" + iterating_var_name + "]" + var_name
        elif child_node_type == "ParenExpr":
            param_node = child_node["inner"][0]
            param_node_type = param_node["kind"]
            param_node_var_name = convert_node_to_str(param_node, True)
            var_name = param_node_var_name + var_name
            break
        elif child_node_type == "CStyleCastExpr":
            cast_var_name, cast_data_type = convert_cast_expr(child_node, True)
            # var_list = var_list + cast_node_aux_list
            var_name = cast_var_name + var_name
            break
        elif child_node_type == "MemberExpr":
            child_node_value = child_node['name']
            # var_data_type = str(child_node["type"]["qualType"])
            if "isArrow" not in child_node.keys():
                var_name = "." + str(child_node_value.split(":")[-1]) + var_name
            else:
                var_name = "->" + str(child_node_value.split(":")[-1]) + var_name
        elif child_node_type == "CallExpr":
            child_var_name = convert_call_expr(child_node, True)
            # var_list = var_list + child_aux_list
            var_name = child_var_name + var_name
            break
        elif child_node_type == "TypeLoc":
            break
        else:
            print(ast_node)
            print(child_node)
            utilities.error_exit("unhandled exception at membership expr -> str")
        if "inner" in child_node and len(child_node["inner"]) > 0:
            child_node = child_node["inner"][0]
        else:
            child_node = None
    if only_string:
        return var_name
    return var_name, var_data_type, var_list



def convert_node_to_str(ast_node, only_string=False):
    node_str = ""
    # print(ast_node)
    node_type = str(ast_node["kind"])
    if node_type == "ImplicitCastExpr":
        return convert_node_to_str(ast_node["inner"][0], only_string)
    if node_type in ["DeclRefExpr"]:
        node_str = str(ast_node['referencedDecl']['name'])
    elif node_type in ["IntegerLiteral", "CharacterLiteral"]:
        node_str = str(ast_node["value"])
    elif node_type in ["DeclStmt", "VarDecl"]:
        node_str = str(ast_node['value'])
    elif node_type == "ArraySubscriptExpr":
        node_str = str(convert_array_subscript(ast_node, True))
    elif node_type == "MemberExpr":
        node_str = str(convert_member_expr(ast_node, True))
    elif node_type == "BinaryOperator":
        operator = str(ast_node['opcode'])
        right_operand = convert_node_to_str(ast_node["inner"][1], only_string)
        left_operand = convert_node_to_str(ast_node["inner"][0])
        node_str = left_operand + " " + operator + " " + right_operand
    elif node_type == "UnaryOperator":
        operator = str(ast_node['opcode'])
        child_operand = convert_node_to_str(ast_node["inner"][0])
        node_str = operator + child_operand
    elif node_type == "CallExpr":
        node_str = convert_call_expr(ast_node, True)
    elif node_type == "CStyleCastExpr":
        node_str = convert_cast_expr(ast_node, True)
    elif node_type == "ParenExpr":
        node_str = convert_paren_node_to_expr(ast_node, True)
    elif node_type == "ConditionalOperator":
        node_str = convert_conditional_op_to_expr(ast_node, True)
    elif node_type == "UnaryExprOrTypeTraitExpr":
        node_str = convert_unaryexprortypetraitexpr_to_expr(ast_node, True)
    else:
        print(ast_node)
        utilities.error_exit("Unhandled AST Node type for String conversion: {}".format(node_type))
    return node_str


def convert_macro_list_to_dict(string_list):
    macro_list = dict()
    for macro_def in string_list:
        macro_name = str(macro_def).split(" ")[1]
        if "(" in macro_name:
            macro_name = macro_name.split("(")[0] + "("
        macro_list[macro_name] = macro_def
    return macro_list


def convert_dict_to_array(ast_tree):
    node_array = dict()
    for ast_node in ast_tree["inner"]:
        child_id = int(ast_node['id'])
        node_array[child_id] = ast_node
        child_list = convert_dict_to_array(ast_node)
        if child_list:
            node_array.update(child_list)
    return node_array
