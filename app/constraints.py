#! /usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from app import emitter, utilities, converter, values

SymbolType = {
                 "INT_CONST": "",
                 "INT_VAR": "",
                 "REAL_CONST": "",
                 "REAL_VAR": "",
                 "VAR_NAME": "",

                 "OP_LT": "<",
                 "OP_LTE": "<=",
                 "OP_GT": ">",
                 "OP_GTE": ">=",
                 "OP_EQ": "==",
                 "OP_NEQ": "!=",

                 "OP_AND": "&&",
                 "OP_OR": "||",
                 "OP_NOT": "!",

                 "OP_INCREMENT": "++",
                 "OP_DECREMENT": "--",

                 "OP_ASSIGN": "=",
                 "OP_ARITH_MINUS": "-",
                 "OP_ARITH_PLUS": "+",
                 "OP_ARITH_DIVIDE": "/",
                 "OP_ARITH_MUL": "*",

                 "OP_SHIFT_RIGHT": ">>",
                 "OP_SHIFT_LEFT": "<<",

                 "OP_LET": "let ",
                 "NULL_VAL": "null",
                 "OP_SIZE_OF": "sizeof "
}


class ConstraintSymbol:
    _m_symbol = None
    _m_cons_type = None

    def __init__(self, m_symbol, m_type):
        self._m_symbol = m_symbol
        self._m_cons_type = m_type

    def get_type(self):
        return self._m_cons_type

    def get_symbol(self):
        return self._m_symbol

    def update_symbol(self, new_symbol_str):
        self._m_symbol = new_symbol_str

    def is_operator(self):
        operator_type_list = [
            "OP_LT",
            "OP_LTE",
            "OP_GT",
            "OP_GTE",
            "OP_EQ",
            "OP_NEQ",
            "OP_AND",
            "OP_OR",
            "OP_NOT",
            "OP_ASSIGN",
            "OP_ARITH_MINUS",
            "OP_ARITH_PLUS",
            "OP_ARITH_DIVIDE",
            "OP_ARITH_MUL",
            "OP_INCREMENT",
            "OP_DECREMENT",
            "OP_SHIFT_RIGHT",
            "OP_SHIFT_LEFT"
        ]
        return self._m_cons_type in operator_type_list

    def is_int_var(self):
        return self._m_cons_type == "INT_VAR"

    def is_real_var(self):
        return self._m_cons_type == "REAL_VAR"

    def is_int_const(self):
        return self._m_cons_type == "INT_CONST"

    def is_real_const(self):
        return self._m_cons_type == "REAL_CONST"

    def is_var_name(self):
        return self._m_cons_type == "VAR_NAME"

    def is_sizeof(self):
        return self._m_cons_type == "OP_SIZE_OF"

    def is_null(self):
        return self._m_symbol is None


class ConstraintExpression:
    _m_symbol:ConstraintSymbol = None
    _m_letsymbol = None
    _m_lvalue = None
    _m_rvalue = None
    _hasLetVal = False
    _m_mapping = None
    _is_leaf = False
    _sizeof = None


    def __init__(self, c_symbol, l_expr, r_expr):
        self._m_symbol = c_symbol
        if l_expr is None and r_expr is None:
            self._is_leaf = True
        else:
            self._m_lvalue = l_expr
            self._m_rvalue = r_expr

    def get_type(self):
        return self._m_symbol.get_type()

    def get_symbol(self)->ConstraintSymbol:
        return self._m_symbol.get_symbol()

    def is_leaf(self):
        return self._is_leaf

    def get_l_expr(self):
        if self._m_lvalue is None:
            return None
        return self._m_lvalue

    def get_r_expr(self):
        if self._m_rvalue is None:
            return None
        return self._m_rvalue

    def to_json(self):
        json_obj = dict()
        json_obj["type"] = self.get_type()
        json_obj["symbol"] = self.get_symbol()
        if not self.is_leaf():
            if self.get_l_expr() is not None:
                json_obj["left"] = self.get_l_expr().to_json()
            if self.get_r_expr() is not None:
                json_obj["right"] = self.get_r_expr().to_json()
        return json_obj


    def to_string(self):
        expr_str = str(self.get_symbol())
        if self._m_symbol.is_sizeof():
            if self._sizeof:
                return self._sizeof
        if not self.is_leaf():
            l_expr = None
            r_expr = None
            if self.get_l_expr() is not None:
                l_expr = self.get_l_expr().to_string()
            if self.get_r_expr() is not None:
                r_expr = self.get_r_expr().to_string()

            if l_expr and r_expr:
                expr_str = "({} {} {})".format(l_expr, expr_str, r_expr)
            elif r_expr:
                if self._m_symbol.is_sizeof():
                    expr_str = "{}{}".format(expr_str, r_expr)
                else:
                    expr_str = "({} {})".format(expr_str, r_expr)
        return expr_str

    def get_symbol_list(self):
        symbol_list = []
        if self._m_symbol.is_int_var() or self._m_symbol.is_real_var():
            symbol_list = [self.get_symbol()]
        elif self._m_symbol.is_sizeof():
            return [self.to_string()]
        if self._m_lvalue:
            symbol_list = symbol_list + self._m_lvalue.get_symbol_list()
        if self._m_rvalue:
            symbol_list = symbol_list + self._m_rvalue.get_symbol_list()
        return list(set(symbol_list))


    def resolve_sizeof(self, cfc_var_info_list):
        if self._m_symbol.is_sizeof():
            ptr_name = self.get_r_expr().to_string()
            if ptr_name in cfc_var_info_list:
                crash_var_expr_list = cfc_var_info_list[ptr_name]['expr_list']
                if len(crash_var_expr_list) > 1:
                    emitter.error("More than one pointer for SizeOf resolution")
                    utilities.error_exit("Unhandled Exception")
                symbolic_ptr = crash_var_expr_list[0].split(" ")[1]
                symbolic_size = values.MEMORY_TRACK[symbolic_ptr]['size']
                self._sizeof = symbolic_size


        if not self.is_leaf():
            if self.get_r_expr() is not None:
                self.get_r_expr().resolve_sizeof(cfc_var_info_list)
            if self.get_l_expr() is not None:
                self.get_l_expr().resolve_sizeof(cfc_var_info_list)



    def update_symbols(self, symbol_mapping):
        if self._m_symbol.is_int_var() or self._m_symbol.is_real_var():
            symbol_str = self.get_symbol()
            if symbol_str in symbol_mapping:
                self._m_symbol.update_symbol(symbol_mapping[symbol_str])
        elif self._m_symbol.is_sizeof():
            symbol_str = self.to_string()
            if symbol_str in symbol_mapping:
                self._sizeof = symbol_mapping[symbol_str]
        if self._m_lvalue:
            self._m_lvalue.update_symbols(symbol_mapping)
        if self._m_rvalue:
            self._m_rvalue.update_symbols(symbol_mapping)


def build_op_symbol(symbol_str):
    op_type = next(key for key, value in SymbolType.items() if value == symbol_str)
    symbolic_op = make_constraint_symbol(symbol_str, op_type)
    return symbolic_op


def make_constraint_symbol(c_symbol, c_type):
    if c_type not in SymbolType.keys():
        utilities.error_exit("Unknown Type for Constraint: {}".format(c_type))
    return ConstraintSymbol(c_symbol, c_type)


def make_binary_expression(c_symbol:ConstraintSymbol, l_val:ConstraintExpression, r_val:ConstraintExpression):
    return ConstraintExpression(c_symbol, l_val, r_val)


def make_unary_expression(c_symbol:ConstraintSymbol, r_val:ConstraintExpression):
    return ConstraintExpression(c_symbol, None, r_val)


def make_symbolic_expression(c_symbol:ConstraintSymbol):
    return ConstraintExpression(c_symbol, None, None)


def make_constraint_expression(c_symbol:ConstraintSymbol, l_val:ConstraintSymbol, r_val:ConstraintSymbol):
    return ConstraintExpression(c_symbol, l_val, r_val)


def generate_expr_for_str(expr_str)->ConstraintExpression:
    symbolic_stack = []
    symbolic_list = []
    str_tokens = expr_str.split(" - ").replace("(", "").replace(")", "")
    for token in str_tokens:
        if token in SymbolType.keys():
            symbolic_stack.append(token)

    for token in str_tokens:
        token_strip = str(token).strip().replace("\n", "").replace("(", "").replace(")", "")
        if token_strip.isnumeric():
            token_type = "INT_CONST"
            if token_strip.isdecimal():
                token_type = "REAL_CONST"
            token_symbol = make_constraint_symbol(token_strip, token_type)


def generate_expr_for_ast(ast_node)->ConstraintExpression:
    node_type = str(ast_node["kind"])
    if node_type == "BinaryOperator":
        op_symbol_str = str(ast_node["opcode"])
        op_type = next(key for key, value in SymbolType.items() if value == op_symbol_str)
        constraint_symbol = make_constraint_symbol(op_symbol_str, op_type)
        left_ast = ast_node["inner"][0]
        right_ast = ast_node["inner"][1]
        left_expr = generate_expr_for_ast(left_ast)
        right_expr = generate_expr_for_ast(right_ast)
        constraint_expr = make_binary_expression(constraint_symbol, left_expr, right_expr)
        return constraint_expr
    elif node_type == "UnaryOperator":
        op_symbol_str = str(ast_node["opcode"])
        op_type = next(key for key, value in SymbolType.items() if value == op_symbol_str)
        constraint_symbol = make_constraint_symbol(op_symbol_str, op_type)
        child_ast = ast_node["inner"][0]
        child_expr = generate_expr_for_ast(child_ast)
        constraint_expr = make_unary_expression(constraint_symbol, child_expr)
        return constraint_expr
    elif node_type == "Macro":
        utilities.error_exit("Unhandled node type for Expression: {}".format(node_type))
    elif node_type in ["ParenExpr", "ImplicitCastExpr"]:
        child_node = ast_node["inner"][0]
        return generate_expr_for_ast(child_node)
    elif node_type == "IntegerLiteral":
        symbol_str = int(ast_node["value"])
        op_type = "INT_CONST"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["DeclRefExpr"]:
        symbol_str = str(ast_node["referencedDecl"]["name"])
        op_type = "INT_VAR"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["MemberExpr"]:
        symbol_str = converter.convert_member_expr(ast_node, True)
        op_type = "INT_VAR"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    else:
        utilities.error_exit("Unknown AST node type for Expression: {}".format(node_type))


def generate_div_zero_constraint(divisor_node):
    left_expr = generate_expr_for_ast(divisor_node)
    constraint_op_str = "!="
    constraint_op_type = next(key for key, value in SymbolType.items() if value == constraint_op_str)
    constraint_op = make_constraint_symbol(constraint_op_str, constraint_op_type)
    constraint_val_str = 0
    constraint_val_type = "INT_CONST"
    constraint_val = make_constraint_symbol(constraint_val_str, constraint_val_type)
    right_expr = make_symbolic_expression(constraint_val)
    constraint_expr = make_binary_expression(constraint_op, left_expr, right_expr)
    return constraint_expr


def generate_int_overflow_constraint(binary_node):
    binary_left_ast = binary_node["inner"][0]
    binary_right_ast = binary_node["inner"][1]
    binary_op_str = binary_node["opcode"]

    # Generating a constraint of type {} <= INT_MAX {} {}
    # first generate the left-side expression
    binary_left_expr = generate_expr_for_ast(binary_left_ast)

    # second generate the constraint logical-operator
    less_than_eq_op = build_op_symbol("<=")

    # last, generate the right-side expression
    crash_op_converter = {"*": "/", "+": "-", "-": "+"}
    inverted_op = build_op_symbol(crash_op_converter[binary_op_str])

    check_val_str = "INT_MAX"
    check_val_type = "INT_CONST"
    check_val_symbol = make_constraint_symbol(check_val_str, check_val_type)
    check_val_expr = make_symbolic_expression(check_val_symbol)
    binary_right_expr = generate_expr_for_ast(binary_right_ast)

    constraint_left_expr = binary_left_expr
    constraint_right_expr = make_binary_expression(inverted_op, check_val_expr, binary_right_expr)
    constraint_expr = make_binary_expression(less_than_eq_op, constraint_left_expr, constraint_right_expr)
    return constraint_expr


def generate_memory_overflow_constraint(reference_node):
    ref_node_type = reference_node["kind"]
    if ref_node_type == "UnaryOperator":
        ptr_node = reference_node["inner"][0]
        # Generating a constraint of type ptr != 0
        constraint_expr = generate_div_zero_constraint(ptr_node)

    else:
        array_node = reference_node["inner"][0]
        iterator_node = reference_node["inner"][1]

        # Generating a constraint of type PTR(I) <= SIZEOF(ARR)
        # first generate the left-side expression
        constraint_left_expr = generate_expr_for_ast(iterator_node)

        # second generate the constraint logical-operator
        less_than_eq_op = build_op_symbol("<=")

        # last generate the expression for array size
        sizeof_op = build_op_symbol("sizeof ")
        array_expr = generate_expr_for_ast(array_node)
        constraint_right_expr = make_unary_expression(sizeof_op,array_expr)
        constraint_expr = make_binary_expression(less_than_eq_op, constraint_left_expr, constraint_right_expr)
    return constraint_expr


def generate_shift_overflow_constraint(shift_node):
    binary_left_ast = shift_node["inner"][0]
    binary_right_ast = shift_node["inner"][1]
    binary_op_str = shift_node["opcode"]

    # Generating a constraint of type INT_MAX >> {} < {} && 0 < {} < bit width
    # first generate the expressions for the two operands
    binary_left_expr = generate_expr_for_ast(binary_left_ast)
    binary_right_expr = generate_expr_for_ast(binary_right_ast)
    result_data_type = binary_left_ast["type"]["qualType"]
    type_min, type_max = get_type_limits(result_data_type)
    max_val_symbol = make_constraint_symbol(type_max, "INT_CONST")
    max_val_expr = make_symbolic_expression(max_val_symbol)

    less_than_op = build_op_symbol("<")
    shift_op = build_op_symbol(">>")
    shifted_value_expr = make_binary_expression(shift_op, max_val_expr, binary_right_expr)
    first_constraint_expr = make_binary_expression(less_than_op, shifted_value_expr, binary_left_expr)


    # next generate the second constraint 0 < {} < bit width
    type_width = get_type_width(result_data_type)
    width_val_symbol = make_constraint_symbol(str(type_width), "INT_CONST")
    width_val_expr = make_symbolic_expression(width_val_symbol)
    zero_symbol = make_constraint_symbol("0", "INT_CONST")
    zero_expr = make_symbolic_expression(zero_symbol)
    first_predicate_expr = make_binary_expression(less_than_op, zero_expr, binary_right_expr)
    second_predicate_expr = make_binary_expression(less_than_op, binary_right_expr, width_val_expr)
    and_op = build_op_symbol("&&")
    second_constraint_expr = make_binary_expression(and_op, first_predicate_expr, second_predicate_expr)

    # last, concatenate both constraints into one
    constraint_expr = make_binary_expression(and_op, first_constraint_expr, second_constraint_expr)
    return constraint_expr


def get_type_limits(data_type):
    if data_type == "int":
        return "INT_MIN", "INT_MAX"
    elif data_type == "short":
        return "SHRT_MIN", "SHRT_MAX"
    elif data_type == "long":
        return  "LONG_MIN", "LONG_MAX"
    elif data_type == "unsigned int":
        return "0", "UINT_MAX"
    else:
        utilities.error_exit("Unknown data type for limit constraints: {}".format(data_type))



def get_type_width(data_type):
    if data_type in ["int", "unsigned int"]:
        return 4
    elif data_type == "short":
        return 2
    elif data_type == "long":
        return 8
    else:
        utilities.error_exit("Unknown data type for width constraints: {}".format(data_type))

