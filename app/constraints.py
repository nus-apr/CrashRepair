#! /usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from sympy import sympify
import os
import typing as t

from app import emitter, utilities, converter, extractor

SymbolType = {
    "INT_CONST": "",
    "PTR": "",
    "INT_VAR": "",
    "REAL_CONST": "",
    "REAL_VAR": "",
    "RESULT_INT": "",
    "RESULT_PTR": "",

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

    "OP_ADD_ASSIGN": "+=",
    "OP_SUB_ASSIGN": "-=",
    "OP_MUL_ASSIGN": "*=",
    "OP_DIV_ASSIGN": "/=",
    "OP_AND_ASSIGN": "&=",
    "OP_OR_ASSIGN": "|=",

    "OP_BIT_AND": "&",
    "OP_BIT_OR": "|",
    "OP_BIT_NOT": "~",
    "OP_BIT_XOR": "^",

    "OP_SHIFT_RIGHT": ">>",
    "OP_SHIFT_LEFT": "<<",

    "NULL_VAL": "null",
    "OP_SIZE_OF": "sizeof ",
    "OP_BASE": "base "
}


class ConstraintSymbol:
    _m_symbol: t.Optional[str]
    _m_cons_type: str = None

    def __init__(self, m_symbol: t.Optional[str], m_type: str) -> None:
        self._m_symbol = m_symbol
        self._m_cons_type = m_type

    def __str__(self) -> str:
        if self._m_cons_type == "NULL_VAL":
            return "null"
        if self._m_cons_type == "INT_VAR":
            return f"@var(integer, {self._m_symbol})"
        if self._m_cons_type == "PTR":
            return f"@var(pointer, {self._m_symbol})"
        if self._m_cons_type == "REAL_VAR":
            return f"@var(float, {self._m_symbol})"
        if self._m_cons_type == "RESULT_INT":
            return f"@result(integer)"
        if self._m_cons_type == "RESULT_PTR":
            return f"@result(pointer)"

        assert self._m_symbol
        return self._m_symbol

    def get_expr(self)->str:
        assert self._m_symbol
        return self._m_symbol

    def get_type(self) -> str:
        return self._m_cons_type

    def get_symbol(self) -> t.Optional[str]:
        return self._m_symbol

    def update_symbol(self, new_symbol_str: t.Optional[str]) -> None:
        self._m_symbol = new_symbol_str

    def is_operator(self) -> bool:
        operator_type_list = [x for x in SymbolType.keys() if "OP" in x]
        return self._m_cons_type in operator_type_list

    def is_int_var(self):
        return self._m_cons_type == "INT_VAR"

    def is_result_int(self):
        return self._m_cons_type == "RESULT_INT"

    def is_result_ptr(self):
        return self._m_cons_type == "RESULT_PTR"

    def is_real_var(self):
        return self._m_cons_type == "REAL_VAR"

    def is_int_const(self):
        return self._m_cons_type == "INT_CONST"

    def is_ptr(self):
        return self._m_cons_type == "PTR"

    def is_real_const(self):
        return self._m_cons_type == "REAL_CONST"

    def is_var_name(self):
        return self._m_cons_type == "VAR_NAME"

    def is_sizeof(self):
        return self._m_cons_type == "OP_SIZE_OF"

    def is_base(self):
        return self._m_cons_type == "OP_BASE"

    def is_null(self):
        return self._m_cons_type == "NULL_VAL"


class ConstraintExpression:
    _m_symbol: ConstraintSymbol
    _m_sizeof_mapping: t.Optional[ConstraintExpression]
    _m_base_mapping: t.Optional[ConstraintExpression]
    _m_lvalue: t.Optional[ConstraintExpression]
    _m_rvalue: t.Optional[ConstraintExpression]

    def __init__(
        self,
        c_symbol: ConstraintSymbol,
        l_expr: t.Optional[ConstraintExpression],
        r_expr: t.Optional[ConstraintExpression],
    ):
        self._m_symbol = c_symbol
        self._m_lvalue = l_expr
        self._m_rvalue = r_expr
        self._m_sizeof_mapping = None
        self._m_base_mapping = None

    def get_type(self) -> str:
        return self._m_symbol.get_type()

    def get_symbol(self) -> t.Optional[str]:
        return self._m_symbol.get_symbol()

    def is_leaf(self) -> bool:
        return not self._m_lvalue and not self._m_rvalue

    def get_l_expr(self) -> t.Optional[ConstraintExpression]:
        return self._m_lvalue

    def get_r_expr(self) -> t.Optional[ConstraintExpression]:
        return self._m_rvalue

    def set_r_expr(self, sym_expr):
        self._m_rvalue = sym_expr

    def set_l_expr(self, sym_expr):
        self._m_lvalue = sym_expr

    def to_json(self) -> t.Dict[str, t.Any]:
        json_obj = dict()
        json_obj["type"] = self.get_type()
        json_obj["symbol"] = self.get_symbol()

        if self._m_lvalue:
            json_obj["left"] = self._m_lvalue.to_json()
        if self._m_rvalue:
            json_obj["right"] = self._m_rvalue.to_json()

        return json_obj

    def to_string(self) -> str:
        expr_str = str(self._m_symbol)

        lhs_str: t.Optional[str] = None
        rhs_str: t.Optional[str] = None

        if self._m_lvalue:
            lhs_str = self._m_lvalue.to_string()
        if self._m_rvalue:
            rhs_str = self._m_rvalue.to_string()

        if self._m_symbol.is_sizeof():
            resolved_expr = self.get_sizeof()
            if resolved_expr is not None:
                return resolved_expr.to_string()
            return f"({expr_str} {rhs_str})"

        if self._m_symbol.is_base():
            resolved_expr = self.get_base()
            if resolved_expr is not None:
                return resolved_expr.to_string()
            return f"({expr_str} {rhs_str})"

        if self._m_symbol.is_result_int() or self._m_symbol.is_result_ptr():
            return f"({expr_str})"

        if lhs_str and rhs_str:
            return f"({lhs_str} {expr_str} {rhs_str})"
        if rhs_str:
            return f"({expr_str} {rhs_str})"
        return expr_str

    def to_expression(self) -> str:
        expr_str = self._m_symbol.get_expr()
        lhs_str: t.Optional[str] = None
        rhs_str: t.Optional[str] = None
        if self._m_lvalue:
            lhs_str = self._m_lvalue.to_expression()
        if self._m_rvalue:
            rhs_str = self._m_rvalue.to_expression()

        if self._m_symbol.is_sizeof():
            resolved_expr = self.get_sizeof()
            if resolved_expr is not None:
                return resolved_expr.to_expression()
            return f"({expr_str} {rhs_str})"

        if self._m_symbol.is_base():
            resolved_expr = self.get_base()
            if resolved_expr is not None:
                return resolved_expr.to_expression()
            return f"({expr_str} {rhs_str})"


        if self._m_symbol.is_result_int() or self._m_symbol.is_result_ptr():
            return f"({expr_str})"

        if lhs_str and rhs_str:
            return f"{lhs_str} {expr_str} {rhs_str}"
        if rhs_str:
            return f"{expr_str}{rhs_str}"
        return expr_str

    def get_symbol_list(self):
        symbol_list = []
        if self._m_symbol.is_int_var() or self._m_symbol.is_real_var() or self._m_symbol.is_ptr():
            symbol_list = [self.get_symbol()]
        elif self._m_symbol.is_sizeof():
            return [self.to_string()]
        elif self._m_symbol.is_base():
            return [self.to_string()]
        if self._m_lvalue:
            symbol_list = symbol_list + self._m_lvalue.get_symbol_list()
        if self._m_rvalue:
            symbol_list = symbol_list + self._m_rvalue.get_symbol_list()
        return list(set(symbol_list))

    def get_sizeof(self):
        return self._m_sizeof_mapping

    def get_base(self):
        return self._m_base_mapping

    def resolve_sizeof(self, symbolic_mapping):
        if self._m_symbol.is_sizeof():
            symbol_name = self.to_string()
            if symbol_name in symbolic_mapping:
                mapping = symbolic_mapping[symbol_name]
                # assumption: mapping is either constant or variable, not an expression i.e. a+b
                if str(mapping).isnumeric():
                    mapped_symbol = make_constraint_symbol(mapping, "INT_CONST")
                    self._m_sizeof_mapping = make_symbolic_expression(mapped_symbol)
                else:
                    mapped_symbol = make_constraint_symbol(mapping, "INT_VAR")
                    self._m_sizeof_mapping = make_symbolic_expression(mapped_symbol)

    def resolve_base(self, symbolic_mapping):
        if self._m_symbol.is_base():
            symbol_name = self.to_string()
            if symbol_name in symbolic_mapping:
                mapping = symbolic_mapping[symbol_name]
                # assumption: mapping is either constant or variable, not an expression i.e. a+b
                if str(mapping).isnumeric():
                    mapped_symbol = make_constraint_symbol(mapping, "INT_CONST")
                    self._m_base_mapping = make_symbolic_expression(mapped_symbol)
                else:
                    mapped_symbol = make_constraint_symbol(mapping, "PTR")
                    self._m_base_mapping = make_symbolic_expression(mapped_symbol)

    def update_symbols(self, symbol_mapping):
        if self._m_symbol.is_int_var() or self._m_symbol.is_real_var() or self._m_symbol.is_ptr():
            symbol_str = self.get_symbol()
            if symbol_str in symbol_mapping:
                self._m_symbol.update_symbol(symbol_mapping[symbol_str])
        elif self._m_symbol.is_sizeof():
            self.resolve_sizeof(symbol_mapping)
        elif self._m_symbol.is_base():
            self.resolve_base(symbol_mapping)

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
        if op_symbol_str in ["++", "--"]:
            child_ast = ast_node["inner"][0]
            is_prefix = True
            if "isPostfix" in ast_node:
                is_prefix = not ast_node["isPostfix"]
            if is_prefix:
                symbol_str = op_symbol_str + str(child_ast["referencedDecl"]["name"])
            else:
                symbol_str = str(child_ast["referencedDecl"]["name"]) + op_symbol_str
            data_type = extractor.extract_data_type(ast_node)
            op_type = "INT_VAR"
            if "*" in data_type or "[" in data_type:
                op_type = "PTR"
            constraint_symbol = make_constraint_symbol(symbol_str, op_type)
            constraint_expr = make_symbolic_expression(constraint_symbol)
            return constraint_expr

        constraint_symbol = make_constraint_symbol(op_symbol_str, op_type)
        child_ast = ast_node["inner"][0]
        child_expr = generate_expr_for_ast(child_ast)
        if "*" == op_symbol_str and child_expr.get_type() == "PTR":
            return child_expr
        constraint_expr = make_unary_expression(constraint_symbol, child_expr)
        return constraint_expr
    elif node_type == "Macro":
        utilities.error_exit("Unhandled node type for Expression: {}".format(node_type))
    elif node_type in ["ParenExpr", "ImplicitCastExpr"]:
        child_node = ast_node["inner"][0]
        return generate_expr_for_ast(child_node)
    elif node_type == "IntegerLiteral":
        symbol_str = str(ast_node["value"])
        op_type = "INT_CONST"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["CStyleCastExpr"]:
        symbol_str = converter.convert_node_to_str(ast_node)
        data_type = extractor.extract_data_type(ast_node)
        op_type = "INT_VAR"
        if "*" in data_type or "[" in data_type:
            op_type = "PTR"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["DeclRefExpr"]:
        symbol_str = str(ast_node["referencedDecl"]["name"])
        data_type = extractor.extract_data_type(ast_node)
        op_type = "INT_VAR"
        if "*" in data_type or "[" in data_type:
            op_type = "PTR"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["MemberExpr"]:
        symbol_str = converter.convert_member_expr(ast_node, True)
        data_type = extractor.extract_data_type(ast_node)
        op_type = "INT_VAR"
        if "*" in data_type or "[" in data_type:
            op_type = "PTR"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["ArraySubscriptExpr"]:
        symbol_str = converter.convert_array_subscript(ast_node, True)
        data_type = extractor.extract_data_type(ast_node)
        op_type = "INT_VAR"
        if "*" in data_type or "[" in data_type:
            op_type = "PTR"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    else:
        print(ast_node)
        utilities.error_exit("Unknown AST node type for Expression: {}".format(node_type))


def generate_div_zero_constraint(divisor_node):
    left_expr = generate_expr_for_ast(divisor_node)
    constraint_op_str = "!="
    constraint_op_type = next(key for key, value in SymbolType.items() if value == constraint_op_str)
    constraint_op = make_constraint_symbol(constraint_op_str, constraint_op_type)
    constraint_val_str = "0"
    constraint_val_type = "INT_CONST"
    constraint_val = make_constraint_symbol(constraint_val_str, constraint_val_type)
    right_expr = make_symbolic_expression(constraint_val)
    constraint_expr = make_binary_expression(constraint_op, left_expr, right_expr)
    return constraint_expr


def generate_type_underflow_constraint(ast_node):
    result_data_type = extractor.extract_data_type(ast_node)
    type_min, type_max = get_type_limits(result_data_type)
    min_val_symbol = make_constraint_symbol(type_min, "INT_CONST")
    min_val_expr = make_symbolic_expression(min_val_symbol)
    node_type = ast_node["kind"]

    # Generating a constraint of type
    # TYPE_MIN (INVERTED_OP) expr_b <= expr_a
    less_than_eq_op = build_op_symbol("<=")
    ast_op_str = ast_node["opcode"]
    crash_op_converter = {"-": "+", "--": "+", "/": "*"}
    arithmetic_op = build_op_symbol(crash_op_converter[ast_op_str])

    if node_type == "BinaryOperator":
        binary_left_ast = ast_node["inner"][0]
        binary_right_ast = ast_node["inner"][1]
        expr_a = generate_expr_for_ast(binary_left_ast)
        expr_b = generate_expr_for_ast(binary_right_ast)
    elif node_type == "UnaryOperator":
        const_one_symbol = make_constraint_symbol("1", "INT_CONST")
        expr_b = make_symbolic_expression(const_one_symbol)
        expr_a = generate_expr_for_ast(ast_node)
    else:
        utilities.error_exit("Unhandled node type {}  in generate_add_overflow_constraint".format(node_type))

    constraint_right_expr = expr_a
    constraint_left_expr = make_binary_expression(arithmetic_op, min_val_expr, expr_b)
    constraint_expr = make_binary_expression(less_than_eq_op, constraint_left_expr, constraint_right_expr)
    return constraint_expr


def generate_type_overflow_constraint(ast_node):
    result_data_type = extractor.extract_data_type(ast_node)
    type_min, type_max = get_type_limits(result_data_type)
    max_val_symbol = make_constraint_symbol(type_max, "INT_CONST")
    max_val_expr = make_symbolic_expression(max_val_symbol)
    node_type = ast_node["kind"]

    # Generating a constraint of type
    # expr_a <= TYPE_MAX (INVERTED_OP) expr_b
    less_than_eq_op = build_op_symbol("<=")
    ast_op_str = ast_node["opcode"]
    crash_op_converter = {"*": "/", "+": "-", "++": "-"}
    arithmetic_op = build_op_symbol(crash_op_converter[ast_op_str])
    if node_type == "BinaryOperator":
        binary_left_ast = ast_node["inner"][0]
        binary_right_ast = ast_node["inner"][1]
        expr_a = generate_expr_for_ast(binary_left_ast)
        expr_b = generate_expr_for_ast(binary_right_ast)
    elif node_type == "UnaryOperator":
        const_one_symbol = make_constraint_symbol("1", "INT_CONST")
        expr_b = make_symbolic_expression(const_one_symbol)
        expr_a = generate_expr_for_ast(ast_node)
    else:
        utilities.error_exit("Unhandled node type {}  in generate_add_overflow_constraint".format(node_type))

    constraint_left_expr = expr_a
    constraint_right_expr = make_binary_expression(arithmetic_op, max_val_expr, expr_b)
    constraint_expr = make_binary_expression(less_than_eq_op, constraint_left_expr, constraint_right_expr)
    return constraint_expr


def generate_memory_overflow_constraint(reference_node, crash_loc):
    ref_node_type = reference_node["kind"]
    if ref_node_type == "ArraySubscriptExpr":
        array_node = reference_node["inner"][0]
        iterator_node = reference_node["inner"][1]

        # Generating a constraint of type PTR(I) <= SIZEOF(ARR)
        # first generate the left-side expression
        iterator_expr = generate_expr_for_ast(iterator_node)

        # second generate the constraint logical-operator
        less_than_op = build_op_symbol("<")

        # last generate the expression for array size
        sizeof_op = build_op_symbol("sizeof ")
        array_expr = generate_expr_for_ast(array_node)
        size_expr = make_unary_expression(sizeof_op, array_expr)
        upper_bound_expr = make_binary_expression(less_than_op, iterator_expr, size_expr)

        lte_op = build_op_symbol("<=")
        zero_symbol = make_constraint_symbol("0", "INT_CONST")
        zero_expr = make_symbolic_expression(zero_symbol)
        lower_bound_expr = make_binary_expression(lte_op, zero_expr, iterator_expr)
        logic_and_op = build_op_symbol("&&")
        constraint_expr = make_binary_expression(logic_and_op, upper_bound_expr, lower_bound_expr)


    else:
        ptr_node = None
        if ref_node_type == "UnaryOperator":
            ptr_node = reference_node["inner"][0]
        elif ref_node_type == "MemberExpr":
            got_pointer = False
            src_file, crash_l, crash_c = crash_loc
            while not got_pointer:
                node_end_loc = int(reference_node["range"]["end"]["col"]) + int(reference_node["range"]["end"]["tokLen"])
                if node_end_loc >= crash_c:
                    reference_node = reference_node["inner"][0]
                else:
                    got_pointer = True
            ptr_node = reference_node["inner"][0]
        else:
            print(reference_node)
            utilities.error_exit("Unknown AST Type in function generate_memory_overflow_constraint")

        sizeof_op = build_op_symbol("sizeof ")
        ptr_expr = generate_expr_for_ast(ptr_node)
        sizeof_expr = make_unary_expression(sizeof_op, ptr_expr)

        base_op = build_op_symbol("base ")
        base_expr = make_unary_expression(base_op, ptr_expr)
        diff_op = build_op_symbol("-")
        diff_expr = make_binary_expression(diff_op, ptr_expr, base_expr)
        lte_op = build_op_symbol("<=")
        constraint_expr = make_binary_expression(lte_op, diff_expr, sizeof_expr)

    return constraint_expr


def generate_memory_null_constraint(reference_node, crash_loc):
    ref_node_type = reference_node["kind"]
    if ref_node_type == "MemberExpr":
        got_pointer = False
        src_file, crash_l, crash_c = crash_loc
        while not got_pointer:
            node_end_loc = int(reference_node["range"]["end"]["col"]) + int(reference_node["range"]["end"]["tokLen"])
            if node_end_loc >= crash_c:
                reference_node = reference_node["inner"][0]
            else:
                got_pointer = True
    left_expr = generate_expr_for_ast(reference_node)
    constraint_op_str = "!="
    constraint_op_type = next(key for key, value in SymbolType.items() if value == constraint_op_str)
    constraint_op = make_constraint_symbol(constraint_op_str, constraint_op_type)
    constraint_val_str = "NULL"
    constraint_val_type = "PTR"
    constraint_val = make_constraint_symbol(constraint_val_str, constraint_val_type)
    right_expr = make_symbolic_expression(constraint_val)
    constraint_expr = make_binary_expression(constraint_op, left_expr, right_expr)
    return constraint_expr


def generate_shift_overflow_constraint(shift_node):
    binary_left_ast = shift_node["inner"][0]
    binary_right_ast = shift_node["inner"][1]
    binary_op_str = shift_node["opcode"]

    # Generating a constraint of type INT_MAX >> {} < {} && 0 < {} < bit width
    # first generate the expressions for the two operands
    binary_left_expr = generate_expr_for_ast(binary_left_ast)
    binary_right_expr = generate_expr_for_ast(binary_right_ast)
    result_data_type = extractor.extract_data_type(binary_left_ast)
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



def generate_memset_constraint(call_node):
    pointer_node = call_node["inner"][1]
    size_node = call_node["inner"][3]
    # pointer_name = converter.convert_node_to_str(pointer_node)
    # size_value = converter.convert_node_to_str(size_node)

    # Generating a constraint of type size_value > 0 && pointer_name != 0
    # first generate the expressions for the two operands
    pointer_expr = generate_expr_for_ast(pointer_node)
    size_expr = generate_expr_for_ast(size_node)

    # generate the first constraint 0 < size_value
    zero_val_symbol = make_constraint_symbol("0", "INT_CONST")
    zero_val_expr = make_symbolic_expression(zero_val_symbol)
    less_than_op = build_op_symbol("<")
    first_constraint_expr = make_binary_expression(less_than_op, zero_val_expr, size_expr)


    # next generate the second constraint pointer != 0
    not_eq_op = build_op_symbol("!=")
    null_symbol = make_constraint_symbol("NULL", "PTR")
    null_expr = make_symbolic_expression(null_symbol)
    second_constraint_expr = make_binary_expression(not_eq_op, null_expr, pointer_expr)

    # last, concatenate both constraints into one
    logical_and_op = build_op_symbol("&&")
    constraint_expr = make_binary_expression(logical_and_op, first_constraint_expr, second_constraint_expr)
    return constraint_expr

## Incomplete lifting of constraint from StringLiteral
def generate_assertion_constraint(call_node, func_node, src_file):
    assertion_str_node = call_node["inner"][1]
    assertion_str = converter.convert_node_to_str(assertion_str_node)
    assertion_expr = sympify(assertion_str)
    var_list = extractor.extract_var_list(func_node, src_file)
    var_name_list = [x[0] for x in var_list]
    str_tokens = assertion_expr.split(" ")
    constraint_expr = None
    if len(str_tokens) == 3:
        comp_op_str = str_tokens[1]
        comp_op = build_op_symbol(comp_op_str)
        left_node_str = str_tokens[0]
        right_node_str = str_tokens[2]
        left_node = make_constraint_symbol(left_node_str, "INT_VAR" if left_node_str in var_name_list else "INT_CONST")
        left_expr = make_symbolic_expression(left_node)
        right_node = make_constraint_symbol(right_node_str, "INT_VAR" if right_node_str in var_name_list else "INT_CONST")
        right_expr = make_symbolic_expression(right_node)
        constraint_expr = make_binary_expression(comp_op, left_expr, right_expr)
    else:
        utilities.error_exit("Not implemented: handling more than 3 tokens in assertion constraint")
    return constraint_expr

def generate_memcpy_constraint(call_node):
    source_ptr_node = call_node["inner"][1]
    target_ptr_node = call_node["inner"][2]
    size_node = call_node["inner"][3]
    # source_name = converter.convert_node_to_str(source_ptr_node)
    # target_name = converter.convert_node_to_str(target_ptr_node)
    # size_value = converter.convert_node_to_str(size_node)

    # Generating a constraint of type
    # target - source < size
    # first generate the expressions for the arithmetic expression
    source_expr = generate_expr_for_ast(source_ptr_node)
    target_expr = generate_expr_for_ast(target_ptr_node)
    arithmetic_op = build_op_symbol("-")
    left_hand_expr = make_binary_expression(arithmetic_op, target_expr, source_expr)

    size_expr = generate_expr_for_ast(size_node)

    # last, concatenate both constraints into one
    less_than_op = build_op_symbol("<")
    constraint_expr = make_binary_expression(less_than_op, left_hand_expr, size_expr)
    return constraint_expr

def get_type_limits(data_type):
    if data_type == "int":
        return "INT_MIN", "INT_MAX"
    elif data_type == "char":
        return "CHAR_MIN", "CHAR_MAX"
    elif data_type == "short":
        return "SHRT_MIN", "SHRT_MAX"
    elif data_type == "long":
        return  "LONG_MIN", "LONG_MAX"
    elif data_type in ["unsigned char"]:
        return "0", "UCHAR_MAX"
    elif data_type in ["unsigned short"]:
        return "0", "USHORT_MAX"
    elif data_type in ["unsigned int", "size_t"]:
        return "0", "UINT_MAX"
    elif data_type in ["unsigned long"]:
        return "0", "ULONG_MAX"
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

