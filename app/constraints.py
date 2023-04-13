#! /usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from sympy import sympify
import os
import copy
import typing as t

from app import values, utilities, converter, extractor, analyzer, generator, solver, emitter

SymbolType = {
    "PTR": "",
    "VAR_INT": "",
    "VAR_REAL": "",
    "CONST_INT": "",
    "CONST_REAL": "",
    "RESULT_INT": "",
    "RESULT_PTR": "",
    "RESULT_REAL": "",

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
    "OP_SIZE": "size ",
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
            return "NULL"
        if self._m_cons_type == "VAR_INT":
            return f"@var(integer, {self._m_symbol})"
        if self._m_cons_type == "PTR":
            return f"@var(pointer, {self._m_symbol})"
        if self._m_cons_type == "VAR_REAL":
            return f"@var(float, {self._m_symbol})"
        if self._m_cons_type == "RESULT_INT":
            return f"@result(integer)"
        if self._m_cons_type == "RESULT_REAL":
            return f"@result(float)"
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

    def is_var_int(self):
        return self._m_cons_type == "VAR_INT"

    def is_result_int(self):
        return self._m_cons_type == "RESULT_INT"

    def is_result_float(self):
        return self._m_cons_type == "RESULT_REAL"

    def is_result_ptr(self):
        return self._m_cons_type == "RESULT_PTR"

    def is_var_real(self):
        return self._m_cons_type == "VAR_REAL"

    def is_const_int(self):
        return self._m_cons_type == "CONST_INT"

    def is_ptr(self):
        return self._m_cons_type == "PTR"

    def is_const_real(self):
        return self._m_cons_type == "CONST_REAL"

    def is_var_name(self):
        return self._m_cons_type == "VAR_NAME"

    def is_size(self):
        return self._m_cons_type == "OP_SIZE"

    def is_diff(self):
        return self._m_cons_type == "OP_DIFF"

    def is_base(self):
        return self._m_cons_type == "OP_BASE"

    def is_null(self):
        return self._m_cons_type == "NULL_VAL"


class ConstraintExpression:
    _m_symbol: ConstraintSymbol
    _m_size_mapping: t.Optional[ConstraintExpression]
    _m_diff_mapping:t.Optional[ConstraintExpression]
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
        self._m_size_mapping = None
        self._m_diff_mapping = None
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

        if self._m_symbol.is_size():
            resolved_expr = self.get_size()
            if resolved_expr is not None:
                return resolved_expr.to_string()
            return f"({expr_str} {rhs_str})"

        if self._m_symbol.is_diff():
            resolved_expr = self.get_diff()
            if resolved_expr is not None:
                return resolved_expr.to_string()
            return f"({expr_str} {rhs_str})"

        if self._m_symbol.is_base():
            resolved_expr = self.get_base()
            if resolved_expr is not None:
                return resolved_expr.to_string()
            return f"({expr_str} {rhs_str})"

        if self._m_symbol.is_result_int() or \
                self._m_symbol.is_result_ptr() or\
                self._m_symbol.is_result_float():
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

        if self._m_symbol.is_size():
            resolved_expr = self.get_size()
            if resolved_expr is not None:
                return resolved_expr.to_expression()
            return f"({expr_str} {rhs_str})"

        if self._m_symbol.is_diff():
            resolved_expr = self.get_diff()
            if resolved_expr is not None:
                return resolved_expr.to_expression()
            return f"({expr_str} {rhs_str})"

        if self._m_symbol.is_base():
            resolved_expr = self.get_base()
            if resolved_expr is not None:
                return resolved_expr.to_expression()
            return f"({expr_str} {rhs_str})"


        if self._m_symbol.is_result_int() or \
                self._m_symbol.is_result_ptr() or \
                self._m_symbol.is_result_float():
            return f"({expr_str})"

        if lhs_str and rhs_str:
            return f"{lhs_str} {expr_str} {rhs_str}"
        if rhs_str:
            return f"{expr_str}{rhs_str}"
        return expr_str

    def get_symbol_list(self):
        symbol_list = []
        if self._m_symbol.is_null():
            return []
        if self._m_symbol.is_var_int() or self._m_symbol.is_var_real() or self._m_symbol.is_ptr():
            symbol_list = [self.get_symbol()]
        elif self._m_symbol.is_size():
            return [self.to_string()]
        elif self._m_symbol.is_diff():
            return [self.to_string()]
        elif self._m_symbol.is_base():
            return [self.to_string()]
        if self._m_lvalue:
            symbol_list = symbol_list + self._m_lvalue.get_symbol_list()
        if self._m_rvalue:
            symbol_list = symbol_list + self._m_rvalue.get_symbol_list()
        return list(set(symbol_list))

    def get_size(self):
        return self._m_size_mapping

    def get_diff(self):
        return self._m_diff_mapping

    def get_base(self):
        return self._m_base_mapping


    def update_symbols(self, symbol_mapping):
        if self._m_symbol.is_var_int() or self._m_symbol.is_var_real() or self._m_symbol.is_ptr():
            symbol_str = self.get_symbol()
            if symbol_str in symbol_mapping:
                self._m_symbol.update_symbol(symbol_mapping[symbol_str])

        if self._m_lvalue:
            left_symbol = self._m_lvalue._m_symbol
            if left_symbol.is_operator():
                if left_symbol.is_size():
                    lhs_str = self._m_lvalue.to_string()
                    resolve_cfc = resolve_size(lhs_str, symbol_mapping)
                    if resolve_cfc:
                        self._m_lvalue = resolve_cfc
                elif left_symbol.is_base():
                    lhs_str = self._m_lvalue.to_string()
                    resolve_cfc = resolve_base(lhs_str, symbol_mapping)
                    if resolve_cfc:
                        self._m_lvalue = resolve_cfc
                else:
                    self._m_lvalue.update_symbols(symbol_mapping)
            elif left_symbol.is_var_int() or left_symbol.is_var_real() or left_symbol.is_ptr():
                left_symbol_str = str(left_symbol._m_symbol)
                if left_symbol_str in symbol_mapping:
                    mapped_str = symbol_mapping[left_symbol_str]
                    mapped_str = transform_increment_decrement(mapped_str)

                    if any(op in mapped_str for op in ["+", "-", "*", "/"]):
                        mapped_expr = generate_expr_for_str(mapped_str,
                                                            self._m_lvalue.get_type())
                        self._m_lvalue = mapped_expr
                    else:
                        self._m_lvalue.update_symbols(symbol_mapping)
                else:
                    self._m_lvalue.update_symbols(symbol_mapping)

            elif left_symbol.is_null() or \
                left_symbol.is_const_int() or \
                left_symbol.is_const_real():
                self._m_lvalue._m_symbol = left_symbol
            else:
                emitter.error(f"constraint expr {self._m_lvalue.to_string()}")
                emitter.error(f"constraint type {left_symbol}")
                utilities.error_exit("Unhandled constraint type")


        if self._m_rvalue:
            right_symbol = self._m_rvalue._m_symbol
            if right_symbol.is_operator():
                if right_symbol.is_size():
                    rhs_str = self._m_rvalue.to_string()
                    resolve_cfc = resolve_size(rhs_str, symbol_mapping)
                    if resolve_cfc:
                        self._m_rvalue = resolve_cfc
                elif right_symbol.is_base():
                    rhs_str = self._m_rvalue.to_string()
                    resolve_cfc = resolve_base(rhs_str, symbol_mapping)
                    if resolve_cfc:
                        self._m_rvalue = resolve_cfc
                else:
                    self._m_rvalue.update_symbols(symbol_mapping)
            elif right_symbol.is_var_int() or right_symbol.is_var_real() or right_symbol.is_ptr():
                right_symbol_str = str(right_symbol._m_symbol)
                if right_symbol_str in symbol_mapping:
                    mapped_str = symbol_mapping[right_symbol_str]
                    mapped_str = transform_increment_decrement(mapped_str)

                    if any(op in mapped_str for op in ["+", "-", "*", "/"]):
                        mapped_expr = generate_expr_for_str(mapped_str,
                                                            self._m_rvalue.get_type())
                        self._m_rvalue = mapped_expr
                    else:
                        self._m_rvalue.update_symbols(symbol_mapping)
                else:
                    self._m_rvalue.update_symbols(symbol_mapping)

            elif right_symbol.is_null() or \
                right_symbol.is_const_int() or \
                right_symbol.is_const_real():
                self._m_rvalue._m_symbol = right_symbol
            else:
                emitter.error(f"constraint expr {self._m_rvalue.to_string()}")
                emitter.error(f"constraint type {right_symbol}")
                utilities.error_exit("Unhandled constraint type")


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


def transform_increment_decrement(expr_str):
    transformed_expr = expr_str
    if "++" in expr_str or "--" in expr_str:
        var_name = expr_str.replace("++", "").replace("--", "")
        if f"++{var_name}" == expr_str or f"--{var_name}" == expr_str:
            transformed_expr = f"{var_name} + 1"
        if f"{var_name}++" == expr_str or f"{var_name}--" == expr_str:
            transformed_expr = var_name
    return transformed_expr


def generate_expr_for_str(expr_str, data_type)->ConstraintExpression:
    constraint_expr = None
    translated_map = dict()
    token_num = 0
    try:
        if any(c in expr_str for c in ["[", "]", ".", "->", "++","--", "len", "field", "(", ")"]):
            token_list = expr_str.split(" ")
            new_token_list = []
            for token in token_list:
                new_token = token
                if "++" in token or "--" in token:
                    stripped_token = token.replace("(", "").replace(")", "")
                    transformed_token = transform_increment_decrement(stripped_token)
                    new_token = transformed_token
                if any(c in token for c in ["[", "]", ".", "->", "len", "field", "(", ")"]):
                    token_name = "__token_{}".format(token_num)
                    token_num = token_num + 1
                    new_token = token_name

                if token != new_token:
                    translated_map[new_token] = token
                new_token_list.append(new_token)
            expr_str = " ".join(new_token_list)
        symbolized_expr = sympify(expr_str)
    except Exception as ex:
        constraint_symbol = make_constraint_symbol(expr_str, data_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr

    if symbolized_expr.as_expr().is_Symbol or symbolized_expr.as_expr().is_Function:
        constraint_symbol = make_constraint_symbol(str(symbolized_expr.as_expr()), data_type)
        constraint_expr =  make_symbolic_expression(constraint_symbol)
    elif symbolized_expr.as_expr().is_Integer:
        constraint_symbol = make_constraint_symbol(str(symbolized_expr.as_expr()), "CONST_INT")
        constraint_expr = make_symbolic_expression(constraint_symbol)
    elif symbolized_expr.as_expr().is_Float:
        constraint_symbol = make_constraint_symbol(str(symbolized_expr.as_expr()), "CONST_REAL")
        constraint_expr = make_symbolic_expression(constraint_symbol)
    elif symbolized_expr.as_expr().is_Add:
        left_child = symbolized_expr.as_two_terms()[0]
        left_child_expr = generate_expr_for_str(str(left_child.as_expr()), data_type)
        right_child = symbolized_expr.as_two_terms()[1]
        binary_op_str = "+"
        if "-" == str(right_child)[0]:
            binary_op_str = "-"
            right_child = sympify(str(right_child)[1:])
        binary_op_symbol = build_op_symbol(binary_op_str)
        right_child_expr = generate_expr_for_str(str(right_child.as_expr()), data_type)
        constraint_expr = make_binary_expression(binary_op_symbol, left_child_expr, right_child_expr)
    elif symbolized_expr.as_expr().is_Pow:
        base_expr =  symbolized_expr.as_base_exp()[0]
        base_constraint_expr = generate_expr_for_str(str(base_expr.as_expr()), data_type)
        binary_op_str = "*"
        binary_op_symbol = build_op_symbol(binary_op_str)
        constraint_expr = make_binary_expression(binary_op_symbol, base_constraint_expr, base_constraint_expr)
    elif symbolized_expr.as_expr().is_Mul:
        left_child = symbolized_expr.as_two_terms()[0]
        right_child = symbolized_expr.as_two_terms()[1]
        binary_op_str = "*"
        if len(str(left_child)) > 1 and "/" == str(left_child)[1]:
            binary_op_str = "/"
            left_child = sympify(str(left_child)[2:])
            right_child_expr = generate_expr_for_str(str(left_child.as_expr()), data_type)
            left_child_expr = generate_expr_for_str(str(right_child.as_expr()), data_type)
        elif len(str(right_child)) > 1 and "/" == str(right_child)[1]:
            binary_op_str = "/"
            right_child = sympify(str(right_child)[2:])
            right_child_expr = generate_expr_for_str(str(right_child.as_expr()), data_type)
            left_child_expr = generate_expr_for_str(str(left_child.as_expr()), data_type)
        else:
            right_child_expr = generate_expr_for_str(str(right_child.as_expr()), data_type)
            left_child_expr = generate_expr_for_str(str(left_child.as_expr()), data_type)
        binary_op_symbol = build_op_symbol(binary_op_str)
        constraint_expr = make_binary_expression(binary_op_symbol, left_child_expr, right_child_expr)
    else:
        print(translated_map)
        print(expr_str)
        print(symbolized_expr.as_expr())
        utilities.error_exit("Unhandled execption in Constraints:generate_expr_for_str")
    constraint_expr.update_symbols(translated_map)
    return constraint_expr

def resolve_size(expr_str, symbolic_mapping):
    resolved_cfc = None
    if expr_str in symbolic_mapping:
        mapping = symbolic_mapping[expr_str]
        mapping = transform_increment_decrement(mapping)
        if str(mapping).isnumeric():
            mapped_symbol = make_constraint_symbol(mapping, "CONST_INT")
            resolved_cfc = make_symbolic_expression(mapped_symbol)
        elif isinstance(mapping, dict):
            constant = str(int(mapping["size"]/ int(mapping["width"])))
            mapped_symbol = make_constraint_symbol(constant, "CONST_INT")
            resolved_cfc = make_symbolic_expression(mapped_symbol)
        elif "crepair_size" in mapping:
            constraint_symbol = make_constraint_symbol(mapping, "VAR_INT")
            resolved_cfc = make_symbolic_expression(constraint_symbol)
        else:
            resolved_cfc = generate_expr_for_str(mapping, "VAR_INT")
    return resolved_cfc


def resolve_base(expr_str, symbolic_mapping):
    resolved_cfc = None
    if expr_str in symbolic_mapping:
        mapping = symbolic_mapping[expr_str]
        # assumption: mapping is either constant or variable, not an expression i.e. a+b
        if str(mapping).isnumeric():
            mapped_symbol = make_constraint_symbol(mapping, "CONST_INT")
            resolved_cfc = make_symbolic_expression(mapped_symbol)
        elif "crepair_base" in mapping:
            constraint_symbol = make_constraint_symbol(mapping, "PTR")
            resolved_cfc = make_symbolic_expression(constraint_symbol)
        else:
            resolved_cfc = generate_expr_for_str(mapping, "PTR")
    return resolved_cfc

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
            data_type = extractor.extract_data_type(ast_node)
            is_pointer =  "*" in data_type or "[" in data_type
            op_type = generator.generate_result_type(data_type)
            symbol_str = str(child_ast["referencedDecl"]["name"])
            if is_pointer:
                if is_prefix:
                    symbol_str = op_symbol_str + symbol_str
                else:
                    symbol_str = symbol_str + op_symbol_str
                constraint_symbol = make_constraint_symbol(symbol_str, op_type)
                constraint_expr = make_symbolic_expression(constraint_symbol)
            else:
                ast_symbol = make_constraint_symbol(symbol_str, op_type)
                ast_expr = make_symbolic_expression(ast_symbol)
                arithmetic_op_str = "+"
                if op_symbol_str == "--":
                    arithmetic_op_str = "-"
                if is_prefix:
                    arithmetic_op_type = next(key for key, value in SymbolType.items() if value == arithmetic_op_str)
                    arithmetic_op = make_constraint_symbol(arithmetic_op_str, arithmetic_op_type)
                    constant_val_str = "1"
                    constant_val_type = "CONST_INT"
                    constant_val_sym = make_constraint_symbol(constant_val_str, constant_val_type)
                    constant_val_expr = make_symbolic_expression(constant_val_sym)
                    constraint_expr = make_binary_expression(arithmetic_op, ast_expr, constant_val_expr)
                else:
                    constraint_expr = ast_expr
            return constraint_expr
        elif op_symbol_str in ["&"]:
            child_ast = ast_node["inner"][0]
            symbol_str = op_symbol_str + converter.get_node_value(child_ast)
            data_type = extractor.extract_data_type(ast_node)
            op_type = generator.generate_result_type(data_type)
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
        op_type = "CONST_INT"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type == "FloatingLiteral":
        symbol_str = str(ast_node["value"])
        op_type = "CONST_REAL"
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["CStyleCastExpr"]:
        symbol_str = converter.get_node_value(ast_node)
        data_type = extractor.extract_data_type(ast_node)
        op_type = generator.generate_result_type(data_type)
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["DeclRefExpr"]:
        symbol_str = str(ast_node["referencedDecl"]["name"])
        data_type = extractor.extract_data_type(ast_node)
        op_type = generator.generate_result_type(data_type)
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["MemberExpr"]:
        symbol_str = converter.convert_member_expr(ast_node, True)
        data_type = extractor.extract_data_type(ast_node)
        op_type = generator.generate_result_type(data_type)
        constraint_symbol = make_constraint_symbol(symbol_str, op_type)
        constraint_expr = make_symbolic_expression(constraint_symbol)
        return constraint_expr
    elif node_type in ["ArraySubscriptExpr"]:
        symbol_str = converter.convert_array_subscript(ast_node, True)
        data_type = extractor.extract_data_type(ast_node)
        op_type = generator.generate_result_type(data_type)
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
    constraint_val_type = "CONST_INT"
    constraint_val = make_constraint_symbol(constraint_val_str, constraint_val_type)
    right_expr = make_symbolic_expression(constraint_val)
    constraint_expr = make_binary_expression(constraint_op, left_expr, right_expr)
    return constraint_expr


def generate_cast_constraint(cast_node):
    result_data_type = extractor.extract_data_type(cast_node)
    type_min, type_max = get_type_limits(result_data_type)
    max_val_symbol = make_constraint_symbol(type_max, "CONST_INT")
    max_val_expr = make_symbolic_expression(max_val_symbol)

    min_val_symbol = make_constraint_symbol(type_min, "CONST_INT")
    min_val_expr = make_symbolic_expression(min_val_symbol)

    casting_source_ast = cast_node['inner'][0]
    casting_expr = generate_expr_for_ast(casting_source_ast)

    less_than_op_str = "<"
    less_than_op_type = next(key for key, value in SymbolType.items() if value == less_than_op_str)
    less_than_op = make_constraint_symbol(less_than_op_str, less_than_op_type)
    first_constraint = make_binary_expression(less_than_op, casting_expr, max_val_expr)
    second_constraint = make_binary_expression(less_than_op, min_val_expr, casting_expr)


    logical_and_op_str = "&&"
    logical_and_op_type = next(key for key, value in SymbolType.items() if value == logical_and_op_str)
    logical_and_op = make_constraint_symbol(logical_and_op_str, logical_and_op_type)
    constraint_expr = make_binary_expression(logical_and_op, first_constraint, second_constraint)

    return constraint_expr


def generate_type_underflow_constraint(ast_node):
    result_data_type = extractor.extract_data_type(ast_node)
    type_min, type_max = get_type_limits(result_data_type)
    min_val_symbol = make_constraint_symbol(type_min, "CONST_INT")
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
        const_one_symbol = make_constraint_symbol("1", "CONST_INT")
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
    max_val_symbol = make_constraint_symbol(type_max, "CONST_INT")
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
        const_one_symbol = make_constraint_symbol("1", "CONST_INT")
        expr_b = make_symbolic_expression(const_one_symbol)
        expr_a = generate_expr_for_ast(ast_node)
    else:
        utilities.error_exit("Unhandled node type {}  in generate_add_overflow_constraint".format(node_type))

    constraint_left_expr = expr_a
    constraint_right_expr = make_binary_expression(arithmetic_op, max_val_expr, expr_b)
    constraint_expr = make_binary_expression(less_than_eq_op, constraint_left_expr, constraint_right_expr)
    return constraint_expr


def generate_memory_overflow_constraint(reference_node, crash_loc, crash_address, src_file):
    constraint_expr = None
    if not reference_node:
        size_op = build_op_symbol("size ")
        ptr_expr = generate_expr_for_str("ghost pointer", "PTR")
        size_expr = make_unary_expression(size_op, copy.deepcopy(ptr_expr))
        base_op = build_op_symbol("base ")
        base_expr = make_unary_expression(base_op, copy.deepcopy(ptr_expr))
        lt_op = build_op_symbol("<")
        arith_plus_op = build_op_symbol("+")
        lhs_constraint = ptr_expr
        rhs_constraint = make_binary_expression(arith_plus_op, base_expr, size_expr)
        constraint_expr = make_binary_expression(lt_op, lhs_constraint, rhs_constraint)
        return constraint_expr
    ref_node_type = reference_node["kind"]
    if ref_node_type == "ArraySubscriptExpr":
        array_node = reference_node["inner"][0]
        iterator_node = reference_node["inner"][1]
        array_pointer_constraint = generate_out_of_bound_ptr_constraint(array_node, src_file, iterator_node)
        if array_pointer_constraint:
            return array_pointer_constraint
        pointer_offset = get_pointer_diff(array_node, src_file, iterator_node)
        if pointer_offset == 0:
            iterator_constraint = generate_iterator_constraint(iterator_node, src_file, array_node)
            if iterator_constraint:
                return iterator_constraint
        else:
            iterator_node = reference_node["inner"][1]
            iterator_offset_constraint = generate_iterator_offset_constraint(iterator_node,
                                                                             array_node,
                                                                             src_file
                                                                             )
            if iterator_offset_constraint:
                return iterator_offset_constraint

    else:
        ptr_node = None
        if ref_node_type == "DeclRefExpr":
            ptr_node = reference_node
        elif ref_node_type == "UnaryOperator":
            if reference_node["inner"][0]["kind"] in ["UnaryOperator", "ImplicitCastExpr"]:
                ptr_node = reference_node["inner"][0]
            else:
                ptr_node = reference_node
        elif ref_node_type == "MemberExpr":
            got_pointer = False
            src_file, crash_l, crash_c = crash_loc
            while not got_pointer:
                node_end_loc = int(reference_node["range"]["end"]["col"]) + \
                               int(reference_node["range"]["end"]["tokLen"])
                if node_end_loc >= crash_c:
                    reference_node = reference_node["inner"][0]
                else:
                    got_pointer = True
            ptr_node = reference_node["inner"][0]

        else:
            print(reference_node)
            utilities.error_exit("Unknown AST Type in function generate_memory_overflow_constraint")

        # Special Case Overflow with Struct Pointer Type when base is NULL
        # check if base pointer exists
        # Hack: access memory info
        # TODO: Refactor properly to get this information
        src_file, crash_l, crash_c = crash_loc
        crash_logical_loc = ":".join([src_file, str(crash_l), str(crash_c), str(int(crash_address) - 1) + " "])
        if crash_logical_loc in values.VALUE_TRACK_CONCRETE:
            pointer_list = values.VALUE_TRACK_CONCRETE[crash_logical_loc]
            if pointer_list:
                crash_pointer = pointer_list[-1].replace("pointer:", "")
                base_pointer = analyzer.get_base_address(crash_pointer,
                                                         values.MEMORY_TRACK_CONCRETE,
                                                         values.POINTER_TRACK_CONCRETE)
                if base_pointer is None or int(base_pointer) == 0:
                    member_expr_node = None
                    while member_expr_node is None:
                        ptr_node_type = ptr_node["kind"]
                        if ptr_node_type == "MemberExpr":
                            member_expr_node = ptr_node
                        if "inner" not in ptr_node:
                            break
                        ptr_node = ptr_node["inner"][0]
                    if member_expr_node:
                        base_ptr_node = member_expr_node["inner"][0]
                        ptr_expr = generate_expr_for_ast(base_ptr_node)
                        null_symbol = make_constraint_symbol("NULL", "NULL_VAL")
                        null_expr = make_symbolic_expression(null_symbol)
                        neq_op = build_op_symbol("!=")
                        constraint_expr = make_binary_expression(neq_op, null_expr, ptr_expr)
                        return constraint_expr
                if base_pointer:
                    if base_pointer in values.MEMORY_TRACK_CONCRETE:
                        alloc_info = values.MEMORY_TRACK_CONCRETE[base_pointer]
                        concrete_value = alloc_info["con_size"]
                        if int(concrete_value) == 0:
                            size_op = build_op_symbol("size ")
                            ptr_expr = generate_expr_for_ast(ptr_node)
                            size_expr = make_unary_expression(size_op, copy.deepcopy(ptr_expr))
                            zero_symbol = make_constraint_symbol("0", "CONST_INT")
                            zero_expr = make_symbolic_expression(zero_symbol)
                            gt_op = build_op_symbol("<")
                            constraint_expr = make_binary_expression(gt_op, zero_expr, size_expr)
                            return constraint_expr


        size_op = build_op_symbol("size ")
        ptr_expr = generate_expr_for_ast(ptr_node)
        size_expr = make_unary_expression(size_op, copy.deepcopy(ptr_expr))

        base_op = build_op_symbol("base ")
        base_expr = make_unary_expression(base_op, copy.deepcopy(ptr_expr))
        lt_op = build_op_symbol("<")

        pointer_diff = get_pointer_diff(ptr_node, src_file)
        if pointer_diff < 0:
            lte_op = build_op_symbol("<=")
            base_op = build_op_symbol("base ")
            base_expr = make_unary_expression(base_op, copy.deepcopy(ptr_expr))
            constraint_expr = make_binary_expression(lte_op, base_expr, ptr_expr)
        else:
            lhs_constraint = ptr_expr
            arith_plus_op = build_op_symbol("+")
            rhs_constraint = make_binary_expression(arith_plus_op, base_expr, size_expr)
            constraint_expr = make_binary_expression(lt_op, lhs_constraint, rhs_constraint)

    return constraint_expr


def generate_memory_null_constraint(reference_node, crash_loc):
    ref_node_kind = reference_node["kind"]
    if ref_node_kind == "MemberExpr":
        got_pointer = False
        src_file, crash_l, crash_c = crash_loc
        while not got_pointer:
            node_end_loc = int(reference_node["range"]["end"]["col"]) + int(reference_node["range"]["end"]["tokLen"])
            if node_end_loc >= crash_c:
                reference_node = reference_node["inner"][0]
            else:
                got_pointer = True
    elif ref_node_kind == "ArraySubscriptExpr":
        reference_node = reference_node["inner"][0]


    left_expr = generate_expr_for_ast(reference_node)
    constraint_op_str = "!="
    constraint_op_type = next(key for key, value in SymbolType.items() if value == constraint_op_str)
    constraint_op = make_constraint_symbol(constraint_op_str, constraint_op_type)
    constraint_val_str = "NULL"
    constraint_val_type = "NULL_VAL"
    constraint_val = make_constraint_symbol(constraint_val_str, constraint_val_type)
    right_expr = make_symbolic_expression(constraint_val)
    constraint_expr = make_binary_expression(constraint_op, left_expr, right_expr)
    return constraint_expr


def generate_shift_overflow_constraint(shift_node):
    binary_left_ast = shift_node["inner"][0]
    binary_right_ast = shift_node["inner"][1]
    binary_op_str = shift_node["opcode"]

    binary_left_expr = generate_expr_for_ast(binary_left_ast)
    binary_right_expr = generate_expr_for_ast(binary_right_ast)
    result_data_type = extractor.extract_data_type(binary_left_ast)
    type_min, type_max = get_type_limits(result_data_type)
    max_val_symbol = make_constraint_symbol(type_max, "CONST_INT")
    max_val_expr = make_symbolic_expression(max_val_symbol)

    # Generating a constraint of type 0 < {} < bit width && INT_MAX >> {} < {}
    less_than_op = build_op_symbol("<")
    type_width = get_type_width(result_data_type)
    width_val_symbol = make_constraint_symbol(str(type_width), "CONST_INT")
    width_val_expr = make_symbolic_expression(width_val_symbol)
    zero_symbol = make_constraint_symbol("0", "CONST_INT")
    zero_expr = make_symbolic_expression(zero_symbol)
    first_predicate_expr = make_binary_expression(less_than_op, zero_expr, binary_right_expr)
    second_predicate_expr = make_binary_expression(less_than_op, binary_right_expr, width_val_expr)
    and_op = build_op_symbol("&&")
    first_constraint_expr = make_binary_expression(and_op, first_predicate_expr, second_predicate_expr)

    gt_eq_op = build_op_symbol(">=")
    shift_op = build_op_symbol(">>")
    shifted_value_expr = make_binary_expression(shift_op, max_val_expr, binary_right_expr)
    second_constraint_expr = make_binary_expression(gt_eq_op, shifted_value_expr, binary_left_expr)

    if binary_op_str == ">>":
        constraint_expr = first_constraint_expr
    else:
        constraint_expr = make_binary_expression(and_op, first_constraint_expr, second_constraint_expr)
    return constraint_expr



def generate_memset_constraint(call_node):
    pointer_node = call_node["inner"][1]
    # pointer_name = converter.convert_node_to_str(pointer_node)
    # size_value = converter.convert_node_to_str(size_node)

    # Generating a constraint of type size_value > 0 && pointer_name != 0
    # first generate the expressions for the two operands
    pointer_expr = generate_expr_for_ast(pointer_node)

    # next generate the second constraint pointer != 0
    not_eq_op = build_op_symbol("!=")
    null_symbol = make_constraint_symbol("NULL", "NULL_VAL")
    null_expr = make_symbolic_expression(null_symbol)
    constraint_expr = make_binary_expression(not_eq_op, null_expr, pointer_expr)

    return constraint_expr

## Incomplete lifting of constraint from StringLiteral
def generate_assertion_constraint(call_node, func_node, src_file):
    assertion_str_node = call_node["inner"][1]
    assertion_str = converter.get_node_value(assertion_str_node)
    assertion_expr = sympify(assertion_str)
    var_list = extractor.extract_ast_var_list(func_node, src_file)
    var_name_list = [x[0] for x in var_list]
    str_tokens = assertion_expr.split(" ")
    constraint_expr = None
    if len(str_tokens) == 3:
        comp_op_str = str_tokens[1]
        comp_op = build_op_symbol(comp_op_str)
        left_node_str = str_tokens[0]
        right_node_str = str_tokens[2]
        left_node = make_constraint_symbol(left_node_str, "VAR_INT" if left_node_str in var_name_list else "CONST_INT")
        left_expr = make_symbolic_expression(left_node)
        right_node = make_constraint_symbol(right_node_str, "VAR_INT" if right_node_str in var_name_list else "CONST_INT")
        right_expr = make_symbolic_expression(right_node)
        constraint_expr = make_binary_expression(comp_op, left_expr, right_expr)
    else:
        utilities.error_exit("Not implemented: handling more than 3 tokens in assertion constraint")
    return constraint_expr

def generate_iterator_location(iterator_node, src_file):
    if iterator_node["kind"] == "BinaryOperator":
        iterator_range = iterator_node["inner"][1]["range"]["begin"]
        source_ptr_loc = extractor.extract_loc(src_file, iterator_range)
        source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2] - 2}"
    elif iterator_node["kind"] == "ImplicitCastExpr":
        iterator_range = iterator_node["range"]["end"]
        source_ptr_loc = extractor.extract_loc(src_file, iterator_range)
        source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
    else:
        iterator_range = iterator_node["range"]["begin"]
        source_ptr_loc = extractor.extract_loc(src_file, iterator_range)
        source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
    return source_ptr_loc_str

def generate_iterator_offset_constraint(iterator_node, ptr_node, src_file):
    constraint_expr = None
    array_offset = get_pointer_diff(ptr_node, src_file, iterator_node)
    if array_offset > 0:
        ptr_expr = generate_expr_for_ast(ptr_node)
        base_op = build_op_symbol("base ")
        base_expr = make_unary_expression(base_op, copy.deepcopy(ptr_expr))
        arith_plus_op = build_op_symbol("+")
        size_op = build_op_symbol("size ")
        size_expr = make_unary_expression(size_op, copy.deepcopy(ptr_expr))
        result_ptr_type = extractor.extract_data_type(ptr_node)
        result_ptr_width = get_type_width(result_ptr_type)
        lt_op = build_op_symbol("<")
        iterator_expr = generate_expr_for_ast(iterator_node)
        ptr_width_bytes = int(result_ptr_width / 8)
        if ptr_width_bytes > 1:
            width_symbol = make_constraint_symbol(str(ptr_width_bytes), "CONST_INT")
            width_expr = make_symbolic_expression(width_symbol)
            arith_mul_op = build_op_symbol("*")
            iterator_offset_expr = make_binary_expression(arith_mul_op, width_expr, iterator_expr)
        else:

            iterator_offset_expr = iterator_expr
        lhs_constraint = make_binary_expression(arith_plus_op, ptr_expr, iterator_offset_expr)
        rhs_constraint = make_binary_expression(arith_plus_op, base_expr, size_expr)
        constraint_expr = make_binary_expression(lt_op, lhs_constraint, rhs_constraint)

    else:
        utilities.error_exit("unhandled offset in generate_iterator_offset_constraint")

    return constraint_expr


def generate_iterator_constraint(iterator_node, src_file, ptr_node):
    source_ptr_loc_str = generate_iterator_location(iterator_node, src_file)
    constraint_expr = None
    result_iterator_type = extractor.extract_data_type(iterator_node)
    result_ptr_type = extractor.extract_data_type(ptr_node)
    result_ptr_width = get_type_width(result_ptr_type)
    is_signed = "unsigned" not in result_iterator_type
    for taint_loc in reversed(values.VALUE_TRACK_CONCRETE):
        if source_ptr_loc_str in taint_loc:
            expr_list = values.VALUE_TRACK_CONCRETE[taint_loc]
            if expr_list and "integer" in expr_list[0]:
                last_expr = expr_list[-1].replace("integer:", "")
                concrete_val_var_expr = int(last_expr.split(" ")[1].replace("bv", ""))
                bit_size_var_expr = int(last_expr.split(" ")[-1].replace(")", ""))
                last_value = solver.solve_sign(concrete_val_var_expr, bit_size_var_expr)
                if int(last_value) < 0 and is_signed:
                    iterator_expr = generate_expr_for_ast(iterator_node)
                    lte_op = build_op_symbol("<=")
                    zero_symbol = make_constraint_symbol("0", "CONST_INT")
                    zero_expr = make_symbolic_expression(zero_symbol)
                    constraint_expr = make_binary_expression(lte_op, zero_expr, iterator_expr)
                else:
                    alloc_size, is_static = get_pointer_size(ptr_node, src_file)
                    if alloc_size.isnumeric():
                        if (0 < int(alloc_size) <= (int(last_value) * result_ptr_width)) or \
                                (int(last_value) < 0 and not is_signed):
                            lt_op = build_op_symbol("<")
                            if is_static:
                                size_symbol = make_constraint_symbol(str(alloc_size), "CONST_INT")
                                size_expr = make_symbolic_expression(size_symbol)
                            else:
                                size_op = build_op_symbol("size ")
                                ptr_expr = generate_expr_for_ast(ptr_node)
                                size_expr = make_unary_expression(size_op, copy.deepcopy(ptr_expr))
                            iterator_expr = generate_expr_for_ast(iterator_node)
                            ptr_width_bytes = int(result_ptr_width / 8)
                            if ptr_width_bytes > 1:
                                width_symbol = make_constraint_symbol(str(ptr_width_bytes), "CONST_INT")
                                width_expr = make_symbolic_expression(width_symbol)
                                arith_mul_op = build_op_symbol("*")
                                lhs_expr = make_binary_expression(arith_mul_op, width_expr, iterator_expr)
                            else:

                                lhs_expr = iterator_expr
                            constraint_expr = make_binary_expression(lt_op, lhs_expr, size_expr)
                    else:
                        iterator_expr = generate_expr_for_ast(iterator_node)
                        lt_op = build_op_symbol("<")
                        size_op = build_op_symbol("size ")
                        ptr_expr = generate_expr_for_ast(ptr_node)
                        size_expr = make_unary_expression(size_op, copy.deepcopy(ptr_expr))
                        constraint_expr = make_binary_expression(lt_op, iterator_expr, size_expr)
    return constraint_expr


def get_pointer_size(ptr_node, src_file):
    source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["begin"])
    source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
    alloc_size = -1
    var_type = extractor.extract_data_type(ptr_node)
    static_size = None
    is_static = False
    if "[" in var_type:
        is_static = True
        static_size = var_type.split("[")[-1].split("]")[0]
        ptr_width = get_type_width(var_type)
        alloc_size = str(int(static_size) * int(ptr_width/8))

    if not static_size:
        for taint_loc in values.VALUE_TRACK_CONCRETE:
            if source_ptr_loc_str in taint_loc:
                expr_list = values.VALUE_TRACK_CONCRETE[taint_loc]
                if expr_list and "pointer" in expr_list[0]:
                    last_pointer = expr_list[-1].replace("pointer:", "")
                    base_pointer = analyzer.get_base_address(last_pointer,
                                                             values.MEMORY_TRACK_CONCRETE,
                                                             values.POINTER_TRACK_CONCRETE)
                    if base_pointer:
                        alloc_info = values.MEMORY_TRACK_CONCRETE[base_pointer]
                        alloc_size = str(alloc_info["con_size"])
    return alloc_size, is_static

def get_pointer_value(ptr_node, src_file):
    source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["begin"])
    source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
    last_pointer = None
    for taint_loc in reversed(values.VALUE_TRACK_CONCRETE):
        if source_ptr_loc_str in taint_loc:
            expr_list = values.VALUE_TRACK_CONCRETE[taint_loc]
            if expr_list and "pointer" in expr_list[0]:
                last_pointer = expr_list[-1].replace("pointer:", "")
    return last_pointer


def get_pointer_base(ptr_node, src_file):
    source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["begin"])
    source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
    base_pointer = None
    for taint_loc in reversed(values.VALUE_TRACK_CONCRETE):
        if source_ptr_loc_str in taint_loc:
            expr_list = values.VALUE_TRACK_CONCRETE[taint_loc]
            if expr_list and "pointer" in expr_list[0]:
                last_pointer = expr_list[-1].replace("pointer:", "")
                base_pointer = analyzer.get_base_address(last_pointer,
                                                         values.MEMORY_TRACK_CONCRETE,
                                                         values.POINTER_TRACK_CONCRETE)
    return base_pointer


def generate_pointer_loc(ptr_node, src_file):
    node_kind = ptr_node["kind"]
    if node_kind in ["ImplicitCastExpr"]:
        return generate_pointer_loc(ptr_node["inner"][0], src_file)
    elif node_kind in ["MemberExpr"]:
        source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["end"])
        source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
    elif node_kind in ["ArraySubscriptExpr"]:
        source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["begin"])
        source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
    elif node_kind == "UnaryOperator":
        op_code = ptr_node["opcode"]
        if op_code in ["++", "--"]:
            is_postfix = ptr_node["isPostfix"]
            if is_postfix:
                source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["end"])
                source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
            else:
                source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["begin"])
                source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
        else:
            source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["begin"])
            source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"

    else:
        source_ptr_loc = extractor.extract_loc(src_file, ptr_node["range"]["begin"])
        source_ptr_loc_str = f"{source_ptr_loc[0]}:{source_ptr_loc[1]}:{source_ptr_loc[2]}"
    return source_ptr_loc_str

def get_pointer_diff(ptr_node, src_file, iterator_node=None):
    source_ptr_loc_str = generate_pointer_loc(ptr_node, src_file)
    pointer_diff = None
    iterator_loc = None
    if "castKind" in ptr_node:
        ptr_cast_kind = ptr_node["castKind"]
        if ptr_cast_kind == "ArrayToPointerDecay":
            return 0
    else:
        ptr_result_type = extractor.extract_data_type(ptr_node)
        if "[" in ptr_result_type:
            return 0
    if iterator_node is not None:
        iterator_node_kind = iterator_node["kind"]
        iterator_loc = generate_iterator_location(iterator_node, src_file)
        if iterator_node_kind == "IntegerLiteral":
            iterator_loc = None

    for taint_loc in reversed(values.VALUE_TRACK_CONCRETE):
        if iterator_loc is not None:
            if iterator_loc in taint_loc:
                iterator_loc = None
            continue
        if source_ptr_loc_str in taint_loc:
            expr_list = values.VALUE_TRACK_CONCRETE[taint_loc]
            if expr_list and "pointer" in expr_list[0]:
                last_pointer = expr_list[-1].replace("pointer:", "")
                base_pointer = analyzer.get_base_address(last_pointer,
                                                         values.MEMORY_TRACK_CONCRETE,
                                                         values.POINTER_TRACK_CONCRETE)
                if base_pointer:
                    last_ptr_concrete = last_pointer.split(" ")[1].replace("bv", "")
                    pointer_diff = int(last_ptr_concrete) - int(base_pointer)
                    break
    return pointer_diff


def generate_out_of_bound_ptr_constraint(ptr_node, src_file, iterator_node=None):
    constraint_expr = None
    pointer_diff = get_pointer_diff(ptr_node, src_file, iterator_node)
    if pointer_diff is not None and pointer_diff < 0:
        ptr_expr = generate_expr_for_ast(ptr_node)
        lte_op = build_op_symbol("<=")
        base_op = build_op_symbol("base ")
        base_expr = make_unary_expression(base_op, copy.deepcopy(ptr_expr))
        constraint_expr = make_binary_expression(lte_op, base_expr, ptr_expr)

    alloc_size, is_static = get_pointer_size(ptr_node, src_file)
    if alloc_size.isnumeric():
        if alloc_size is not None and int(alloc_size) <= int(pointer_diff):
            ptr_expr = generate_expr_for_ast(ptr_node)
            if is_static:
                size_symbol = make_constraint_symbol(str(alloc_size), "CONST_INT")
                size_expr = make_symbolic_expression(size_symbol)
            else:
                size_op = build_op_symbol("size ")
                size_expr = make_unary_expression(size_op, copy.deepcopy(ptr_expr))

            base_op = build_op_symbol("base ")
            base_expr = make_unary_expression(base_op, copy.deepcopy(ptr_expr))
            arith_plus_op = build_op_symbol("+")
            lt_op = build_op_symbol("<")
            lhs_constraint = ptr_expr
            rhs_constraint = make_binary_expression(arith_plus_op, base_expr, size_expr)
            constraint_expr = make_binary_expression(lt_op, lhs_constraint, rhs_constraint)
    return constraint_expr


def generate_memcpy_constraint(call_node, src_file):
    source_ptr_node = call_node["inner"][1]
    target_ptr_node = call_node["inner"][2]
    size_node = call_node["inner"][3]

    # first check if the pointers are in bound
    source_ptr_bound_constraint = generate_out_of_bound_ptr_constraint(source_ptr_node, src_file)
    if source_ptr_bound_constraint:
        return source_ptr_bound_constraint
    target_ptr_bound_constraint = generate_out_of_bound_ptr_constraint(target_ptr_node, src_file)
    if target_ptr_bound_constraint:
        return target_ptr_bound_constraint

    # source_name = converter.convert_node_to_str(source_ptr_node)
    # target_name = converter.convert_node_to_str(target_ptr_node)
    # size_value = converter.convert_node_to_str(size_node)

    # Generating a constraint of type
    # target - source < size
    # first generate the expressions for the arithmetic expression
    source_expr = generate_expr_for_ast(source_ptr_node)
    target_expr = generate_expr_for_ast(target_ptr_node)
    arithmetic_op = build_op_symbol("-")
    diff_expr_1 = make_binary_expression(arithmetic_op, target_expr, source_expr)
    diff_expr_2 = make_binary_expression(arithmetic_op, source_expr, target_expr)
    less_than_op = build_op_symbol("<")
    size_expr = generate_expr_for_ast(size_node)
    first_constraint = make_binary_expression(less_than_op, diff_expr_1, size_expr)
    second_constraint = make_binary_expression(less_than_op, diff_expr_2, size_expr)

    source_ptr_val = get_pointer_value(source_ptr_node, src_file)
    target_ptr_val = get_pointer_value(target_ptr_node, src_file)

    if target_ptr_val < source_ptr_val:
        constraint_expr = second_constraint
    else:
        constraint_expr = first_constraint

    # # last, concatenate both constraints into one
    # logical_and_op = build_op_symbol("&&")
    # constraint_expr = make_binary_expression(logical_and_op, first_constraint, second_constraint)
    return constraint_expr


def generate_memmove_constraint(call_node):
    source_ptr_node = call_node["inner"][1]
    target_ptr_node = call_node["inner"][2]
    size_node = call_node["inner"][3]

    # Generating first constraint of type
    # target - source < size
    # first generate the expressions for the arithmetic expression
    source_expr = generate_expr_for_ast(source_ptr_node)
    target_expr = generate_expr_for_ast(target_ptr_node)
    arithmetic_op = build_op_symbol("-")
    diff_expr = make_binary_expression(arithmetic_op, target_expr, source_expr)
    try:
        diff_expr_str = diff_expr.to_expression()
        simplified_diff_expr_str = str(sympify(diff_expr_str))
        simplified_diff_expr = generate_expr_for_str(simplified_diff_expr_str, "VAR_INT")
    except Exception as ex:
        simplified_diff_expr = diff_expr
    size_expr = generate_expr_for_ast(size_node)

    # last, concatenate both constraints into one
    less_than_op = build_op_symbol("<")
    first_constraint = make_binary_expression(less_than_op, simplified_diff_expr, size_expr)

    # Generating second constraint of type
    # check if the size constraint is a diff operator
    if size_expr.get_type() == "OP_ARITH_MINUS":
        rhs_size_expr = size_expr.get_r_expr()
        lhs_size_expr = size_expr.get_l_expr()
        second_constraint = make_binary_expression(less_than_op, rhs_size_expr, lhs_size_expr)
    # 0 < size
    else:
        zero_symbol = make_constraint_symbol("0", "CONST_INT")
        zero_expr = make_symbolic_expression(zero_symbol)
        second_constraint = make_binary_expression(less_than_op, zero_expr, size_expr)

    # Final constraint is a concatenation
    logical_and_op = build_op_symbol("&&")
    constraint_expr = make_binary_expression(logical_and_op, second_constraint, first_constraint)

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
    data_type = str(data_type).lower()
    if "**" in data_type or "][" in data_type:
        return 64
    elif any(t in data_type for t in ["long double"]):
        return 128
    elif any(t in data_type for t in ["char", "unsigned char", "int8_t", "uint8_t"]):
        return 8
    elif any(t in data_type for t in ["short", "int16_t", "uint16_t", "float", "uint16"]):
        return 16
    elif any(t in data_type for t in ["long long", "int64_t", "uint64_t", "uint64"]):
        return 64
    elif any(t in data_type for t in ["int", "unsigned int", "long", "int32_t", "uint32_t", "double", "uint32"]):
        return 32
    else:
        utilities.error_exit("Unknown data type for width constraints: {}".format(data_type))

