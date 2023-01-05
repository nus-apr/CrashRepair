from pathlib import Path
from typing import List, Dict
from six.moves import cStringIO
from pysmt.shortcuts import Not, And, Or
import os
from pysmt.exceptions import UndefinedSymbolError, PysmtValueError,PysmtTypeError
from pysmt.smtlib.parser import SmtLibParser
from pysmt.typing import BV32, BV8, ArrayType
from pysmt.shortcuts import write_smtlib, get_model, Symbol, is_unsat, is_sat
from app import emitter, values, reader, definitions, extractor, oracle, utilities, logger
import re
import struct
import random
import copy

File_Log_Path = "/tmp/log_sym_path"
File_Ktest_Path = "/tmp/concolic.ktest"



def generate_mask_bytes(klee_out_dir, poc_path):
    mask_byte_list = list()
    log_path = klee_out_dir + "/concrete.log"
    concretized_byte_list = reader.collect_concretized_bytes(log_path)
    smt2_file_path = klee_out_dir + "/test000001.smt2"
    control_byte_list = reader.collect_bytes_from_smt2(smt2_file_path)
    emitter.data("Control Byte List", control_byte_list)
    fixed_byte_list = list()
    if "A-data" in concretized_byte_list:
        influence_byte_list = sorted(list(concretized_byte_list["A-data"]))
        emitter.data("Influencing Byte List", influence_byte_list)
    fixed_byte_list = control_byte_list
    if poc_path:
        byte_length = os.path.getsize(poc_path)
        for i in range(0, byte_length):
            if i not in fixed_byte_list:
                mask_byte_list.append(i)
    return sorted(mask_byte_list)


def generate_binary_file(byte_array, seed_file_path, gen_file_path=None):
    byte_list = []
    modified_index_list = []
    with open(seed_file_path, "rb") as poc_file:
        byte = poc_file.read(1)
        while byte:
            number = int(struct.unpack('>B', byte)[0])
            byte_list.append(number)
            byte = poc_file.read(1)
    mask_byte_list = values.MASK_BYTE_LIST[seed_file_path]
    emitter.data("Masked Byte List", mask_byte_list)
    for index in byte_array:
        if index not in mask_byte_list:
            byte_list[index] = byte_array[index]
            modified_index_list.append(index)
    emitter.data("Modified Byte List", modified_index_list)
    file_extension = ""
    if "." in seed_file_path:
        file_extension = str(seed_file_path).split(".")[-1]
    if not gen_file_path:
        gen_file_path = definitions.DIRECTORY_OUTPUT + "/input-" + str(values.ITERATION_NO)
    values.FILE_POC_GEN = gen_file_path
    if file_extension:
        values.FILE_POC_GEN = values.FILE_POC_GEN + "." + file_extension
    with open(values.FILE_POC_GEN, "wb") as new_input_file:
        new_input_file.write(bytearray(byte_list))


def generate_formula(formula_str):
    parser = SmtLibParser()
    script = parser.get_script(cStringIO(formula_str))
    formula = script.get_last_formula()
    return formula


def generate_ktest(argument_list, second_var_list, print_output=False):
    """
    This function will generate the ktest file provided the argument list and second order variable list
        argument_list : a list containing each argument in the order that should be fed to the program
        second_var_list: a list of tuples where a tuple is (var identifier, var size, var value)
    """
    global File_Ktest_Path
    emitter.normal("\tgenerating ktest file")
    ktest_path = File_Ktest_Path
    ktest_command = "gen-bout --out-file {0}".format(ktest_path)

    for argument in argument_list:
        index = list(argument_list).index(argument)
        if "$POC" in argument:
            binary_file_path = values.FILE_POC_GEN
            # if "_" in argument:
            #     file_index = "_".join(str(argument).split("_")[1:])
            #     binary_file_path = values.LIST_TEST_FILES[file_index]
            # else:
            #     binary_file_path = values.CONF_PATH_POC
            #     if values.FILE_POC_GEN:
            #         binary_file_path = values.FILE_POC_GEN
            #     elif values.FILE_POC_SEED:
            #         binary_file_path = values.FILE_POC_SEED
            ktest_command += " --sym-file " + binary_file_path
        elif str(index) in values.CONF_MASK_ARG:
            continue
        else:
            if argument in ["''"]:
                argument = ""
            if "\"" in argument:
                ktest_command += " --sym-arg '" + str(argument) + "'"
                continue
            ktest_command += " --sym-arg \"" + str(argument) + "\""

    for var in second_var_list:
        ktest_command += " --second-var \'{0}\' {1} {2}".format(var['identifier'], var['size'], var['value'])
    return_code = utilities.execute_command(ktest_command)
    return ktest_path, return_code


def generate_z3_code_for_expr(var_expr, var_name, bit_size):
    var_name = var_name + "_" + str(bit_size)
    zero = "x0"
    if int(bit_size) > 4:
        zero = "x" + "0"*int(int(bit_size)/4)
    code = "(set-logic QF_AUFBV )\n"
    declarations = generate_source_declarations(var_expr, var_expr)
    declarations += "(declare-fun " + var_name + "() (_ BitVec " + str(bit_size) + "))\n"
    extended_expression = extend_formula(declarations, var_expr, var_name)
    assertions = "(assert (= {} {}))\n".format(var_name, extended_expression)
    assertions += "(assert  (not (= " + var_name + " #" + zero + ")))\n"
    code += declarations
    code += assertions
    code += "(check-sat)\n"
    return code


def generate_z3_code_for_var(var_expr, var_name):
    var_name = str(var_name).replace("->", "")
    var_name = str(var_name).replace("[", "-").replace("]", "-")
    var_name = str(var_name).replace("(", "-").replace(")", "-")
    var_name = str(var_name).replace(" ", "")
    if "sizeof " in var_name or "diff " in var_name:
        var_name = "sizeof_" + var_name.split(" ")[3]
    bit_size = 2
    code = ""
    while True:
        try:
            code = generate_z3_code_for_expr(var_expr, var_name, bit_size)
            if bit_size == 64:
                break
            parser = SmtLibParser()
            script = parser.get_script(cStringIO(code))
            formula = script.get_last_formula()
            result = is_sat(formula, solver_name="z3")
            break
        except PysmtTypeError as ex:
            bit_size = bit_size * 2
        except AssertionError as ex:
            break
        except Exception as exception:
            logger.exception(exception, code)
            break
    return code


def generate_source_declarations(sym_expr_a, sym_expr_b):
    source_list_a = [x.group() for x in re.finditer(r'select (.*?)\)', sym_expr_a)]
    source_list_b = [x.group() for x in re.finditer(r'select (.*?)\)', sym_expr_b)]
    source_def_str = ""
    source_list = list(set(source_list_a + source_list_b))
    unique_source_list = []
    for source in source_list:
        source_name = re.search(r'select  (.*) \(',source).group(1)
        if source_name in unique_source_list:
            continue
        unique_source_list.append(source_name)
        source_def_str = source_def_str + \
                         ("(declare-fun {} () (Array (_ BitVec 32) (_ BitVec 8) ) )\n".
                               format(source_name))
    return source_def_str


def extend_formula(sym_dec, sym_expr, var_name):
    extended_expr = sym_expr
    z3_init = "(set-logic QF_AUFBV )\n"
    z3_init += sym_dec + "\n"
    for bits in [0,1,2,4,6,8,12,16,24,32,48,56,64]:
        z3_code = z3_init
        extended_expr = "((_ zero_extend {}) {})".format(bits, sym_expr)
        z3_code += "(assert (= " + str(var_name) + " " + str(extended_expr) + "))\n"
        z3_code += "(check-sat)\n"
        try:
            parser = SmtLibParser()
            script = parser.get_script(cStringIO(z3_code))
            formula = script.get_last_formula()
            result = is_sat(formula, solver_name="z3")
            break
        except PysmtTypeError as ex:
            continue
        except AssertionError as ex:
            return sym_expr
        except Exception as ex:
            logger.exception(ex, z3_code)
            return sym_expr
    return extended_expr


def extract_definition(sym_expr):
    lines = sym_expr.split("\n")
    var_dec_list = [x for x in lines if "declare" in x]
    sym_expr = [x for x in lines if "assert" in x][0]
    var_name = str(var_dec_list[-1].split(" ")[1]).replace("(", "").replace(")", "")
    bit_size = int(var_name.split("_")[-1])
    return var_name, sym_expr, var_dec_list, bit_size


def generate_definitions(sym_expr_a, sym_expr_b):
    lines_a = sym_expr_a.split("\n")
    var_dec_a = [x for x in lines_a if "declare" in x][-1]
    sym_expr_a = [x for x in lines_a if "assert" in x][0]
    lines_b = sym_expr_b.split("\n")
    var_dec_b = [x for x in lines_b if "declare" in x][-1]
    sym_expr_b = [x for x in lines_b if "assert" in x][0]
    var_name_a = str(var_dec_a.split(" ")[1]).replace("(", "").replace(")", "")
    var_name_b = str(var_dec_b.split(" ")[1]).replace("(", "").replace(")", "")
    bit_size_a = int(var_name_a.split("_")[-1])
    bit_size_b = int(var_name_b.split("_")[-1])

    if bit_size_a > bit_size_b:
        var_dec_b = var_dec_b.replace("_ BitVec {}".format(bit_size_b), "_ BitVec {}".format(bit_size_a))
        var_expr_b_tokens = sym_expr_b.split(" ")
        var_expr_b_tokens[3] = "((_ zero_extend {})".format(bit_size_a - bit_size_b) + var_expr_b_tokens[3]
        sym_expr_b = " ".join(var_expr_b_tokens)
        sym_expr_b += ")"

    if bit_size_b > bit_size_a:
        var_dec_a = var_dec_a.replace("_ BitVec {}".format(bit_size_a), "_ BitVec {}".format(bit_size_b))
        var_expr_a_tokens = sym_expr_a.split(" ")
        var_expr_a_tokens[3] = "((_ zero_extend {})".format(bit_size_b - bit_size_a) + var_expr_a_tokens[3]
        sym_expr_a = " ".join(var_expr_a_tokens)
        sym_expr_a += ")"


    if var_name_a == var_name_b:
        sym_expr_b = sym_expr_b.replace(var_name_b, "b_" + var_name_b )
        var_dec_b = var_dec_b.replace(var_name_b, "b_" + var_name_b)
        var_name_b = "b_" + var_name_b
        sym_expr_a = sym_expr_a.replace(var_name_a, "a_" + var_name_a)
        var_dec_a = var_dec_a.replace(var_name_a, "a_" + var_name_a)
        var_name_a = "a_" + var_name_a
    return (var_name_a, sym_expr_a, var_dec_a), (var_name_b, sym_expr_b, var_dec_b)


def generate_z3_code_for_combination_add(sym_expr_list, ref_sym_expr):
    ref_z3_code = generate_z3_code_for_var(ref_sym_expr, "crash_var_ref")
    ref_name, _, ref_dec_list, ref_bit_size = extract_definition(ref_z3_code)
    code = "(set-logic QF_AUFBV )\n"
    complete_decl_list = ref_dec_list
    z3_code_list = list()
    max_bit_size = 0
    i = 0
    for sym_expr in sym_expr_list:
        i = i + 1
        z3_code = generate_z3_code_for_var(sym_expr, "expr_{}".format(i))
        z3_code_list.append(z3_code)
        prog_expr, _, declaration_list, bit_size = extract_definition(z3_code)
        complete_decl_list += declaration_list
        if bit_size > max_bit_size:
            max_bit_size = bit_size

    if max_bit_size < ref_bit_size:
        max_bit_size = ref_bit_size

    for dec in list(set(complete_decl_list)):
        if ref_name in dec or "expr_" in dec:
            bit_size = re.search(r'\(_ BitVec (.*)\)', dec).group(0)
            dec = dec.replace(bit_size, "(_ BitVec {}))".format(max_bit_size))
        code += dec + "\n"

    combination_z3_code = ""
    zero = "x0"
    one = "x1"
    if int(max_bit_size) > 4:
        count_zeros = int(int(max_bit_size) / 4)
        zero = "x" + "0" * count_zeros
        one = "x" + "0" * (count_zeros - 1) + "1"
    for i in range(len(sym_expr_list)):
        z3_code = z3_code_list[i]
        sym_expr = sym_expr_list[i]
        select_list = [x.group() for x in re.finditer(r'select (.*?)\)', sym_expr)]
        prog_expr, _, declaration_list, bit_size = extract_definition(z3_code)
        extended_sym_expr = sym_expr
        if bit_size < max_bit_size:
            dummy_name = "__check__"
            declaration = "(declare-fun " + dummy_name + "() (_ BitVec " + str(max_bit_size) + "))\n"
            for decl in declaration_list:
                declaration += decl + "\n"
            extended_sym_expr = extend_formula(declaration,
                                               sym_expr, dummy_name)
        code += "(assert (not (= {} {})))\n".format(prog_expr, extended_sym_expr)
        code += "(assert  (not (= " + prog_expr + " #" + zero + ")))\n"
        if combination_z3_code:
            combination_z3_code = "(bvadd {} {})".format(combination_z3_code, prog_expr)
        else:
            combination_z3_code = prog_expr

    code += "(assert (= {} {}))\n".format(ref_name, ref_sym_expr)
    code += "(assert (= {} {}))\n".format(combination_z3_code, ref_name)
    code += "(check-sat)\n"
    return code



def generate_z3_code_for_combination_mul(sym_expr_list, ref_sym_expr):
    ref_z3_code = generate_z3_code_for_var(ref_sym_expr, "crash_var_ref")
    ref_name, _, ref_dec_list, ref_bit_size = extract_definition(ref_z3_code)
    code = "(set-logic QF_AUFBV )\n"
    complete_decl_list = ref_dec_list
    z3_code_list = list()
    max_bit_size = 0
    i = 0
    for sym_expr in sym_expr_list:
        i = i + 1
        z3_code = generate_z3_code_for_var(sym_expr, "expr_{}".format(i))
        z3_code_list.append(z3_code)
        prog_expr, _, declaration, bit_size = extract_definition(z3_code)
        complete_decl_list += declaration
        if bit_size > max_bit_size:
            max_bit_size = bit_size

    if max_bit_size < ref_bit_size:
        max_bit_size = ref_bit_size
    for dec in list(set(complete_decl_list)):
        if ref_name in dec or "expr_" in dec:
            bit_size = re.search(r'\(_ BitVec (.*)\)', dec).group(0)
            dec = dec.replace(bit_size, "(_ BitVec {}))".format(max_bit_size))
        code += dec + "\n"

    combination_z3_code = ""
    zero = "x0"
    one = "x1"
    if int(max_bit_size) > 4:
        count_zeros = int(int(max_bit_size) / 4)
        zero = "x" + "0" * count_zeros
        one = "x" + "0" * (count_zeros - 1) + "1"

    for i in range(len(sym_expr_list)):
        z3_code = z3_code_list[i]
        prog_expr, _, declaration_list, bit_size = extract_definition(z3_code)
        sym_expr = sym_expr_list[i]
        extended_sym_expr = sym_expr
        if bit_size < max_bit_size:
            dummy_name = "__check__"
            declaration = "(declare-fun " + dummy_name + "() (_ BitVec " + str(max_bit_size) + "))\n"
            for decl in declaration_list:
                declaration += decl + "\n"
            extended_sym_expr = extend_formula(declaration,
                                               sym_expr, dummy_name)
        code += "(assert (not (= {} {})))\n".format(prog_expr, extended_sym_expr)
        code += "(assert  (not (= " + prog_expr + " #" + zero + ")))\n"
        if combination_z3_code:
            combination_z3_code = "(bvmul {} {})".format(combination_z3_code, prog_expr)
        else:
            combination_z3_code = prog_expr

    code += "(assert (= {} {}))\n".format(ref_name, ref_sym_expr)
    code += "(assert (= {} {}))\n".format(combination_z3_code, ref_name)
    code += "(check-sat)\n"
    return code

def generate_z3_code_for_equivalence(sym_expr_code_a, sym_expr_code_b):
    def_a, def_b = generate_definitions(sym_expr_code_a, sym_expr_code_b)
    var_name_a, sym_expr_a, var_dec_a = def_a
    var_name_b, sym_expr_b, var_dec_b = def_b
    code = "(set-logic QF_AUFBV )\n"
    code += generate_source_declarations(sym_expr_code_a, sym_expr_code_b)
    code += var_dec_a + "\n"
    code += var_dec_b + "\n"
    code += sym_expr_a + "\n"
    code += sym_expr_b + "\n"
    code += "(assert (not (= " + var_name_a + " " + var_name_b + ")))\n"
    code += "(check-sat)\n"
    return code



def generate_z3_code_for_offset(sym_expr_code_a, sym_expr_code_b):
    def_a, def_b = generate_definitions(sym_expr_code_a, sym_expr_code_b)
    var_name_a, sym_expr_a, var_dec_a = def_a
    var_name_b, sym_expr_b, var_dec_b = def_b

    code = "(set-logic QF_AUFBV )\n"
    code += generate_source_declarations(sym_expr_code_a, sym_expr_code_b)
    code += var_dec_a + "\n"
    code += var_dec_b + "\n"
    bit_size_a = int(var_name_a.split("_")[-1])
    bit_size_b = int(var_name_b.split("_")[-1])
    bit_size = bit_size_a
    if bit_size_a < bit_size_b:
        bit_size = bit_size_b
    zero = "x0"
    one = "x1"
    if int(bit_size) > 4:
        count_zeros = int(int(bit_size) / 4)
        zero = "x" + "0" * count_zeros
        one = "x" + "0" * (count_zeros-1) + "1"
    code += "(declare-fun constant_offset() (_ BitVec {}))\n".format(bit_size)
    code += sym_expr_a + "\n"
    code += sym_expr_b + "\n"
    code += "(assert (= " + var_name_a + " (bvadd " + var_name_b + " constant_offset)))\n"
    code += "(assert  (not (= " + var_name_a + " #" + zero + ")))\n"
    code += "(assert  (not (= " + var_name_b + " #" + zero + ")))\n"
    code += "(assert  (not (= constant_offset #" + zero + ")))\n"
    code += "(check-sat)\n"
    return code, bit_size

def generate_z3_code_for_factor(sym_expr_code_a, sym_expr_code_b):
    def_a, def_b = generate_definitions(sym_expr_code_a, sym_expr_code_b)
    var_name_a, sym_expr_a, var_dec_a = def_a
    var_name_b, sym_expr_b, var_dec_b = def_b

    code = "(set-logic QF_AUFBV )\n"
    code += generate_source_declarations(sym_expr_code_a, sym_expr_code_b)
    code += var_dec_a + "\n"
    code += var_dec_b + "\n"
    bit_size_a = int(var_name_a.split("_")[-1])
    bit_size_b = int(var_name_b.split("_")[-1])
    bit_size = bit_size_a
    if bit_size_a < bit_size_b:
        bit_size = bit_size_b
    zero = "x0"
    one = "x1"
    if int(bit_size) > 4:
        count_zeros = int(int(bit_size) / 4)
        zero = "x" + "0" * count_zeros
        one = "x" + "0" * (count_zeros - 1) + "1"
    code += "(declare-fun constant_offset() (_ BitVec {}))\n".format(bit_size)
    code += sym_expr_a + "\n"
    code += sym_expr_b + "\n"
    code += "(assert (= " + var_name_a + " (bvmul " + var_name_b + " constant_offset)))\n"
    code += "(assert  (not (= " + var_name_a + " #" + zero + ")))\n"
    code += "(assert  (not (= " + var_name_b + " #" + zero + ")))\n"
    code += "(assert  (bvsgt constant_offset #" + one + "))\n"
    code += "(check-sat)\n"
    return code, bit_size

def generate_offset_to_line(src_file_path):
    offset_to_line = dict()
    line = 1
    with open(src_file_path, "r") as src_file:
        contents = src_file.read()
        offset = 0
        for offset, char in enumerate(contents):
            # note that we map each line to the newline character that begins the line
            # this allows us to simply add a one-indexed column number to find an offset
            # FIXME does this need to be more robust?
            if char == "\n":
                line += 1
            offset_to_line[offset] = line
        offset_to_line[offset+1] = line
    return offset_to_line

