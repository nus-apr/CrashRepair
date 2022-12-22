from app import definitions, values, emitter, logger, utilities
from pysmt.smtlib.parser import SmtLibParser
from six.moves import cStringIO
from pysmt.typing import BV32, BV8, ArrayType, BV64, BV16, BV8
from pysmt.shortcuts import write_smtlib, get_model, Symbol, is_unsat, reset_env
import ctypes


def get_offset(z3_code, bit_size):
    z3_code += "(get-model)\n"
    reset_env()
    parser = SmtLibParser()
    offset = None
    try:
        script = parser.get_script(cStringIO(z3_code))
        formula = script.get_last_formula()
        model = get_model(formula, solver_name="z3")
        var_name = "constant_offset"
        if bit_size == 64:
            sym_def = Symbol(var_name, BV64)
        elif bit_size == 32:
            sym_def = Symbol(var_name, BV32)
        elif bit_size == 16:
            sym_def = Symbol(var_name, BV16)
        elif bit_size == 8:
            sym_def = Symbol(var_name, BV8)
        else:
            utilities.error_exit("Unhandled exception in offset solver")
        if sym_def in model:
            x = model[sym_def].simplify()
            offset = int(str(x).split("_")[0])
    except Exception as ex:
        logger.exception(ex, z3_code)

    if offset:
        hex_string = "0x" + "F"*int(bit_size/4)
        number = offset & int(hex_string, 16)
        offset = ctypes.c_long(number).value
    return offset

