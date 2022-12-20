from app import definitions, values, emitter, logger, utilities
from pysmt.smtlib.parser import SmtLibParser
from six.moves import cStringIO
from pysmt.typing import BV32, BV8, ArrayType, BV64, BV16, BV8
from pysmt.shortcuts import write_smtlib, get_model, Symbol, is_unsat, reset_env


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
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        logger.error("Unhandled exception")
        logger.information(z3_code)
        logger.error(message)
    return offset

