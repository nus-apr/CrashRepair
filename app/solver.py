from app import definitions, values, emitter, extractor, utilities
from pysmt.smtlib.parser import SmtLibParser
from six.moves import cStringIO
from pysmt.typing import BV32, BV8, ArrayType, BV64
from pysmt.shortcuts import write_smtlib, get_model, Symbol, is_unsat, reset_env


def get_offset(z3_code):
    z3_code += "(get-model)\n"
    reset_env()
    parser = SmtLibParser()
    offset = None
    try:
        script = parser.get_script(cStringIO(z3_code))
        formula = script.get_last_formula()
        model = get_model(formula, solver_name="z3")
        var_name = "constant_offset"
        if "_64" in z3_code:
            sym_def = Symbol(var_name, BV64)
        else:
            sym_def = Symbol(var_name, BV32)
        if sym_def in model:
            x = model[sym_def].simplify()
            offset = int(str(x).split("_")[0])
    except Exception as ex:
        print(ex)
        emitter.warning("\t\t[warning] Z3 Exception")
    return offset

