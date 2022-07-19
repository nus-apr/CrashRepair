#include <string>

#include "Exprs.h"

namespace crashrepairfix {

std::unique_ptr<Expr> parse(std::string const &code);

}
