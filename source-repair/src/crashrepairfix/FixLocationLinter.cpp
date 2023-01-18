#include <crashrepairfix/FixLocationLinter.h>

#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>
#include <crashrepairfix/Expr/ClangToExprConverter.h>
#include <crashrepairfix/Expr/ExprGenerator.h>
#include <crashrepairfix/Expr/Mutation/Mutations.h>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

using json = nlohmann::json;

namespace crashrepairfix {

void FixLocationLinter::validate(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto stmtLocation = location->getLocation();
    auto *stmt = StmtFinder::find(context, stmtLocation);
    if (stmt == nullptr) {
      spdlog::warn("bad fix location [{}]: unable to find statement", stmtLocation.toString());
      badLocations.push_back(location.get());
    }

    AstLinkedFixLocation linkedLocation = AstLinkedFixLocation::create(*location, stmt, context);
    if (!linkedLocation.validate()) {
      spdlog::error(
        "bad fix location [{}]: illegal constraint at given location [{}]",
        stmtLocation.toString(),
        location->getConstraint()->toString()
      );
      badLocations.push_back(location.get());
    }
  }
}

bool FixLocationLinter::hasFoundErrors() const {
  return !badLocations.empty();
}

void FixLocationLinter::save() const {
  spdlog::info("writing linter report to disk");
  json j = json::array();
  for (auto &location : badLocations) {
    j.push_back(location->toJson());
  }

  std::ofstream o(saveToFilename);
  o << std::setw(2) << j << std::endl;
  spdlog::info("wrote linter report to disk");
}

}
