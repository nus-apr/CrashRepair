#include <crashrepairfix/ProgramMutator.h>
#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>

#include <spdlog/spdlog.h>

using json = nlohmann::json;

namespace crashrepairfix {

void ProgramMutator::mutate(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto *stmt = StmtFinder::find(context, location.getLocation());
    if (stmt == nullptr) {
      continue;
    }

    spdlog::info("found matching statement: {}", getSource(stmt, context));
    mutate(stmt, context);
  }
}

void ProgramMutator::mutate(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("mutating statement [{}]: {}", stmt->getStmtClassName(), getSource(stmt, context));

  // is this an if statement?
  // is this an assignment?
  // while loop? for loop?
}

void ProgramMutator::save() {
  // FIXME allow this to be customized
  std::string filename = "mutations.json";

  json j = json::array();
  for (auto &mutation : mutations) {
    j.push_back(mutation.toJson());
  }

  std::ofstream o(filename);
  o << std::setw(2) << j << std::endl;
}

}
