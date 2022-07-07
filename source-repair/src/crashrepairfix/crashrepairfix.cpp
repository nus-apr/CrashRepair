#include <iostream>

#include <spdlog/spdlog.h>

#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/Tooling.h>
#include <clang/Tooling/CommonOptionsParser.h>

#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Rewrite/Core/Rewriter.h>

#include <crashrepairfix/FixLocalization.h>
#include <crashrepairfix/StmtFinder.h>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;

using namespace crashrepairfix;

static llvm::cl::OptionCategory CrashRepairFixOptions("crashrepairfix options");
static llvm::cl::extrahelp CommonHelp(clang::tooling::CommonOptionsParser::HelpMessage);

static llvm::cl::opt<std::string> localizationFilename(
  "localization-filename",
  llvm::cl::desc("The name of file from which the fix localization should be read."),
  llvm::cl::value_desc("filename"),
  llvm::cl::Required
);


// TODO find corresponding Clang stmt


class GeneratePatchesConsumer : public clang::ASTConsumer {
public:
  explicit GeneratePatchesConsumer(
    ASTContext &context,
    FixLocalization &fixLocalization
  ) : fixLocalization(fixLocalization) {}

  virtual void HandleTranslationUnit(clang::ASTContext &context) {
    for (auto &location : fixLocalization) {
      auto *stmt = StmtFinder::find(context, location.getLocation());
      if (stmt == nullptr) {
        continue;
      }

      spdlog::info("found matching statement: {}", getSource(stmt, context));
      llvm::outs() << stmt;
      
      // mutate this statement
      // TODO mutate(stmt, context)
    }
  }

private:
  [[maybe_unused]] FixLocalization &fixLocalization;
};

class GeneratePatchesAction : public clang::ASTFrontendAction {
public:
  GeneratePatchesAction(FixLocalization &fixLocalization)
    : clang::ASTFrontendAction(),
      fixLocalization(fixLocalization)
  {}

  virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
    clang::CompilerInstance &compiler,
    llvm::StringRef file
  ) {
    return std::make_unique<GeneratePatchesConsumer>(compiler.getASTContext(), fixLocalization);
  }

private:
  FixLocalization &fixLocalization;
};

class GeneratePatchesActionFactory : public clang::tooling::FrontendActionFactory {
public:
  GeneratePatchesActionFactory(FixLocalization &fixLocalization)
    : clang::tooling::FrontendActionFactory(),
      fixLocalization(fixLocalization)
  {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<GeneratePatchesAction>(fixLocalization);
  }

private:
  FixLocalization &fixLocalization;
};


int main(int argc, const char **argv) {
  spdlog::set_level(spdlog::level::debug);

  CommonOptionsParser optionsParser(argc, argv, CrashRepairFixOptions);

  FixLocalization fixLocalization = FixLocalization::load(localizationFilename);

  // TODO obtain source paths from the fix localization?

  ClangTool tool(optionsParser.getCompilations(), optionsParser.getSourcePathList());
  tool.setDiagnosticConsumer(new clang::IgnoringDiagConsumer());

  spdlog::info("generating patches...");
  auto actionFactory = std::make_unique<GeneratePatchesActionFactory>(fixLocalization);
  auto retcode = tool.run(actionFactory.get());
  return retcode;
}
