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
#include <crashrepairfix/FixLocationLinter.h>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;

using namespace crashrepairfix;

static llvm::cl::OptionCategory CrashRepairFixOptions("crashrepairlint options");
static llvm::cl::extrahelp CommonHelp(clang::tooling::CommonOptionsParser::HelpMessage);

static llvm::cl::opt<std::string> outputFilename(
  "output-to",
  llvm::cl::desc("The name of file to which the linter report should be written."),
  llvm::cl::value_desc("filename"),
  llvm::cl::init("crashrepair-linter-summary.json")
);

static llvm::cl::opt<std::string> localizationFilename(
  "localization-filename",
  llvm::cl::desc("The name of file from which the fix localization should be read."),
  llvm::cl::value_desc("filename"),
  llvm::cl::Required
);


class LintLocationsConsumer : public clang::ASTConsumer {
public:
  explicit LintLocationsConsumer(FixLocationLinter &linter) : linter(linter) {}

  virtual void HandleTranslationUnit(clang::ASTContext &context) {
    linter.validate(context);
  }

private:
  FixLocationLinter &linter;
};

class LintLocationsAction : public clang::ASTFrontendAction {
public:
  LintLocationsAction(FixLocationLinter &linter)
    : clang::ASTFrontendAction(),
      linter(linter)
  {}

  virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
    clang::CompilerInstance &compiler,
    llvm::StringRef file
  ) {
    return std::make_unique<LintLocationsConsumer>(linter);
  }

private:
  FixLocationLinter &linter;
};

class LintLocationsActionFactory : public clang::tooling::FrontendActionFactory {
public:
  LintLocationsActionFactory(FixLocationLinter &linter)
    : clang::tooling::FrontendActionFactory(),
      linter(linter)
  {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<LintLocationsAction>(linter);
  }

private:
  FixLocationLinter &linter;
};


int main(int argc, const char **argv) {
  spdlog::set_level(spdlog::level::debug);

  // TODO automatically inject correct include path for clang-packaged stdlib headers
  // https://stackoverflow.com/questions/51695806/clang-tool-include-path
  // https://stackoverflow.com/questions/19642590/libtooling-cant-find-stddef-h-nor-other-headers
  // https://clang.llvm.org/docs/LibTooling.html
  CommonOptionsParser optionsParser(argc, argv, CrashRepairFixOptions);

  // TODO obtain source paths from the fix localization?
  FixLocalization fixLocalization = FixLocalization::load(localizationFilename);
  ClangTool tool(optionsParser.getCompilations(), optionsParser.getSourcePathList());
  // tool.setDiagnosticConsumer(new clang::IgnoringDiagConsumer());

  FixLocationLinter linter(fixLocalization, outputFilename);
  auto actionFactory = std::make_unique<LintLocationsActionFactory>(linter);
  auto retcode = tool.run(actionFactory.get());
  linter.save();

  return retcode;
}
