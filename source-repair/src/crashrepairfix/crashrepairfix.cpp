#include <iostream>

#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/Tooling.h>
#include <clang/Tooling/CommonOptionsParser.h>

#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Rewrite/Core/Rewriter.h>

#include <crashrepairfix/FixLocalization.h>

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

int main(int argc, const char **argv) {
  CommonOptionsParser optionsParser(argc, argv, CrashRepairFixOptions);

  FixLocalization location = FixLocalization::load(localizationFilename);

  // TODO find corresponding Clang locations

  // TODO obtain source paths from the fix localization?

  ClangTool tool(optionsParser.getCompilations(), optionsParser.getSourcePathList());
  tool.setDiagnosticConsumer(new clang::IgnoringDiagConsumer());

  // TODO run an action
  // tool.run();

  return 0;
}
