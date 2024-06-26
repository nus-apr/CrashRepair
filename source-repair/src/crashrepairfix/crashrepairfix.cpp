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
#include <crashrepairfix/ProgramMutator.h>

#include <crashrepairfix/Expr/Mutation/Mutations.h>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;

using namespace crashrepairfix;

static llvm::cl::OptionCategory CrashRepairFixOptions("crashrepairfix options");
static llvm::cl::extrahelp CommonHelp(clang::tooling::CommonOptionsParser::HelpMessage);

static llvm::cl::opt<std::string> outputFilename(
  "output-to",
  llvm::cl::desc("The name of file to which the candidate patches should be written."),
  llvm::cl::value_desc("filename"),
  llvm::cl::init("candidates.json")
);

static llvm::cl::opt<std::string> localizationFilename(
  "localization-filename",
  llvm::cl::desc("The name of file from which the fix localization should be read."),
  llvm::cl::value_desc("filename"),
  llvm::cl::Required
);


class GeneratePatchesConsumer : public clang::ASTConsumer {
public:
  explicit GeneratePatchesConsumer(ProgramMutator &mutator) : mutator(mutator) {}

  virtual void HandleTranslationUnit(clang::ASTContext &context) {
    mutator.mutate(context);
  }

private:
  ProgramMutator &mutator;
};

class GeneratePatchesAction : public clang::ASTFrontendAction {
public:
  GeneratePatchesAction(ProgramMutator &mutator)
    : clang::ASTFrontendAction(),
      mutator(mutator)
  {}

  virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
    clang::CompilerInstance &compiler,
    llvm::StringRef file
  ) {
    return std::make_unique<GeneratePatchesConsumer>(mutator);
  }

private:
  ProgramMutator &mutator;
};

class GeneratePatchesActionFactory : public clang::tooling::FrontendActionFactory {
public:
  GeneratePatchesActionFactory(ProgramMutator &mutator)
    : clang::tooling::FrontendActionFactory(),
      mutator(mutator)
  {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<GeneratePatchesAction>(mutator);
  }

private:
  ProgramMutator &mutator;
};


int main(int argc, const char **argv) {
  spdlog::set_level(spdlog::level::debug);

  // TODO automatically inject correct include path for clang-packaged stdlib headers
  // https://stackoverflow.com/questions/51695806/clang-tool-include-path
  // https://stackoverflow.com/questions/19642590/libtooling-cant-find-stddef-h-nor-other-headers
  // https://clang.llvm.org/docs/LibTooling.html
  CommonOptionsParser optionsParser(argc, argv, CrashRepairFixOptions);

  FixLocalization fixLocalization = FixLocalization::load(localizationFilename);
  ProgramMutator mutator(fixLocalization, outputFilename);

  // TODO obtain source paths from the fix localization?

  ClangTool tool(optionsParser.getCompilations(), optionsParser.getSourcePathList());
  // tool.setDiagnosticConsumer(new clang::IgnoringDiagConsumer());

  spdlog::info("generating patches...");
  auto actionFactory = std::make_unique<GeneratePatchesActionFactory>(mutator);
  auto retcode = tool.run(actionFactory.get());

  // save generated mutations to disk
  mutator.save();

  return retcode;
}
