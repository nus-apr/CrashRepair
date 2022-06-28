#include "FixPass.h"

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include <nlohmann/json.hpp>

#include <llvm-supermutate/Supermutator.h>
#include <llvm-supermutate/Mutators.h>

#include <crashrepair/SourceLocation.h>
#include <crashrepair/SourceLocationInstructionFilter.h>

using namespace llvm;

static llvm::cl::opt<std::string> localizationFilename(
  "localization-filename",
  llvm::cl::desc("The name of file from which the annotated fix localization should be read."),
  llvm::cl::value_desc("filename"),
  llvm::cl::Required
);

void loadImplicatedSourceLocations(std::string const &filename, std::set<crashrepair::SourceLocation> &locations) {

}

bool crashrepair::FixPass::runOnModule(Module &module) {
  llvmsupermutate::Supermutator supermutator(module);
  auto mutationEngine = supermutator.getMutationEngine();
  auto sourceMapping = supermutator.getSourceMapping();

  // register mutators
  supermutator.addMutator(new llvmsupermutate::LoadMutator(mutationEngine));

  // filter to the set of implicated instructions
  std::set<SourceLocation> implicatedSourceLocations;
  loadImplicatedSourceLocations(localizationFilename, implicatedSourceLocations);
  supermutator.addFilter(
    std::make_unique<SourceLocationInstructionFilter>(sourceMapping, implicatedSourceLocations)
  );

  // build the supermutant
  supermutator.run();

  llvm::outs() << "hello!\n";
  return true;
}

char crashrepair::FixPass::ID = 0;
static RegisterPass<crashrepair::FixPass> X(
  "crashfix", "Fixes a given vulnerability in a LLVM bitcode file", false, true
);

static RegisterStandardPasses Y(
  PassManagerBuilder::EP_OptimizerLast,
  [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
    PM.add(new crashrepair::FixPass());
  }
);
