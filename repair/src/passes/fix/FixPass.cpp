#include "FixPass.h"

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include <nlohmann/json.hpp>

#include <crashrepair/SourceLocation.h>

using namespace llvm;

bool crashrepair::FixPass::runOnModule(Module &module) {
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
