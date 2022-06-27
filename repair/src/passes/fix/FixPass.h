#pragma once

#include <llvm/Pass.h>
#include <llvm/IR/Module.h>

namespace crashrepair {

struct FixPass : public llvm::ModulePass {
  static char ID;

  FixPass() : ModulePass(ID) {}

  bool runOnModule(llvm::Module &module) override;
};

} // crashrepair
