#pragma once

#include <set>

#include <llvm-supermutate/InstructionFilter.h>
#include <llvm-supermutate/Mapping/LLVMToSourceMapping.h>

#include "SourceLocation.h"

namespace crashrepair {

/**
 * This filter ensures that only instructions that correspond to certain source locations are mutated.
 */
class SourceLocationInstructionFilter : public llvmsupermutate::InstructionFilter {
public:
  SourceLocationInstructionFilter(
    llvmsupermutate::LLVMToSourceMapping *sourceMapping,
    std::set<SourceLocation> const &sourceLocations
  ) : sourceMapping(sourceMapping), sourceLocations(sourceLocations) {}
  ~SourceLocationInstructionFilter(){};

  bool isMutable(llvm::Instruction const &instruction) const override {
    auto *info = sourceMapping->get(const_cast<llvm::Instruction*>(&instruction));

    if (info == nullptr) {
      return false;
    }

    auto maybeLineCol = info->getLineCol();
    if (!maybeLineCol.hasValue()) {
      return false;
    }
    size_t line = maybeLineCol.getValue().first;
    size_t column = maybeLineCol.getValue().second;
    std::string const &filename = info->getFilename();

    auto location = SourceLocation(filename, line, column);
    return sourceLocations.find(location) != sourceLocations.end();
  }

private:
  llvmsupermutate::LLVMToSourceMapping *sourceMapping;
  std::set<SourceLocation> const &sourceLocations;
};

}
