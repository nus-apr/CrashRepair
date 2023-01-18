#pragma once

#include <string>

#include <clang/AST/ASTContext.h>

#include "AstLinkedFixLocation.h"
#include "FixLocalization.h"

namespace crashrepairfix {

class FixLocationLinter {
public:
  FixLocationLinter(FixLocalization &fixLocalization, std::string const &saveToFilename)
  : fixLocalization(fixLocalization),
    badLocations(),
    saveToFilename(saveToFilename)
  {}

  void validate(clang::ASTContext &context);

  void save();

  bool hasFoundErrors() const;

private:
  FixLocalization &fixLocalization;
  std::vector<FixLocation const *> badLocations;
  std::string saveToFilename;
};

}

