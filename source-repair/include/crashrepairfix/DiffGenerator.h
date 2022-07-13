#pragma once

#include <map>
#include <string>
#include <vector>

#include "Mutation.h"

namespace crashrepairfix {

class DiffGenerator {
public:
  DiffGenerator() : filenameToContents() {}
  ~DiffGenerator(){}

  // Generates a unified diff from a sequence of replacements
  std::string diff(std::vector<Replacement> const &replacements);

private:
  // Stores the contents of source files, indexed by their absolute paths
  std::map<std::string, std::string> filenameToContents;

  // Returns the original contents of a file, given by its absolute path
  std::string const & getOriginalSource(std::string const &filename);

  // Caches the original contents of a file, given by its absolute path
  void cacheFileContents(std::string const &filename);

  // Applies a set of replacements to a given file and returns the mutated contents of that file
  std::string apply(std::string const &original, std::vector<Replacement> const &replacements);

};

}
