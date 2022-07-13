#include <crashrepairfix/DiffGenerator.h>

#include <dtl/dtl.hpp>

#include <assert.h>

#include <fstream>

namespace crashrepairfix {

void DiffGenerator::cacheFileContents(std::string const &filename) {
  std::ifstream file(filename);
  std::ostringstream buffer;
  buffer << file.rdbuf();
  filenameToContents[filename] = buffer.str();
}

std::string const & DiffGenerator::getOriginalSource(std::string const &filename) {
  // TODO ensure that filename is an absolute path
  if (filenameToContents.find(filename) == filenameToContents.end()) {
    cacheFileContents(filename);
  }
  return filenameToContents[filename];
}

std::string DiffGenerator::diff(std::vector<Replacement> const &replacements) {
  assert(!replacements.empty());

  std::string filename = replacements[0].getFilename();
  std::string const &originalContents = getOriginalSource(filename);
  std::string mutatedContents = apply(replacements);

  std::vector<std::string> originalLines = getLines(originalContents);
  std::vector<std::string> mutatedLines = getLines(mutatedContents);

  std::stringstream buffer;
  dtl::Diff<std::string> diff(originalLines, mutatedLines);
  diff.compose();
  diff.composeUnifiedHunks();
  diff.printUnifiedFormat(buffer);

  return buffer.str();
}

std::string DiffGenerator::apply(std::vector<Replacement> const &replacements) {
  // TODO for now we assume that the replacements are correctly ordered
  std::string filename = replacements[0].getFilename();
  [[maybe_unused]] std::string const &originalContents = getOriginalSource(filename);

  // TODO implement!
  // return originalContents;
  return "foobar";
}

}
