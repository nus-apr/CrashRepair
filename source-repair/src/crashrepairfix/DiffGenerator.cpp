#include <crashrepairfix/DiffGenerator.h>

#include <dtl/dtl.hpp>
#include <spdlog/fmt/fmt.h>

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
  std::string mutatedContents = apply(originalContents, replacements);

  std::vector<std::string> originalLines = getLines(originalContents);
  std::vector<std::string> mutatedLines = getLines(mutatedContents);

  std::stringstream buffer;
  dtl::Diff<std::string> diff(originalLines, mutatedLines);
  diff.compose();
  diff.composeUnifiedHunks();
  diff.printUnifiedFormat(buffer);

  return buffer.str();
}

std::string DiffGenerator::apply(std::string const &original, std::vector<Replacement> const &replacements) {
  // TODO we currently assume all replacements are in the correct order
  // apply each replacement in order (work from end of file to beginning)
  std::string mutated = original;

  for (auto const &replacement : replacements) {
    mutated = fmt::format(
      "{}{}{}",
      mutated.substr(0, replacement.getOffset()),
      replacement.getText(),
      mutated.substr(replacement.getOffset() + replacement.getLength())
    );
  }

  return mutated;
}

}
