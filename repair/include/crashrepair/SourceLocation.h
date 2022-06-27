#pragma once

#include <string>

namespace crashrepair {

class SourceLocation {
public:
  std::string file;
  size_t line;
  size_t column;

  SourceLocation(
    std::string const &file,
    size_t line,
    size_t column
  ) : file(file), line(line), column(column) {}
};

}
