#pragma once

#include <string>

#include <spdlog/fmt/fmt.h>

#include "Utils.h"

namespace crashrepairfix {

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

  bool operator==(const SourceLocation &rhs) const {
    return file == rhs.file && line == rhs.line && column == rhs.column;
  }

  bool operator<(const SourceLocation &rhs) const {
    return file < rhs.file && line < rhs.line && column < rhs.column;
  }

  std::string toString() const {
    return fmt::format("{}:{}:{}", file, line, column);
  }

  static SourceLocation fromString(std::string const &str) {
    auto parts = split(str, ':');
    assert (parts.size() == 3);

    auto file = parts[0];
    auto line = std::stoi(parts[1]);
    auto column = std::stoi(parts[2]);
    return SourceLocation(file, line, column);
  }
};

}
