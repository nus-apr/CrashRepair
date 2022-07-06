#pragma once

#include <fstream>

#include <nlohmann/json.hpp>

#include "FixLocation.h"

namespace crashrepairfix {

class FixLocalization {
private:
  std::vector<FixLocation> locations;

  void add(FixLocation const &location) {
    locations.push_back(std::move(location));
  }

public:
  static FixLocalization load(std::string const &filename) {
    std::ifstream input(filename);
    nlohmann::json j;
    input >> j;
    return fromJSON(j);
  }

  static FixLocalization fromJSON(nlohmann::json j) {
    FixLocalization localization;
    for (auto &entry : j) {
      localization.add(FixLocation::fromJSON(entry));
    }
    return localization;
  }

  std::vector<FixLocation>::iterator begin() {
    return locations.begin();
  }

  std::vector<FixLocation>::iterator end() {
    return locations.end();
  }

  std::vector<FixLocation>::const_iterator cbegin() const {
    return locations.cbegin();
  }

  std::vector<FixLocation>::const_iterator cend() const {
    return locations.cend();
  }

  size_t size() const {
    return locations.size();
  }
};

}
