#pragma once

#include <fstream>

#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

#include "FixLocation.h"

namespace crashrepairfix {

class FixLocalization {
private:
  std::vector<std::unique_ptr<FixLocation>> locations;

  void add(std::unique_ptr<FixLocation> location) {
    locations.push_back(std::move(location));
  }

public:
  static FixLocalization load(std::string const &filename) {
    std::ifstream input(filename);
    nlohmann::json j;
    input >> j;
    return fromJSON(j, filename);
  }

  static FixLocalization fromJSON(nlohmann::json j, std::string const &filename) {
    FixLocalization localization;
    for (auto &entry : j) {
      // skip entries that are marked as "ignore"
      if (entry.contains("ignore") and entry["ignore"]) {
        spdlog::info("skipping fix location marked as \"ignore\"");
        continue;
      }

      auto location = FixLocation::fromJSON(entry, filename);
      if (location == nullptr) {
        continue;
      }

      localization.add(std::move(location));
    }
    return localization;
  }

  void save(std::string const &filename) const {
    spdlog::info("saving fix localization to disk: {}", filename);
    std::ofstream o(filename);
    o << std::setw(2) << toJSON() << std::endl;
    spdlog::info("saved fix localization to disk: {}", filename);
  }

  nlohmann::json toJSON() const {
    auto j = nlohmann::json::array();
    for (auto &location : locations) {
      j.push_back(location->toJSON());
    }
    return j;
  }

  std::vector<std::unique_ptr<FixLocation>>::iterator begin() {
    return locations.begin();
  }

  std::vector<std::unique_ptr<FixLocation>>::iterator end() {
    return locations.end();
  }

  std::vector<std::unique_ptr<FixLocation>>::const_iterator cbegin() const {
    return locations.cbegin();
  }

  std::vector<std::unique_ptr<FixLocation>>::const_iterator cend() const {
    return locations.cend();
  }

  size_t size() const {
    return locations.size();
  }
};

}
