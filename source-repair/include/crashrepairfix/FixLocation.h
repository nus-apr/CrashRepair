#pragma once

#include <nlohmann/json.hpp>

#include "SourceLocation.h"

namespace crashrepairfix {

class FixLocation {
private:
  SourceLocation sourceLocation;

public:
  FixLocation(
    SourceLocation &sourceLocation
  ) : sourceLocation(sourceLocation) {}

  static FixLocation fromJSON(nlohmann::json j) {
    SourceLocation location = SourceLocation::fromString(j["location"]);
    return FixLocation(location);
  }

  SourceLocation const & getLocation() const {
    return sourceLocation;
  }
};

}
