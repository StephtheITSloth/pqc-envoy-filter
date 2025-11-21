// src/pqc_filter_config.h
#pragma once

#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

class PqcFilterConfig {
public:
  PqcFilterConfig(const std::string& algorithm_name);

  const std::string& getAlgorithmName() const { return algorithm_name_; }

private:
  std::string algorithm_name_;
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy