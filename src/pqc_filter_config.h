// src/pqc_filter_config.h
#pragma once

#include <string>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

class PqcFilterConfig {
public:
  PqcFilterConfig(const std::string& algorithm_name,
                  const std::string& kem_algorithm = "Kyber768",
                  const std::string& sig_algorithm = "ML-DSA-65");

  const std::string& getAlgorithmName() const { return algorithm_name_; }
  const std::string& getKemAlgorithm() const { return kem_algorithm_; }
  const std::string& getSigAlgorithm() const { return sig_algorithm_; }

private:
  std::string algorithm_name_;
  std::string kem_algorithm_;
  std::string sig_algorithm_;
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy