// src/pqc_filter_config.cc

#include "pqc_filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

PqcFilterConfig::PqcFilterConfig(const std::string& algorithm_name,
                                 const std::string& kem_algorithm,
                                 const std::string& sig_algorithm)
    : algorithm_name_(algorithm_name),
      kem_algorithm_(kem_algorithm),
      sig_algorithm_(sig_algorithm) {}

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy