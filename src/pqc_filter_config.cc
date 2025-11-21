// src/pqc_filter_config.cc

#include "pqc_filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

PqcFilterConfig::PqcFilterConfig(const std::string& algorithm_name) : algorithm_name_(algorithm_name) {}

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy