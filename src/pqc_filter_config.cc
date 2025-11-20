// src/pqc_filter_config.cc

#include "pqc_filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

PqcFilterConfig::PqcFilterConfig() : algorithm_name_("Kyber768") {}

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy