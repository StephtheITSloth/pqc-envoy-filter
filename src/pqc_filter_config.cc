// src/pqc_filter_config.cc

#include "pqc_filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

PqcFilterConfig::PqcFilterConfig(const std::string& algorithm_name,
                                 const std::string& kem_algorithm,
                                 const std::string& sig_algorithm,
                                 DegradationPolicy degradation_policy,
                                 CircuitBreakerConfig circuit_breaker_config,
                                 RateLimitConfig rate_limit_config,
                                 bool log_crypto_errors)
    : algorithm_name_(algorithm_name),
      kem_algorithm_(kem_algorithm),
      sig_algorithm_(sig_algorithm),
      degradation_policy_(degradation_policy),
      circuit_breaker_config_(circuit_breaker_config),
      rate_limit_config_(rate_limit_config),
      log_crypto_errors_(log_crypto_errors) {}

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy