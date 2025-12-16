// src/pqc_filter_config.h
#pragma once

#include <string>
#include <chrono>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

/**
 * Graceful degradation policy configuration.
 * Controls what happens when PQC operations fail.
 */
enum class DegradationPolicy {
  REJECT_ON_FAILURE,    // Default: Fail closed (most secure) - reject requests
  ALLOW_PLAINTEXT,      // Fallback to unencrypted (INSECURE - migration only)
  BEST_EFFORT           // Try PQC, continue on failure without encryption
};

/**
 * Circuit breaker configuration for error handling.
 */
struct CircuitBreakerConfig {
  uint32_t failure_threshold = 5;                         // Failures before opening circuit
  std::chrono::seconds timeout = std::chrono::seconds(60); // Time to keep circuit open
  uint32_t success_threshold = 2;                         // Successes to close circuit
};

/**
 * Rate limiting configuration for error responses.
 */
struct RateLimitConfig {
  uint32_t max_errors_per_minute = 10;  // Per client IP
  bool enabled = true;
};

class PqcFilterConfig {
public:
  PqcFilterConfig(const std::string& algorithm_name,
                  const std::string& kem_algorithm = "Kyber768",
                  const std::string& sig_algorithm = "ML-DSA-65",
                  DegradationPolicy degradation_policy = DegradationPolicy::REJECT_ON_FAILURE,
                  CircuitBreakerConfig circuit_breaker_config = CircuitBreakerConfig{},
                  RateLimitConfig rate_limit_config = RateLimitConfig{},
                  bool log_crypto_errors = false);

  const std::string& getAlgorithmName() const { return algorithm_name_; }
  const std::string& getKemAlgorithm() const { return kem_algorithm_; }
  const std::string& getSigAlgorithm() const { return sig_algorithm_; }

  // Error handling configuration getters
  DegradationPolicy getDegradationPolicy() const { return degradation_policy_; }
  const CircuitBreakerConfig& getCircuitBreakerConfig() const { return circuit_breaker_config_; }
  const RateLimitConfig& getRateLimitConfig() const { return rate_limit_config_; }
  bool shouldLogCryptoErrors() const { return log_crypto_errors_; }

private:
  std::string algorithm_name_;
  std::string kem_algorithm_;
  std::string sig_algorithm_;

  // Error handling configuration
  DegradationPolicy degradation_policy_;
  CircuitBreakerConfig circuit_breaker_config_;
  RateLimitConfig rate_limit_config_;
  bool log_crypto_errors_;  // SECURITY: Default OFF to prevent info leaks in logs
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy