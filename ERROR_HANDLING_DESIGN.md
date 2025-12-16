# Error Handling & Graceful Degradation - Design Document

## 1. Existing Envoy Patterns for Error Handling

### Envoy's Standard Approaches:
- **Direct Response**: Filters can send immediate HTTP responses without reaching backend
- **StopIteration**: Return `Http::FilterHeadersStatus::StopIteration` to halt processing
- **Local Reply**: Use `decoder_callbacks_->sendLocalReply()` for error responses
- **Stats/Metrics**: Envoy uses stats for tracking errors (we'll add PQC-specific counters)
- **Circuit Breakers**: Envoy has built-in circuit breakers at cluster level, we add filter-level

### Our Approach:
```cpp
// Pattern 1: Local Reply (Envoy standard)
decoder_callbacks_->sendLocalReply(
    Http::Code::Unauthorized,           // HTTP status code
    "PQC authentication failed",        // Generic message
    nullptr,                            // No response body modifier
    absl::nullopt,                      // No gRPC status
    "pqc_filter_error"                  // Details for logging
);
return Http::FilterHeadersStatus::StopIteration;

// Pattern 2: Add error headers + continue (for metrics)
response_headers.addCopy(
    Http::LowerCaseString("x-pqc-error-code"),
    std::to_string(static_cast<int>(PqcErrorCode::CRYPTO_OPERATION_FAILED))
);
```

## 2. Configuration Options for Operators

### Config Structure (pqc_filter_config.h):
```cpp
class PqcFilterConfig {
public:
  // Error handling configuration
  enum class DegradationPolicy {
    REJECT_ON_FAILURE,    // Default: Fail closed (most secure)
    ALLOW_PLAINTEXT,      // Fallback to unencrypted (migration only)
    BEST_EFFORT           // Try PQC, continue on failure
  };

  struct CircuitBreakerConfig {
    uint32_t failure_threshold = 5;     // Failures before opening circuit
    std::chrono::seconds timeout = std::chrono::seconds(60);  // Time to keep circuit open
    uint32_t success_threshold = 2;     // Successes to close circuit
  };

  struct RateLimitConfig {
    uint32_t max_errors_per_minute = 10;  // Per client IP
    bool enabled = true;
  };

  // Getters
  Degradation Policy getDegradationPolicy() const { return degradation_policy_; }
  const CircuitBreakerConfig& getCircuitBreakerConfig() const { return circuit_breaker_config_; }
  const RateLimitConfig& getRateLimitConfig() const { return rate_limit_config_; }
  bool shouldLogCryptoErrors() const { return log_crypto_errors_; }  // For debugging

private:
  DegradationPolicy degradation_policy_ = DegradationPolicy::REJECT_ON_FAILURE;
  CircuitBreakerConfig circuit_breaker_config_;
  RateLimitConfig rate_limit_config_;
  bool log_crypto_errors_ = false;  // SECURITY: Default OFF to prevent info leaks in logs
};
```

### Envoy YAML Configuration:
```yaml
http_filters:
- name: pqc_filter
  typed_config:
    "@type": type.googleapis.com/pqc.PqcFilterConfig
    algorithm_name: "Kyber768"
    degradation_policy: "reject_on_failure"  # Options: reject_on_failure | allow_plaintext | best_effort
    circuit_breaker:
      failure_threshold: 5
      timeout_seconds: 60
      success_threshold: 2
    rate_limit:
      enabled: true
      max_errors_per_minute: 10
    log_crypto_errors: false  # Set true only for debugging, NEVER in production
```

## 3. Interaction with Existing Features

### Session Management Interaction:
- **Expired sessions** → `INVALID_REQUEST` (not `CRYPTO_OPERATION_FAILED`)
- **Invalid session ID** → `INVALID_REQUEST`
- **Decapsulation failure** → `CRYPTO_OPERATION_FAILED`

### Key Rotation Interaction:
- **Rotation failure during request** → Rollback rotation, return `SERVICE_UNAVAILABLE`
- **Grace period** → Both keys fail → `CRYPTO_OPERATION_FAILED`

### Hybrid Mode Interaction:
- **Kyber fails** → `CRYPTO_OPERATION_FAILED`
- **X25519 fails** → `CRYPTO_OPERATION_FAILED`
- **HKDF combine fails** → `CRYPTO_OPERATION_FAILED`
- SECURITY: All crypto failures use SAME error code (no oracle)

### Circuit Breaker Interaction:
```
Client IP → Error Count → Circuit State
- 0-4 errors: CLOSED (allow requests)
- 5+ errors: OPEN (reject with SERVICE_UNAVAILABLE)
- After timeout: HALF_OPEN (allow 1 request to test)
- 2 successes in HALF_OPEN: CLOSED
```

## 4. Performance Implications

### Memory Overhead:
```cpp
// Per-client tracking
struct ClientErrorState {
    uint32_t error_count;                              // 4 bytes
    std::chrono::system_clock::time_point last_error;  // 8 bytes
    CircuitState circuit_state;                        // 1 byte (enum)
    // Total: ~16 bytes per IP
};
std::unordered_map<std::string, ClientErrorState> client_errors_;  // ~10KB for 500 IPs
```

**Memory Impact**: ~20 bytes per tracked IP address
- **10 IPs**: 200 bytes
- **1000 IPs**: 20 KB
- **10,000 IPs**: 200 KB (acceptable for high-traffic filters)

### CPU Overhead:
- **Error counting**: O(1) hash map lookup + increment
- **Circuit breaker check**: O(1) hash map lookup + time comparison
- **Rate limit check**: O(1) hash map lookup + sliding window calculation
- **Impact**: <0.1ms per request

### Cleanup Strategy:
```cpp
// Periodic cleanup of old error states (every 10 minutes)
void cleanupOldErrorStates() {
  auto now = std::chrono::system_clock::now();
  auto cleanup_threshold = now - std::chrono::hours(1);  // Remove after 1 hour

  for (auto it = client_errors_.begin(); it != client_errors_.end();) {
    if (it->second.last_error < cleanup_threshold && it->second.circuit_state == CLOSED) {
      it = client_errors_.erase(it);  // Remove old, healthy clients
    } else {
      ++it;
    }
  }
}
```

## 5. Failure Modes to Test

### Test 29: Generic Error Responses (No Oracle Attacks)
**Objective**: Ensure all crypto failures return same error code
```cpp
// Test different failure scenarios
1. Invalid ciphertext length → CRYPTO_OPERATION_FAILED (2000)
2. Decapsulation with wrong key → CRYPTO_OPERATION_FAILED (2000)
3. HKDF failure → CRYPTO_OPERATION_FAILED (2000)
4. X25519 exchange failure → CRYPTO_OPERATION_FAILED (2000)

// Verify: All return same error code, no timing differences
EXPECT_EQ(error_code_1, error_code_2);
EXPECT_EQ(error_code_2, error_code_3);
// Oracle attack prevented: attacker cannot distinguish failures
```

### Test 30: No Secret Leakage in Error Messages
**Objective**: Verify error logs don't expose sensitive data
```cpp
// Trigger error with specific key/ciphertext
auto result = filter->serverDecapsulate(invalid_ciphertext, len, out_secret);
EXPECT_FALSE(result);

// Check error message does NOT contain:
// ❌ Key material (hex dumps)
// ❌ Ciphertext content
// ❌ Session IDs
// ❌ Specific OpenSSL error codes (oracle)

// Allowed in errors:
// ✅ Generic error codes (CRYPTO_OPERATION_FAILED)
// ✅ Generic messages ("Decapsulation failed")
// ✅ Operation type ("KEM decapsulation")
```

### Test 31: Circuit Breaker Triggers After N Failures
**Objective**: Verify circuit breaker protects against repeated attacks
```cpp
std::string attacker_ip = "192.168.1.100";

// Send 5 requests with invalid ciphertext (failure_threshold = 5)
for (int i = 0; i < 5; i++) {
  auto status = filter->decodeHeaders(headers_with_invalid_ciphertext, false);
  EXPECT_EQ(status, Http::FilterHeadersStatus::Continue);  // First 5 fail normally
}

// 6th request triggers circuit breaker
auto status = filter->decodeHeaders(headers_with_invalid_ciphertext, false);
EXPECT_EQ(status, Http::FilterHeadersStatus::StopIteration);  // Circuit OPEN

// Verify response header
EXPECT_EQ(response_headers.get("x-pqc-error-code"), "4000");  // SERVICE_UNAVAILABLE

// After timeout, circuit goes to HALF_OPEN
std::this_thread::sleep_for(std::chrono::seconds(61));  // Wait for timeout

// Next request allowed (HALF_OPEN)
status = filter->decodeHeaders(valid_headers, false);
EXPECT_EQ(status, Http::FilterHeadersStatus::Continue);

// After 2 successes, circuit CLOSES
status = filter->decodeHeaders(valid_headers, false);
EXPECT_EQ(status, Http::FilterHeadersStatus::Continue);
EXPECT_FALSE(filter->isCircuitBreakerOpen(attacker_ip));
```

### Test 32: Graceful Degradation Config Honored
**Objective**: Verify each degradation policy behaves correctly
```cpp
// Test 1: REJECT_ON_FAILURE (default)
config->setDegradationPolicy(DegradationPolicy::REJECT_ON_FAILURE);
auto status = triggerCryptoFailure();
EXPECT_EQ(status, Http::FilterHeadersStatus::StopIteration);  // Request blocked
EXPECT_EQ(response_code, Http::Code::Unauthorized);  // 401 response

// Test 2: ALLOW_PLAINTEXT (insecure fallback)
config->setDegradationPolicy(DegradationPolicy::ALLOW_PLAINTEXT);
status = triggerCryptoFailure();
EXPECT_EQ(status, Http::FilterHeadersStatus::Continue);  // Request continues
// Verify no encryption applied (plaintext to backend)

// Test 3: BEST_EFFORT
config->setDegradationPolicy(DegradationPolicy::BEST_EFFORT);
status = triggerCryptoFailure();
EXPECT_EQ(status, Http::FilterHeadersStatus::Continue);  // Request continues
// Verify error logged but request not blocked
```

### Test 33: Rate Limiting Per Client IP
**Objective**: Prevent DoS via error responses
```cpp
std::string client_ip = "10.0.0.1";

// Send 10 requests in 1 minute (rate limit = 10/min)
for (int i = 0; i < 10; i++) {
  auto status = filter->recordError(client_ip);
  EXPECT_TRUE(status);  // First 10 allowed
}

// 11th request exceeds rate limit
auto status = filter->recordError(client_ip);
EXPECT_FALSE(status);  // Rate limit exceeded

// Verify response
EXPECT_EQ(response_headers.get("x-pqc-error-code"), "3000");  // RATE_LIMIT_EXCEEDED

// After 1 minute, counter resets
std::this_thread::sleep_for(std::chrono::seconds(61));
status = filter->recordError(client_ip);
EXPECT_TRUE(status);  // Allowed again
```

## 6. Security Guarantees

### 1. No Oracle Attacks
- ✅ All crypto failures return same error code (2000)
- ✅ Constant-time error responses (no timing side channels)
- ✅ No error differentiation for invalid key vs invalid ciphertext

### 2. No Information Leakage
- ✅ Error messages NEVER contain:
  - Key material
  - Ciphertext content
  - Session IDs
  - Specific crypto library errors
- ✅ Logs redacted in production (config: `log_crypto_errors: false`)

### 3. DoS Prevention
- ✅ Circuit breaker stops repeated attacks (5 failures → block for 60s)
- ✅ Rate limiting prevents error spam (10 errors/min per IP)
- ✅ Automatic cleanup prevents memory exhaustion

### 4. Fail Secure
- ✅ Default policy: REJECT_ON_FAILURE (fail closed)
- ✅ No automatic fallback to plaintext
- ✅ Operators must explicitly enable insecure modes

## 7. Implementation Checklist

- [x] Design error handling architecture
- [ ] Add error types and codes to header
- [ ] Implement circuit breaker state machine
- [ ] Implement rate limiting with sliding window
- [ ] Implement secure error response methods
- [ ] Add configuration for degradation policies
- [ ] Write Test 29: Generic error responses
- [ ] Write Test 30: No secret leakage
- [ ] Write Test 31: Circuit breaker functionality
- [ ] Write Test 32: Degradation policy enforcement
- [ ] Write Test 33: Rate limiting per IP
- [ ] Add Envoy stats for error tracking
- [ ] Document operational procedures for circuit breaker

## 8. Operational Considerations

### Monitoring Metrics:
```
pqc_filter.errors.invalid_request
pqc_filter.errors.crypto_operation_failed
pqc_filter.errors.rate_limit_exceeded
pqc_filter.errors.service_unavailable
pqc_filter.circuit_breaker.open_count
pqc_filter.circuit_breaker.half_open_count
pqc_filter.degradation.plaintext_fallback_count  // Alert on this!
```

### Alert Rules:
```yaml
- alert: PqcCryptoFailureSpike
  expr: rate(pqc_filter.errors.crypto_operation_failed[5m]) > 10
  annotations:
    summary: "High rate of PQC crypto failures"
    action: "Check if attack in progress or key rotation issue"

- alert: PqcCircuitBreakerOpen
  expr: pqc_filter.circuit_breaker.open_count > 0
  annotations:
    summary: "PQC circuit breaker open for client"
    action: "Investigate repeated failures from specific IP"
```

---

**Status**: Design complete, ready for implementation
**Next**: Implement error handling in pqc_filter.h/cc
