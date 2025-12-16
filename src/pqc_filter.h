#pragma once

#include <oqs/oqs.h>

#include "envoy/http/filter.h"
#include "source/common/common/logger.h"
#include "src/pqc_crypto_utils.h"
#include "src/pqc_filter_config.h"

// OpenSSL includes for AES-256-GCM and HKDF
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

// C++ standard library for session management and error tracking
#include <chrono>
#include <map>
#include <unordered_map>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

/**
 * The actual HTTP filter that processes requests AND responses.
 * Implements both StreamDecoderFilter (requests) and StreamEncoderFilter (responses)
 * for full bidirectional PQC key exchange via HTTP headers.
 */
class PqcFilter : public Http::StreamFilter,
                  public Logger::Loggable<Logger::Id::filter> {
public:
  explicit PqcFilter(std::shared_ptr<PqcFilterConfig> config);

  // Http::StreamDecoderFilter (Request processing)
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data,
                                    bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

  // Http::StreamEncoderFilter (Response processing)
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance& data,
                                    bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap& trailers) override;
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override;

  // Public key access methods (for key exchange operations)
  // NOTE: Private keys are intentionally NOT exposed for security reasons

  // Kyber KEM public key access
  const uint8_t* getKyberPublicKey() const { return kyber_public_key_.get(); }
  size_t getKyberPublicKeySize() const {
    return kyber_kem_ ? kyber_kem_->length_public_key : 0;
  }

  // Dilithium signature public key access
  const uint8_t* getDilithiumPublicKey() const { return dilithium_public_key_.get(); }
  size_t getDilithiumPublicKeySize() const {
    return dilithium_sig_ ? dilithium_sig_->length_public_key : 0;
  }

  // X25519 ECDH public key access (for hybrid mode)
  const uint8_t* getX25519PublicKey() const { return x25519_public_key_.get(); }
  size_t getX25519PublicKeySize() const { return 32; }  // X25519 always 32 bytes

  // Status check methods
  bool hasKyberInitialized() const { return kyber_kem_ != nullptr; }
  bool hasDilithiumInitialized() const { return dilithium_sig_ != nullptr; }
  bool hasX25519Initialized() const { return x25519_public_key_ != nullptr; }

  // Shared secret access (established after server decapsulation)
  const uint8_t* getSharedSecret() const;
  size_t getSharedSecretSize() const;

  // Session management
  const std::string& getSessionId() const { return session_id_; }

  // Key rotation management
  /**
   * Manually rotate the Kyber keypair to a new version.
   * This implements Phase 1 of key rotation (manual trigger).
   *
   * The rotation process:
   * 1. Move current key to previous_key_ (for grace period support)
   * 2. Generate new keypair with incremented version number
   * 3. Update legacy pointers for backward compatibility
   * 4. Update current_key_ to new keypair
   *
   * During the grace period, both current and previous keys are available
   * for decapsulation, allowing old sessions to continue working.
   *
   * @return true if rotation succeeded, false otherwise
   */
  bool rotateKyberKeypair();

  /**
   * Get the current key version number.
   * @return Current key version (1, 2, 3, ...)
   */
  uint32_t getCurrentKeyVersion() const;

  /**
   * Enable automatic time-based key rotation (Phase 2).
   *
   * When enabled, keys will automatically rotate after the specified interval.
   * This uses a background timer mechanism to trigger rotations without manual intervention.
   *
   * @param rotation_interval Time between automatic rotations (default: 24 hours)
   */
  void enableAutomaticKeyRotation(std::chrono::milliseconds rotation_interval = std::chrono::hours(24));

  /**
   * Disable automatic time-based key rotation.
   */
  void disableAutomaticKeyRotation();

  /**
   * Timer callback for automatic key rotation.
   * This is called by the Envoy dispatcher when the rotation timer expires.
   */
  void onRotationTimerEvent();

  /**
   * Get the total number of key rotations that have occurred.
   * @return Rotation count metric
   */
  uint64_t getRotationCount() const { return rotation_count_; }

  /**
   * Get the timestamp of the last key rotation.
   * @return Last rotation time
   */
  std::chrono::system_clock::time_point getLastRotationTime() const {
    return last_rotation_time_;
  }

  // KEM operations for key exchange

  /**
   * Simulate client-side KEM encapsulation.
   *
   * This method performs the client's role in the key exchange:
   * 1. Takes the server's public key
   * 2. Generates a random shared secret
   * 3. Encapsulates the secret using the public key, producing ciphertext
   *
   * @param server_public_key The server's public key (from getKyberPublicKey())
   * @param server_public_key_len Length of the public key
   * @param out_ciphertext Output buffer for ciphertext (must be pre-allocated)
   * @param out_shared_secret Output buffer for shared secret (must be pre-allocated)
   * @return true if encapsulation succeeded, false otherwise
   */
  bool clientEncapsulate(const uint8_t* server_public_key,
                         size_t server_public_key_len,
                         uint8_t* out_ciphertext,
                         uint8_t* out_shared_secret) const;

  /**
   * Server-side KEM decapsulation.
   *
   * This method performs the server's role in the key exchange:
   * 1. Takes the ciphertext from the client
   * 2. Uses the server's secret key to decrypt it
   * 3. Recovers the same shared secret the client generated
   *
   * @param ciphertext The ciphertext from the client (1088 bytes for Kyber768)
   * @param ciphertext_len Length of the ciphertext
   * @param out_shared_secret Output buffer for shared secret (must be pre-allocated, 32 bytes)
   * @return true if decapsulation succeeded, false otherwise
   */
  bool serverDecapsulate(const uint8_t* ciphertext,
                         size_t ciphertext_len,
                         uint8_t* out_shared_secret) const;

  /**
   * AES-256-GCM Encryption (Client-side operation)
   *
   * Encrypts plaintext using the shared secret derived from Kyber768 key exchange.
   * Uses AES-256-GCM (Galois/Counter Mode) for authenticated encryption.
   *
   * @param plaintext The data to encrypt
   * @param plaintext_len Length of plaintext in bytes
   * @param key The 32-byte encryption key (shared secret from Kyber768)
   * @param iv The 12-byte initialization vector (must be unique per encryption)
   * @param ciphertext Output vector for encrypted data
   * @param auth_tag Output buffer for 16-byte authentication tag
   * @return true if encryption succeeded, false otherwise
   */
  bool encryptAES256GCM(const uint8_t* plaintext,
                        size_t plaintext_len,
                        const uint8_t* key,
                        uint8_t* iv,
                        std::vector<uint8_t>& ciphertext,
                        uint8_t* auth_tag) const;

  /**
   * AES-256-GCM Decryption (Server-side operation)
   *
   * Decrypts ciphertext using the shared secret derived from Kyber768 key exchange.
   * Verifies the authentication tag to detect tampering.
   *
   * @param ciphertext The encrypted data
   * @param ciphertext_len Length of ciphertext in bytes
   * @param key The 32-byte decryption key (shared secret from Kyber768)
   * @param iv The 12-byte initialization vector (from encryption)
   * @param auth_tag The 16-byte authentication tag (from encryption)
   * @param plaintext Output vector for decrypted data
   * @return true if decryption succeeded and tag verified, false otherwise
   */
  bool decryptAES256GCM(const uint8_t* ciphertext,
                        size_t ciphertext_len,
                        const uint8_t* key,
                        const uint8_t* iv,
                        const uint8_t* auth_tag,
                        std::vector<uint8_t>& plaintext) const;

  // Hybrid mode (Kyber768 + X25519) operations

  /**
   * Client-side X25519 key exchange (for hybrid mode).
   *
   * Performs X25519 ECDH key exchange:
   * 1. Generates client's X25519 keypair
   * 2. Performs DH with server's X25519 public key
   * 3. Computes shared secret
   *
   * @param server_x25519_public_key Server's X25519 public key (32 bytes)
   * @param server_public_key_len Length (must be 32)
   * @param out_client_public_key Output: client's X25519 public key (32 bytes)
   * @param out_shared_secret Output: X25519 shared secret (32 bytes)
   * @return true if exchange succeeded, false otherwise
   */
  bool clientX25519Exchange(const uint8_t* server_x25519_public_key,
                            size_t server_public_key_len,
                            uint8_t* out_client_public_key,
                            uint8_t* out_shared_secret) const;

  /**
   * Server-side X25519 key exchange (for hybrid mode).
   *
   * Performs server-side X25519 ECDH using server's private key:
   * 1. Takes client's X25519 public key
   * 2. Uses server's X25519 private key (from initializeX25519())
   * 3. Computes shared secret via DH
   *
   * @param client_x25519_public_key Client's X25519 public key (32 bytes)
   * @param client_public_key_len Length (must be 32)
   * @param out_shared_secret Output: X25519 shared secret (32 bytes)
   * @return true if exchange succeeded, false otherwise
   */
  bool serverX25519Exchange(const uint8_t* client_x25519_public_key,
                            size_t client_public_key_len,
                            uint8_t* out_shared_secret) const;

  /**
   * Combine Kyber768 and X25519 secrets for hybrid mode.
   *
   * Uses HKDF-SHA256 to combine:
   * final_secret = HKDF-Extract-And-Expand(kyber_secret || x25519_secret)
   *
   * @param kyber_secret Kyber768 shared secret (32 bytes)
   * @param kyber_len Length of Kyber secret
   * @param x25519_secret X25519 shared secret (32 bytes)
   * @param x25519_len Length of X25519 secret
   * @param out_combined_secret Output: combined secret (32 bytes)
   * @return true if combination succeeded, false otherwise
   */
  bool combineHybridSecrets(const uint8_t* kyber_secret, size_t kyber_len,
                            const uint8_t* x25519_secret, size_t x25519_len,
                            uint8_t* out_combined_secret) const;

  // ============================================================================
  // ERROR HANDLING & GRACEFUL DEGRADATION
  // ============================================================================

  /**
   * Generic error codes for X-PQC-Error-Code header.
   * These codes are intentionally vague to prevent oracle attacks.
   * SECURITY: All crypto failures MUST return CRYPTO_OPERATION_FAILED.
   */
  enum class PqcErrorCode {
    SUCCESS = 0,                    // No error
    INVALID_REQUEST = 1000,         // Generic request validation failure (missing headers, bad format)
    CRYPTO_OPERATION_FAILED = 2000, // Generic cryptographic operation failure (ALL crypto errors)
    RATE_LIMIT_EXCEEDED = 3000,     // Too many errors from this client IP
    SERVICE_UNAVAILABLE = 4000,     // Circuit breaker open or system overloaded
    INTERNAL_ERROR = 5000           // Generic internal error
  };

  /**
   * Circuit breaker state for per-client error tracking.
   */
  enum class CircuitState {
    CLOSED,      // Normal operation - requests allowed
    OPEN,        // Too many failures - rejecting all requests
    HALF_OPEN    // Testing recovery - allowing limited requests
  };

  /**
   * Extract client IP address from request headers.
   * Checks X-Forwarded-For, X-Real-IP, and falls back to peer address.
   *
   * @param headers Request headers
   * @return Client IP address (e.g., "192.168.1.100")
   */
  std::string getClientIp(const Http::RequestHeaderMap& headers) const;

  /**
   * Record error for circuit breaker and rate limiting.
   * SECURITY: This method enforces both circuit breaker and rate limiting.
   *
   * @param client_ip Client IP address
   * @return true if request should be allowed, false if blocked by circuit breaker or rate limit
   */
  bool recordError(const std::string& client_ip);

  /**
   * Check if circuit breaker is open for a client IP.
   *
   * @param client_ip Client IP address
   * @return true if circuit breaker is open (requests should be rejected)
   */
  bool isCircuitBreakerOpen(const std::string& client_ip) const;

  /**
   * Record successful operation (for circuit breaker recovery).
   *
   * @param client_ip Client IP address
   */
  void recordSuccess(const std::string& client_ip);

  /**
   * Clean up old error states to prevent memory exhaustion.
   * Should be called periodically (e.g., every 10 minutes).
   */
  void cleanupOldErrorStates();

  /**
   * Convert error code to string for header value.
   *
   * @param error_code Error code enum
   * @return String representation (e.g., "2000")
   */
  static std::string errorCodeToString(PqcErrorCode error_code);

  /**
   * Handle PQC error securely - send error response without leaking information.
   * SECURITY: All crypto errors use CRYPTO_OPERATION_FAILED to prevent oracle attacks.
   *
   * @param error_code Generic error code
   * @param client_ip Client IP address (for logging context only)
   * @return FilterHeadersStatus::Continue (degradation policy dependent)
   */
  Http::FilterHeadersStatus handlePqcError(PqcErrorCode error_code,
                                            const std::string& client_ip);

private:
  std::shared_ptr<PqcFilterConfig> config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{nullptr};

  // ============================================================================
  // ERROR HANDLING STATE
  // ============================================================================

  /**
   * Per-client error tracking for circuit breaker and rate limiting.
   * SECURITY: Memory bounded - cleanup removes old entries.
   */
  struct ClientErrorState {
    uint32_t error_count = 0;                                         // Total errors in current window
    std::chrono::system_clock::time_point last_error;                 // Timestamp of last error
    std::chrono::system_clock::time_point window_start;               // Start of current rate limit window
    CircuitState circuit_state = CircuitState::CLOSED;                // Current circuit breaker state
    std::chrono::system_clock::time_point circuit_opened_at;          // When circuit was opened
    uint32_t success_count = 0;                                       // Successes in HALF_OPEN state
  };

  mutable std::unordered_map<std::string, ClientErrorState> client_errors_;  // IP -> error state
  mutable std::chrono::system_clock::time_point last_cleanup_;                // Last cleanup time

  // HTTP header key exchange state
  bool client_requested_pqc_{false};  // Track if client sent X-PQC-Init header
  bool client_requested_hybrid_mode_{false};  // Track if client requested hybrid mode (Kyber768 + X25519)

  // Session management
  struct SessionData {
    std::string session_id;
    std::chrono::system_clock::time_point created_at;
    SecureBuffer shared_secret;      // Raw Kyber768 shared secret (32 bytes)
    SecureBuffer session_key;        // Derived session key (32 bytes) = KDF(shared_secret || session_id || timestamp)
    bool has_shared_secret{false};

    SessionData()
      : created_at(std::chrono::system_clock::now()),
        shared_secret(32),  // Kyber768 produces 32-byte secrets
        session_key(32),    // Derived session key for encryption
        has_shared_secret(false) {}
  };

  std::string session_id_;  // Current session identifier (UUID-style)
  std::map<std::string, SessionData> sessions_;  // Active sessions storage
  std::chrono::minutes session_timeout_{5};  // Default 5-minute timeout

  // Helper: Generate cryptographically secure session ID
  std::string generateSessionId();

  // Helper: Validate session exists and is not expired
  bool validateSession(const std::string& session_id);

  // Helper: Derive session-specific key from shared secret + session metadata
  // Uses HKDF-SHA256 to bind key to session (prevents replay attacks)
  bool deriveSessionKey(const uint8_t* shared_secret,
                        size_t shared_secret_len,
                        const std::string& session_id,
                        const std::chrono::system_clock::time_point& timestamp,
                        uint8_t* out_session_key);

  // Kyber-768 KEM instance (manages the algorithm)
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kyber_kem_;

  // Key versioning structure for rotation support
  struct KeyVersion {
    uint32_t version;
    SecureBuffer public_key;
    SecureBuffer secret_key;
    std::chrono::system_clock::time_point created_at;
  };

  // Current and previous key versions (for graceful rotation)
  std::unique_ptr<KeyVersion> current_key_;
  std::unique_ptr<KeyVersion> previous_key_;
  uint32_t next_key_version_{1};  // Next version number to assign

  // Legacy direct access (points to current_key_ for backward compatibility)
  SecureBuffer kyber_public_key_;
  SecureBuffer kyber_secret_key_;

  // Shared secret storage (32 bytes for Kyber768)
  // This is populated when server receives ciphertext from client
  SecureBuffer shared_secret_;
  bool has_shared_secret_{false};  // Track if shared secret has been established

  // Dilithium3 (ML-DSA-65) signature instance
  std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> dilithium_sig_;

  // Dilithium3 keys (securely managed)
  SecureBuffer dilithium_public_key_;
  SecureBuffer dilithium_secret_key_;

  // X25519 ECDH keypair (for hybrid mode)
  SecureBuffer x25519_public_key_;
  SecureBuffer x25519_secret_key_;

  // Automatic key rotation state (Phase 2)
  bool automatic_rotation_enabled_{false};
  std::chrono::milliseconds rotation_interval_{std::chrono::hours(24)};  // Default: 24 hours
  uint64_t rotation_count_{0};  // Metric: total number of rotations
  std::chrono::system_clock::time_point last_rotation_time_;  // Metric: last rotation timestamp

  // Initialization functions
  void initializeKyber();
  void initializeDilithium();
  void initializeX25519();
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy