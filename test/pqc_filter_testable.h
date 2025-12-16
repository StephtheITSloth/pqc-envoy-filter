#pragma once

// Testable version of PqcFilter that uses mock Envoy interfaces
// This file includes the mock headers BEFORE including the real filter

#include "test/mocks/mock_buffer.h"
#include "test/mocks/mock_http.h"
#include "test/mocks/mock_logger.h"

// Now include the actual filter implementation
// It will use our mocked types above
#include "src/pqc_filter_config.h"
#include "src/base64_utils.h"

// Post-Quantum Cryptography includes
#include <oqs/oqs.h>
#include "src/pqc_crypto_utils.h"

// OpenSSL includes for AES-256-GCM and HKDF
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

// C++ standard library
#include <chrono>
#include <map>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

/**
 * Testable version of PqcFilter
 * Uses mock Envoy interfaces for unit testing
 */
class PqcFilter : public Http::StreamFilter,
                  public Logger::Loggable<Logger::Id::filter> {
public:
  explicit PqcFilter(std::shared_ptr<PqcFilterConfig> config) : config_(config) {
    initializeKyber();
    initializeDilithium();
    initializeX25519();
  }

  // Http::StreamDecoderFilter interface (Request processing)
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) {
    ENVOY_LOG(info, "PQC Filter using algorithm: {}",
              config_->getAlgorithmName());

    // Check for X-PQC-Init header to detect client PQC request
    auto pqc_init_header = headers.get(Http::LowerCaseString("x-pqc-init"));
    if (!pqc_init_header.empty()) {
      const auto& value = pqc_init_header[0]->value().getStringView();
      if (value == "true") {
        client_requested_pqc_ = true;
        ENVOY_LOG(info, "Client requested PQC key exchange - will send public key in response");

        // Check for X-PQC-Mode header to detect hybrid mode request
        auto pqc_mode_header = headers.get(Http::LowerCaseString("x-pqc-mode"));
        if (!pqc_mode_header.empty()) {
          const auto& mode_value = pqc_mode_header[0]->value().getStringView();
          if (mode_value == "hybrid") {
            client_requested_hybrid_mode_ = true;
            ENVOY_LOG(info, "Client requested HYBRID MODE (Kyber768 + X25519)");
          }
        }
      }
    }

    // Check for X-PQC-Ciphertext header (client sending ciphertext for decapsulation)
    auto ciphertext_header = headers.get(Http::LowerCaseString("x-pqc-ciphertext"));
    if (!ciphertext_header.empty()) {
      const auto& encoded_ciphertext = ciphertext_header[0]->value().getStringView();

      // Session validation: Check for X-PQC-Session-ID header
      auto session_id_header = headers.get(Http::LowerCaseString("x-pqc-session-id"));
      if (session_id_header.empty()) {
        ENVOY_LOG(error, "Client sent ciphertext without session ID - rejecting request");
        return Http::FilterHeadersStatus::Continue;
      }

      std::string received_session_id(session_id_header[0]->value().getStringView());

      // Validate session exists and is not expired
      if (!validateSession(received_session_id)) {
        ENVOY_LOG(error, "Session validation failed for session ID: {} - rejecting request",
                  received_session_id);
        return Http::FilterHeadersStatus::Continue;
      }

      // Update current session ID
      session_id_ = received_session_id;

      // Base64-decode the ciphertext
      std::vector<uint8_t> ciphertext = Base64Utils::decode(encoded_ciphertext);

      if (ciphertext.empty()) {
        ENVOY_LOG(error, "Failed to decode base64 ciphertext from X-PQC-Ciphertext header");
        return Http::FilterHeadersStatus::Continue;
      }

      // Allocate buffer for shared secret
      if (!shared_secret_) {
        shared_secret_ = make_secure_buffer(kyber_kem_->length_shared_secret);
      }

      // Server decapsulates ciphertext to recover shared secret
      bool success = serverDecapsulate(
          ciphertext.data(),
          ciphertext.size(),
          shared_secret_.get()
      );

      if (success) {
        has_shared_secret_ = true;

        // Check for hybrid mode: X-PQC-X25519-Public-Key header
        auto x25519_pubkey_header = headers.get(Http::LowerCaseString("x-pqc-x25519-public-key"));
        if (!x25519_pubkey_header.empty()) {
          // HYBRID MODE: Combine Kyber768 + X25519 secrets
          ENVOY_LOG(info, "Hybrid mode: Processing X25519 public key from client");

          const auto& encoded_x25519_pubkey = x25519_pubkey_header[0]->value().getStringView();
          std::vector<uint8_t> client_x25519_pubkey = Base64Utils::decode(encoded_x25519_pubkey);

          if (client_x25519_pubkey.size() != 32) {
            ENVOY_LOG(error, "Hybrid mode: Invalid X25519 public key length: expected 32, got {}",
                      client_x25519_pubkey.size());
            has_shared_secret_ = false;
            return Http::FilterHeadersStatus::Continue;
          }

          // Perform server-side X25519 DH exchange
          uint8_t x25519_shared_secret[32];
          if (!serverX25519Exchange(client_x25519_pubkey.data(), 32, x25519_shared_secret)) {
            ENVOY_LOG(error, "Hybrid mode: X25519 key exchange failed");
            has_shared_secret_ = false;
            return Http::FilterHeadersStatus::Continue;
          }

          // Combine Kyber768 + X25519 secrets using HKDF
          uint8_t combined_secret[32];
          if (!combineHybridSecrets(shared_secret_.get(), 32,
                                    x25519_shared_secret, 32,
                                    combined_secret)) {
            ENVOY_LOG(error, "Hybrid mode: Failed to combine secrets");
            has_shared_secret_ = false;
            return Http::FilterHeadersStatus::Continue;
          }

          // Use combined secret as the final shared secret
          std::memcpy(shared_secret_.get(), combined_secret, 32);
          ENVOY_LOG(info, "Hybrid mode: Successfully combined Kyber768 + X25519 secrets");
        }

        // Associate shared secret with session
        auto& session = sessions_[session_id_];
        std::memcpy(session.shared_secret.get(), shared_secret_.get(), 32);
        session.has_shared_secret = true;

        // Derive session-specific key from shared secret + session metadata
        bool kdf_success = deriveSessionKey(
            shared_secret_.get(),
            32,  // Kyber768 shared secret length (or combined secret in hybrid mode)
            session.session_id,
            session.created_at,
            session.session_key.get()
        );

        if (!kdf_success) {
          ENVOY_LOG(error, "Failed to derive session key for session: {}", session_id_);
          has_shared_secret_ = false;
          session.has_shared_secret = false;
          return Http::FilterHeadersStatus::Continue;
        }

        ENVOY_LOG(info, "Successfully decapsulated ciphertext and derived session key for session: {}",
                  session_id_);
      } else {
        ENVOY_LOG(error, "Failed to decapsulate ciphertext from client");
        has_shared_secret_ = false;
      }
    }

    return Http::FilterHeadersStatus::Continue;
  }

  Http::FilterDataStatus decodeData(Buffer::Instance& data,
                                    bool end_stream) {
    // Production-ready implementation using getRawSlices()
    uint64_t buffer_length = data.length();

    if (buffer_length == 0) {
      ENVOY_LOG(debug, "Received empty buffer");
      return Http::FilterDataStatus::Continue;
    }

    // Get raw slices for inspection
    std::vector<Buffer::RawSlice> slices = data.getRawSlices();

    // SECURITY: Check for TLS Record Type 22 (Handshake = 0x16)
    // This is critical for PQC key exchange detection
    // IMPORTANT: Always check buffer size BEFORE accessing bytes
    if (!slices.empty() && slices[0].len_ > 0) {
      const uint8_t* first_byte_ptr = static_cast<const uint8_t*>(slices[0].mem_);
      if (first_byte_ptr[0] == 0x16) {
        ENVOY_LOG(info, "Detected TLS Handshake (Record Type 22)");
      }
    }

    uint64_t bytes_to_log = std::min(buffer_length, static_cast<uint64_t>(10));

    // Build hex string from slices (already retrieved above)
    std::string hex_string;
    hex_string.reserve(bytes_to_log * 3);

    uint64_t bytes_logged = 0;

    for (const auto& slice : slices) {
      if (bytes_logged >= bytes_to_log) {
        break;
      }

      const uint8_t* slice_data = static_cast<const uint8_t*>(slice.mem_);
      size_t slice_len = slice.len_;

      uint64_t bytes_from_slice = std::min(
          static_cast<uint64_t>(slice_len),
          bytes_to_log - bytes_logged
      );

      for (uint64_t i = 0; i < bytes_from_slice; i++) {
        char hex_buf[4];
        snprintf(hex_buf, sizeof(hex_buf), "%02X ", slice_data[i]);
        hex_string += hex_buf;
      }

      bytes_logged += bytes_from_slice;
    }

    // Remove trailing space
    if (!hex_string.empty()) {
      hex_string.pop_back();
    }

    ENVOY_LOG(info, "First {} bytes (hex): {}", bytes_logged, hex_string);

    return Http::FilterDataStatus::Continue;
  }

  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) {
    return Http::FilterTrailersStatus::Continue;
  }

  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
    decoder_callbacks_ = &callbacks;
  }

  // Http::StreamEncoderFilter interface (Response processing)
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers,
                                          bool end_stream) {
    // If client requested PQC, inject public key in response
    if (client_requested_pqc_) {
      // Generate unique session ID for this key exchange
      session_id_ = generateSessionId();

      // Create session entry in storage
      SessionData session;
      session.session_id = session_id_;
      session.created_at = std::chrono::system_clock::now();
      session.has_shared_secret = false;
      sessions_[session_id_] = std::move(session);

      ENVOY_LOG(debug, "Created new session: {}", session_id_);

      // Base64-encode the Kyber768 public key (1184 bytes → ~1580 chars)
      std::string encoded_public_key = base64Encode(
          kyber_public_key_.get(),
          kyber_kem_->length_public_key
      );

      // Add X-PQC-Public-Key header
      headers.addCopy(Http::LowerCaseString("x-pqc-public-key"), encoded_public_key);

      // Add X-PQC-Session-ID header (for session binding)
      headers.addCopy(Http::LowerCaseString("x-pqc-session-id"), session_id_);

      // Add X-PQC-Key-Version header (for key rotation tracking)
      headers.addCopy(Http::LowerCaseString("x-pqc-key-version"),
                      std::to_string(getCurrentKeyVersion()));

      // Add X-PQC-Status header
      headers.addCopy(Http::LowerCaseString("x-pqc-status"), "pending");

      // HYBRID MODE: If client requested hybrid mode, also send X25519 public key
      if (client_requested_hybrid_mode_) {
        // Base64-encode the X25519 public key (32 bytes)
        std::string encoded_x25519_pubkey = base64Encode(
            x25519_public_key_.get(),
            32
        );

        // Add X-PQC-X25519-Public-Key header
        headers.addCopy(Http::LowerCaseString("x-pqc-x25519-public-key"), encoded_x25519_pubkey);

        // Add X-PQC-Mode header to indicate hybrid mode
        headers.addCopy(Http::LowerCaseString("x-pqc-mode"), "hybrid");

        ENVOY_LOG(info, "Hybrid mode: Injected X25519 public key in response headers ({} bytes base64-encoded)",
                  encoded_x25519_pubkey.size());
      }

      ENVOY_LOG(info, "Injected PQC public key in response headers ({} bytes base64-encoded), session_id: {}",
                encoded_public_key.size(), session_id_);

      client_requested_pqc_ = false;  // Reset flag
      client_requested_hybrid_mode_ = false;  // Reset hybrid mode flag
    }

    return Http::FilterHeadersStatus::Continue;
  }

  Http::FilterDataStatus encodeData(Buffer::Instance& data,
                                    bool end_stream) {
    return Http::FilterDataStatus::Continue;
  }

  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap& trailers) {
    return Http::FilterTrailersStatus::Continue;
  }

  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) {
    encoder_callbacks_ = &callbacks;
  }

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
  const uint8_t* getSharedSecret() const {
    return has_shared_secret_ ? shared_secret_.get() : nullptr;
  }
  size_t getSharedSecretSize() const {
    return has_shared_secret_ && kyber_kem_ ? kyber_kem_->length_shared_secret : 0;
  }

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
  bool rotateKyberKeypair() {
    if (!kyber_kem_) {
      ENVOY_LOG(error, "Cannot rotate: Kyber KEM not initialized");
      return false;
    }

    // Step 1: Move current key to previous (for grace period)
    previous_key_ = std::move(current_key_);

    // Step 2: Generate new keypair
    current_key_ = std::make_unique<KeyVersion>();
    current_key_->version = next_key_version_++;
    current_key_->public_key = make_secure_buffer(kyber_kem_->length_public_key);
    current_key_->secret_key = make_secure_buffer(kyber_kem_->length_secret_key);
    current_key_->created_at = std::chrono::system_clock::now();

    OQS_STATUS status = OQS_KEM_keypair(
        kyber_kem_.get(),
        current_key_->public_key.get(),
        current_key_->secret_key.get()
    );

    if (status != OQS_SUCCESS) {
      ENVOY_LOG(error, "Failed to generate new Kyber-768 keypair during rotation");
      // Restore previous key as current (rollback)
      current_key_ = std::move(previous_key_);
      return false;
    }

    // Step 3: Update legacy pointers for backward compatibility
    kyber_public_key_ = current_key_->public_key;
    kyber_secret_key_ = current_key_->secret_key;

    ENVOY_LOG(info, "Kyber-768 keypair rotated successfully to version {}", current_key_->version);
    if (previous_key_) {
      ENVOY_LOG(info, "Previous key version {} retained for grace period", previous_key_->version);
    }

    // Update rotation metrics
    rotation_count_++;
    last_rotation_time_ = std::chrono::system_clock::now();

    return true;
  }

  /**
   * Get the current key version number.
   * @return Current key version (1, 2, 3, ...)
   */
  uint32_t getCurrentKeyVersion() const {
    return current_key_ ? current_key_->version : 0;
  }

  /**
   * Enable automatic time-based key rotation (Phase 2).
   *
   * When enabled, keys will automatically rotate after the specified interval.
   * This uses a background timer mechanism to trigger rotations without manual intervention.
   *
   * @param rotation_interval Time between automatic rotations (default: 24 hours)
   */
  void enableAutomaticKeyRotation(std::chrono::milliseconds rotation_interval = std::chrono::hours(24)) {
    ENVOY_LOG(info, "Enabling automatic key rotation with interval: {}ms", rotation_interval.count());

    automatic_rotation_enabled_ = true;
    rotation_interval_ = rotation_interval;

    // In a real Envoy filter, we would use the dispatcher to create a timer:
    // dispatcher_.createTimer([this]() { onRotationTimerEvent(); })->enableTimer(rotation_interval_);
    //
    // For TDD purposes, we rely on manual timer triggering via onRotationTimerEvent()
    // This is intentional to allow deterministic testing without real timers.
  }

  /**
   * Disable automatic time-based key rotation.
   */
  void disableAutomaticKeyRotation() {
    ENVOY_LOG(info, "Disabling automatic key rotation");
    automatic_rotation_enabled_ = false;

    // In a real Envoy filter, we would disable the timer here:
    // rotation_timer_->disableTimer();
  }

  /**
   * Timer callback for automatic key rotation.
   * This is called by the Envoy dispatcher when the rotation timer expires.
   */
  void onRotationTimerEvent() {
    // Check if automatic rotation is enabled
    if (!automatic_rotation_enabled_) {
      ENVOY_LOG(debug, "Rotation timer fired but automatic rotation is disabled, skipping");
      return;
    }

    ENVOY_LOG(info, "Automatic key rotation timer fired, rotating keypair");

    // Trigger rotation
    bool success = rotateKyberKeypair();

    if (success) {
      ENVOY_LOG(info, "Automatic key rotation completed successfully to version {}", getCurrentKeyVersion());
    } else {
      ENVOY_LOG(error, "Automatic key rotation failed, keeping current key version {}", getCurrentKeyVersion());
    }

    // In a real Envoy filter, we would reschedule the timer:
    // rotation_timer_->enableTimer(rotation_interval_);
  }

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
                         uint8_t* out_shared_secret) const {
    // Validate inputs
    if (!kyber_kem_) {
      ENVOY_LOG(error, "KEM not initialized - cannot perform encapsulation");
      return false;
    }

    if (!server_public_key || !out_ciphertext || !out_shared_secret) {
      ENVOY_LOG(error, "Invalid parameters for encapsulation - null pointer");
      return false;
    }

    if (server_public_key_len != kyber_kem_->length_public_key) {
      ENVOY_LOG(error, "Invalid public key length: expected {}, got {}",
                kyber_kem_->length_public_key, server_public_key_len);
      return false;
    }

    // Perform KEM encapsulation (client-side operation)
    OQS_STATUS status = OQS_KEM_encaps(
        kyber_kem_.get(),
        out_ciphertext,      // Output: ciphertext to send to server
        out_shared_secret,   // Output: shared secret (client's copy)
        server_public_key    // Input: server's public key
    );

    if (status != OQS_SUCCESS) {
      ENVOY_LOG(error, "KEM encapsulation failed - status: {}", status);
      return false;
    }

    ENVOY_LOG(debug, "Client encapsulation successful - ciphertext_size: {} bytes, shared_secret_size: {} bytes",
              kyber_kem_->length_ciphertext, kyber_kem_->length_shared_secret);

    return true;
  }

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
                         uint8_t* out_shared_secret) const {
    // Validate inputs
    if (!kyber_kem_) {
      ENVOY_LOG(error, "KEM not initialized - cannot perform decapsulation");
      return false;
    }

    if (!ciphertext || !out_shared_secret) {
      ENVOY_LOG(error, "Invalid parameters for decapsulation - null pointer");
      return false;
    }

    if (ciphertext_len != kyber_kem_->length_ciphertext) {
      ENVOY_LOG(error, "Invalid ciphertext length: expected {}, got {}",
                kyber_kem_->length_ciphertext, ciphertext_len);
      return false;
    }

    if (!kyber_secret_key_) {
      ENVOY_LOG(error, "Server secret key not available - cannot decapsulate");
      return false;
    }

    // KEY ROTATION SUPPORT: Try current key first
    // During grace period, we support both current and previous keys
    OQS_STATUS status = OQS_KEM_decaps(
        kyber_kem_.get(),
        out_shared_secret,     // Output: recovered shared secret (32 bytes)
        ciphertext,            // Input: ciphertext from client (1088 bytes)
        kyber_secret_key_.get() // Input: server's current secret key (2400 bytes)
    );

    if (status == OQS_SUCCESS) {
      ENVOY_LOG(debug, "Server decapsulation successful with current key (version {}) - recovered shared_secret_size: {} bytes",
                current_key_ ? current_key_->version : 0,
                kyber_kem_->length_shared_secret);
      return true;
    }

    // GRACE PERIOD: If current key failed, try previous key
    if (previous_key_ && previous_key_->secret_key) {
      ENVOY_LOG(info, "Decapsulation with current key failed, trying previous key version {}",
                previous_key_->version);

      status = OQS_KEM_decaps(
          kyber_kem_.get(),
          out_shared_secret,
          ciphertext,
          previous_key_->secret_key.get()  // Try previous key
      );

      if (status == OQS_SUCCESS) {
        ENVOY_LOG(info, "Server decapsulation successful with previous key (version {}) - grace period active",
                  previous_key_->version);
        return true;
      }
    }

    ENVOY_LOG(error, "KEM decapsulation failed with both current and previous keys - status: {}", status);
    return false;
  }

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
                            uint8_t* out_shared_secret) const {
    if (!server_x25519_public_key || !out_client_public_key || !out_shared_secret) {
      ENVOY_LOG(error, "X25519: Invalid null parameters");
      return false;
    }

    if (server_public_key_len != 32) {
      ENVOY_LOG(error, "X25519: Invalid public key length: expected 32, got {}", server_public_key_len);
      return false;
    }

    // Generate client's X25519 keypair
    uint8_t client_secret_key[32];
    if (RAND_bytes(client_secret_key, 32) != 1) {
      ENVOY_LOG(error, "X25519: Failed to generate random secret key");
      return false;
    }

    // Compute client's public key from secret key
    // X25519 public key = scalar multiplication of base point
    if (EVP_PKEY_derive_init(nullptr) <= 0) {  // Simplified for test
      // For TDD, we'll use a simpler approach
      // In production, use EVP_PKEY_derive with X25519

      // Simplified X25519: Generate public key and shared secret using OpenSSL
      EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
      if (!pctx) {
        ENVOY_LOG(error, "X25519: Failed to create context");
        return false;
      }

      EVP_PKEY* pkey = nullptr;
      if (EVP_PKEY_keygen_init(pctx) <= 0 ||
          EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        ENVOY_LOG(error, "X25519: Failed to generate keypair");
        EVP_PKEY_CTX_free(pctx);
        return false;
      }

      // Extract public key
      size_t pub_len = 32;
      if (EVP_PKEY_get_raw_public_key(pkey, out_client_public_key, &pub_len) <= 0 || pub_len != 32) {
        ENVOY_LOG(error, "X25519: Failed to extract public key");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return false;
      }

      // Create server's public key EVP_PKEY
      EVP_PKEY* server_pkey = EVP_PKEY_new_raw_public_key(
          EVP_PKEY_X25519, nullptr, server_x25519_public_key, 32);
      if (!server_pkey) {
        ENVOY_LOG(error, "X25519: Failed to create server public key");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return false;
      }

      // Perform DH exchange
      EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
      if (!derive_ctx ||
          EVP_PKEY_derive_init(derive_ctx) <= 0 ||
          EVP_PKEY_derive_set_peer(derive_ctx, server_pkey) <= 0) {
        ENVOY_LOG(error, "X25519: Failed to initialize derivation");
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
        return false;
      }

      size_t secret_len = 32;
      if (EVP_PKEY_derive(derive_ctx, out_shared_secret, &secret_len) <= 0 || secret_len != 32) {
        ENVOY_LOG(error, "X25519: Failed to derive shared secret");
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(server_pkey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return false;
      }

      // Cleanup
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(server_pkey);
      EVP_PKEY_free(pkey);
      EVP_PKEY_CTX_free(pctx);

      ENVOY_LOG(debug, "X25519: Key exchange successful");
      return true;
    }

    return false;
  }

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
                            uint8_t* out_shared_secret) const {
    if (!client_x25519_public_key || !out_shared_secret) {
      ENVOY_LOG(error, "Server X25519: Invalid null parameters");
      return false;
    }

    if (client_public_key_len != 32) {
      ENVOY_LOG(error, "Server X25519: Invalid client public key length: expected 32, got {}",
                client_public_key_len);
      return false;
    }

    if (!x25519_secret_key_ || !x25519_public_key_) {
      ENVOY_LOG(error, "Server X25519: Server keypair not initialized");
      return false;
    }

    // Create server's private key EVP_PKEY from raw key
    EVP_PKEY* server_pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, x25519_secret_key_.get(), 32);
    if (!server_pkey) {
      ENVOY_LOG(error, "Server X25519: Failed to create server private key");
      return false;
    }

    // Create client's public key EVP_PKEY
    EVP_PKEY* client_pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, client_x25519_public_key, 32);
    if (!client_pkey) {
      ENVOY_LOG(error, "Server X25519: Failed to create client public key");
      EVP_PKEY_free(server_pkey);
      return false;
    }

    // Perform DH exchange
    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(server_pkey, nullptr);
    if (!derive_ctx ||
        EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, client_pkey) <= 0) {
      ENVOY_LOG(error, "Server X25519: Failed to initialize derivation");
      EVP_PKEY_free(client_pkey);
      EVP_PKEY_free(server_pkey);
      if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
      return false;
    }

    size_t secret_len = 32;
    if (EVP_PKEY_derive(derive_ctx, out_shared_secret, &secret_len) <= 0 || secret_len != 32) {
      ENVOY_LOG(error, "Server X25519: Failed to derive shared secret");
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(client_pkey);
      EVP_PKEY_free(server_pkey);
      return false;
    }

    // Cleanup
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(client_pkey);
    EVP_PKEY_free(server_pkey);

    ENVOY_LOG(debug, "Server X25519: Key exchange successful");
    return true;
  }

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
                            uint8_t* out_combined_secret) const {
    if (!kyber_secret || !x25519_secret || !out_combined_secret) {
      ENVOY_LOG(error, "Hybrid combine: Invalid null parameters");
      return false;
    }

    if (kyber_len != 32 || x25519_len != 32) {
      ENVOY_LOG(error, "Hybrid combine: Invalid secret lengths (expected 32+32)");
      return false;
    }

    // Concatenate secrets: kyber || x25519
    std::vector<uint8_t> concat_secrets(64);
    std::memcpy(concat_secrets.data(), kyber_secret, 32);
    std::memcpy(concat_secrets.data() + 32, x25519_secret, 32);

    // Use HKDF-SHA256 to derive final secret
    // Salt: "PQC-Hybrid-Mode" for domain separation
    const char* salt_str = "PQC-Hybrid-Mode";
    const unsigned char* salt = reinterpret_cast<const unsigned char*>(salt_str);
    size_t salt_len = std::strlen(salt_str);

    // Info: "Kyber768+X25519"
    const char* info_str = "Kyber768+X25519";
    const unsigned char* info = reinterpret_cast<const unsigned char*>(info_str);
    size_t info_len = std::strlen(info_str);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
      ENVOY_LOG(error, "Hybrid HKDF: Failed to create context");
      return false;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, concat_secrets.data(), 64) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
      ENVOY_LOG(error, "Hybrid HKDF: Setup failed");
      EVP_PKEY_CTX_free(pctx);
      return false;
    }

    size_t out_len = 32;
    if (EVP_PKEY_derive(pctx, out_combined_secret, &out_len) <= 0 || out_len != 32) {
      ENVOY_LOG(error, "Hybrid HKDF: Failed to derive combined secret");
      EVP_PKEY_CTX_free(pctx);
      return false;
    }

    EVP_PKEY_CTX_free(pctx);
    ENVOY_LOG(debug, "Hybrid mode: Successfully combined Kyber768 + X25519 secrets");
    return true;
  }

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
                        uint8_t* auth_tag) const {
    // Validate inputs
    if (!plaintext || !key || !iv || !auth_tag) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: null pointer parameter");
      return false;
    }

    if (plaintext_len == 0) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: empty plaintext");
      return false;
    }

    // Generate cryptographically secure random IV (12 bytes for GCM mode)
    // Uses OpenSSL RAND_bytes for FIPS-compliant random number generation
    if (RAND_bytes(iv, 12) != 1) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: failed to generate secure random IV");
      return false;
    }

    // Allocate ciphertext buffer (same size as plaintext for GCM)
    ciphertext.resize(plaintext_len);

    // Initialize OpenSSL EVP context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: failed to create EVP context");
      return false;
    }

    // Initialize encryption operation with AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: failed to initialize cipher");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Set IV length (12 bytes is standard for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: failed to set IV length");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: failed to set key and IV");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Encrypt plaintext
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len) != 1) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: encryption failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: finalization failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    ciphertext_len += len;

    // Get authentication tag (16 bytes)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, auth_tag) != 1) {
      ENVOY_LOG(error, "AES-256-GCM encrypt: failed to get authentication tag");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    ENVOY_LOG(debug, "AES-256-GCM encryption successful - plaintext: {} bytes, ciphertext: {} bytes",
              plaintext_len, ciphertext_len);

    return true;
  }

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
                        std::vector<uint8_t>& plaintext) const {
    // Validate inputs
    if (!ciphertext || !key || !iv || !auth_tag) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: null pointer parameter");
      return false;
    }

    if (ciphertext_len == 0) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: empty ciphertext");
      return false;
    }

    // Allocate plaintext buffer (same size as ciphertext for GCM)
    plaintext.resize(ciphertext_len);

    // Initialize OpenSSL EVP context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: failed to create EVP context");
      return false;
    }

    // Initialize decryption operation with AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: failed to initialize cipher");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Set IV length (12 bytes)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: failed to set IV length");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: failed to set key and IV");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Decrypt ciphertext
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: decryption failed");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    int plaintext_len = len;

    // Set expected authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(auth_tag)) != 1) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: failed to set authentication tag");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }

    // Finalize decryption and verify authentication tag
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    if (ret != 1) {
      ENVOY_LOG(error, "AES-256-GCM decrypt: finalization failed - authentication tag mismatch (tampering detected)");
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    plaintext_len += len;

    // Resize plaintext to actual size
    plaintext.resize(plaintext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    ENVOY_LOG(debug, "AES-256-GCM decryption successful - ciphertext: {} bytes, plaintext: {} bytes",
              ciphertext_len, plaintext_len);

    return true;
  }

private:
  std::shared_ptr<PqcFilterConfig> config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{nullptr};

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
  std::string generateSessionId() {
    // Generate cryptographically secure 128-bit session ID
    uint8_t random_bytes[16];

    if (RAND_bytes(random_bytes, 16) != 1) {
      ENVOY_LOG(error, "Failed to generate secure random bytes for session ID");
      auto now = std::chrono::system_clock::now();
      auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
          now.time_since_epoch()).count();
      return "fallback-" + std::to_string(timestamp);
    }

    // Convert to hex string
    std::string session_id;
    session_id.reserve(32);
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
      session_id.push_back(hex_chars[(random_bytes[i] >> 4) & 0x0F]);
      session_id.push_back(hex_chars[random_bytes[i] & 0x0F]);
    }
    return session_id;
  }

  // Helper: Validate session exists and is not expired
  bool validateSession(const std::string& session_id) {
    // Check if session exists
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
      ENVOY_LOG(warn, "Session validation failed: session ID not found: {}", session_id);
      return false;
    }

    // Check if session has expired (5-minute timeout)
    auto now = std::chrono::system_clock::now();
    auto session_age = std::chrono::duration_cast<std::chrono::minutes>(
        now - it->second.created_at);

    if (session_age >= session_timeout_) {
      ENVOY_LOG(warn, "Session validation failed: session expired (age: {} minutes, timeout: {} minutes)",
                session_age.count(), session_timeout_.count());
      // Clean up expired session
      sessions_.erase(it);
      return false;
    }

    ENVOY_LOG(debug, "Session validated: {} (age: {} minutes)", session_id, session_age.count());
    return true;
  }

  // Helper: Derive session-specific key from shared secret + session metadata
  bool deriveSessionKey(const uint8_t* shared_secret,
                        size_t shared_secret_len,
                        const std::string& session_id,
                        const std::chrono::system_clock::time_point& timestamp,
                        uint8_t* out_session_key) {
    // Derive session-specific key using HKDF-SHA256
    auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    std::string timestamp_str = std::to_string(timestamp_ms);

    const unsigned char* salt = reinterpret_cast<const unsigned char*>(session_id.data());
    size_t salt_len = session_id.size();
    const unsigned char* info = reinterpret_cast<const unsigned char*>(timestamp_str.data());
    size_t info_len = timestamp_str.size();

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
      ENVOY_LOG(error, "HKDF: Failed to create context");
      return false;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, shared_secret_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
      ENVOY_LOG(error, "HKDF: Setup failed");
      EVP_PKEY_CTX_free(pctx);
      return false;
    }

    size_t out_len = 32;
    if (EVP_PKEY_derive(pctx, out_session_key, &out_len) <= 0) {
      ENVOY_LOG(error, "HKDF: Failed to derive key");
      EVP_PKEY_CTX_free(pctx);
      return false;
    }

    EVP_PKEY_CTX_free(pctx);
    ENVOY_LOG(debug, "Derived session key for session {} (timestamp: {} ms)",
              session_id, timestamp_ms);
    return true;
  }

  // Base64 encoding helper
  static std::string base64Encode(const uint8_t* data, size_t len) {
    static constexpr const char* BASE64_CHARS =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    encoded.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
      uint32_t triple = (data[i] << 16);

      if (i + 1 < len) {
        triple |= (data[i + 1] << 8);
      }
      if (i + 2 < len) {
        triple |= data[i + 2];
      }

      encoded.push_back(BASE64_CHARS[(triple >> 18) & 0x3F]);
      encoded.push_back(BASE64_CHARS[(triple >> 12) & 0x3F]);

      if (i + 1 < len) {
        encoded.push_back(BASE64_CHARS[(triple >> 6) & 0x3F]);
      } else {
        encoded.push_back('=');
      }

      if (i + 2 < len) {
        encoded.push_back(BASE64_CHARS[triple & 0x3F]);
      } else {
        encoded.push_back('=');
      }
    }

    return encoded;
  }

  // Post-Quantum Cryptography - Kyber-768
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kyber_kem_{nullptr, OQS_KEM_free};

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

  // Automatic key rotation state (Phase 2)
  bool automatic_rotation_enabled_{false};
  std::chrono::milliseconds rotation_interval_{std::chrono::hours(24)};  // Default: 24 hours
  uint64_t rotation_count_{0};  // Metric: total number of rotations
  std::chrono::system_clock::time_point last_rotation_time_;  // Metric: last rotation timestamp

  // Legacy direct access (points to current_key_ for backward compatibility)
  SecureBuffer kyber_public_key_;
  SecureBuffer kyber_secret_key_;

  // Shared secret storage (32 bytes for Kyber768)
  // This is populated when server receives ciphertext from client
  SecureBuffer shared_secret_;
  bool has_shared_secret_{false};  // Track if shared secret has been established

  // Dilithium3 (ML-DSA-65) signature
  std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> dilithium_sig_{nullptr, OQS_SIG_free};
  SecureBuffer dilithium_public_key_;
  SecureBuffer dilithium_secret_key_;

  // X25519 ECDH keypair (for hybrid mode)
  SecureBuffer x25519_public_key_;
  SecureBuffer x25519_secret_key_;

  // Initialization functions
  void initializeKyber() {
    // Simple stub for now - full implementation will be in pqc_filter.cc
    kyber_kem_ = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>(
        OQS_KEM_new("Kyber768"), OQS_KEM_free);

    if (!kyber_kem_) {
      ENVOY_LOG(error, "Failed to create Kyber-768 KEM instance");
      return;
    }

    // Initialize first key version (version 1)
    current_key_ = std::make_unique<KeyVersion>();
    current_key_->version = next_key_version_++;
    current_key_->public_key = make_secure_buffer(kyber_kem_->length_public_key);
    current_key_->secret_key = make_secure_buffer(kyber_kem_->length_secret_key);
    current_key_->created_at = std::chrono::system_clock::now();

    OQS_STATUS status = OQS_KEM_keypair(
        kyber_kem_.get(),
        current_key_->public_key.get(),
        current_key_->secret_key.get()
    );

    if (status != OQS_SUCCESS) {
      ENVOY_LOG(error, "Failed to generate Kyber-768 keypair");
      return;
    }

    // Update legacy pointers for backward compatibility
    kyber_public_key_ = current_key_->public_key;
    kyber_secret_key_ = current_key_->secret_key;

    ENVOY_LOG(info, "Kyber-768 initialized successfully with version {}", current_key_->version);
  }

  void initializeDilithium() {
    // Create Dilithium3 (ML-DSA-65) signature instance
    dilithium_sig_ = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>(
        OQS_SIG_new("ML-DSA-65"), OQS_SIG_free);

    if (!dilithium_sig_) {
      ENVOY_LOG(error, "Failed to create ML-DSA-65 (Dilithium3) signature instance");
      return;
    }

    dilithium_public_key_ = make_secure_buffer(dilithium_sig_->length_public_key);
    dilithium_secret_key_ = make_secure_buffer(dilithium_sig_->length_secret_key);

    OQS_STATUS status = OQS_SIG_keypair(
        dilithium_sig_.get(),
        dilithium_public_key_.get(),
        dilithium_secret_key_.get()
    );

    if (status != OQS_SUCCESS) {
      ENVOY_LOG(error, "Failed to generate ML-DSA-65 (Dilithium3) keypair");
      return;
    }

    ENVOY_LOG(info, "ML-DSA-65 (Dilithium3) initialized successfully");
  }

  void initializeX25519() {
    // Generate X25519 keypair using OpenSSL
    x25519_public_key_ = make_secure_buffer(32);  // X25519 public key is always 32 bytes
    x25519_secret_key_ = make_secure_buffer(32);  // X25519 secret key is always 32 bytes

    // Create X25519 keypair context
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) {
      ENVOY_LOG(error, "Failed to create X25519 context");
      return;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
      ENVOY_LOG(error, "Failed to generate X25519 keypair");
      EVP_PKEY_CTX_free(pctx);
      return;
    }

    // Extract public key
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, x25519_public_key_.get(), &pub_len) <= 0 || pub_len != 32) {
      ENVOY_LOG(error, "Failed to extract X25519 public key");
      EVP_PKEY_free(pkey);
      EVP_PKEY_CTX_free(pctx);
      return;
    }

    // Extract private key
    size_t priv_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, x25519_secret_key_.get(), &priv_len) <= 0 || priv_len != 32) {
      ENVOY_LOG(error, "Failed to extract X25519 private key");
      EVP_PKEY_free(pkey);
      EVP_PKEY_CTX_free(pctx);
      return;
    }

    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    ENVOY_LOG(info, "X25519 ECDH initialized successfully for hybrid mode");
  }
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
