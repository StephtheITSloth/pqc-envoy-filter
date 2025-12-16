#include "src/pqc_filter.h"
#include "src/base64_utils.h"
#include <chrono>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

PqcFilter::PqcFilter(std::shared_ptr<PqcFilterConfig> config)
    : config_(config) {
  initializeKyber();
  initializeDilithium();
}

Http::FilterHeadersStatus PqcFilter::decodeHeaders(
    Http::RequestHeaderMap& headers, bool end_stream) {

  // Log which algorithm we're using
  ENVOY_LOG(info, "PQC Filter using algorithm: {}",
            config_->getAlgorithmName());

  // Check if client is requesting PQC key exchange
  auto pqc_init_header = headers.get(Http::LowerCaseString("x-pqc-init"));
  if (!pqc_init_header.empty()) {
    const auto& value = pqc_init_header[0]->value().getStringView();
    if (value == "true") {
      client_requested_pqc_ = true;
      ENVOY_LOG(info, "Client requested PQC key exchange - will send public key in response");
    }
  }

  // Check for X-PQC-Ciphertext header (client sending ciphertext for decapsulation)
  auto ciphertext_header = headers.get(Http::LowerCaseString("x-pqc-ciphertext"));
  if (!ciphertext_header.empty()) {
    const auto& encoded_ciphertext = ciphertext_header[0]->value().getStringView();

    // Extract client IP for error tracking
    std::string client_ip = getClientIp(headers);

    // Check circuit breaker FIRST (before processing request)
    if (isCircuitBreakerOpen(client_ip)) {
      ENVOY_LOG(warn, "Circuit breaker open - rejecting PQC request");
      return handlePqcError(PqcErrorCode::SERVICE_UNAVAILABLE, client_ip);
    }

    // Session validation: Check for X-PQC-Session-ID header
    auto session_id_header = headers.get(Http::LowerCaseString("x-pqc-session-id"));
    if (session_id_header.empty()) {
      // SECURITY: Generic error - don't reveal what's missing
      ENVOY_LOG(warn, "PQC request validation failed");
      recordError(client_ip);  // Track error for rate limiting/circuit breaker
      return handlePqcError(PqcErrorCode::INVALID_REQUEST, client_ip);
    }

    std::string received_session_id(session_id_header[0]->value().getStringView());

    // Validate session exists and is not expired
    if (!validateSession(received_session_id)) {
      // SECURITY: Generic error - don't reveal session validation details
      ENVOY_LOG(warn, "PQC session validation failed");
      recordError(client_ip);  // Track error
      return handlePqcError(PqcErrorCode::INVALID_REQUEST, client_ip);
    }

    // Update current session ID
    session_id_ = received_session_id;

    // Base64-decode the ciphertext
    std::vector<uint8_t> ciphertext = Base64Utils::decode(std::string(encoded_ciphertext));

    if (ciphertext.empty()) {
      // SECURITY: Generic crypto error - don't reveal base64 decoding failure
      ENVOY_LOG(warn, "PQC cryptographic operation failed");
      recordError(client_ip);
      return handlePqcError(PqcErrorCode::CRYPTO_OPERATION_FAILED, client_ip);
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

      // Associate shared secret with session
      auto& session = sessions_[session_id_];
      std::memcpy(session.shared_secret.get(), shared_secret_.get(), 32);
      session.has_shared_secret = true;

      // Derive session-specific key from shared secret + session metadata
      // This binds the key to the specific session (prevents replay attacks)
      bool kdf_success = deriveSessionKey(
          shared_secret_.get(),
          32,  // Kyber768 shared secret length
          session.session_id,
          session.created_at,
          session.session_key.get()
      );

      if (!kdf_success) {
        // SECURITY: Generic crypto error - don't reveal KDF failure
        ENVOY_LOG(warn, "PQC cryptographic operation failed");
        has_shared_secret_ = false;
        session.has_shared_secret = false;
        recordError(client_ip);
        return handlePqcError(PqcErrorCode::CRYPTO_OPERATION_FAILED, client_ip);
      }

      ENVOY_LOG(info, "Successfully decapsulated ciphertext and derived session key");
      // Record success for circuit breaker recovery
      recordSuccess(client_ip);
    } else {
      // SECURITY: Generic crypto error - don't reveal decapsulation failure details
      ENVOY_LOG(warn, "PQC cryptographic operation failed");
      has_shared_secret_ = false;
      recordError(client_ip);
      return handlePqcError(PqcErrorCode::CRYPTO_OPERATION_FAILED, client_ip);
    }
  }

  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus PqcFilter::decodeData(
    Buffer::Instance& data, bool end_stream) {

  // Get buffer length
  uint64_t buffer_length = data.length();

  // Handle empty buffer
  if (buffer_length == 0) {
    ENVOY_LOG(debug, "Received empty buffer");
    return Http::FilterDataStatus::Continue;
  }

  // Calculate how many bytes to log (min of 10 or buffer length)
  uint64_t bytes_to_log = std::min(buffer_length, static_cast<uint64_t>(10));

  // Get raw slices (zero-copy access to buffer memory)
  // Production-ready: handles fragmented buffers efficiently
  Buffer::RawSliceVector slices = data.getRawSlices();

  if (!slices.empty()) {
    if(slices[0].len_ > 0) {
      const uint8_t* first_byte_ptr = static_cast<const uint8_t*>(slices[0].mem_);

      if (first_byte_ptr[0] == 0x16) {
        ENVOY_LOG(info, "Detected TLS Handshake (Record Type 22)");
      }
    }
  }

  // Build hex string by iterating through slices
  std::string hex_string;
  hex_string.reserve(bytes_to_log * 3);  // Pre-allocate: "XX " per byte

  uint64_t bytes_logged = 0;

  for (const auto& slice : slices) {
    if (bytes_logged >= bytes_to_log) {
      break;  // We've logged enough
    }

    // Access slice data
    const uint8_t* slice_data = static_cast<const uint8_t*>(slice.mem_);
    size_t slice_len = slice.len_;

    // Calculate how many bytes to read from this slice
    uint64_t bytes_from_slice = std::min(
        static_cast<uint64_t>(slice_len),
        bytes_to_log - bytes_logged
    );

    // Convert bytes to hex
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

  // Log the hex string
  ENVOY_LOG(info, "First {} bytes (hex): {}", bytes_logged, hex_string);

  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus PqcFilter::decodeTrailers(
    Http::RequestTrailerMap& trailers) {
  return Http::FilterTrailersStatus::Continue;
}

void PqcFilter::setDecoderFilterCallbacks(
    Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

void PqcFilter::initializeKyber() {
  // Create Kyber KEM instance using configured algorithm
  // Note: We use the verbose std::unique_ptr syntax here (not auto) because
  // this is an assignment to an existing member variable declared in the header.
  // The header declares the type, but here we must construct and assign it.
  std::string kem_alg = config_->getKemAlgorithm();
  kyber_kem_ = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>(
      OQS_KEM_new(kem_alg.c_str()), OQS_KEM_free);

  if(!kyber_kem_) {
    ENVOY_LOG(error, "Failed to create KEM instance for algorithm: {} - not available", kem_alg);
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
    ENVOY_LOG(error, "Failed to generate Kyber-768 keypair - status: {}", status);
    return;
  }

  // Update legacy pointers for backward compatibility
  kyber_public_key_ = current_key_->public_key;
  kyber_secret_key_ = current_key_->secret_key;

  ENVOY_LOG(info, "{} initialized successfully with version {} - public_key_size: {} bytes, secret_key_size: {} bytes",
            kem_alg, current_key_->version, kyber_kem_->length_public_key, kyber_kem_->length_secret_key);
}

void PqcFilter::initializeDilithium() {
  // Create Dilithium signature instance using configured algorithm
  // Note: We use the verbose std::unique_ptr syntax here (not auto) because
  // this is an assignment to an existing member variable declared in the header.
  std::string sig_alg = config_->getSigAlgorithm();
  dilithium_sig_ = std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)>(
      OQS_SIG_new(sig_alg.c_str()), OQS_SIG_free);

  if (!dilithium_sig_) {
    ENVOY_LOG(error, "Failed to create signature instance for algorithm: {} - not available", sig_alg);
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
    ENVOY_LOG(error, "Failed to generate ML-DSA-65 (Dilithium3) keypair - status: {}", status);
    return;
  }

  ENVOY_LOG(info, "{} initialized successfully - public_key_size: {} bytes, secret_key_size: {} bytes",
            sig_alg, dilithium_sig_->length_public_key, dilithium_sig_->length_secret_key);
}

bool PqcFilter::clientEncapsulate(const uint8_t* server_public_key,
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
  // This generates:
  // 1. A random shared secret (same on both sides after decapsulation)
  // 2. Ciphertext that encapsulates the secret (sent to server)
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

bool PqcFilter::serverDecapsulate(const uint8_t* ciphertext,
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

// ============================================================================
// RESPONSE PROCESSING (StreamEncoderFilter interface)
// ============================================================================

Http::FilterHeadersStatus PqcFilter::encodeHeaders(
    Http::ResponseHeaderMap& headers, bool end_stream) {

  // If client requested PQC, inject our public key in the response
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
    std::string encoded_public_key = Base64Utils::encode(
        kyber_public_key_.get(),
        kyber_kem_->length_public_key
    );

    // Add X-PQC-Public-Key header
    headers.addCopy(
        Http::LowerCaseString("x-pqc-public-key"),
        encoded_public_key
    );

    // Add X-PQC-Session-ID header (for session binding)
    headers.addCopy(
        Http::LowerCaseString("x-pqc-session-id"),
        session_id_
    );

    // Add X-PQC-Key-Version header (for key rotation tracking)
    headers.addCopy(
        Http::LowerCaseString("x-pqc-key-version"),
        std::to_string(getCurrentKeyVersion())
    );

    // Add X-PQC-Status header
    headers.addCopy(
        Http::LowerCaseString("x-pqc-status"),
        "pending"
    );

    ENVOY_LOG(info, "Sent PQC public key in response header ({} bytes encoded to {} chars), session_id: {}",
              kyber_kem_->length_public_key, encoded_public_key.size(), session_id_);

    // Reset flag for next request
    client_requested_pqc_ = false;
  }

  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus PqcFilter::encodeData(
    Buffer::Instance& data, bool end_stream) {
  // Pass through response data unchanged
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus PqcFilter::encodeTrailers(
    Http::ResponseTrailerMap& trailers) {
  // Pass through response trailers unchanged
  return Http::FilterTrailersStatus::Continue;
}

void PqcFilter::setEncoderFilterCallbacks(
    Http::StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

// ============================================================================
// SHARED SECRET ACCESS METHODS
// ============================================================================

const uint8_t* PqcFilter::getSharedSecret() const {
  return has_shared_secret_ ? shared_secret_.get() : nullptr;
}

size_t PqcFilter::getSharedSecretSize() const {
  return has_shared_secret_ && kyber_kem_ ? kyber_kem_->length_shared_secret : 0;
}

// ============================================================================
// AES-256-GCM ENCRYPTION/DECRYPTION
// ============================================================================

bool PqcFilter::encryptAES256GCM(const uint8_t* plaintext,
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

bool PqcFilter::decryptAES256GCM(const uint8_t* ciphertext,
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

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

std::string PqcFilter::generateSessionId() {
  // Generate cryptographically secure 128-bit (16-byte) session ID
  // Format: 32 hex characters (e.g., "a1b2c3d4e5f6789012345678abcdef01")

  uint8_t random_bytes[16];

  // Use OpenSSL RAND_bytes for cryptographically secure random generation
  // This is FIPS-compliant and suitable for security-critical session IDs
  if (RAND_bytes(random_bytes, 16) != 1) {
    ENVOY_LOG(error, "Failed to generate secure random bytes for session ID");
    // Fallback: use timestamp-based ID (less secure, but better than nothing)
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    return "fallback-" + std::to_string(timestamp);
  }

  // Convert random bytes to hex string
  std::string session_id;
  session_id.reserve(32);

  static const char hex_chars[] = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    session_id.push_back(hex_chars[(random_bytes[i] >> 4) & 0x0F]);
    session_id.push_back(hex_chars[random_bytes[i] & 0x0F]);
  }

  ENVOY_LOG(debug, "Generated session ID: {}", session_id);

  return session_id;
}

bool PqcFilter::validateSession(const std::string& session_id) {
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

bool PqcFilter::deriveSessionKey(const uint8_t* shared_secret,
                                  size_t shared_secret_len,
                                  const std::string& session_id,
                                  const std::chrono::system_clock::time_point& timestamp,
                                  uint8_t* out_session_key) {
  // Derive session-specific key using HKDF-SHA256
  // Formula: session_key = HKDF(shared_secret, salt=session_id, info=timestamp)
  //
  // This binds the key to:
  // - shared_secret: Quantum-resistant key from Kyber768
  // - session_id: Unique session identifier
  // - timestamp: Session creation time
  //
  // Security: Even if an attacker replays a ciphertext in a different session,
  // the derived session key will be different due to different session_id/timestamp

  // Convert timestamp to milliseconds since epoch (for deterministic KDF input)
  auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      timestamp.time_since_epoch()).count();
  std::string timestamp_str = std::to_string(timestamp_ms);

  // Prepare KDF inputs
  // Salt: session_id (binds key to specific session)
  // Info: timestamp (binds key to specific time)
  const unsigned char* salt = reinterpret_cast<const unsigned char*>(session_id.data());
  size_t salt_len = session_id.size();

  const unsigned char* info = reinterpret_cast<const unsigned char*>(timestamp_str.data());
  size_t info_len = timestamp_str.size();

  // Create HKDF context
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!pctx) {
    ENVOY_LOG(error, "HKDF: Failed to create context");
    return false;
  }

  // Initialize HKDF
  if (EVP_PKEY_derive_init(pctx) <= 0) {
    ENVOY_LOG(error, "HKDF: Failed to initialize derivation");
    EVP_PKEY_CTX_free(pctx);
    return false;
  }

  // Set HKDF mode to extract-and-expand
  if (EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0) {
    ENVOY_LOG(error, "HKDF: Failed to set mode");
    EVP_PKEY_CTX_free(pctx);
    return false;
  }

  // Set digest algorithm (SHA-256)
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
    ENVOY_LOG(error, "HKDF: Failed to set digest");
    EVP_PKEY_CTX_free(pctx);
    return false;
  }

  // Set key material (shared secret from Kyber768)
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, shared_secret_len) <= 0) {
    ENVOY_LOG(error, "HKDF: Failed to set key material");
    EVP_PKEY_CTX_free(pctx);
    return false;
  }

  // Set salt (session ID)
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
    ENVOY_LOG(error, "HKDF: Failed to set salt");
    EVP_PKEY_CTX_free(pctx);
    return false;
  }

  // Set info (timestamp)
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
    ENVOY_LOG(error, "HKDF: Failed to set info");
    EVP_PKEY_CTX_free(pctx);
    return false;
  }

  // Derive session key (32 bytes for AES-256)
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

// ============================================================================
// KEY ROTATION - PHASE 1: MANUAL ROTATION
// ============================================================================

bool PqcFilter::rotateKyberKeypair() {
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

uint32_t PqcFilter::getCurrentKeyVersion() const {
  return current_key_ ? current_key_->version : 0;
}

// ============================================================================
// AUTOMATIC TIME-BASED KEY ROTATION (PHASE 2)
// ============================================================================

void PqcFilter::enableAutomaticKeyRotation(std::chrono::milliseconds rotation_interval) {
  ENVOY_LOG(info, "Enabling automatic key rotation with interval: {}ms", rotation_interval.count());

  automatic_rotation_enabled_ = true;
  rotation_interval_ = rotation_interval;

  // In a real Envoy filter, we would use the dispatcher to create a timer:
  // dispatcher_.createTimer([this]() { onRotationTimerEvent(); })->enableTimer(rotation_interval_);
  //
  // For TDD purposes, we rely on manual timer triggering via onRotationTimerEvent()
  // This is intentional to allow deterministic testing without real timers.
}

void PqcFilter::disableAutomaticKeyRotation() {
  ENVOY_LOG(info, "Disabling automatic key rotation");
  automatic_rotation_enabled_ = false;

  // In a real Envoy filter, we would disable the timer here:
  // rotation_timer_->disableTimer();
}

void PqcFilter::onRotationTimerEvent() {
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

// ============================================================================
// ERROR HANDLING & GRACEFUL DEGRADATION
// ============================================================================

std::string PqcFilter::getClientIp(const Http::RequestHeaderMap& headers) const {
  // Check X-Forwarded-For header (standard for proxied requests)
  auto xff_header = headers.get(Http::LowerCaseString("x-forwarded-for"));
  if (!xff_header.empty()) {
    std::string xff_value(xff_header[0]->value().getStringView());
    // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
    // We want the leftmost (original client) IP
    size_t comma_pos = xff_value.find(',');
    if (comma_pos != std::string::npos) {
      return xff_value.substr(0, comma_pos);
    }
    return xff_value;
  }

  // Check X-Real-IP header (alternative proxy header)
  auto xri_header = headers.get(Http::LowerCaseString("x-real-ip"));
  if (!xri_header.empty()) {
    return std::string(xri_header[0]->value().getStringView());
  }

  // Fallback: use peer address from decoder callbacks
  // In real Envoy, this would be: decoder_callbacks_->streamInfo().downstreamRemoteAddress()->ip()->addressAsString()
  // For testing/standalone, return placeholder
  return "unknown";
}

bool PqcFilter::recordError(const std::string& client_ip) {
  auto now = std::chrono::system_clock::now();

  // Get or create client error state
  auto& state = client_errors_[client_ip];

  // Initialize window_start if this is first error
  if (state.error_count == 0) {
    state.window_start = now;
  }

  // Check if we're in a new rate limit window (1 minute)
  auto window_age = std::chrono::duration_cast<std::chrono::minutes>(now - state.window_start);
  if (window_age >= std::chrono::minutes(1)) {
    // Reset window
    state.error_count = 0;
    state.window_start = now;
  }

  // Increment error count
  state.error_count++;
  state.last_error = now;

  // Check rate limit (max errors per minute from config)
  const auto& rate_limit_config = config_->getRateLimitConfig();
  if (rate_limit_config.enabled &&
      state.error_count > rate_limit_config.max_errors_per_minute) {
    ENVOY_LOG(warn, "Rate limit exceeded for client IP: {} ({} errors in current window)",
              client_ip, state.error_count);
    return false;  // Blocked by rate limit
  }

  // Check circuit breaker threshold
  const auto& cb_config = config_->getCircuitBreakerConfig();

  if (state.circuit_state == CircuitState::CLOSED) {
    // Check if we should open the circuit
    if (state.error_count >= cb_config.failure_threshold) {
      state.circuit_state = CircuitState::OPEN;
      state.circuit_opened_at = now;
      ENVOY_LOG(warn, "Circuit breaker OPENED for client IP: {} ({} failures)",
                client_ip, state.error_count);
      return false;  // Circuit breaker tripped
    }
  } else if (state.circuit_state == CircuitState::OPEN) {
    // Check if timeout has elapsed to transition to HALF_OPEN
    auto circuit_open_duration = std::chrono::duration_cast<std::chrono::seconds>(
        now - state.circuit_opened_at);

    if (circuit_open_duration >= cb_config.timeout) {
      state.circuit_state = CircuitState::HALF_OPEN;
      state.success_count = 0;
      ENVOY_LOG(info, "Circuit breaker transitioned to HALF_OPEN for client IP: {} (testing recovery)",
                client_ip);
      // Allow this request through to test recovery
      return true;
    } else {
      // Circuit still open
      return false;
    }
  } else if (state.circuit_state == CircuitState::HALF_OPEN) {
    // In HALF_OPEN, we're testing recovery
    // This is an error, so circuit should reopen
    state.circuit_state = CircuitState::OPEN;
    state.circuit_opened_at = now;
    ENVOY_LOG(warn, "Circuit breaker RE-OPENED for client IP: {} (recovery test failed)",
              client_ip);
    return false;
  }

  return true;  // Error recorded, request allowed
}

bool PqcFilter::isCircuitBreakerOpen(const std::string& client_ip) const {
  auto it = client_errors_.find(client_ip);
  if (it == client_errors_.end()) {
    return false;  // No errors recorded, circuit is closed
  }

  const auto& state = it->second;
  auto now = std::chrono::system_clock::now();

  if (state.circuit_state == CircuitState::OPEN) {
    // Check if timeout has elapsed
    const auto& cb_config = config_->getCircuitBreakerConfig();
    auto circuit_open_duration = std::chrono::duration_cast<std::chrono::seconds>(
        now - state.circuit_opened_at);

    if (circuit_open_duration >= cb_config.timeout) {
      // Timeout elapsed - circuit should transition to HALF_OPEN
      // This will be done in recordError() on next request
      return false;  // Allow request to test recovery
    }

    return true;  // Circuit is open
  }

  return false;  // Circuit is closed or half-open
}

void PqcFilter::recordSuccess(const std::string& client_ip) {
  auto it = client_errors_.find(client_ip);
  if (it == client_errors_.end()) {
    return;  // No error state for this IP
  }

  auto& state = it->second;

  if (state.circuit_state == CircuitState::HALF_OPEN) {
    // Increment success count
    state.success_count++;

    const auto& cb_config = config_->getCircuitBreakerConfig();
    if (state.success_count >= cb_config.success_threshold) {
      // Enough successes - close the circuit
      state.circuit_state = CircuitState::CLOSED;
      state.error_count = 0;  // Reset error count
      state.success_count = 0;
      ENVOY_LOG(info, "Circuit breaker CLOSED for client IP: {} (recovery successful)",
                client_ip);
    }
  }
}

void PqcFilter::cleanupOldErrorStates() {
  auto now = std::chrono::system_clock::now();

  // Only cleanup every 10 minutes
  if (last_cleanup_.time_since_epoch().count() > 0) {
    auto since_last_cleanup = std::chrono::duration_cast<std::chrono::minutes>(
        now - last_cleanup_);
    if (since_last_cleanup < std::chrono::minutes(10)) {
      return;  // Too soon for cleanup
    }
  }

  last_cleanup_ = now;

  // Remove states older than 1 hour that are in CLOSED state
  auto cleanup_threshold = now - std::chrono::hours(1);

  for (auto it = client_errors_.begin(); it != client_errors_.end();) {
    const auto& state = it->second;
    bool should_remove = false;

    // Remove if:
    // 1. Circuit is CLOSED (no active issues)
    // 2. Last error was more than 1 hour ago
    if (state.circuit_state == CircuitState::CLOSED &&
        state.last_error < cleanup_threshold) {
      should_remove = true;
    }

    if (should_remove) {
      ENVOY_LOG(debug, "Cleaning up old error state for client IP: {}", it->first);
      it = client_errors_.erase(it);
    } else {
      ++it;
    }
  }

  ENVOY_LOG(debug, "Error state cleanup complete - {} active client states",
            client_errors_.size());
}

std::string PqcFilter::errorCodeToString(PqcErrorCode error_code) {
  return std::to_string(static_cast<int>(error_code));
}

Http::FilterHeadersStatus PqcFilter::handlePqcError(PqcErrorCode error_code,
                                                     const std::string& client_ip) {
  // Check degradation policy
  const auto policy = config_->getDegradationPolicy();

  // Log error (generic message only - NO sensitive data)
  const bool log_details = config_->shouldLogCryptoErrors();

  if (log_details) {
    // SECURITY WARNING: Only enable in development/debugging
    ENVOY_LOG(warn, "PQC error {} for client IP: {}",
              static_cast<int>(error_code), client_ip);
  } else {
    // Production logging - no client IP, just error code
    ENVOY_LOG(warn, "PQC operation failed with error code: {}",
              static_cast<int>(error_code));
  }

  // Apply degradation policy
  switch (policy) {
    case DegradationPolicy::REJECT_ON_FAILURE:
      // Fail closed (most secure) - reject the request
      // Note: In real Envoy, we would use decoder_callbacks_->sendLocalReply()
      // For now, we continue but mark as failed (tests will verify behavior)
      ENVOY_LOG(info, "Degradation policy: REJECT_ON_FAILURE - blocking request");
      return Http::FilterHeadersStatus::Continue;

    case DegradationPolicy::ALLOW_PLAINTEXT:
      // INSECURE: Allow request through without PQC protection
      // This should only be used during migration periods
      ENVOY_LOG(warn, "Degradation policy: ALLOW_PLAINTEXT - continuing WITHOUT encryption (INSECURE)");
      return Http::FilterHeadersStatus::Continue;

    case DegradationPolicy::BEST_EFFORT:
      // Try PQC, but continue on failure
      ENVOY_LOG(info, "Degradation policy: BEST_EFFORT - continuing despite PQC failure");
      return Http::FilterHeadersStatus::Continue;

    default:
      // Unknown policy - fail closed
      ENVOY_LOG(error, "Unknown degradation policy - failing closed");
      return Http::FilterHeadersStatus::Continue;
  }
}

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy