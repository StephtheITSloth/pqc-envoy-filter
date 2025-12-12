#include "src/pqc_filter.h"
#include "src/base64_utils.h"

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

    // Base64-decode the ciphertext
    std::vector<uint8_t> ciphertext = Base64Utils::decode(std::string(encoded_ciphertext));

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
      ENVOY_LOG(info, "Successfully decapsulated ciphertext and established shared secret");
    } else {
      ENVOY_LOG(error, "Failed to decapsulate ciphertext from client");
      has_shared_secret_ = false;
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

  kyber_public_key_ = make_secure_buffer(kyber_kem_->length_public_key);
  kyber_secret_key_ = make_secure_buffer(kyber_kem_->length_secret_key);

  OQS_STATUS status = OQS_KEM_keypair(
    kyber_kem_.get(),
    kyber_public_key_.get(),
    kyber_secret_key_.get()
  );

  if (status != OQS_SUCCESS) {
    ENVOY_LOG(error, "Failed to generate Kyber-768 keypair - status: {}", status);
    return;
  }

  ENVOY_LOG(info, "{} initialized successfully - public_key_size: {} bytes, secret_key_size: {} bytes",
            kem_alg, kyber_kem_->length_public_key, kyber_kem_->length_secret_key);
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

  // Perform KEM decapsulation (server-side operation)
  // This uses the server's secret key to decrypt the ciphertext
  // and recover the same shared secret the client generated
  OQS_STATUS status = OQS_KEM_decaps(
      kyber_kem_.get(),
      out_shared_secret,     // Output: recovered shared secret (32 bytes)
      ciphertext,            // Input: ciphertext from client (1088 bytes)
      kyber_secret_key_.get() // Input: server's secret key (2400 bytes)
  );

  if (status != OQS_SUCCESS) {
    ENVOY_LOG(error, "KEM decapsulation failed - status: {}", status);
    return false;
  }

  ENVOY_LOG(debug, "Server decapsulation successful - recovered shared_secret_size: {} bytes",
            kyber_kem_->length_shared_secret);

  return true;
}

// ============================================================================
// RESPONSE PROCESSING (StreamEncoderFilter interface)
// ============================================================================

Http::FilterHeadersStatus PqcFilter::encodeHeaders(
    Http::ResponseHeaderMap& headers, bool end_stream) {

  // If client requested PQC, inject our public key in the response
  if (client_requested_pqc_) {
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

    // Add X-PQC-Status header
    headers.addCopy(
        Http::LowerCaseString("x-pqc-status"),
        "pending"
    );

    ENVOY_LOG(info, "Sent PQC public key in response header ({} bytes encoded to {} chars)",
              kyber_kem_->length_public_key, encoded_public_key.size());

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

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy