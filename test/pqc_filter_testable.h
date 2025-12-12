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

// OpenSSL includes for AES-256-GCM
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

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
      }
    }

    // Check for X-PQC-Ciphertext header (client sending ciphertext for decapsulation)
    auto ciphertext_header = headers.get(Http::LowerCaseString("x-pqc-ciphertext"));
    if (!ciphertext_header.empty()) {
      const auto& encoded_ciphertext = ciphertext_header[0]->value().getStringView();

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
        ENVOY_LOG(info, "Successfully decapsulated ciphertext and established shared secret");
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
      // Base64-encode the Kyber768 public key (1184 bytes → ~1580 chars)
      std::string encoded_public_key = base64Encode(
          kyber_public_key_.get(),
          kyber_kem_->length_public_key
      );

      // Add X-PQC-Public-Key header
      headers.addCopy(Http::LowerCaseString("x-pqc-public-key"), encoded_public_key);

      // Add X-PQC-Status header
      headers.addCopy(Http::LowerCaseString("x-pqc-status"), "pending");

      ENVOY_LOG(info, "Injected PQC public key in response headers ({} bytes base64-encoded)",
                encoded_public_key.size());

      client_requested_pqc_ = false;  // Reset flag
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

  // Status check methods
  bool hasKyberInitialized() const { return kyber_kem_ != nullptr; }
  bool hasDilithiumInitialized() const { return dilithium_sig_ != nullptr; }

  // Shared secret access (established after server decapsulation)
  const uint8_t* getSharedSecret() const {
    return has_shared_secret_ ? shared_secret_.get() : nullptr;
  }
  size_t getSharedSecretSize() const {
    return has_shared_secret_ && kyber_kem_ ? kyber_kem_->length_shared_secret : 0;
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

    // Perform KEM decapsulation (server-side operation)
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

  // Initialization functions
  void initializeKyber() {
    // Simple stub for now - full implementation will be in pqc_filter.cc
    kyber_kem_ = std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)>(
        OQS_KEM_new("Kyber768"), OQS_KEM_free);

    if (!kyber_kem_) {
      ENVOY_LOG(error, "Failed to create Kyber-768 KEM instance");
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
      ENVOY_LOG(error, "Failed to generate Kyber-768 keypair");
      return;
    }

    ENVOY_LOG(info, "Kyber-768 initialized successfully");
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
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
