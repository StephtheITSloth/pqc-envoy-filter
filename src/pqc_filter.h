#pragma once

#include <oqs/oqs.h>

#include "envoy/http/filter.h"
#include "source/common/common/logger.h"
#include "src/pqc_crypto_utils.h"
#include "src/pqc_filter_config.h"

// OpenSSL includes for AES-256-GCM
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

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

  // Status check methods
  bool hasKyberInitialized() const { return kyber_kem_ != nullptr; }
  bool hasDilithiumInitialized() const { return dilithium_sig_ != nullptr; }

  // Shared secret access (established after server decapsulation)
  const uint8_t* getSharedSecret() const;
  size_t getSharedSecretSize() const;

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

private:
  std::shared_ptr<PqcFilterConfig> config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{nullptr};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{nullptr};

  // HTTP header key exchange state
  bool client_requested_pqc_{false};  // Track if client sent X-PQC-Init header

  // Kyber-768 KEM instance (manages the algorithm)
  std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kyber_kem_;

  // Kyber-768 keys (securely managed)
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

  // Initialization functions
  void initializeKyber();
  void initializeDilithium();
};

} // namespace PqcFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy