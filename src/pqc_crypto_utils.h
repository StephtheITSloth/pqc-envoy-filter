#pragma once

#include <memory>
#include <cstdint>
#include <cstring>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

    /**
     * Secure memory deleter for cryptographic key material.
     *
     * Security features:
     * 1. Zeros memory before freeing to prevent key material from persisting
     * 2. Uses volatile to prevent compiler from optimizing away the zeroing
     * 3. Uses reinterpret_cast for raw memory access
     *
     * Production note: For maximum security, consider using OQS_MEM_secure_alloc
     * which additionally locks memory pages to prevent swapping to disk.
     * However, this requires platform-specific support (mlock on Linux).
     */
    template <typename T>
    struct SecureDeleter {
        size_t size;

        explicit SecureDeleter(size_t s = 0) : size(s) {}

        void operator()(T* ptr) const {
            if (ptr && size > 0) {
                // Zero memory before freeing - prevents key material from persisting
                volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
                for (size_t i = 0; i < size; ++i) {
                    p[i] = 0;
                }
            }
            delete[] ptr;
        }
    };

    using SecureBuffer = std::unique_ptr<uint8_t[], SecureDeleter<uint8_t>>;

    /**
     * Allocate secure memory for cryptographic keys.
     *
     * The returned buffer will:
     * - Automatically zero its contents when destroyed
     * - Use RAII for automatic cleanup
     *
     * @param size Number of bytes to allocate
     * @return Smart pointer managing the secure memory
     */
    inline SecureBuffer make_secure_buffer(size_t size) {
        return SecureBuffer(new uint8_t[size], SecureDeleter<uint8_t>(size));
    }

}// namespace PqcFilter
}// namespace HttpFilters
}// namespace Extensions
}// namespace Envoy
