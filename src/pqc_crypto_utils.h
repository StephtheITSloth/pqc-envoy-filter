#pragma once

#include <memory>
#include <cstdint>
#include <cstring>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PqcFilter {

    template <typename T>
    struct SecureDeleter {
        size_t size;

        explicit SecureDeleter(size_t s = 0) : size(s) {};

        void operator()(T* ptr) const {
            if (ptr && size > 0) {
                volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
                for (size_t i = 0; i < size; ++i) {
                    p[i] = 0; //Shred each byte;
                }
            }
            delete[] ptr;
        }
    };

    using SecureBuffer = std::unique_ptr<uint8_t[], SecureDeleter<uint8_t>>;

    inline SecureBuffer make_secure_buffer(size_t size) {
        return SecureBuffer(new uint8_t[size], SecureDeleter<uint8_t>(size));
    }

}// namespace PqcFilter
}// namespace HttpFilters
}// namespace Extensions
}// namespace Envoy