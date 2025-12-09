#pragma once

#include <cstdint>
#include <cstring>  // For std::memcpy
#include <string>
#include <vector>

// Mock implementation of Envoy's Buffer::Instance for unit testing
// This lets us test filter logic without pulling in full Envoy dependency

namespace Envoy {
namespace Buffer {

/**
 * RawSlice represents a contiguous chunk of buffer memory
 * Matches Envoy's Buffer::RawSlice structure
 */
struct RawSlice {
  void* mem_;    // Pointer to the data
  size_t len_;   // Length of this slice

  RawSlice(void* mem, size_t len) : mem_(mem), len_(len) {}
};

/**
 * Minimal mock of Buffer::Instance interface
 * Only implements methods needed for our PqcFilter tests
 */
class Instance {
public:
  // Constructor: Create buffer with initial data
  explicit Instance(const std::vector<uint8_t>& data) : data_(data) {}

  // Constructor: Create buffer from string
  explicit Instance(const std::string& str) {
    data_.assign(str.begin(), str.end());
  }

  // Constructor: Empty buffer
  Instance() = default;

  // Get buffer length (this is what our filter will call)
  uint64_t length() const { return data_.size(); }

  // Copy data out of buffer (simplified version)
  // In real Envoy, this is more complex due to fragmentation
  void copyOut(size_t start, size_t size, void* data) const {
    if (start + size > data_.size()) {
      size = data_.size() - start;  // Don't read past end
    }
    std::memcpy(data, data_.data() + start, size);
  }

  // Get raw slices (production-ready API)
  // In real Envoy, buffer can be fragmented across multiple slices
  // Our mock simulates this by returning a single slice
  std::vector<RawSlice> getRawSlices() const {
    std::vector<RawSlice> slices;
    if (!data_.empty()) {
      // Cast away const for the mock (safe because we control the lifetime)
      // In production Envoy, slices point to actual buffer memory
      slices.emplace_back(const_cast<uint8_t*>(data_.data()), data_.size());
    }
    return slices;
  }

  // Access underlying data (for testing convenience)
  const std::vector<uint8_t>& data() const { return data_; }

private:
  std::vector<uint8_t> data_;
};

} // namespace Buffer
} // namespace Envoy
