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

  // Access underlying data (for testing convenience)
  const std::vector<uint8_t>& data() const { return data_; }

private:
  std::vector<uint8_t> data_;
};

} // namespace Buffer
} // namespace Envoy
