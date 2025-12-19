// STUB: Minimal buffer implementation
#pragma once

#include <cstdint>
#include <cstddef>

namespace Envoy {
namespace Buffer {

class Instance {
public:
  virtual ~Instance() = default;
  virtual uint64_t length() const = 0;
  virtual void drain(uint64_t size) = 0;
  virtual const uint8_t* linearize(uint32_t size) = 0;
};

} // namespace Buffer
} // namespace Envoy
