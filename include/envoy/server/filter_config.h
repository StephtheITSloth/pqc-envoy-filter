// STUB: Minimal Envoy server filter config interface
#pragma once

namespace Envoy {
namespace Server {
namespace Configuration {

class FactoryContext {
public:
  virtual ~FactoryContext() = default;
};

} // namespace Configuration
} // namespace Server
} // namespace Envoy
