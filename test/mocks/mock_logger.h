#pragma once

#include <iostream>
#include <sstream>

// Mock implementation of Envoy's Logger for unit testing
// Captures log messages instead of sending to Envoy's logging system

namespace Envoy {
namespace Logger {

// Logger IDs (minimal set for our filter)
enum class Id {
  filter,
};

// Mock loggable base class
template<Id id>
class Loggable {
  // Empty base class for now - in real Envoy, this provides logging methods
};

} // namespace Logger
} // namespace Envoy

// Mock ENVOY_LOG macro - captures instead of actually logging
// In tests, we can verify what was logged
namespace EnvoyLogCapture {
  inline std::ostringstream last_log;
  inline std::string log_level;
}

#define ENVOY_LOG(level, ...) \
  do { \
    EnvoyLogCapture::log_level = #level; \
    EnvoyLogCapture::last_log.str(""); \
    EnvoyLogCapture::last_log.clear(); \
    /* Note: We'll implement proper format string handling when needed */ \
  } while(0)
