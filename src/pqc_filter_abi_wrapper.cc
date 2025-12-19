// C ABI Wrapper for Envoy Dynamic Modules
// This file provides the C interface required by Envoy while delegating to
// the existing C++ PqcFilter implementation.
//
// MIGRATION STRATEGY:
// - Phase 1: This wrapper calls existing C++ code (zero logic changes)
// - Phase 2: Gradually move logic from C++ to C as we gain confidence
// - All existing tests continue to work during migration

#include "envoy/dynamic_modules/abi.h"
#include "envoy/dynamic_modules/abi_version.h"
#include "src/pqc_filter.h"
#include "src/pqc_filter_config.h"
#include <string>
#include <memory>

// Use C++ features internally (we're just providing a C interface)
using namespace Envoy::Extensions::HttpFilters::PqcFilter;
using namespace Envoy::Extensions::DynamicModules;

// ============================================================================
// Internal state structures (not exposed to Envoy)
// ============================================================================

// Per-filter-config state (created once per filter config in envoy.yaml)
struct pqc_filter_config_t {
  std::shared_ptr<PqcFilterConfig> cpp_config;
};

// Per-stream state (created once per HTTP stream)
struct pqc_filter_instance_t {
  std::unique_ptr<PqcFilter> cpp_filter;
  envoy_dynamic_module_type_http_filter_envoy_ptr envoy_filter;
};

// ============================================================================
// Required Event Hooks - These are called by Envoy
// ============================================================================

extern "C" {

/**
 * Called when module is loaded. Return ABI version string.
 */
envoy_dynamic_module_type_abi_version_module_ptr
envoy_dynamic_module_on_program_init() {
  // Return the ABI version from abi_version.h
  return kAbiVersion;
}

/**
 * Create filter configuration (called once per filter config in envoy.yaml)
 */
envoy_dynamic_module_type_http_filter_config_module_ptr
envoy_dynamic_module_on_http_filter_config_new(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr envoy_filter_config,
    const char* name,
    size_t name_length,
    const char* config,
    size_t config_length) {

  // Create our internal config structure
  auto* pqc_config = new pqc_filter_config_t();

  // Parse configuration (for now, just use default algorithm)
  // TODO: Parse JSON/YAML config to extract algorithm name
  std::string algorithm_name = "Kyber768";  // Default

  // Delegate to existing C++ config class
  pqc_config->cpp_config = std::make_shared<PqcFilterConfig>(algorithm_name);

  return reinterpret_cast<envoy_dynamic_module_type_http_filter_config_module_ptr>(pqc_config);
}

/**
 * Destroy filter configuration
 */
void envoy_dynamic_module_on_http_filter_config_destroy(
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config) {

  auto* pqc_config = reinterpret_cast<pqc_filter_config_t*>(
      const_cast<void*>(filter_config));
  delete pqc_config;
}

/**
 * Create new filter instance (called once per HTTP stream)
 */
envoy_dynamic_module_type_http_filter_module_ptr
envoy_dynamic_module_on_http_filter_new(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr envoy_filter_config,
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr,
    envoy_dynamic_module_type_http_filter_envoy_ptr envoy_filter) {

  auto* pqc_config = reinterpret_cast<pqc_filter_config_t*>(
      const_cast<void*>(filter_config_ptr));

  // Create per-stream instance
  auto* instance = new pqc_filter_instance_t();
  instance->envoy_filter = envoy_filter;

  // Delegate to existing C++ filter class
  instance->cpp_filter = std::make_unique<PqcFilter>(pqc_config->cpp_config);

  return reinterpret_cast<envoy_dynamic_module_type_http_filter_module_ptr>(instance);
}

/**
 * Destroy filter instance
 */
void envoy_dynamic_module_on_http_filter_destroy(
    envoy_dynamic_module_type_http_filter_module_ptr filter_ptr) {

  auto* instance = reinterpret_cast<pqc_filter_instance_t*>(
      const_cast<void*>(filter_ptr));
  delete instance;
}

/**
 * Handle request headers (equivalent to decodeHeaders)
 *
 * This is where we bridge from C ABI to our existing C++ filter logic.
 */
envoy_dynamic_module_type_event_http_request_headers_status
envoy_dynamic_module_on_http_filter_request_headers(
    envoy_dynamic_module_type_http_filter_module_ptr filter_ptr,
    envoy_dynamic_module_type_http_request_headers_envoy_ptr request_headers,
    bool end_stream) {

  auto* instance = reinterpret_cast<pqc_filter_instance_t*>(
      const_cast<void*>(filter_ptr));

  // TODO: Convert C ABI headers to C++ HeaderMap and call cpp_filter->decodeHeaders()
  // For now, just continue

  return envoy_dynamic_module_type_event_http_request_headers_status_continue;
}

/**
 * Handle response headers (equivalent to encodeHeaders)
 */
envoy_dynamic_module_type_event_http_response_headers_status
envoy_dynamic_module_on_http_filter_response_headers(
    envoy_dynamic_module_type_http_filter_module_ptr filter_ptr,
    envoy_dynamic_module_type_http_response_headers_envoy_ptr response_headers,
    bool end_stream) {

  // TODO: Bridge to cpp_filter->encodeHeaders()

  return envoy_dynamic_module_type_event_http_response_headers_status_continue;
}

// Implement remaining optional hooks with pass-through behavior
// We don't need these for basic PQC filter functionality

envoy_dynamic_module_type_event_http_request_body_status
envoy_dynamic_module_on_http_filter_request_body(
    envoy_dynamic_module_type_http_filter_module_ptr filter_ptr,
    envoy_dynamic_module_type_http_request_body_envoy_ptr request_body,
    bool end_stream) {
  return envoy_dynamic_module_type_event_http_request_body_status_continue;
}

envoy_dynamic_module_type_event_http_request_trailers_status
envoy_dynamic_module_on_http_filter_request_trailers(
    envoy_dynamic_module_type_http_filter_module_ptr filter_ptr,
    envoy_dynamic_module_type_http_request_trailers_envoy_ptr request_trailers) {
  return envoy_dynamic_module_type_event_http_request_trailers_status_continue;
}

envoy_dynamic_module_type_event_http_response_body_status
envoy_dynamic_module_on_http_filter_response_body(
    envoy_dynamic_module_type_http_filter_module_ptr filter_ptr,
    envoy_dynamic_module_type_http_response_body_envoy_ptr response_body,
    bool end_stream) {
  return envoy_dynamic_module_type_event_http_response_body_status_continue;
}

envoy_dynamic_module_type_event_http_response_trailers_status
envoy_dynamic_module_on_http_filter_response_trailers(
    envoy_dynamic_module_type_http_filter_module_ptr filter_ptr,
    envoy_dynamic_module_type_http_response_trailers_envoy_ptr response_trailers) {
  return envoy_dynamic_module_type_event_http_response_trailers_status_continue;
}

} // extern "C"
