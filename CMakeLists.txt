cmake_minimum_required(VERSION 3.15)
project(pqc_envoy_filter CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_library(OQS_LIBRARY NAMES oqs REQUIRED)
find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h REQUIRED)

# ============================================================================
# Core filter library (C++ implementation - unchanged for existing tests)
# ============================================================================
set(FILTER_CORE_SOURCES
    src/pqc_filter.cc
    src/pqc_filter_config.cc
    src/pqc_filter_factory.cc
    src/base64_utils.cc
)

add_library(pqc_filter_core STATIC ${FILTER_CORE_SOURCES})

target_include_directories(pqc_filter_core PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include  # Stub Envoy headers for compilation
    ${OQS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pqc_filter_core PUBLIC
    ${OQS_LIBRARY}
    OpenSSL::Crypto
    OpenSSL::SSL
)

# ============================================================================
# Dynamic module shared library (C ABI wrapper + core)
# ============================================================================
# This is what Envoy loads at runtime via dynamic modules

add_library(pqc_filter SHARED
    src/pqc_filter_abi_wrapper.cc
)

target_include_directories(pqc_filter PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include  # For abi.h
    ${OQS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pqc_filter PRIVATE
    pqc_filter_core  # Link against core C++ implementation
)

# Set RPATH for runtime library loading
set_target_properties(pqc_filter PROPERTIES
    PREFIX "lib"  # Envoy expects libpqc_filter.so
    OUTPUT_NAME "pqc_filter"
    SUFFIX ".so"
    BUILD_RPATH "/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
)
