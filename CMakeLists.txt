cmake_minimum_required(VERSION 3.15)
project(pqc_envoy_filter CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_library(OQS_LIBRARY NAMES oqs REQUIRED)
find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h REQUIRED)

# Filter source files
set(FILTER_SOURCES
    src/pqc_filter.cc
    src/pqc_filter_config.cc
    src/base64_utils.cc
)

# Build shared library
add_library(pqc_filter SHARED ${FILTER_SOURCES})

target_include_directories(pqc_filter PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${OQS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    # Envoy headers will be added in Docker build
)

target_link_libraries(pqc_filter PRIVATE
    ${OQS_LIBRARY}
    OpenSSL::Crypto
    OpenSSL::SSL
)

# Set RPATH for runtime library loading
set_target_properties(pqc_filter PROPERTIES
    OUTPUT_NAME "pqc_filter"
    SUFFIX ".so"
    BUILD_RPATH "/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
)
