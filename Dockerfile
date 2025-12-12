# Multi-stage Dockerfile for PQC Envoy Filter
# Production-ready build with TDD verification
# Architecture: Build filter .so → Load into official Envoy binary

# ============================================================================
# STAGE 1: Build the PQC filter using Bazel
# ============================================================================
FROM envoyproxy/envoy-build-ubuntu:latest AS builder

# Install build-time dependencies for PQC support
# CMake: Required by rules_foreign_cc to build liboqs
# Ninja: Fast build system used by CMake
RUN cd /tmp && \
    wget -q https://github.com/Kitware/CMake/releases/download/v3.27.7/cmake-3.27.7-linux-x86_64.sh && \
    sh cmake-3.27.7-linux-x86_64.sh --prefix=/usr/local --skip-license && \
    rm cmake-3.27.7-linux-x86_64.sh && \
    cmake --version

COPY . /workspace
WORKDIR /workspace

# TDD: Run all tests to verify filter correctness
RUN bazel test //test:pqc_filter_test --test_output=errors

# Build the PQC filter as a shared library (.so)
# This creates a loadable module for Envoy
RUN bazel build //src:pqc_filter.so --verbose_failures

# Extract the built .so file
RUN mkdir -p /output && \
    cp bazel-bin/src/pqc_filter.so /output/pqc_filter.so && \
    ls -lh /output/pqc_filter.so

# ============================================================================
# STAGE 2: Runtime with official Envoy v1.28.0
# ============================================================================
FROM envoyproxy/envoy:v1.28.0

# Install OpenSSL runtime libraries (needed for AES-256-GCM)
USER root
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled PQC filter from builder stage
COPY --from=builder /output/pqc_filter.so /etc/envoy/filters/pqc_filter.so

# Copy Envoy configuration
COPY envoy.yaml /etc/envoy/envoy.yaml

# Expose ports
# 10000: Main HTTP listener (with PQC filter)
# 9901: Admin interface
EXPOSE 10000 9901

# Set LD_LIBRARY_PATH to ensure filter dependencies are found
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu

# Health check on admin endpoint
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:9901/ready || exit 1

# Run Envoy with our configuration
# Debug logging enabled to see PQC filter in action
CMD ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]