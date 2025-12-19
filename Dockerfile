# Multi-stage Dockerfile for PQC Envoy Filter
# Production-ready build with TDD verification
# Architecture: Build filter .so → Load into official Envoy binary

# ============================================================================
# STAGE 1: Build the PQC filter using CMake
# ============================================================================
# Bazel build fails due to unresolvable rules_python conflicts with Envoy
# Using CMake instead with vendored Envoy headers
FROM ubuntu:22.04 AS builder

# Install build dependencies
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .

# Install liboqs from source
WORKDIR /tmp/liboqs-build
RUN git clone --depth 1 --branch 0.9.0 https://github.com/open-quantum-safe/liboqs.git . && \
    mkdir build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -B build && \
    ninja -C build && \
    ninja -C build install

# Build the filter using CMake (no Envoy headers needed - using C ABI!)
WORKDIR /workspace/build
RUN cmake -GNinja -DCMAKE_BUILD_TYPE=Release .. && \
    ninja && \
    mkdir -p /output && \
    cp libpqc_filter.so /output/ && \
    ls -lh /output/libpqc_filter.so

# ============================================================================
# STAGE 2: Runtime with official Envoy v1.36 (Dynamic Modules support)
# ============================================================================
FROM envoyproxy/envoy:v1.36.2

# Install OpenSSL runtime libraries (needed for AES-256-GCM)
USER root
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs shared library from builder stage
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/

# SECURITY: Create non-root user for Envoy
RUN groupadd --system --gid 101 envoy && \
    useradd --system --gid envoy --uid 101 --home-dir /var/empty \
    --no-create-home --shell /sbin/nologin envoy && \
    mkdir -p /etc/envoy/filters /var/log/envoy && \
    chown -R envoy:envoy /etc/envoy /var/log/envoy

# SECURITY: Copy files with non-root ownership
COPY --from=builder --chown=envoy:envoy /output/libpqc_filter.so /etc/envoy/filters/libpqc_filter.so
COPY --chown=envoy:envoy envoy.yaml /etc/envoy/envoy.yaml

# Set environment variable for dynamic module search path
ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/etc/envoy/filters

# Expose ports
# 10000: Main HTTP listener (with PQC filter)
# 9901: Admin interface
EXPOSE 10000 9901

# Set LD_LIBRARY_PATH to ensure filter dependencies are found
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu

# Health check on admin endpoint
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:9901/ready || exit 1

# Security labels
LABEL security.non-root=true
LABEL security.user=envoy
LABEL security.uid=101

# SECURITY: Switch to non-root user before running Envoy
USER envoy

# Run Envoy with our configuration (now as non-root user)
CMD ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]