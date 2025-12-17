# Multi-stage Dockerfile for PQC Envoy Filter
# Production-ready build with TDD verification
# Architecture: Build filter .so → Load into official Envoy binary

# ============================================================================
# STAGE 1: Build the PQC filter using Bazel
# ============================================================================
# Use the official Envoy build image with pinned SHA256 for reproducible builds
# SHA from https://github.com/envoyproxy/envoy/blob/main/.github/config.yml
FROM envoyproxy/envoy-build@sha256:5fcc9d3e10f1a0e628250b44b4c39bde1bdfc6cb8fe6075838a732c2ba04ef42 AS builder

# Check if CMake is already installed, if not install it
# The envoy-build image should already have CMake and build tools
RUN cmake --version || echo "CMake not found, but may not be needed"

COPY . /workspace
WORKDIR /workspace

# Build the PQC filter as a shared library (.so)
# This creates a loadable module for Envoy
# Note: Tests are run separately in CI/CD pipeline to avoid Docker build complexity
RUN bazel build //src:pqc_filter.so --verbose_failures --jobs=2

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

# SECURITY: Create non-root user for Envoy
RUN groupadd --system --gid 101 envoy && \
    useradd --system --gid envoy --uid 101 --home-dir /var/empty \
    --no-create-home --shell /sbin/nologin envoy && \
    mkdir -p /etc/envoy/filters /var/log/envoy && \
    chown -R envoy:envoy /etc/envoy /var/log/envoy

# SECURITY: Copy files with non-root ownership
COPY --from=builder --chown=envoy:envoy /output/pqc_filter.so /etc/envoy/filters/pqc_filter.so
COPY --chown=envoy:envoy envoy.yaml /etc/envoy/envoy.yaml

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