# Stage 1: The Build Stage
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

# TDD step: build and run tests first
RUN bazel build //test/...

# RUN bazel test //test/... 

# Stage 2: The Final Runtime Stage (Minimal)
# FROM ubuntu:20.04  # Will be finalized later, but shows the concept
# COPY --from=builder /path/to/compiled/envoy_binary /usr/local/bin/envoy 
# CMD ["/usr/local/bin/envoy", "-c", "envoy.yaml"]