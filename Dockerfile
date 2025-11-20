# Stage 1: The Build Stage
FROM envoyproxy/envoy-build-ubuntu:latest AS builder
COPY . /workspace
WORKDIR /workspace


# Install the necessary build-time tools (like liboqs later)
# RUN ...

# TDD step: build and run tests first
RUN bazel build //test/...

# RUN bazel test //test/... 

# Stage 2: The Final Runtime Stage (Minimal)
# FROM ubuntu:20.04  # Will be finalized later, but shows the concept
# COPY --from=builder /path/to/compiled/envoy_binary /usr/local/bin/envoy 
# CMD ["/usr/local/bin/envoy", "-c", "envoy.yaml"]