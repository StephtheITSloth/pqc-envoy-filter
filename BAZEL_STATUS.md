# Bazel Build Status

## Current Status: Docker-Only Build

**Bazel unit tests are disabled.** Use Docker for all builds and tests.

## Why Bazel Tests Don't Work

After extensive investigation attempting multiple approaches, Bazel unit tests cannot build due to Envoy's complex dependency requirements:

### Root Cause: Dependency Chain Complexity

1. **rules_python Version Conflict**
   - Envoy v1.28.0 requires `python_register_toolchains` from rules_python
   - This function exists in some versions but not in a way compatible with Envoy's usage
   - Attempting to patch Envoy's BUILD files causes cycle dependencies

2. **Generated Proto Headers**
   - Envoy headers include `.pb.h` files (protobuf-generated)
   - These don't exist in Envoy source - only generated during Envoy's full build
   - Cannot vendor headers without also generating ~100+ proto files

3. **Transitive Dependencies**
   - Envoy headers transitively depend on:
     - Abseil (absl::string_view, etc.)
     - Protobuf runtime
     - gRPC
     - Many more...
   - Vendoring all dependencies would require maintaining a complex fork

### Approaches Attempted

1. ✗ **Loading Envoy dependencies**: rules_python version conflicts
2. ✗ **Patching Envoy BUILD files**: Cycle dependency errors
3. ✗ **Using build_file_content with glob()**: glob() runs before archive extraction
4. ✗ **Vendoring headers**: Missing generated proto files
5. ✗ **Creating stub headers**: Requires stubbing dozens of dependencies

## Recommended Approach: Docker

### Building

```bash
# Build filter in Docker (uses envoyproxy/envoy-build image)
docker-compose build

# Or build manually
docker build -t pqc-envoy-filter .
```

### Testing

```bash
# Run integration tests
docker-compose up
./test-client.py

# Or use test script
./test-docker.sh
```

### CI/CD

GitHub Actions workflow:
1. ✅ Builds Docker image with full Envoy environment
2. ✅ Runs integration tests against running container
3. ✅ Publishes multi-platform images (amd64, arm64)

## What Still Works in Bazel

The following Bazel targets work fine:

```bash
# liboqs builds successfully
bazel build @liboqs//:oqs

# Proto definitions compile
bazel build //src/proto:pqc_config_proto
```

## Future: envoy-headers-bazel Package

For a proper Bazel solution, we could create a separate `envoy-headers-bazel` repository that:

1. Downloads Envoy source
2. Extracts ALL headers (envoy/, source/)
3. Generates ALL proto files
4. Vendors ALL dependencies (Abseil, Protobuf, etc.)
5. Publishes as tarball release with working BUILD file

This would be reusable across projects but requires significant effort (~1 week).

See conversation history for detailed design.

## Summary

**Use Docker for everything.** It works perfectly and is production-ready.

Bazel tests are disabled to avoid maintaining a complex dependency fork.
