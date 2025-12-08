# PQC Envoy Filter

A production-ready Post-Quantum Cryptography (PQC) HTTP filter for Envoy Proxy, built with a headers-only approach for fast builds and easy deployment.

## Architecture Overview

This project implements a **standalone external Envoy filter** using a headers-only build strategy:

- **Build Phase**: Compile filter against protobuf definitions only (no Envoy source needed)
- **Runtime Phase**: Filter `.so` links against official Envoy binary in Docker
- **Result**: Fast CI/CD builds (~4 seconds), small artifacts (~8KB), production-ready from day 1

### Key Benefits

✅ **Fast Builds**: 4 seconds vs 30+ minutes for full Envoy builds
✅ **Official Envoy**: Uses `envoyproxy/envoy` official images with independent security updates
✅ **Small Artifacts**: 8KB filter library vs 300MB+ Envoy binary
✅ **Easy Testing**: Swap Envoy docker tags to test different versions
✅ **TDD Approach**: Test-Driven Development with Google Test framework

---

## Build and Development Environment

### Prerequisites

- Docker Desktop
- VS Code with Remote - Containers Extension
- Bazel 6.5.0 (automatically configured via `.bazelversion`)

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/StephtheITSloth/pqc-envoy-filter.git
   cd pqc-envoy-filter
   ```

2. **Open in VS Code Dev Container:**
   - Open the folder in VS Code
   - Click "Reopen in Container" when prompted
   - The dev container will build automatically

3. **Build the filter:**
   ```bash
   bazel build //src:pqc_filter_config_lib
   ```

4. **Run tests:**
   ```bash
   bazel test //test:pqc_filter_config_test
   ```

---

## Project Structure

```
pqc-envoy-filter/
├── .bazelversion              # Pin to Bazel 6.5.0 for compatibility
├── WORKSPACE                  # Minimal dependencies (protobuf, googletest)
├── .bazelrc                   # C++17, non-root build configuration
├── src/
│   ├── BUILD                  # Filter library targets
│   ├── pqc_filter_config.h    # Configuration wrapper
│   ├── pqc_filter_config.cc
│   └── proto/
│       ├── BUILD              # Protobuf compilation
│       └── pqc_filter.proto   # Filter configuration schema
├── test/
│   ├── BUILD                  # Test targets
│   └── pqc_filter_config_test.cc
└── README.md
```

---

## Current Status

### ✅ Completed (Minimal Build)

- [x] Bazel 6.5.0 build system configured
- [x] Headers-only approach implemented
- [x] Protobuf configuration schema (PqcFilterConfig)
- [x] Configuration wrapper class with validation
- [x] Unit tests passing with Google Test
- [x] Build artifacts: static library (.a) and shared library (.so)

### 🚧 Next Steps

1. Add runtime Envoy headers for HTTP filter implementation
2. Re-enable protobuf validation rules (protoc-gen-validate)
3. Implement actual HTTP filter logic
4. Create filter factory for Envoy integration
5. Add Docker multi-stage build
6. Create Kubernetes deployment manifests

---

## Configuration Schema

The filter accepts the following configuration (defined in [src/proto/pqc_filter.proto](src/proto/pqc_filter.proto)):

```protobuf
message PqcFilterConfig {
    // Post-quantum algorithm to use
    // Supported: "kyber512", "kyber768", "kyber1024", "ml-kem-512", "ml-kem-768", "ml-kem-1024"
    string algorithm_name = 1;

    // Enable verbose logging for debugging
    bool enable_logging = 2;

    // Maximum bytes to inspect per request for PQC handshake
    // Range: 0 bytes (disabled) to 1MB
    uint32 max_inspect_bytes = 3;
}
```

---

## Build Performance

Current build metrics (after initial protobuf compilation):

- **Library build**: ~4 seconds
- **Test execution**: ~12 seconds
- **Initial setup**: ~196 seconds (one-time, cached after)
- **Build output**:
  - `libpqc_filter_config_lib.a` (2.3KB)
  - `libpqc_filter_config_lib.so` (7.7KB)

---

## Development Workflow

### Building

```bash
# Build the filter library
bazel build //src:pqc_filter_config_lib

# Build everything
bazel build //...
```

### Testing

```bash
# Run specific test
bazel test //test:pqc_filter_config_test

# Run all tests
bazel test //test/...

# Run tests with verbose output
bazel test //test/... --test_output=all
```

### Cleaning

```bash
# Clean build artifacts
bazel clean

# Full clean including external dependencies
bazel clean --expunge
```

---

## Dependencies

Minimal dependencies for fast builds:

- **Protocol Buffers 3.15.8**: Message definitions
- **Google Test 1.12.1**: Unit testing framework
- **Go Rules 0.35.0**: Required by protoc-gen-validate
- **protoc-gen-validate 0.6.7**: Available for future validation rules

See [WORKSPACE](WORKSPACE) for complete dependency configuration.

---

## Contributing

This project follows Test-Driven Development (TDD):

1. Write failing test first
2. Implement minimal code to pass test
3. Refactor while keeping tests green
4. Commit with descriptive messages

---

## License

[Add your license here]

---

## Contact

[Add contact information]
