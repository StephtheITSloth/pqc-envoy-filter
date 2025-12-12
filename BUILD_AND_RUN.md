# Building and Running PQC Envoy Filter

This guide shows how to build and deploy the production-ready PQC Envoy filter.

## Quick Start

```bash
# Build and run with Docker Compose
docker-compose up --build

# Test the filter
curl -v http://localhost:10000/get \
  -H "X-PQC-Init: true"

# Check admin interface
curl http://localhost:9901/stats | grep pqc
```

## Architecture

```
┌─────────────────────────────────────────┐
│  Stage 1: Builder                       │
│  ┌────────────────────────────────┐    │
│  │ 1. Run TDD tests               │    │
│  │ 2. Build filter .so            │    │
│  │ 3. Link with liboqs + OpenSSL  │    │
│  └────────────────────────────────┘    │
└─────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Stage 2: Runtime                       │
│  ┌────────────────────────────────┐    │
│  │ Official Envoy v1.28.0 binary  │    │
│  │ + PQC filter .so               │    │
│  │ + envoy.yaml config            │    │
│  └────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

## Build Steps

### 1. Build Filter Locally

```bash
# Run tests first (TDD)
bazel test //test:pqc_filter_test --test_output=errors

# Build the .so library
bazel build //src:pqc_filter.so --verbose_failures

# Check the output
ls -lh bazel-bin/src/pqc_filter.so
```

### 2. Build Docker Image

```bash
# Build the multi-stage Docker image
docker build -t pqc-envoy-filter:latest .

# This will:
# 1. Run all TDD tests
# 2. Build the filter .so
# 3. Copy to official Envoy image
# 4. Configure and run
```

### 3. Run Container

```bash
# Run with docker-compose (recommended)
docker-compose up

# Or run directly
docker run -p 10000:10000 -p 9901:9901 pqc-envoy-filter:latest
```

## Testing the Filter

### Basic Health Check

```bash
# Check Envoy is running
curl http://localhost:9901/ready

# Should return: LIVE
```

### Test PQC Key Exchange (Test 20 from TDD)

```bash
# Client requests PQC key exchange
curl -v http://localhost:10000/get \
  -H "X-PQC-Init: true"

# Expected response headers:
# X-PQC-Public-Key: <base64-encoded Kyber768 public key>
# X-PQC-Status: pending
```

### Test Full Cryptographic Flow

```bash
# 1. Request public key
PUBKEY=$(curl -s http://localhost:10000/get \
  -H "X-PQC-Init: true" \
  | grep -i "x-pqc-public-key" \
  | cut -d: -f2 \
  | tr -d ' ')

# 2. Client encapsulates (requires Python script - see test_client.py)
# This simulates Test 21 from TDD

# 3. Send ciphertext to establish shared secret
curl -v http://localhost:10000/get \
  -H "X-PQC-Ciphertext: $CIPHERTEXT"
```

## Debugging

### View Envoy Logs

```bash
# With docker-compose
docker-compose logs -f envoy-pqc

# Direct container
docker logs -f <container-id>
```

### Check Filter Loading

```bash
# Verify filter is loaded
curl http://localhost:9901/config_dump | grep -A 10 "pqc"

# Check stats
curl http://localhost:9901/stats | grep pqc
```

### Inspect .so File

```bash
# Check symbols in built filter
nm -D bazel-bin/src/pqc_filter.so | grep -i envoy

# Check dependencies
ldd bazel-bin/src/pqc_filter.so
```

## Production Deployment

### Security Considerations

1. **TLS Required**: Always run behind TLS for transport security
2. **Rate Limiting**: Add rate limits for key exchange endpoints
3. **Key Rotation**: Implement periodic Kyber keypair rotation
4. **Monitoring**: Track PQC operations via Envoy stats

### Performance Benchmarks

```bash
# Benchmark with wrk
wrk -t4 -c100 -d30s http://localhost:10000/get \
  -H "X-PQC-Init: true"

# Expected: ~5-10ms overhead for key exchange
```

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: envoy-pqc
spec:
  containers:
  - name: envoy
    image: pqc-envoy-filter:latest
    ports:
    - containerPort: 10000
    - containerPort: 9901
    resources:
      limits:
        memory: "512Mi"
        cpu: "1000m"
```

## Troubleshooting

### Filter Not Loading

```bash
# Check .so file exists
docker exec <container> ls -l /etc/envoy/filters/pqc_filter.so

# Check Envoy config
docker exec <container> cat /etc/envoy/envoy.yaml
```

### Cryptographic Errors

```bash
# Check OpenSSL is available
docker exec <container> openssl version

# Verify liboqs algorithms
docker exec <container> strings /etc/envoy/filters/pqc_filter.so | grep -i kyber
```

### Build Failures

```bash
# Clean Bazel cache
bazel clean --expunge

# Rebuild with verbose output
bazel build //src:pqc_filter.so --verbose_failures --sandbox_debug
```

## Architecture Details

### Filter Pipeline

```
HTTP Request
    │
    ▼
┌──────────────────────┐
│ X-PQC-Init header?   │──Yes──> Generate Kyber keypair
│                      │         Add public key to response
└──────────────────────┘
    │ No
    ▼
┌──────────────────────┐
│ X-PQC-Ciphertext?    │──Yes──> Decapsulate shared secret
│                      │         Store for AES-256-GCM
└──────────────────────┘
    │
    ▼
Continue to backend
```

### Cryptographic Components

- **Kyber768 (ML-KEM)**: NIST-standardized KEM for key exchange
- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Dilithium3 (ML-DSA-65)**: Digital signatures (initialized, not yet used)
- **OpenSSL RAND_bytes**: FIPS-compliant random IV generation

## Next Steps

1. Add Dilithium signatures for public key authentication (Test 25-26)
2. Implement encrypted body transmission (Test 24)
3. Add replay attack protection with nonces
4. Benchmark performance under load
5. Add Prometheus metrics for monitoring
