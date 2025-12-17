# PQC Test Client Guide

## Overview

Python test client that performs a complete post-quantum key exchange with the PQC Envoy filter using Kyber768 (ML-KEM-768).

## Features

- ✅ Complete PQC handshake (request public key → encapsulate → send ciphertext)
- ✅ Hybrid mode testing (Kyber768 + X25519)
- ✅ Error handling validation (circuit breaker)
- ✅ Color-coded output for easy debugging
- ✅ Multiple test modes

---

## Quick Start

### 1. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Or install individually
pip install requests liboqs-python cryptography
```

### 2. Start PQC Envoy Filter

```bash
# Start with Docker Compose
docker-compose up --build

# Wait for "Envoy is ready" message
```

### 3. Run Test Client

```bash
# Run basic PQC key exchange test
./test-client.py

# Or specify URL
./test-client.py --url http://localhost:10000
```

---

## Usage

### Basic PQC Key Exchange

```bash
./test-client.py --test basic
```

**Output:**
```
============================================================
PQC Envoy Filter - Test Client
============================================================
Target: http://localhost:10000
Algorithm: Kyber768 (ML-KEM-768)
============================================================

Step 1: Request server's Kyber768 public key
[✓] Received public key: 1184 bytes
[✓] Session ID: a1b2c3d4e5f6789012345678abcdef01

Step 2: Encapsulate shared secret with server's public key
[INFO] Using Kyber768 (NIST Level 3)
[✓] Generated ciphertext: 1088 bytes
[✓] Generated shared secret: 32 bytes

Step 3: Send ciphertext to server
[✓] Server accepted ciphertext
[✓] Server successfully decapsulated shared secret

Step 4: Verify key exchange completion
[✓] Client shared secret (SHA256): 7f9a8b3c...
[INFO] Server has derived session key from this secret

============================================================
✓ SUCCESS: PQC Key Exchange Complete!
============================================================

Both client and server now share a quantum-resistant secret!
The secret is protected against attacks by quantum computers.
```

---

### Hybrid Mode Test

Test defense-in-depth with Kyber768 + X25519:

```bash
./test-client.py --test hybrid
```

**What It Tests:**
- Server supports hybrid mode header
- Returns both Kyber768 and X25519 public keys
- Validates X25519 key is 32 bytes

---

### Error Handling Test

Test circuit breaker and error responses:

```bash
./test-client.py --test errors
```

**What It Tests:**
- Sends 6 invalid requests
- Triggers circuit breaker (threshold = 5)
- Validates generic error codes (no oracle attacks)

---

### Run All Tests

```bash
./test-client.py --test all
```

Runs all three tests sequentially.

---

## How It Works

### Step-by-Step Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Request Server's Public Key                       │
│  Client → Server: X-PQC-Init: true                          │
│  Server → Client: X-PQC-Public-Key (1184 bytes)             │
│                   X-PQC-Session-ID                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Encapsulate Shared Secret                         │
│  Client:                                                    │
│    - Uses liboqs Kyber768 implementation                    │
│    - Generates random 32-byte shared secret                 │
│    - Encapsulates with server's public key                  │
│    - Produces 1088-byte ciphertext                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: Send Ciphertext to Server                         │
│  Client → Server: X-PQC-Ciphertext (base64)                 │
│                   X-PQC-Session-ID                          │
│  Server:                                                    │
│    - Decodes base64 ciphertext                              │
│    - Decapsulates with private key                          │
│    - Recovers same 32-byte shared secret                    │
│    - Derives session key using HKDF                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 4: Success                                            │
│  Both sides now have identical shared secret                │
│  Secret is quantum-resistant (Kyber768)                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Code Structure

### Main Class: `PQCClient`

```python
class PQCClient:
    """Post-Quantum Cryptography test client."""

    def __init__(self, envoy_url: str):
        self.envoy_url = envoy_url
        self.kem = None                    # liboqs KeyEncapsulation
        self.session_id = None             # From server
        self.server_public_key = None      # 1184 bytes (Kyber768)
        self.ciphertext = None             # 1088 bytes
        self.shared_secret = None          # 32 bytes
```

### Key Methods

1. **`step1_request_public_key()`**
   - Sends `X-PQC-Init: true`
   - Receives public key + session ID
   - Validates key length (1184 bytes)

2. **`step2_encapsulate_secret()`**
   - Uses liboqs to encapsulate
   - Generates ciphertext (1088 bytes)
   - Generates shared secret (32 bytes)

3. **`step3_send_ciphertext()`**
   - Base64-encodes ciphertext
   - Sends with session ID
   - Checks for error codes

4. **`step4_verify_success()`**
   - Shows shared secret hash
   - Confirms key exchange complete

---

## Dependencies

### liboqs-python

The Open Quantum Safe (OQS) project provides liboqs-python:

```bash
pip install liboqs-python
```

**Supported Algorithms:**
- Kyber512, Kyber768, Kyber1024
- NTRU, Saber, FrodoKEM
- And more...

**Documentation**: https://github.com/open-quantum-safe/liboqs-python

---

## Troubleshooting

### Error: Cannot connect to http://localhost:10000

**Problem**: Envoy container not running

**Solution**:
```bash
# Check if container is running
docker ps | grep pqc-envoy

# If not running, start it
docker-compose up --build

# Check logs
docker logs envoy-pqc
```

---

### Error: liboqs-python not installed

**Problem**: Missing liboqs dependency

**Solution**:
```bash
# Install liboqs-python
pip install liboqs-python

# Or install all requirements
pip install -r requirements.txt

# Verify installation
python -c "import oqs; print(oqs.get_enabled_KEM_mechanisms())"
```

---

### Error: Missing X-PQC-Public-Key header

**Problem**: Filter not loaded or not responding

**Solution**:
```bash
# Check Envoy logs
docker logs envoy-pqc

# Should see:
# "PQC Filter using algorithm: Kyber768"
# "Kyber768 initialized successfully"

# Check filter is loaded
curl http://localhost:9901/config_dump | grep pqc
```

---

### Error: Invalid public key length

**Problem**: Server returned wrong key size

**Possible Causes**:
1. Server using different algorithm (not Kyber768)
2. Corruption in base64 encoding
3. Wrong Envoy configuration

**Solution**:
```bash
# Check server configuration
docker exec envoy-pqc cat /etc/envoy/envoy.yaml

# Verify algorithm in logs
docker logs envoy-pqc | grep "algorithm:"
```

---

## Advanced Usage

### Custom Envoy URL

```bash
# Test remote server
./test-client.py --url https://pqc-envoy.example.com

# Test different port
./test-client.py --url http://localhost:8080
```

### Integration with pytest

```python
# test_pqc_integration.py
from test_client import PQCClient

def test_pqc_key_exchange():
    client = PQCClient("http://localhost:10000")
    assert client.run_basic_test()

def test_hybrid_mode():
    client = PQCClient("http://localhost:10000")
    assert client.test_hybrid_mode()
```

Run with:
```bash
pytest test_pqc_integration.py -v
```

---

## Performance Metrics

Typical timings on modern hardware:

| Operation | Time | Notes |
|-----------|------|-------|
| Request public key | ~5ms | HTTP request + Kyber keygen |
| Encapsulation | ~0.3ms | Client-side liboqs |
| Send ciphertext | ~5ms | HTTP request + server decaps |
| **Total** | **~10-15ms** | Complete handshake |

---

## Security Notes

### What This Proves

✅ **Quantum Resistance**: Uses ML-KEM-768 (NIST standard)
✅ **Key Exchange Works**: Both sides derive same secret
✅ **Session Binding**: Unique session ID prevents replay
✅ **Error Handling**: Circuit breaker protects against attacks

### What This Doesn't Test

⚠️ **Mutual Authentication**: No Dilithium3 signatures yet
⚠️ **MITM Protection**: No certificate validation (HTTP only)
⚠️ **Full Protocol**: Real apps need TLS wrapping

---

## Next Steps

1. **Add Hybrid Mode Support**
   - Implement X25519 key exchange in client
   - Combine secrets with HKDF
   - Test defense-in-depth

2. **Add Dilithium3 Signatures**
   - Sign public keys
   - Verify signatures
   - Prevent MITM attacks

3. **Integration Testing**
   - Load testing (1000+ requests/sec)
   - Failure scenarios
   - Network latency simulation

4. **Production Client**
   - Add retry logic
   - Connection pooling
   - Metrics collection

---

## Example Output (Full Run)

```bash
$ ./test-client.py --test all

============================================================
PQC Envoy Filter - Test Client
============================================================
Target: http://localhost:10000
Algorithm: Kyber768 (ML-KEM-768)
============================================================

Step 1: Request server's Kyber768 public key
[INFO] Connecting to http://localhost:10000/get
[✓] Received public key: 1184 bytes
[✓] Session ID: 7f8a9b2c1d3e4f5a6b7c8d9e0f1a2b3c

Step 2: Encapsulate shared secret with server's public key
[INFO] Using Kyber768 (NIST Level 3)
[INFO] Claimed NIST Level: 3
[✓] Generated ciphertext: 1088 bytes
[✓] Generated shared secret: 32 bytes
[INFO] Shared secret hash: 8d3f7a1c...

Step 3: Send ciphertext to server
[INFO] Sending ciphertext (1088 bytes base64-encoded)
[✓] Server accepted ciphertext
[✓] Server successfully decapsulated shared secret

Step 4: Verify key exchange completion
[✓] Client shared secret (SHA256): 8d3f7a1c4e9b2f6a7d3c1b5e9f2a8c4d
[INFO] Server has derived session key from this secret

============================================================
✓ SUCCESS: PQC Key Exchange Complete!
============================================================

Both client and server now share a quantum-resistant secret!
The secret is protected against attacks by quantum computers.

Step 1: Test hybrid mode (Kyber768 + X25519)
[✓] Hybrid mode active
[✓] X25519 public key: 32 bytes

Step 1: Test error handling and circuit breaker
[INFO] Attempt 1: Error code = 2000
[INFO] Attempt 2: Error code = 2000
[INFO] Attempt 3: Error code = 2000
[INFO] Attempt 4: Error code = 2000
[INFO] Attempt 5: Error code = 2000
[INFO] Attempt 6: Error code = 4000  ← Circuit breaker activated
[✓] Error handling test complete
[INFO] Check server logs for circuit breaker activation

All tests passed!
```

---

**Status**: Test client ready to use
**Dependencies**: Python 3.7+, liboqs-python, requests
**Test Coverage**: Basic handshake, hybrid mode, error handling
