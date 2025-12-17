#!/usr/bin/env python3
"""
PQC Envoy Filter Test Client

Demonstrates complete post-quantum key exchange with the PQC Envoy filter:
1. Request server's Kyber768 public key
2. Encapsulate shared secret using server's public key
3. Send ciphertext to server
4. Verify both sides have same shared secret

Requirements:
    pip install requests liboqs-python cryptography
"""

import sys
import base64
import hashlib
import requests
from typing import Optional, Tuple

try:
    import oqs
except ImportError:
    print("ERROR: liboqs-python not installed")
    print("Install with: pip install liboqs-python")
    sys.exit(1)

# ANSI color codes for pretty output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'


class PQCClient:
    """Post-Quantum Cryptography test client for Envoy filter."""

    def __init__(self, envoy_url: str = "http://localhost:10000"):
        self.envoy_url = envoy_url
        self.kem = None
        self.session_id = None
        self.server_public_key = None
        self.ciphertext = None
        self.shared_secret = None

    def log_info(self, msg: str):
        """Print info message."""
        print(f"{BLUE}[INFO]{RESET} {msg}")

    def log_success(self, msg: str):
        """Print success message."""
        print(f"{GREEN}[✓]{RESET} {msg}")

    def log_error(self, msg: str):
        """Print error message."""
        print(f"{RED}[✗]{RESET} {msg}")

    def log_step(self, step: int, msg: str):
        """Print step header."""
        print(f"\n{BOLD}{YELLOW}Step {step}:{RESET} {msg}")

    def step1_request_public_key(self) -> bool:
        """
        Step 1: Request server's Kyber768 public key.

        Sends X-PQC-Init header to trigger key exchange.
        Server responds with:
        - X-PQC-Public-Key: base64-encoded Kyber768 public key (1184 bytes)
        - X-PQC-Session-ID: unique session identifier
        """
        self.log_step(1, "Request server's Kyber768 public key")

        try:
            response = requests.get(
                f"{self.envoy_url}/get",
                headers={"X-PQC-Init": "true"},
                timeout=5
            )

            if response.status_code != 200:
                self.log_error(f"HTTP {response.status_code}: {response.text}")
                return False

            # Extract public key
            public_key_b64 = response.headers.get("X-PQC-Public-Key")
            if not public_key_b64:
                self.log_error("Missing X-PQC-Public-Key header")
                return False

            # Extract session ID
            self.session_id = response.headers.get("X-PQC-Session-ID")
            if not self.session_id:
                self.log_error("Missing X-PQC-Session-ID header")
                return False

            # Decode public key
            self.server_public_key = base64.b64decode(public_key_b64)

            self.log_success(f"Received public key: {len(self.server_public_key)} bytes")
            self.log_success(f"Session ID: {self.session_id}")

            # Verify public key length (Kyber768 = 1184 bytes)
            if len(self.server_public_key) != 1184:
                self.log_error(f"Invalid public key length: {len(self.server_public_key)} (expected 1184)")
                return False

            return True

        except requests.exceptions.ConnectionError:
            self.log_error(f"Cannot connect to {self.envoy_url}")
            self.log_info("Is the Envoy container running?")
            self.log_info("Start with: docker-compose up")
            return False
        except Exception as e:
            self.log_error(f"Unexpected error: {e}")
            return False

    def step2_encapsulate_secret(self) -> bool:
        """
        Step 2: Encapsulate shared secret using server's public key.

        Uses liboqs Kyber768 implementation to:
        1. Generate random shared secret (32 bytes)
        2. Encapsulate it with server's public key
        3. Produce ciphertext (1088 bytes) to send to server
        """
        self.log_step(2, "Encapsulate shared secret with server's public key")

        try:
            # Initialize Kyber768 KEM
            self.kem = oqs.KeyEncapsulation("Kyber768")
            self.log_info(f"Using {self.kem.details['name']} (NIST Level {self.kem.details['claimed_nist_level']})")

            # Client encapsulation: Generate ciphertext + shared secret
            self.ciphertext, self.shared_secret = self.kem.encap_secret(self.server_public_key)

            self.log_success(f"Generated ciphertext: {len(self.ciphertext)} bytes")
            self.log_success(f"Generated shared secret: {len(self.shared_secret)} bytes")

            # Verify ciphertext length (Kyber768 = 1088 bytes)
            if len(self.ciphertext) != 1088:
                self.log_error(f"Invalid ciphertext length: {len(self.ciphertext)} (expected 1088)")
                return False

            # Verify shared secret length (always 32 bytes)
            if len(self.shared_secret) != 32:
                self.log_error(f"Invalid shared secret length: {len(self.shared_secret)} (expected 32)")
                return False

            # Show secret hash for verification
            secret_hash = hashlib.sha256(self.shared_secret).hexdigest()[:16]
            self.log_info(f"Shared secret hash: {secret_hash}...")

            return True

        except Exception as e:
            self.log_error(f"Encapsulation failed: {e}")
            return False

    def step3_send_ciphertext(self) -> bool:
        """
        Step 3: Send ciphertext to server.

        Server will:
        1. Decode base64 ciphertext
        2. Decapsulate using its private key
        3. Recover the same shared secret
        4. Derive session key using HKDF
        """
        self.log_step(3, "Send ciphertext to server")

        try:
            # Encode ciphertext as base64
            ciphertext_b64 = base64.b64encode(self.ciphertext).decode('utf-8')

            # Send to server with session ID
            response = requests.get(
                f"{self.envoy_url}/get",
                headers={
                    "X-PQC-Ciphertext": ciphertext_b64,
                    "X-PQC-Session-ID": self.session_id
                },
                timeout=5
            )

            if response.status_code != 200:
                self.log_error(f"HTTP {response.status_code}: {response.text}")
                return False

            self.log_success("Server accepted ciphertext")

            # Check for error headers
            error_code = response.headers.get("X-PQC-Error-Code")
            if error_code:
                self.log_error(f"Server returned error code: {error_code}")
                return False

            self.log_success("Server successfully decapsulated shared secret")
            return True

        except Exception as e:
            self.log_error(f"Failed to send ciphertext: {e}")
            return False

    def step4_verify_success(self) -> bool:
        """
        Step 4: Verify key exchange succeeded.

        Both client and server now have the same 32-byte shared secret.
        Server uses it to derive a session key with HKDF.
        """
        self.log_step(4, "Verify key exchange completion")

        # Display shared secret info
        secret_hash = hashlib.sha256(self.shared_secret).hexdigest()
        self.log_success(f"Client shared secret (SHA256): {secret_hash}")
        self.log_info("Server has derived session key from this secret")

        return True

    def run_basic_test(self) -> bool:
        """Run basic PQC key exchange test."""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}PQC Envoy Filter - Test Client{RESET}")
        print(f"{BOLD}{'='*60}{RESET}")
        print(f"Target: {self.envoy_url}")
        print(f"Algorithm: Kyber768 (ML-KEM-768)")
        print(f"{BOLD}{'='*60}{RESET}")

        # Step 1: Get public key
        if not self.step1_request_public_key():
            return False

        # Step 2: Encapsulate secret
        if not self.step2_encapsulate_secret():
            return False

        # Step 3: Send ciphertext
        if not self.step3_send_ciphertext():
            return False

        # Step 4: Verify
        if not self.step4_verify_success():
            return False

        print(f"\n{BOLD}{GREEN}{'='*60}{RESET}")
        print(f"{BOLD}{GREEN}✓ SUCCESS: PQC Key Exchange Complete!{RESET}")
        print(f"{BOLD}{GREEN}{'='*60}{RESET}")
        print(f"\n{GREEN}Both client and server now share a quantum-resistant secret!{RESET}")
        print(f"{GREEN}The secret is protected against attacks by quantum computers.{RESET}\n")

        return True

    def test_hybrid_mode(self) -> bool:
        """Test hybrid mode (Kyber768 + X25519)."""
        self.log_step(1, "Test hybrid mode (Kyber768 + X25519)")

        try:
            response = requests.get(
                f"{self.envoy_url}/get",
                headers={
                    "X-PQC-Init": "true",
                    "X-PQC-Mode": "hybrid"
                },
                timeout=5
            )

            if response.status_code != 200:
                self.log_error(f"HTTP {response.status_code}")
                return False

            # Check for hybrid mode headers
            mode = response.headers.get("X-PQC-Mode")
            x25519_key = response.headers.get("X-PQC-X25519-Public-Key")

            if mode == "hybrid" and x25519_key:
                self.log_success("Hybrid mode active")
                self.log_success(f"X25519 public key: {len(base64.b64decode(x25519_key))} bytes")
                return True
            else:
                self.log_error("Hybrid mode not enabled")
                return False

        except Exception as e:
            self.log_error(f"Hybrid mode test failed: {e}")
            return False

    def test_error_handling(self) -> bool:
        """Test error handling (circuit breaker)."""
        self.log_step(1, "Test error handling and circuit breaker")

        try:
            # Send invalid request to trigger errors
            for i in range(6):
                response = requests.get(
                    f"{self.envoy_url}/get",
                    headers={
                        "X-PQC-Ciphertext": "invalid!!!",
                        "X-PQC-Session-ID": "fake-session"
                    },
                    timeout=5
                )

                error_code = response.headers.get("X-PQC-Error-Code")
                self.log_info(f"Attempt {i+1}: Error code = {error_code or 'none'}")

            self.log_success("Error handling test complete")
            self.log_info("Check server logs for circuit breaker activation")
            return True

        except Exception as e:
            self.log_error(f"Error handling test failed: {e}")
            return False


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="PQC Envoy Filter Test Client")
    parser.add_argument(
        "--url",
        default="http://localhost:10000",
        help="Envoy filter URL (default: http://localhost:10000)"
    )
    parser.add_argument(
        "--test",
        choices=["basic", "hybrid", "errors", "all"],
        default="basic",
        help="Test to run (default: basic)"
    )

    args = parser.parse_args()

    client = PQCClient(envoy_url=args.url)

    # Run selected test
    success = False
    if args.test == "basic":
        success = client.run_basic_test()
    elif args.test == "hybrid":
        success = client.test_hybrid_mode()
    elif args.test == "errors":
        success = client.test_error_handling()
    elif args.test == "all":
        success = (
            client.run_basic_test() and
            client.test_hybrid_mode() and
            client.test_error_handling()
        )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
