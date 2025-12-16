#!/bin/bash
# Automated test script for PQC Envoy Filter Docker deployment
# Tests all major functionality including error handling

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ENVOY_PORT=10000
ADMIN_PORT=9901
CONTAINER_NAME="pqc-envoy-test"
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${YELLOW}[TEST $TEST_COUNT]${NC} $1"
}

test_passed() {
    ((PASS_COUNT++))
    echo -e "${GREEN}✓ PASSED${NC}"
    echo ""
}

test_failed() {
    ((FAIL_COUNT++))
    echo -e "${RED}✗ FAILED${NC} $1"
    echo ""
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
}

# Set trap to cleanup on exit
trap cleanup EXIT

# ============================================================================
# SETUP
# ============================================================================

log_info "Starting PQC Envoy Filter Docker Tests"
echo "=========================================="
echo ""

# Stop any existing container
cleanup

# Start the container
log_info "Starting PQC Envoy container..."
docker run -d \
    --name $CONTAINER_NAME \
    -p $ENVOY_PORT:10000 \
    -p $ADMIN_PORT:9901 \
    pqc-envoy-filter:latest

# Wait for Envoy to be ready
log_info "Waiting for Envoy to become ready..."
for i in {1..30}; do
    if curl -s http://localhost:$ADMIN_PORT/ready | grep -q "LIVE"; then
        log_info "Envoy is ready!"
        break
    fi
    echo -n "."
    sleep 1
done
echo ""

# Verify Envoy is actually ready
if ! curl -s http://localhost:$ADMIN_PORT/ready | grep -q "LIVE"; then
    log_error "Envoy failed to start"
    exit 1
fi

# ============================================================================
# TEST 1: Basic Health Check
# ============================================================================

((TEST_COUNT++))
log_test "Basic health check"

if curl -s http://localhost:$ADMIN_PORT/ready | grep -q "LIVE"; then
    test_passed
else
    test_failed "Health check endpoint not responding"
fi

# ============================================================================
# TEST 2: PQC Public Key Exchange (Test 20 from TDD)
# ============================================================================

((TEST_COUNT++))
log_test "PQC public key exchange"

RESPONSE=$(curl -s -v http://localhost:$ENVOY_PORT/get -H "X-PQC-Init: true" 2>&1)

if echo "$RESPONSE" | grep -q "X-PQC-Public-Key:" && \
   echo "$RESPONSE" | grep -q "X-PQC-Session-ID:"; then
    test_passed
else
    test_failed "Missing PQC headers in response"
fi

# ============================================================================
# TEST 3: Session ID Generation
# ============================================================================

((TEST_COUNT++))
log_test "Session ID generation and format"

SESSION_ID=$(echo "$RESPONSE" | grep -i "X-PQC-Session-ID:" | awk '{print $3}' | tr -d '\r')

if [ ${#SESSION_ID} -eq 32 ]; then
    test_passed
else
    test_failed "Session ID has incorrect length: ${#SESSION_ID} (expected 32)"
fi

# ============================================================================
# TEST 4: Hybrid Mode Support (Test 28)
# ============================================================================

((TEST_COUNT++))
log_test "Hybrid mode (Kyber768 + X25519)"

HYBRID_RESPONSE=$(curl -s -v http://localhost:$ENVOY_PORT/get \
    -H "X-PQC-Init: true" \
    -H "X-PQC-Mode: hybrid" 2>&1)

if echo "$HYBRID_RESPONSE" | grep -q "X-PQC-X25519-Public-Key:" && \
   echo "$HYBRID_RESPONSE" | grep -q "X-PQC-Mode: hybrid"; then
    test_passed
else
    test_failed "Hybrid mode not working correctly"
fi

# ============================================================================
# TEST 5: Error Handling - Missing Session ID (Test 29)
# ============================================================================

((TEST_COUNT++))
log_test "Error handling - missing session ID"

ERROR_RESPONSE=$(curl -s -v http://localhost:$ENVOY_PORT/get \
    -H "X-PQC-Ciphertext: invalid_ciphertext" 2>&1)

# Should handle error gracefully without crash
if echo "$ERROR_RESPONSE" | grep -q "HTTP/"; then
    test_passed
else
    test_failed "Server crashed or didn't respond"
fi

# ============================================================================
# TEST 6: Circuit Breaker - Repeated Failures (Test 31)
# ============================================================================

((TEST_COUNT++))
log_test "Circuit breaker after repeated failures"

# Send 6 invalid requests from same IP to trigger circuit breaker (threshold=5)
for i in {1..6}; do
    curl -s http://localhost:$ENVOY_PORT/get \
        -H "X-PQC-Ciphertext: invalid!!!" \
        -H "X-PQC-Session-ID: fake-session" \
        -H "X-Forwarded-For: 10.0.0.100" >/dev/null 2>&1
done

# Check logs for circuit breaker activation
if docker logs $CONTAINER_NAME 2>&1 | grep -q "Circuit breaker OPENED"; then
    test_passed
else
    test_failed "Circuit breaker did not activate"
fi

# ============================================================================
# TEST 7: Admin Interface Stats
# ============================================================================

((TEST_COUNT++))
log_test "Admin interface statistics"

if curl -s http://localhost:$ADMIN_PORT/stats | grep -q "listener"; then
    test_passed
else
    test_failed "Admin stats not available"
fi

# ============================================================================
# TEST 8: Filter Loaded Successfully
# ============================================================================

((TEST_COUNT++))
log_test "PQC filter loaded in Envoy"

if docker logs $CONTAINER_NAME 2>&1 | grep -q "PQC Filter using algorithm"; then
    test_passed
else
    test_failed "PQC filter not loaded or not logging"
fi

# ============================================================================
# TEST 9: Key Rotation Support (Test 26/27)
# ============================================================================

((TEST_COUNT++))
log_test "Key version tracking"

KEY_VERSION_RESPONSE=$(curl -s -v http://localhost:$ENVOY_PORT/get \
    -H "X-PQC-Init: true" 2>&1)

if echo "$KEY_VERSION_RESPONSE" | grep -q "X-PQC-Key-Version:"; then
    test_passed
else
    test_failed "Key version header not present"
fi

# ============================================================================
# TEST 10: Container Resource Usage
# ============================================================================

((TEST_COUNT++))
log_test "Container resource usage"

STATS=$(docker stats $CONTAINER_NAME --no-stream --format "{{.CPUPerc}} {{.MemUsage}}")
CPU=$(echo $STATS | awk '{print $1}' | tr -d '%')
MEM=$(echo $STATS | awk '{print $2}')

log_info "Container using: CPU=${CPU}%, Memory=${MEM}"

# Reasonable resource usage (< 100% CPU, check passes if we can get stats)
if [ -n "$CPU" ]; then
    test_passed
else
    test_failed "Could not get container stats"
fi

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total Tests:  $TEST_COUNT"
echo -e "Passed:       ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed:       ${RED}$FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    log_info "All tests passed! ✓"
    echo ""
    log_info "You can access the running container:"
    echo "  - Main HTTP listener: http://localhost:$ENVOY_PORT"
    echo "  - Admin interface:    http://localhost:$ADMIN_PORT"
    echo ""
    log_info "To stop the container: docker stop $CONTAINER_NAME"
    exit 0
else
    log_error "$FAIL_COUNT test(s) failed"
    echo ""
    log_info "Check container logs: docker logs $CONTAINER_NAME"
    exit 1
fi
