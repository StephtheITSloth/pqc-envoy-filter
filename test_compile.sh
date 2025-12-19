#!/bin/bash
# Quick test to see if stub headers work

set -e

echo "Testing stub header compilation..."

# Create a minimal test file
cat > /tmp/test_stub.cc << 'EOF'
#include "include/envoy/http/filter.h"
#include <iostream>

int main() {
  Envoy::Http::LowerCaseString key("test");
  std::cout << "Stub headers work!" << std::endl;
  return 0;
}
EOF

# Try to compile
g++ -std=c++17 -I. /tmp/test_stub.cc -o /tmp/test_stub && echo "✓ Compilation succeeded" || echo "✗ Compilation failed"

rm -f /tmp/test_stub.cc /tmp/test_stub
