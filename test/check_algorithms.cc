#include <iostream>
#include <oqs/oqs.h>

int main() {
  std::cout << "=== Available KEM Algorithms ===" << std::endl;
  for (size_t i = 0; i < OQS_KEM_alg_count(); i++) {
    const char *alg_name = OQS_KEM_alg_identifier(i);
    int is_enabled = OQS_KEM_alg_is_enabled(alg_name);
    std::cout << (is_enabled ? "[✓] " : "[ ] ") << alg_name << std::endl;
  }

  std::cout << "\n=== Available Signature Algorithms ===" << std::endl;
  for (size_t i = 0; i < OQS_SIG_alg_count(); i++) {
    const char *alg_name = OQS_SIG_alg_identifier(i);
    int is_enabled = OQS_SIG_alg_is_enabled(alg_name);
    std::cout << (is_enabled ? "[✓] " : "[ ] ") << alg_name << std::endl;
  }

  return 0;
}
