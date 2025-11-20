# PQC Envoy Filter MVP

This repository contains an implementation of a Post-Quantum Cryptography (PQC) filter for Envoy Proxy, built using a Test-Driven Development (TDD) methodology.

The primary goal of the initial MVP is to implement the necessary structure and logic to:
1. Parse PQC configuration (algorithm name).
2. Interface with the OpenQuantumSafe (OQS) library.

---

## 🛠️ Build and Development Environment

This project uses Bazel for building and testing, utilizing the official Envoy build container for a consistent Linux development environment.

### Prerequisites

* Docker Desktop
* VS Code with the Remote - Containers Extension

### Getting Started (Day 1 Complete State)

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/StephtheITSloth/pqc-envoy-filter.git](https://github.com/StephtheITSloth/pqc-envoy-filter.git)
   cd pqc-envoy-filter
