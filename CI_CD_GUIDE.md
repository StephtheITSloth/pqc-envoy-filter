# CI/CD Guide - PQC Envoy Filter

## Overview

This project uses GitHub Actions for automated CI/CD with comprehensive testing, security scanning, and multi-platform Docker image builds.

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Trigger: Push / PR / Release                               │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Job 1: Lint & Code Quality                                 │
│  - Check file formatting                                    │
│  - Validate Docker files (Hadolint)                         │
│  - Find TODOs                                               │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Job 2: Security Scanning                                   │
│  - Trivy vulnerability scan                                 │
│  - Upload results to GitHub Security                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Job 3: Build & Test (All 32 Tests)                         │
│  - Build Docker image with Bazel tests                      │
│  - Run automated integration tests (test-docker.sh)         │
│  - Upload test artifacts                                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Job 4: Build Multi-Platform Images                         │
│  - Build for linux/amd64, linux/arm64                       │
│  - Push to Docker Hub                                       │
│  - Tag: latest, branch name, SHA, version                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼ (only on release)
┌─────────────────────────────────────────────────────────────┐
│  Job 5: Create GitHub Release                               │
│  - Generate release notes                                   │
│  - Upload documentation artifacts                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Workflows

### 1. Continuous Integration (CI)

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main`

**Jobs**:
1. Lint and code quality checks
2. Security scanning (Trivy)
3. Build Docker image with all tests
4. Run integration tests

**Expected Duration**: ~15-20 minutes

### 2. Continuous Deployment (CD)

**Triggers**:
- Push to `main` branch
- GitHub release published

**Jobs**:
- All CI jobs
- Build and push multi-platform Docker images
- Create GitHub release (on release only)

**Docker Hub Tags**:
```bash
stephtheitsloth/pqc-envoy-filter:latest        # Latest main branch
stephtheitsloth/pqc-envoy-filter:main          # Main branch
stephtheitsloth/pqc-envoy-filter:develop       # Develop branch
stephtheitsloth/pqc-envoy-filter:v1.0.0        # Release version
stephtheitsloth/pqc-envoy-filter:1.0           # Major.minor
stephtheitsloth/pqc-envoy-filter:main-abc123   # Branch-SHA
```

---

## Setup Instructions

### 1. GitHub Repository Secrets

Add these secrets to your GitHub repository:
**Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Description | How to Get |
|-------------|-------------|------------|
| `DOCKER_HUB_USERNAME` | Docker Hub username | Your Docker Hub account name |
| `DOCKER_HUB_TOKEN` | Docker Hub access token | Docker Hub → Account Settings → Security → New Access Token |

### 2. Docker Hub Access Token

```bash
# 1. Go to Docker Hub
https://hub.docker.com/settings/security

# 2. Click "New Access Token"
Name: GitHub Actions
Permissions: Read, Write, Delete

# 3. Copy the token and add to GitHub secrets
```

### 3. Enable GitHub Actions

```bash
# 1. Go to repository Settings → Actions → General
# 2. Set "Actions permissions" to "Allow all actions"
# 3. Set "Workflow permissions" to "Read and write permissions"
# 4. Check "Allow GitHub Actions to create and approve pull requests"
```

---

## Running Tests Locally

### Docker Build & Test

```bash
# 1. Build the Docker image (runs all 32 Bazel tests)
docker build -t pqc-envoy-filter:latest .

# 2. Run automated integration tests
chmod +x test-docker.sh
./test-docker.sh

# Expected output:
# [TEST 1] Basic health check
# ✓ PASSED
#
# [TEST 2] PQC public key exchange
# ✓ PASSED
# ...
# ========================================
# Test Summary
# ========================================
# Total Tests:  10
# Passed:       10
# Failed:       0
```

### Manual Docker Run

```bash
# Start the container
docker run -d \
  --name pqc-envoy \
  -p 10000:10000 \
  -p 9901:9901 \
  pqc-envoy-filter:latest

# Test PQC key exchange
curl -v http://localhost:10000/get -H "X-PQC-Init: true"

# Check admin stats
curl http://localhost:9901/stats | grep pqc

# View logs
docker logs pqc-envoy

# Cleanup
docker stop pqc-envoy
docker rm pqc-envoy
```

---

## Test Coverage

### Unit Tests (Bazel)

**Location**: `test/pqc_filter_test.cc`
**Count**: 32 tests

Tests include:
- ✅ Core PQC functionality (Tests 1-24)
- ✅ Session binding (Test 25)
- ✅ Key rotation (Tests 26-27)
- ✅ Hybrid mode (Test 28)
- ✅ Error handling (Tests 29-32)

### Integration Tests (Docker)

**Location**: `test-docker.sh`
**Count**: 10 tests

Tests include:
1. Basic health check
2. PQC public key exchange
3. Session ID generation
4. Hybrid mode support
5. Error handling (missing session ID)
6. Circuit breaker activation
7. Admin interface stats
8. Filter loading verification
9. Key version tracking
10. Container resource usage

---

## Security Scanning

### Trivy Vulnerability Scanner

**Scans**:
- Docker image layers
- Dependencies (liboqs, OpenSSL, Envoy)
- Known CVEs

**Reports**:
- Uploaded to GitHub Security tab
- Available in workflow artifacts

**View Results**:
```bash
# In GitHub UI
Repository → Security → Code scanning alerts
```

### Hadolint (Dockerfile Linter)

**Checks**:
- Best practices for Dockerfile
- Security issues (running as root, etc.)
- Optimization opportunities

**Local Run**:
```bash
docker run --rm -i hadolint/hadolint < Dockerfile
```

---

## Deployment Strategies

### 1. Development Deployment

**Trigger**: Push to `develop` branch

```bash
# CI builds and tests
# Docker image tagged as: develop, develop-<sha>
# Available on Docker Hub immediately

# Pull and run
docker pull stephtheitsloth/pqc-envoy-filter:develop
docker run -p 10000:10000 stephtheitsloth/pqc-envoy-filter:develop
```

### 2. Production Deployment

**Trigger**: Create GitHub release

```bash
# 1. Create release on GitHub
# Releases → Draft a new release
# Tag: v1.0.0
# Title: PQC Envoy Filter v1.0.0
# Description: (auto-generated from CI)

# 2. CI runs full pipeline
# - All tests
# - Security scan
# - Multi-platform build
# - Push to Docker Hub with version tags

# 3. Deploy to production
docker pull stephtheitsloth/pqc-envoy-filter:v1.0.0
docker-compose -f docker-compose.prod.yml up -d
```

### 3. Rollback Strategy

```bash
# List available versions
docker images stephtheitsloth/pqc-envoy-filter

# Rollback to previous version
docker pull stephtheitsloth/pqc-envoy-filter:v1.0.0
docker-compose down
docker-compose up -d
```

---

## Monitoring CI/CD

### GitHub Actions Dashboard

**View Workflows**:
```
Repository → Actions
```

**Check Status**:
- ✅ Green: All jobs passed
- ❌ Red: Job failed (click for details)
- 🟡 Yellow: Job in progress

### Notifications

**Email Notifications**:
- GitHub → Settings → Notifications
- Enable "Actions" notifications

**Slack Integration** (optional):
```yaml
# Add to workflow
- name: Notify Slack
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

---

## Performance Benchmarks

### Benchmark Job

**Runs**: On every push to `main`

**Metrics**:
- Throughput (requests/second)
- Memory usage
- Container startup time

**View Results**:
```bash
# In workflow logs
Actions → Benchmark → Performance Benchmarks
```

### Load Testing (Optional)

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Run load test
ab -n 1000 -c 10 \
  -H "X-PQC-Init: true" \
  http://localhost:10000/get
```

---

## Troubleshooting

### Build Fails on Tests

**Symptom**: Bazel tests fail during Docker build

**Solution**:
```bash
# Run tests locally
bazel test //test:pqc_filter_test --test_output=errors

# Check which test failed
bazel test //test:pqc_filter_test --test_output=all

# Fix the test and commit
git add test/
git commit -m "fix: Fix failing test"
git push
```

### Docker Push Fails

**Symptom**: "unauthorized: authentication required"

**Solution**:
1. Verify Docker Hub credentials in GitHub secrets
2. Check token hasn't expired
3. Ensure repository name matches Docker Hub username

```bash
# Test locally
docker login -u stephtheitsloth
# Enter token when prompted

# Try manual push
docker tag pqc-envoy-filter stephtheitsloth/pqc-envoy-filter:test
docker push stephtheitsloth/pqc-envoy-filter:test
```

### Integration Tests Fail

**Symptom**: test-docker.sh reports failures

**Solution**:
```bash
# Run tests with verbose output
./test-docker.sh 2>&1 | tee test-output.log

# Check container logs
docker logs pqc-envoy-test

# Debug specific test
docker exec -it pqc-envoy-test bash
curl -v http://localhost:10000/get -H "X-PQC-Init: true"
```

---

## CI/CD Metrics

### Key Performance Indicators (KPIs)

| Metric | Target | Current |
|--------|--------|---------|
| Test Success Rate | 100% | 100% |
| Build Time | <20 min | ~15 min |
| Test Coverage | 100% features | 32/32 tests |
| Security Vulns | 0 high/critical | TBD |
| Docker Image Size | <500 MB | ~300 MB |

### Improvement Roadmap

**Phase 1** (Current):
- ✅ Automated testing
- ✅ Docker builds
- ✅ Security scanning
- ✅ Multi-platform support

**Phase 2** (Future):
- [ ] Performance regression testing
- [ ] Automated dependency updates (Dependabot)
- [ ] Helm chart publishing
- [ ] Kubernetes deployment automation

---

## Best Practices

### Commit Messages

Follow Conventional Commits:
```bash
feat: Add new feature
fix: Fix bug
docs: Update documentation
test: Add tests
ci: Update CI/CD
chore: Maintenance tasks
```

### Branch Strategy

```
main       → Production-ready code
develop    → Development branch
feature/*  → Feature branches
fix/*      → Bug fix branches
release/*  → Release preparation
```

### Pull Request Checklist

- [ ] All tests pass locally
- [ ] Code follows project style
- [ ] Documentation updated
- [ ] Security implications considered
- [ ] Performance impact assessed

---

## Resources

### Documentation
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Docker Build Push Action](https://github.com/docker/build-push-action)
- [Trivy Scanner](https://github.com/aquasecurity/trivy-action)

### Project Documentation
- [BUILD_AND_RUN.md](BUILD_AND_RUN.md) - Build and deployment
- [ERROR_HANDLING_COMPLETE.md](ERROR_HANDLING_COMPLETE.md) - Error handling
- [VIABILITY_ASSESSMENT.md](VIABILITY_ASSESSMENT.md) - Project status

---

**Status**: CI/CD pipeline ready for production
**Last Updated**: 2025-12-16
**Maintained By**: PQC Envoy Filter Team
