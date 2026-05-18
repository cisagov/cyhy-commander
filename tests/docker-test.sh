#!/bin/sh
# Integration test script for cyhy-commander Docker image
#
# Orchestrates the full CI test pipeline:
#   1. Lint: hadolint for Dockerfile best practices
#   2. Build: docker build with --no-cache
#   3. Structure: container-structure-test against built image
#   4. Security: trivy image scan
#
# Usage:
#   ./tests/docker-test.sh [--skip-lint] [--skip-security] [--image-name NAME]
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Required tool (docker) is missing

set -eu

# Configuration
IMAGE_NAME="cyhy-commander:test"
DOCKERFILE="Dockerfile"
STRUCTURE_TEST_CONFIG="tests/container-structure-test.yaml"
HADOLINT_CONFIG=".hadolint.yaml"
SKIP_LINT=false
SKIP_SECURITY=false

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-lint)
            SKIP_LINT=true
            shift
            ;;
        --skip-security)
            SKIP_SECURITY=true
            shift
            ;;
        --image-name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-lint] [--skip-security] [--image-name NAME]"
            exit 1
            ;;
    esac
done

# Track overall result
FAILURES=0

# Color output helpers (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

pass() {
    printf "${GREEN}PASS${NC}: %s\n" "$1"
}

fail() {
    printf "${RED}FAIL${NC}: %s\n" "$1"
    FAILURES=$((FAILURES + 1))
}

skip() {
    printf "${YELLOW}SKIP${NC}: %s\n" "$1"
}

info() {
    printf "---- %s\n" "$1"
}

# Check for required tools
check_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Docker is required - everything else is optional
if ! check_tool docker; then
    echo "ERROR: docker is required but not found in PATH"
    exit 2
fi

###############################################################################
# Step 1: Lint with hadolint
###############################################################################
info "Step 1: Dockerfile linting"

if [ "$SKIP_LINT" = "true" ]; then
    skip "hadolint (--skip-lint)"
elif ! check_tool hadolint; then
    skip "hadolint (not installed)"
else
    if hadolint --config "$HADOLINT_CONFIG" "$DOCKERFILE"; then
        pass "hadolint"
    else
        fail "hadolint found issues"
    fi
fi

###############################################################################
# Step 2: Build the image
###############################################################################
info "Step 2: Docker build"

# Use current git commit timestamp for reproducible builds, or fallback
if check_tool git && git rev-parse --git-dir >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2>/dev/null || echo "")
else
    SOURCE_DATE_EPOCH=""
fi

BUILD_ARGS="--no-cache --tag ${IMAGE_NAME}"
if [ -n "$SOURCE_DATE_EPOCH" ]; then
    BUILD_ARGS="${BUILD_ARGS} --build-arg SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
fi

if docker build ${BUILD_ARGS} --file "$DOCKERFILE" .; then
    pass "docker build"
else
    fail "docker build"
    echo "ERROR: Build failed. Skipping remaining tests."
    exit 1
fi

###############################################################################
# Step 3: Container structure tests
###############################################################################
info "Step 3: Container structure tests"

if ! check_tool container-structure-test; then
    skip "container-structure-test (not installed)"
else
    if container-structure-test test \
        --image "$IMAGE_NAME" \
        --config "$STRUCTURE_TEST_CONFIG"; then
        pass "container-structure-test"
    else
        fail "container-structure-test"
    fi
fi

###############################################################################
# Step 4: Security scan with trivy
###############################################################################
info "Step 4: Security scan"

if [ "$SKIP_SECURITY" = "true" ]; then
    skip "trivy (--skip-security)"
elif ! check_tool trivy; then
    skip "trivy (not installed)"
else
    if trivy image --exit-code 1 --severity HIGH,CRITICAL "$IMAGE_NAME"; then
        pass "trivy scan (no HIGH/CRITICAL vulnerabilities)"
    else
        fail "trivy scan found HIGH/CRITICAL vulnerabilities"
    fi
fi

###############################################################################
# Summary
###############################################################################
echo ""
info "Test summary"
if [ "$FAILURES" -eq 0 ]; then
    printf "${GREEN}All tests passed.${NC}\n"
    exit 0
else
    printf "${RED}%d test(s) failed.${NC}\n" "$FAILURES"
    exit 1
fi
