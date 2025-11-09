#!/bin/bash
# Simple pre-commit hook for cwebsocket
# This is a lightweight alternative to the full pre-commit framework
# Copy this to .git/hooks/pre-commit and make it executable

set -e

echo "Running pre-commit checks..."
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track if any check failed
FAILED=0

# Function to run a check
run_check() {
    local name="$1"
    local cmd="$2"

    echo -n "[CHECK] $name... "
    if eval "$cmd" > /tmp/precommit-$$.log 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        cat /tmp/precommit-$$.log
        rm -f /tmp/precommit-$$.log
        return 1
    fi
}

# 1. Build check
run_check "Build" "make -j$(nproc 2>/dev/null || echo 1) tests-unit > /dev/null 2>&1" || FAILED=1

# 2. Unit tests
run_check "Unit Tests" "./tests-unit > /dev/null 2>&1" || FAILED=1

# 3. Static analysis (cppcheck)
if command -v cppcheck &> /dev/null; then
    run_check "Static Analysis" "cppcheck --enable=warning --std=c99 --suppress=missingIncludeSystem --error-exitcode=1 -I src/cwebsocket src/cwebsocket/*.c src/*.c 2>&1 | grep -v 'Checking'" || FAILED=1
else
    echo -e "${YELLOW}[SKIP] Static Analysis (cppcheck not installed)${NC}"
fi

# 4. Security scan (flawfinder) - only warn, don't fail
if command -v flawfinder &> /dev/null; then
    echo -n "[CHECK] Security Scan... "
    flawfinder --quiet --minlevel=3 src/cwebsocket/*.c src/*.c > /tmp/flawfinder-$$.log 2>&1 || true
    if [ -s /tmp/flawfinder-$$.log ]; then
        echo -e "${YELLOW}WARNINGS${NC}"
        cat /tmp/flawfinder-$$.log
    else
        echo -e "${GREEN}PASSED${NC}"
    fi
    rm -f /tmp/flawfinder-$$.log
else
    echo -e "${YELLOW}[SKIP] Security Scan (flawfinder not installed)${NC}"
fi

echo ""

# Final result
if [ $FAILED -ne 0 ]; then
    echo -e "${RED}Pre-commit checks FAILED${NC}"
    echo "Please fix the issues above before committing."
    echo "To bypass this check (not recommended): git commit --no-verify"
    exit 1
else
    echo -e "${GREEN}All pre-commit checks PASSED${NC}"
    exit 0
fi
