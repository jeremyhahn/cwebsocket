#!/bin/bash
# Code Coverage Script
# Generates coverage reports using lcov/gcov

set -e

echo "================================"
echo "  Code Coverage Report Generator"
echo "================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if lcov is installed
if ! command -v lcov &> /dev/null; then
    echo -e "${RED}Error: lcov is not installed${NC}"
    echo "Install with: sudo apt-get install lcov (Ubuntu) or brew install lcov (macOS)"
    exit 1
fi

# Check if we need to rebuild with coverage flags
if [ ! -f "tests-unit" ]; then
    echo -e "${YELLOW}Building with coverage flags...${NC}"
    ./autogen.sh
    ./configure CFLAGS="-fprofile-arcs -ftest-coverage -O0 -g"
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
fi

# Clean previous coverage data
echo -e "${GREEN}Cleaning previous coverage data...${NC}"
find . -name "*.gcda" -delete
lcov --zerocounters --directory . 2>/dev/null || true

# Run tests
echo -e "${GREEN}Running tests...${NC}"
./tests-unit

# Capture coverage data
echo -e "${GREEN}Capturing coverage data...${NC}"
lcov --capture --directory . --output-file coverage.info

# Remove unwanted files from coverage
echo -e "${GREEN}Filtering coverage data...${NC}"
lcov --remove coverage.info \
    '/usr/*' \
    '*/test/*' \
    '*/tests-unit.c' \
    --output-file coverage.info

# Generate summary
echo ""
echo "================================"
echo "  Coverage Summary"
echo "================================"
lcov --list coverage.info

# Generate HTML report
echo ""
echo -e "${GREEN}Generating HTML report...${NC}"
genhtml coverage.info --output-directory coverage-html --title "cwebsocket Coverage Report"

# Calculate coverage percentage
coverage_percent=$(lcov --summary coverage.info 2>&1 | grep "lines" | awk '{print $2}' | sed 's/%//')

echo ""
echo "================================"
echo "  Coverage Results"
echo "================================"
echo "Coverage: ${coverage_percent}%"
echo "HTML Report: coverage-html/index.html"

# Check coverage threshold
if (( $(echo "$coverage_percent >= 90" | bc -l) )); then
    echo -e "${GREEN}Excellent! Coverage is >= 90%${NC}"
    exit 0
elif (( $(echo "$coverage_percent >= 70" | bc -l) )); then
    echo -e "${YELLOW}Good! Coverage is >= 70% but below 90%${NC}"
    exit 0
else
    echo -e "${RED}Warning! Coverage is below 70%${NC}"
    echo -e "${YELLOW}Please add more tests to improve coverage${NC}"
    exit 1
fi
