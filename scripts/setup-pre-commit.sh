#!/bin/bash
# Setup pre-commit hooks for cwebsocket development

set -e

echo "================================"
echo "  Pre-commit Hook Setup"
echo "================================"
echo ""

# Check if git repository
if [ ! -d ".git" ]; then
    echo "Error: Not a git repository"
    exit 1
fi

# Check if pre-commit is installed
if ! command -v pre-commit &> /dev/null; then
    echo "Installing pre-commit..."
    if command -v pip3 &> /dev/null; then
        pip3 install pre-commit
    elif command -v pip &> /dev/null; then
        pip install pre-commit
    else
        echo "Error: pip not found. Please install Python and pip first."
        exit 1
    fi
fi

# Install pre-commit hooks
echo "Installing pre-commit hooks..."
pre-commit install
pre-commit install --hook-type pre-push

echo ""
echo "================================"
echo "  Pre-commit Hooks Installed"
echo "================================"
echo ""
echo "The following checks will run automatically:"
echo "  - On commit:"
echo "    * Unit tests"
echo "    * Static analysis (cppcheck)"
echo "    * Security scan (flawfinder)"
echo "    * Code formatting"
echo ""
echo "  - On push:"
echo "    * Full build check"
echo "    * Memory leak check (valgrind)"
echo ""
echo "To skip hooks (not recommended):"
echo "  git commit --no-verify"
echo ""
echo "To run hooks manually:"
echo "  pre-commit run --all-files"
echo ""
