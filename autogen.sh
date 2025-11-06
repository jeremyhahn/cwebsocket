#!/bin/sh

set -e

echo "Cleaning up old generated files..."
rm -rf autom4te.cache m4
rm -f aclocal.m4 configure config.h.in
rm -f Makefile.in
rm -f compile config.guess config.sub depcomp install-sh missing ltmain.sh

echo "Creating m4 directory..."
mkdir -p m4

echo "Running autoreconf..."
autoreconf --install --force --verbose

echo ""
echo "Autogen complete! Now run:"
echo "  ./configure"
echo "  make"
