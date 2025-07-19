#!/bin/bash
# Build script for minimal test unikernel
# This compilation approach produces a unikernel-compatible binary

set -e  # Exit on any error

echo "Building minimal test unikernel..."

# Clean previous build
if [ -f minimal_unikernel ]; then
    echo "Cleaning previous build..."
    rm -f minimal_unikernel
fi

# Compile with flags that create unikernel-compatible binary:
# -nostdlib: Don't link standard library
# -static: Force static linking (no dynamic dependencies)
# -nostartfiles: Don't use standard startup files
# -fno-stack-protector: Disable stack protection (simplifies binary)
# -O2: Optimize for size and performance
# -Wall: Enable warnings
# -Wextra: Additional warnings
gcc -nostdlib -static -nostartfiles -fno-stack-protector -O2 -Wall -Wextra \
    -o minimal_unikernel minimal_unikernel.c

echo "Build successful!"
echo "Binary size: $(ls -lh minimal_unikernel | awk '{print $5}')"
echo "File type: $(file minimal_unikernel)"
echo ""
echo "Testing execution..."
./minimal_unikernel
echo "Exit status: $?"

# Optional: Display binary information
echo ""
echo "Binary analysis:"
echo "Entry point: $(readelf -h minimal_unikernel 2>/dev/null | grep 'Entry point' || echo 'N/A')"
echo "Dependencies: $(ldd minimal_unikernel 2>/dev/null || echo 'statically linked')"