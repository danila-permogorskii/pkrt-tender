#!/bin/bash
# Build script for minimal test unikernel
# This compilation approach produces a unikernel-compatible binary

echo "Building minimal test unikernel..."

# Compile with flags that create unikernel-compatible binary:
# -nostdlib: Don't link standard library
# -static: Force static linking (no dynamic dependencies)
# -nostartfiles: Don't use standard startup files
# -fno-stack-protector: Disable stack protection (simplifies binary)
# -O2: Optimize for size and performance
# -Wall: Enable warnings
gcc -nostdlib -static -nostartfiles -fno-stack-protector -O2 -Wall \
    -o minimal_unikernel minimal_unikernel.c

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Binary size: $(ls -lh minimal_unikernel | awk '{print $5}')"
    echo "Testing execution..."
    ./minimal_unikernel
    echo "Exit status: $?"
else
    echo "Build failed!"
    exit 1
fi