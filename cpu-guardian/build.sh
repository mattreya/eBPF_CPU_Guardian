#!/bin/bash
set -e

# Build the eBPF program
echo "Building guardian-ebpf..."
cd guardian-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core
cd ..

# Build the user-space controller
echo "Building guardian..."
cd guardian
cargo build
cd ..

echo "Build complete."
