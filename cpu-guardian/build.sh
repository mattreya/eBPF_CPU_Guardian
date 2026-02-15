#!/bin/bash
set -e

# Go to the cpu-guardian directory
cd "$(dirname "$0")"

# Build eBPF program
echo "Building eBPF program..."
cargo +nightly build -p guardian-ebpf --target bpfel-unknown-none -Z build-std=core

# Build user-space program
echo "Building user-space program..."
cargo build -p guardian

echo "Build successful!"
