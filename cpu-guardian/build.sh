#!/bin/bash

set -e

# Build eBPF programs
echo "Building eBPF programs..."
cargo +nightly build --package guardian-ebpf --target bpfel-unknown-none -Z build-std=core --release

# Build user-space application
echo "Building user-space application..."
cargo build --package guardian --release

echo "Build complete. Artifacts are in target/"
