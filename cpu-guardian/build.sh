#!/bin/bash
set -e

# Build eBPF program
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --package guardian-ebpf

# Build user-space program
cargo build --package guardian
