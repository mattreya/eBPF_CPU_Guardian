#!/bin/bash
set -e

# Build the eBPF program
cargo +nightly build --package guardian-ebpf --target bpfel-unknown-none -Z build-std=core

# Build the user-space application
cargo build --package guardian
