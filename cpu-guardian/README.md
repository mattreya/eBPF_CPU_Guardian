# CPU Guardian

A behavioral-based bot detection and resource enforcement tool using eBPF and cgroups v2.

## Project Structure

- `guardian`: User-space controller (Rust).
- `guardian-ebpf`: Kernel-space eBPF programs (Rust/Aya).
- `guardian-common`: Shared data structures between kernel and user space.

## Features

- **Behavioral Analysis:** Detects bots based on:
    - Process name (e.g., `chromium`, `firefox`, `headless`, `openclaw`).
    - High-volume network requests.
    - Rapid sequential access to document files (.pdf, .txt, .doc, .docx).
- **Resource Enforcement:** Automatically moves detected bots to a restricted cgroup v2 with configurable CPU limits.
- **Inheritance:** Automatically throttles child processes of detected bots.

## Building

To build the eBPF component, you need Rust nightly and `bpf-linker`.

```bash
cargo +nightly build --package guardian-ebpf --target bpfel-unknown-none -Z build-std=core
```

To build the user-space component:

```bash
cargo build --package guardian
```

## Running

```bash
sudo ./target/debug/guardian --cpu-limit 20 --threshold 100
```

## Behavioral Scoring

The guardian uses a scoring system to identify bots:
- Spawning a browser/headless process: +40 points.
- Spawning a known bot process: +100 points.
- 10+ network connections in 10 seconds: +20 points.
- 3+ document file accesses in 10 seconds: +30 points.

Once a process reaches the threshold (default 100), it is throttled.
