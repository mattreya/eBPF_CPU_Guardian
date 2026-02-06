# Proposal Summary for eBPF CPU Guardian

This document summarizes the agreed-upon technical direction for the `eBPF CPU Guardian` project.

## Core Objective

To protect CPU usage from resource-intensive bots (specifically "OpenClaw," formerly "moltbot" or "clawbot") by detecting their behavioral patterns using eBPF and enforcing CPU limits via cgroups within a micro-VM environment.

## Agreed-Upon Technical Choices

### 1. Micro-VM Technology
*   **Choice:** Firecracker
*   **Reasoning:** Firecracker is ideal for creating lightweight, secure micro-VMs optimized for serverless functions and container workloads, offering minimal overhead and strong security.

### 2. User-Space Controller Application Language
*   **Choice:** Rust
*   **Reasoning:** While Python offers faster development, Rust's superior performance, memory safety guarantees, and suitability for system-level programming are critical for a low-latency, robust, and efficient guardian that interacts directly with kernel events and applies resource limits. This will minimize delays in detection and enforcement.

### 3. Initial CPU Limit for Detected Bots
*   **Choice:** 10-25% of a single CPU core
*   **Reasoning:** This range provides a starting point for throttling, allowing bots to function at a significantly reduced capacity without monopolizing system resources. This value will be tunable.

### 4. Enhanced Bot Detection Strategy (Behavioral Analysis)
*   **Method:** eBPF will be used to monitor a wider set of kernel events (syscalls) to build a behavioral profile of processes, making detection resilient against process renaming.
*   **Key Behavioral Indicators to Target:**
    *   **High-volume network requests:** Especially to external AI/LLM services or messaging platforms, indicating communication patterns.
    *   **Rapid sequential access/modification of multiple document files:** Such as PDFs or text files, aligning with summarization and reading capabilities.
    *   **Spawning of specific helper processes:** For instance, web browser processes (`chromium`, `firefox`) in rapid succession or for extended periods when not expected from other applications.

## Next Steps

With these foundational decisions made, the next phase will involve:
1.  Setting up the development environment for Rust and eBPF.
2.  Developing initial eBPF programs for basic behavioral monitoring.
3.  Implementing the user-space Rust controller to receive eBPF events and apply cgroup rules.
4.  Setting up a Firecracker micro-VM for testing and deployment.
5.  Refining behavioral detection patterns through observation and iteration.
