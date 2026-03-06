# eBPF CPU Guardian (a.k.a: "The Galactic Rubba")

This project aims to protect CPU usage from resource-intensive bots, specifically targeting "moltbot" (also known as "clawbot" or "OpenClaw"), by employing a micro-VM environment combined with eBPF for behavioral analysis and cgroups for resource enforcement.

So no matter how hard or how many bots are in your system, you will stretch...but not break!

## Problem Statement

Bots, especially autonomous AI assistants like OpenClaw, can consume significant CPU resources. Traditional methods of identification, such as relying solely on process names, are easily bypassed if the bot process is renamed. A more robust solution is required to identify and limit these processes based on their observed behavior.

## High-Level Design: eBPF + Behavioral Analysis + cgroups

The core idea is to use eBPF to monitor the behavior of all running processes in a lightweight micro-VM environment. When a process exhibits patterns characteristic of the target bot, a user-space application will use cgroups to enforce CPU limits.

```
+-------------------------------------------------+
|               User-Space                        |
|                                                 |
|  +-------------------------------------------+  |
|  |       Controller Application              |  |
|  |  (Receives events, analyzes behavior,     |  |
|  |   sets cgroup rules for suspected bots)   |  |
|  +-------------------------------------------+  |
|      ^                        |                 |
|      | (Behavioral Events)    | (cgroup         |
|      |                        |  config)        |
+------|------------------------|-----------------+
       |                        v
+------|-----------------------------------------+
|      |                 Kernel-Space            |
|      |                                         |
|  +-----------------+   +---------------------+  +---------+
|  | eBPF Program    |   | eBPF Program        |  | cgroups |
|  | (on execve for  |   | (on Network/FS/     |  | (cpu.max)
|  |  initial PID)   |   |  Process syscalls)  |  +---------+
|  +-----------------+   +---------------------+
|      | (PID)             | (Behavioral Data)     |
+------|-------------------|-----------------------+
       v                   v
+-------------------------------------------------+
|             All Running Processes               |
|  (including potentially renamed "OpenClaw" bots)|
+-------------------------------------------------+
```

### Key Components and Their Roles:

1.  **Micro-VM Environment (e.g., Firecracker, QEMU/KVM):**
    *   Provides an isolated and lightweight execution environment for the processes, enhancing security and resource management.

2.  **eBPF Programs (Kernel-Space):**
    *   **Initial Process Monitoring:** An eBPF program attached to the `execve` syscall will capture initial process information (PID, command name), providing a starting point for monitoring.
    *   **Behavioral Monitoring:** Additional eBPF programs will be attached to critical syscalls to monitor process behavior:
        *   **Network Activity:** Hooks on `connect`, `sendmsg`, `recvmsg`, `socket` to observe network connections, destinations, and potentially user-agent strings.
        *   **File System Activity:** Hooks on `openat`, `read`, `write`, `unlink` to track file access patterns, types of files accessed (e.g., `.pdf`), and unusual I/O operations.
        *   **Process Spawning:** Continue monitoring `execve` and `fork` to detect if the bot is spawning other processes (e.g., web browsers, helper utilities).
    *   These eBPF programs will efficiently filter and send relevant behavioral events to user-space.

3.  **User-Space Controller Application (e.g., Go, Rust, Python):**
    *   **Event Receiver:** Listens for behavioral events streamed from the eBPF programs in the kernel.
    *   **Behavioral Analyzer:** Maintains a state for each monitored process, correlating events over time to build a behavioral profile. It will implement a rule-based engine or a scoring system to identify "bot-like" patterns specific to "OpenClaw." This analysis will be resilient to process renaming.
    *   **cgroup Enforcer:** Once a process is identified as a bot, the controller will create a dedicated cgroup (if not already present) and configure its CPU limits (e.g., using `cpu.max` for cgroups v2). The identified bot process will then be moved into this restricted cgroup.

## Enhanced Detection Capabilities

This design moves beyond simple name-based detection by:
*   **Observing actual syscalls:** Directly monitoring how processes interact with the system.
*   **Pattern Recognition:** Correlating multiple behavioral events (e.g., network calls + file access + process spawning) to create a more accurate "fingerprint" of bot activity.
*   **Resilience:** Making the detection resistant to simple evasion techniques like process renaming.

## Next Steps

1.  Confirm micro-VM technology preference.
2.  Confirm user-space controller application language preference.
3.  Define specific CPU limits.
4.  Further refine the "bot-like" behavioral patterns to be detected by eBPF and analyzed by the user-space controller.
