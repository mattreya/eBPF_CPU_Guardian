import os
import sys
import subprocess

def get_cpu_status():
    print("\n--- CPU Status (Top 5 Processes) ---")
    try:
        # Get top 5 CPU-consuming processes
        cmd = "ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -n 6"
        output = subprocess.check_output(cmd, shell=True).decode()
        print(output)
    except Exception as e:
        print(f"Error getting CPU status: {e}")

    print("\n--- Throttled Bots (eBPF CPU Guardian) ---")
    cgroup_base = "/sys/fs/cgroup/guardian"
    if not os.path.exists(cgroup_base):
        print("Guardian cgroup directory not found. Is the guardian running?")
        return

    found_any = False
    for item in os.listdir(cgroup_base):
        if item.startswith("bot_"):
            found_any = True
            pid = item.split("_")[1]
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip()

                with open(os.path.join(cgroup_base, item, "cpu.max"), "r") as f:
                    cpu_max = f.read().strip()

                print(f"PID: {pid} | Name: {comm} | Limit: {cpu_max}")
            except FileNotFoundError:
                # Process might have exited
                print(f"PID: {pid} | Name: [EXITED]")

    if not found_any:
        print("No bots currently throttled.")

def get_build_help():
    print("\n--- eBPF CPU Guardian: Build Instructions ---")
    print("This project requires Rust and bpf-linker to compile.")
    print("1. Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
    print("2. Install bpf-linker: cargo install bpf-linker")
    print("3. Build project: cargo build --workspace")
    print("\nAfter building, the guardian binary can be run with sudo to load the eBPF program.")

def main():
    if len(sys.argv) < 2:
        print("Usage: /guardian [status|build-help]")
        return

    arg = sys.argv[1].lower()
    if arg == "status":
        get_cpu_status()
    elif arg == "build-help":
        get_build_help()
    else:
        print(f"Unknown command: {arg}")
        print("Usage: /guardian [status|build-help]")

if __name__ == "__main__":
    main()
