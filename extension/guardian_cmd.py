import os
import sys

def get_cpu_status():
    print("\n--- eBPF CPU Guardian: Throttled Processes ---")
    base_path = "/sys/fs/cgroup/guardian"
    if not os.path.exists(base_path):
        print(f"Guardian cgroup directory {base_path} not found.")
        return

    found = False
    for item in os.listdir(base_path):
        if item.startswith("bot_"):
            try:
                pid = item.split("_")[1]
                comm_path = f"/proc/{pid}/comm"
                if os.path.exists(comm_path):
                    with open(comm_path, "r") as f:
                        name = f.read().strip()
                else:
                    name = "[terminated]"

                cpu_max_path = os.path.join(base_path, item, "cpu.max")
                if os.path.exists(cpu_max_path):
                    with open(cpu_max_path, "r") as f:
                        cpu_max = f.read().strip()
                else:
                    cpu_max = "unknown"

                print(f"PID: {pid:6} | Name: {name:15} | CPU Limit (quota period): {cpu_max}")
                found = True
            except Exception as e:
                continue

    if not found:
        print("No throttled processes found.")

def get_build_help():
    print("\n--- eBPF CPU Guardian: Build Instructions ---")
    print("This project requires Rust and bpf-linker to compile.")
    print("1. Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
    print("2. Install bpf-linker: cargo install bpf-linker")
    print("3. Build eBPF: cargo +nightly build -p guardian-ebpf --target bpfel-unknown-none -Z build-std=core")
    print("4. Build Controller: cargo build -p guardian")
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
