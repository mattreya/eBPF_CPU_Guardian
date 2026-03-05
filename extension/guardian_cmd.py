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

    print("\n--- eBPF CPU Guardian: Throttled Bots ---")
    if os.path.exists("/sys/fs/cgroup/guardian"):
        print(f"{'PID':<8} {'COMM':<16} {'LIMIT':<8}")
        print(f"{'-'*32}")
        try:
            found = False
            for entry in os.listdir("/sys/fs/cgroup/guardian"):
                if entry.startswith("bot_"):
                    pid = entry.split("_")[1]
                    comm = "[unknown]"
                    try:
                        with open(f"/proc/{pid}/comm", "r") as f:
                            comm = f.read().strip()
                    except:
                        pass
                    print(f"{pid:<8} {comm:<16} {'20%':<8}")
                    found = True
            if not found:
                print("No bots currently throttled.")
        except Exception:
            print("Error reading cgroup status.")
    else:
        print("Guardian cgroup base not found. Is the service running?")

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
