use std::fs::File;
use std::io::prelude::*;
use std::thread;
use std::time::Duration;
use std::process;

fn main() -> std::io::Result<()> {
    let pid = process::id();
    println!("Bot simulator started with PID: {}", pid);

    // 1. Rapid file opens (simulating bot behavior)
    println!("Performing rapid file opens...");
    for i in 0..15 {
        let filename = format!("temp_file_{}.txt", i);
        let mut file = File::create(&filename)?;
        file.write_all(b"Hello from bot simulator")?;
        thread::sleep(Duration::from_millis(50)); // Less than 100ms threshold
    }

    // 2. Accessing sensitive documents
    println!("Accessing sensitive document...");
    let mut file = File::create("leaked_data.pdf")?;
    file.write_all(b"Sensitive content")?;

    // 3. Network connection simulation (we can't easily simulate connect without a listener,
    // but the eBPF program should catch it if we try to connect to something)
    // For now, we'll focus on FS activity.

    // 4. File deletions
    println!("Deleting files...");
    for i in 0..15 {
        let filename = format!("temp_file_{}.txt", i);
        let _ = std::fs::remove_file(filename);
        thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file("leaked_data.pdf");

    println!("Bot simulator finished tasks. Keeping process alive to observe throttling...");

    // Busy loop to consume CPU and test throttling
    let mut x: u64 = 0;
    loop {
        x = x.wrapping_add(1);
        if x % 1_000_000_000 == 0 {
            println!("Bot still running... (PID: {})", pid);
        }
    }
}
