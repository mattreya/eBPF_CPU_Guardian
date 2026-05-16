use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::process;

fn main() {
    println!("Starting bot simulation (PID: {})...", process::id());

    // 1. Rapid file opens (Simulate behavioral pattern)
    println!("Performing rapid file opens...");
    for i in 0..15 {
        let filename = format!("/tmp/sim_file_{}.tmp", i);
        let _ = File::create(&filename);
        let _ = fs::remove_file(&filename);
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Network connections
    println!("Simulating network activity...");
    for _ in 0..5 {
        let _ = TcpStream::connect("8.8.8.8:53");
        thread::sleep(Duration::from_millis(100));
    }

    // 3. Document access and deletion
    println!("Simulating document deletion...");
    let doc_path = "/tmp/sensitive_report.pdf";
    if let Ok(mut file) = File::create(doc_path) {
        let _ = file.write_all(b"fake pdf content");
    }
    thread::sleep(Duration::from_millis(500));
    let _ = fs::remove_file(doc_path);

    println!("Simulation complete. If the guardian is running, this process should have been flagged.");
}
