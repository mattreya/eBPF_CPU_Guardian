use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::process;

fn main() {
    let pid = process::id();
    println!("Simulator started with PID: {}", pid);

    println!("1. Simulating rapid file opens...");
    for i in 0..15 {
        let filename = format!("test_file_{}.tmp", i);
        let _ = File::create(&filename);
        let _ = fs::remove_file(&filename);
        thread::sleep(Duration::from_millis(50));
    }

    println!("2. Simulating network connections...");
    for _ in 0..5 {
        // Just attempt a connection to a local port
        let _ = TcpStream::connect("127.0.0.1:80");
        thread::sleep(Duration::from_millis(100));
    }

    println!("3. Simulating sensitive file deletion...");
    let sensitive_file = "sensitive_data.pdf";
    {
        let mut f = File::create(sensitive_file).unwrap();
        f.write_all(b"Important data").unwrap();
    }
    thread::sleep(Duration::from_millis(500));
    fs::remove_file(sensitive_file).unwrap();
    println!("Deleted {}", sensitive_file);

    println!("Simulator finished. Stay alive for 10s to observe throttling...");
    thread::sleep(Duration::from_secs(10));
}
