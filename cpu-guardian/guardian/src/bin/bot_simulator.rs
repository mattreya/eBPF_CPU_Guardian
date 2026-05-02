use std::fs::{self, File};
use std::io::prelude::*;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::process;

fn main() -> std::io::Result<()> {
    println!("Bot Simulator started (PID: {})", process::id());

    // 1. Rapid file opens (non-documents)
    println!("Simulating rapid file opens...");
    for i in 0..15 {
        let filename = format!("temp_{}.tmp", i);
        let mut _file = File::create(&filename)?;
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Create and delete document files
    println!("Creating and deleting document files...");
    let docs = vec!["research.pdf", "notes.txt", "budget.doc"];
    for doc in docs {
        {
            let mut file = File::create(doc)?;
            file.write_all(b"Important content")?;
        }
        thread::sleep(Duration::from_millis(100));
        fs::remove_file(doc)?;
    }

    // 3. Make network connections (mocking external calls)
    println!("Simulating network connections...");
    // We just try to connect to localhost on some ports to trigger the eBPF hook
    for port in [80, 443, 8080] {
        let _ = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(100),
        );
    }

    println!("Simulation complete. Keeping process alive for observation...");
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
