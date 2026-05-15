use std::fs::{File, remove_file};
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::process;

fn main() -> std::io::Result<()> {
    println!("Bot Simulator starting... PID: {}", process::id());

    // 1. Rapid file opens (11 times within 1s)
    println!("Simulating rapid file opens...");
    for i in 0..15 {
        let filename = format!("test_file_{}.tmp", i);
        let _file = File::create(&filename)?;
        thread::sleep(Duration::from_millis(50));
        let _ = remove_file(&filename);
    }

    // 2. Network connections
    println!("Simulating network connections...");
    for _ in 0..5 {
        // Just try to connect to localhost, it doesn't need to succeed for the eBPF hook to trigger
        let _ = TcpStream::connect_timeout(&"127.0.0.1:8080".parse().unwrap(), Duration::from_millis(10));
        thread::sleep(Duration::from_millis(100));
    }

    // 3. Document deletions
    println!("Simulating document deletions...");
    let docs = vec!["report.pdf", "notes.txt", "data.doc"];
    for doc in docs {
        let mut file = File::create(doc)?;
        file.write_all(b"dummy data")?;
        thread::sleep(Duration::from_millis(100));
        remove_file(doc)?;
        println!("Deleted {}", doc);
    }

    println!("Simulation complete. If this was a real bot, the Guardian should have detected it.");
    Ok(())
}
