use std::fs::{self, File};
use std::io::{self, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() -> io::Result<()> {
    println!("Bot Simulator started. PID: {}", std::process::id());

    // 1. Simulate rapid file opens (behavioral indicator)
    println!("Simulating rapid file opens...");
    let test_file = "rapid_open_test.tmp";
    for i in 0..15 {
        let _ = File::create(test_file)?;
        let _ = fs::remove_file(test_file);
        thread::sleep(Duration::from_millis(50));
        if i % 5 == 0 {
            println!("  Opened {} files...", i);
        }
    }

    // 2. Simulate document access (behavioral indicator)
    println!("Simulating document access...");
    let docs = ["report.pdf", "data.txt", "notes.doc"];
    for doc in docs {
        println!("  Creating and deleting {}...", doc);
        let mut f = File::create(doc)?;
        f.write_all(b"dummy data")?;
        thread::sleep(Duration::from_millis(500));
        fs::remove_file(doc)?;
    }

    // 3. Simulate network connections (behavioral indicator)
    println!("Simulating network connections...");
    // Just try to connect to localhost on a common port (might fail, but syscall will be logged)
    for _ in 0..3 {
        println!("  Attempting connection to localhost:8080...");
        let _ = TcpStream::connect_timeout(
            &"127.0.0.1:8080".parse().unwrap(),
            Duration::from_millis(100)
        );
        thread::sleep(Duration::from_millis(500));
    }

    println!("Bot simulation complete. Check guardian logs for detection.");

    // Keep alive for a bit to allow for throttling observation
    println!("Staying alive for 30 seconds...");
    thread::sleep(Duration::from_secs(30));

    Ok(())
}
