use std::fs::{self, File};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    println!("Starting bot simulation (PID: {})...", std::process::id());

    // 1. Rapid file opens
    println!("Simulating rapid file opens...");
    for i in 0..15 {
        let filename = format!("/tmp/bot_sim_{}.tmp", i);
        let _ = File::create(&filename)?;
        let _ = fs::remove_file(&filename);
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Network connections
    println!("Simulating network connections...");
    for _ in 0..5 {
        // Attempt to connect to a local port (might fail, but sys_enter_connect will trigger)
        let _ = TcpStream::connect_timeout(
            &"127.0.0.1:8080".parse().unwrap(),
            Duration::from_millis(100),
        );
        thread::sleep(Duration::from_millis(500));
    }

    // 3. Document deletions
    println!("Simulating document deletions...");
    let docs = ["report.pdf", "data.txt", "manual.doc"];
    for doc in docs {
        let _ = File::create(doc)?;
        fs::remove_file(doc)?;
        println!("Deleted {}", doc);
        thread::sleep(Duration::from_millis(500));
    }

    println!("Simulation complete. Entering infinite loop to keep process alive...");
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
