use std::fs::File;
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Bot Simulator starting (PID: {})...", std::process::id());

    // 1. Rapid file opens
    println!("Simulating rapid file opens...");
    for i in 0..15 {
        let filename = format!("temp_file_{}.tmp", i);
        let _ = File::create(&filename);
        let _ = std::fs::remove_file(&filename);
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Network activity
    println!("Simulating network activity...");
    for _ in 0..5 {
        // Just try to connect to localhost on a random port
        let _ = TcpStream::connect_timeout(
            &"127.0.0.1:8080".parse().unwrap(),
            Duration::from_millis(10),
        );
        thread::sleep(Duration::from_millis(100));
    }

    // 3. Document deletions
    println!("Simulating document deletions...");
    let docs = ["report.pdf", "notes.txt", "memo.doc"];
    for doc in docs.iter() {
        {
            let mut f = File::create(doc).unwrap();
            f.write_all(b"fake content").unwrap();
        }
        std::fs::remove_file(doc).unwrap();
        thread::sleep(Duration::from_millis(100));
    }

    println!("Simulation complete. Entering infinite loop to keep process alive...");
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
