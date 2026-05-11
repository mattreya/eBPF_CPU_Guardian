use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Bot simulator started (PID: {})", std::process::id());

    // 1. Rapid file opens
    println!("Performing rapid file opens...");
    for i in 0..15 {
        let filename = format!("temp_file_{}.tmp", i);
        let _ = File::create(&filename);
        let _ = fs::remove_file(&filename);
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Network connection
    println!("Connecting to a server...");
    let _ = TcpStream::connect("8.8.8.8:53");

    // 3. Document deletion
    println!("Creating and deleting document files...");
    let docs = vec!["report.pdf", "data.txt", "resume.doc"];
    for doc in docs {
        let mut file = File::create(doc).unwrap();
        file.write_all(b"dummy data").unwrap();
        fs::remove_file(doc).unwrap();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Simulation complete. Hanging around to keep PID valid for throttling check...");
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
