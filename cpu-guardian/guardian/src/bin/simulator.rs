use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    println!("Starting bot simulation (PID: {})...", std::process::id());

    // 1. Rapid file opens
    println!("Performing rapid file opens...");
    for i in 0..15 {
        let filename = format!("test_file_{}.tmp", i);
        let mut f = File::create(&filename)?;
        f.write_all(b"test data")?;
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Network connection
    println!("Performing network connection...");
    let _ = TcpStream::connect("8.8.8.8:80");

    // 3. Document access/deletion
    println!("Accessing and deleting sensitive documents...");
    let docs = ["report.pdf", "data.txt", "notes.doc"];
    for doc in docs {
        let mut f = File::create(doc)?;
        f.write_all(b"sensitive content")?;
        thread::sleep(Duration::from_millis(100));
        fs::remove_file(doc)?;
    }

    println!("Simulation complete. Cleaning up...");
    for i in 0..15 {
        let filename = format!("test_file_{}.tmp", i);
        let _ = fs::remove_file(filename);
    }

    Ok(())
}
