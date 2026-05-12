use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::process;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let pid = process::id();
    println!("Simulator started with PID: {}", pid);

    // 1. Network Activity
    println!("Simulating network activity...");
    for _ in 0..5 {
        let _ = TcpStream::connect("127.0.0.1:80");
        thread::sleep(Duration::from_millis(100));
    }

    // 2. Rapid File Opens
    println!("Simulating rapid file opens...");
    for i in 0..15 {
        let filename = format!("/tmp/sim_file_{}.tmp", i);
        let mut file = File::create(&filename)?;
        file.write_all(b"test data")?;
        thread::sleep(Duration::from_millis(50));
    }

    // 3. Document Deletion
    println!("Simulating document deletions...");
    let docs = ["report.pdf", "data.txt", "notes.doc"];
    for doc in docs {
        let mut file = File::create(doc)?;
        file.write_all(b"fake document")?;
        thread::sleep(Duration::from_millis(100));
        fs::remove_file(doc)?;
    }

    println!("Simulation complete. PID {} should have been detected.", pid);

    // Keep alive for a bit so we can observe cgroup changes if running live
    thread::sleep(Duration::from_secs(5));

    Ok(())
}
