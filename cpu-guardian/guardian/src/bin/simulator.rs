use std::fs::File;
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::fs;

fn main() {
    println!("Starting Bot Simulator (PID: {})", std::process::id());

    // 1. Rapidly opening files (Bot behavior)
    println!("Simulating rapid file opens...");
    for i in 0..20 {
        let filename = format!("sim_file_{}.tmp", i);
        if let Ok(mut f) = File::create(&filename) {
            let _ = f.write_all(b"test");
        }
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Making network connections
    println!("Simulating network connections...");
    for _ in 0..5 {
        let _ = TcpStream::connect("8.8.8.8:53");
        thread::sleep(Duration::from_millis(100));
    }

    // 3. Deleting document files
    println!("Simulating document deletions...");
    let docs = vec!["doc1.pdf", "doc2.txt", "doc3.doc"];
    for doc in docs {
        if let Ok(mut f) = File::create(doc) {
            let _ = f.write_all(b"bot content");
        }
        thread::sleep(Duration::from_millis(100));
        let _ = fs::remove_file(doc);
    }

    println!("Simulation complete. If I were a bot, I should be throttled by now!");
}
