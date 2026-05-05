use std::fs::{File, remove_file};
use std::io::Write;
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    println!("Bot Simulator starting... PID: {}", std::process::id());

    // 1. Rapid file opens
    println!("Simulating rapid file opens...");
    for i in 0..15 {
        let filename = format!("test_file_{}.txt", i);
        let mut f = File::create(&filename).unwrap();
        f.write_all(b"hello").unwrap();
        sleep(Duration::from_millis(50));
    }

    // 2. Network connections
    println!("Simulating network connections...");
    for _ in 0..5 {
        let _ = TcpStream::connect("8.8.8.8:53");
        sleep(Duration::from_millis(100));
    }

    // 3. File deletions (documents)
    println!("Simulating document deletions...");
    for i in 0..15 {
        let filename = format!("test_doc_{}.pdf", i);
        {
            let _ = File::create(&filename);
        }
        let _ = remove_file(&filename);
        sleep(Duration::from_millis(50));
    }

    println!("Simulation complete. Check guardian logs.");
}
