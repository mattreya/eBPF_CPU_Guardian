use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::process;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Simulator started with PID: {}", process::id());

    // 1. Simulate rapid file opens
    println!("Simulating rapid file opens...");
    for i in 0..15 {
        let filename = format!("/tmp/sim_file_{}.tmp", i);
        if let Ok(mut file) = fs::File::create(&filename) {
            let _ = file.write_all(b"test");
        }
        let _ = fs::remove_file(&filename);
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Simulate network connection
    println!("Simulating network connection...");
    let _ = TcpStream::connect("8.8.8.8:53");

    // 3. Simulate sensitive file deletions
    println!("Simulating sensitive file deletions...");
    for i in 0..5 {
        let filename = format!("/tmp/sim_doc_{}.pdf", i);
        if let Ok(_) = fs::File::create(&filename) {
            let _ = fs::remove_file(&filename);
        }
        thread::sleep(Duration::from_millis(100));
    }

    println!("Simulation complete. If I were a bot, I should be throttled by now!");

    // Keep running to allow observation of throttling if needed
    loop {
        let mut sum = 0u64;
        for i in 0..1_000_000 {
            sum = sum.wrapping_add(i);
        }
        thread::sleep(Duration::from_millis(1));
    }
}
