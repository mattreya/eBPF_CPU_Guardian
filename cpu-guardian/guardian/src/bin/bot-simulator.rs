use std::fs::File;
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Bot Simulator started. PID: {}", std::process::id());

    // 1. Perform rapid file opens to trigger scoring
    println!("Performing rapid file opens...");
    for i in 0..15 {
        let filename = format!("test_file_{}.txt", i);
        {
            let mut file = File::create(&filename).expect("Failed to create file");
            writeln!(file, "Bot activity simulation").expect("Failed to write to file");
        }
        // Small delay to ensure they are sequential but fast
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Perform some network connections
    println!("Performing network connections...");
    for _ in 0..5 {
        // Attempting to connect to localhost on a likely closed port just to trigger the syscall
        let _ = TcpStream::connect_timeout(
            &"127.0.0.1:9999".parse().unwrap(),
            Duration::from_millis(100),
        );
        thread::sleep(Duration::from_millis(100));
    }

    // 3. Unlink some document files
    println!("Deleting sensitive documents...");
    for i in 0..3 {
        let filename = format!("simulated_doc_{}.pdf", i);
        let _ = File::create(&filename);
        let _ = std::fs::remove_file(&filename);
        thread::sleep(Duration::from_millis(100));
    }

    println!("Bot simulation complete. Keeping process alive for observation...");
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
