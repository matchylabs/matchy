//! Example: Sharing Extractor across threads using Arc
//!
//! Demonstrates that Extractor is now Send + Sync and can be safely
//! shared across threads using Arc for efficient parallel processing.

use matchy::extractor::Extractor;
use std::sync::Arc;
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Concurrent Extractor Demo ===\n");

    // Create one extractor and share it across threads
    let extractor = Arc::new(Extractor::new()?);

    println!("Created extractor, spawning 8 worker threads...\n");

    // Simulate parallel workers processing different data
    let test_data: Vec<&[u8]> = vec![
        b"Check test@example.com and 192.168.1.1",
        b"Found malware.evil.com at 10.0.0.5",
        b"Contact admin@company.org from 172.16.0.1",
        b"Visit api.github.com and staging.aws.amazon.com",
        b"Email support@help.net or call 555-1234",
        b"Server 2001:db8:85a3::8a2e:370:7334 responded",
        b"Hash: 5d41402abc4b2a76b9719d911017c592",
        b"Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ];

    let handles: Vec<_> = test_data
        .into_iter()
        .enumerate()
        .map(|(i, data)| {
            let ext = Arc::clone(&extractor);
            thread::spawn(move || {
                let results = ext.extract_from_chunk(data);
                println!(
                    "Thread {}: Found {} matches in: {}",
                    i,
                    results.len(),
                    String::from_utf8_lossy(data)
                );
                for m in &results {
                    println!("  - {}: {}", m.item.type_name(), m.item.as_value());
                }
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    println!("\n✓ All threads completed successfully!");
    println!("✓ Extractor was safely shared via Arc<Extractor>");

    Ok(())
}
