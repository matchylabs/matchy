//! Fast log file generator for benchmarking
//!
//! Generates realistic-looking log files with embedded IP addresses and domains.

use std::io::{self, Write};

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let size_gb: f64 = if args.len() > 1 {
        args[1].parse().unwrap_or(1.0)
    } else {
        1.0
    };

    eprintln!("Generating {:.2} GB of log data...", size_gb);

    let target_bytes = (size_gb * 1024.0 * 1024.0 * 1024.0) as usize;
    let mut bytes_written = 0;
    let mut line_num = 0;

    // Normal traffic IPs (98% of traffic) - internal/common IPs
    let normal_ips = [
        "192.168.1.100",
        "10.0.0.1",
        "172.16.0.50",
        "192.168.50.23",
        "10.20.30.40",
        "172.31.255.1",
        "203.0.113.45",
    ];

    // Threat IPs matching our threat database (2% of traffic)
    let threat_ips = [
        "185.220.101.55", // Tor exit node
        "23.129.64.12",   // Botnet C2
        "45.142.212.88",  // Cryptomining
        "103.253.145.99", // Phishing
        "89.248.165.42",  // DDoS source
        "141.98.80.77",   // Brute force
    ];

    let domains = ["example.com", "google.com", "github.com", "api.service.io"];

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    while bytes_written < target_bytes {
        // 0.001% of lines contain threat IPs (1 in 100,000), 99.999% are normal traffic
        let ip = if line_num % 100_000 == 0 {
            // Every 100,000th line gets a threat IP (0.001%)
            threat_ips[line_num % threat_ips.len()]
        } else {
            normal_ips[line_num % normal_ips.len()]
        };
        let domain = domains[line_num % domains.len()];

        let line = match line_num % 4 {
            0 => format!(
                "2025-10-14 05:45:00 INFO Connection from {} to {} succeeded\n",
                ip, domain
            ),
            1 => format!("2025-10-14 05:45:01 WARN Authentication failure from {}\n", ip),
            2 => format!(
                "2025-10-14 05:45:02 ERROR Failed to resolve {} for client {}\n",
                domain, ip
            ),
            _ => format!(
                "2025-10-14 05:45:03 DEBUG Processing request from {} to https://{}/api/v1/endpoint\n",
                ip, domain
            ),
        };

        bytes_written += line.len();
        out.write_all(line.as_bytes())?;

        line_num += 1;

        if line_num % 100_000 == 0 {
            eprintln!(
                "  Generated {} lines ({:.2} MB)...",
                line_num,
                bytes_written as f64 / (1024.0 * 1024.0)
            );
        }
    }

    out.flush()?;
    eprintln!(
        "Done! Generated {} lines ({:.2} GB)",
        line_num,
        bytes_written as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    Ok(())
}
