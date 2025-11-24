//! Example demonstrating pattern extraction from logs
//!
//! This example shows how to use Extractor to find domains,
//! IP addresses (IPv4 and IPv6), and email addresses in unstructured log data.

use matchy::extractor::Extractor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matchy Pattern Extractor Demo ===\n");

    // Example 1: Basic extraction with default settings
    println!("1. Basic Extraction (domains, IPv4, emails):");
    println!(
        "   Input: \"2024-01-15 10:32:45 GET /api evil.example.com 192.168.1.1 - user@test.com\""
    );

    let extractor = Extractor::new()?;
    let log_line = b"2024-01-15 10:32:45 GET /api evil.example.com 192.168.1.1 - user@test.com";

    println!("   Extracted:");
    for match_item in extractor.extract_from_line(log_line) {
        println!("     - {}", match_item.as_str(log_line));
    }
    println!();

    // Example 2: Domain extraction
    println!("2. Domain Extraction:");
    println!("   Input: \"Visit api.example.com or https://www.github.com/user/repo\"");

    let line = b"Visit api.example.com or https://www.github.com/user/repo";
    println!("   Domains found:");
    for match_item in extractor.extract_from_line(line) {
        if let matchy::extractor::ExtractedItem::Domain(domain) = match_item.item {
            println!("     - {}", domain);
        }
    }
    println!();

    // Example 3: IPv4 extraction
    println!("3. IPv4 Address Extraction:");
    println!("   Input: \"Traffic from 10.0.0.5 to 172.16.0.10 via 192.168.1.1\"");

    let line = b"Traffic from 10.0.0.5 to 172.16.0.10 via 192.168.1.1";
    println!("   IPs found:");
    for match_item in extractor.extract_from_line(line) {
        if let matchy::extractor::ExtractedItem::Ipv4(ip) = match_item.item {
            println!("     - {}", ip);
        }
    }
    println!();

    // Example 4: IPv6 extraction
    println!("4. IPv6 Address Extraction:");
    println!("   Input: \"Server at 2001:db8::1 responded from fe80::1\"");

    let line = b"Server at 2001:db8::1 responded from fe80::1";
    println!("   IPv6 addresses found:");
    for match_item in extractor.extract_from_line(line) {
        if let matchy::extractor::ExtractedItem::Ipv6(ip) = match_item.item {
            println!("     - {}", ip);
        }
    }
    println!();

    // Example 5: Email extraction
    println!("4. Email Address Extraction:");
    println!("   Input: \"Contact alice@example.com or bob+tag@company.org\"");

    let line = b"Contact alice@example.com or bob+tag@company.org";
    println!("   Emails found:");
    for match_item in extractor.extract_from_line(line) {
        if let matchy::extractor::ExtractedItem::Email(email) = match_item.item {
            println!("     - {}", email);
        }
    }
    println!();

    // Example 6: Unicode domain extraction
    println!("6. Unicode Domain Extraction:");
    println!("   Input: \"Visit münchen.de or café.fr for more info\"");

    let line = "Visit münchen.de or café.fr for more info".as_bytes();
    println!("   Unicode domains found:");
    for match_item in extractor.extract_from_line(line) {
        if let matchy::extractor::ExtractedItem::Domain(domain) = match_item.item {
            println!("     - {} (contains UTF-8)", domain);
        }
    }
    println!();

    // Example 7: Custom configuration
    println!("7. Custom Configuration (3+ label domains only):");
    println!("   Input: \"Check example.com and api.test.example.com\"");

    let custom_extractor = Extractor::builder()
        .extract_domains(true)
        .min_domain_labels(3) // Require at least 3 labels (e.g., api.test.example.com)
        .extract_ipv4(false) // Disable IPv4 extraction
        .extract_ipv6(false) // Disable IPv6 extraction
        .extract_emails(false) // Disable email extraction
        .build()?;
    let line = b"Check example.com and api.test.example.com";

    println!("   Domains with 3+ labels:");
    for match_item in custom_extractor.extract_from_line(line) {
        println!("     - {}", match_item.as_str(line));
    }
    println!();

    // Example 8: Realistic log line
    println!("8. Realistic Log Line:");
    let log =
        b"[2024-10-16 23:45:00] INFO 192.168.1.100 user@company.com accessed api.prod.example.com";
    println!("   Input: {:?}", std::str::from_utf8(log)?);
    println!("   All patterns:");

    for match_item in extractor.extract_from_line(log) {
        let type_name = match match_item.item {
            matchy::extractor::ExtractedItem::Domain(_) => "Domain",
            matchy::extractor::ExtractedItem::Ipv4(_) => "IPv4",
            matchy::extractor::ExtractedItem::Ipv6(_) => "IPv6",
            matchy::extractor::ExtractedItem::Email(_) => "Email",
            matchy::extractor::ExtractedItem::Hash(_, _) => "Hash",
            matchy::extractor::ExtractedItem::Bitcoin(_) => "Bitcoin",
            matchy::extractor::ExtractedItem::Ethereum(_) => "Ethereum",
            matchy::extractor::ExtractedItem::Monero(_) => "Monero",
        };
        println!("     - {} ({})", match_item.as_str(log), type_name);
    }
    println!();

    // Example 9: Binary log with ASCII patterns
    println!("9. Binary Log (extracts ASCII patterns from non-UTF-8 data):");
    let mut binary_log = Vec::new();
    binary_log.extend_from_slice(b"Log: ");
    binary_log.push(0xFF); // Invalid UTF-8
    binary_log.push(0xFE);
    binary_log.extend_from_slice(b" evil.com ");
    binary_log.push(0x80);

    println!("   Input: Binary data with embedded ASCII domain");
    println!("   ASCII patterns extracted:");
    for match_item in extractor.extract_from_line(&binary_log) {
        if let matchy::extractor::ExtractedItem::Domain(domain) = match_item.item {
            println!("     - {}", domain);
        }
    }
    println!();

    // Performance characteristics
    println!("=== Performance Characteristics ===");
    println!("✓ SIMD-accelerated using memchr (2-3 GB/sec on typical logs)");
    println!("✓ Zero-copy extraction (no string allocation until match)");
    println!("✓ Unicode-aware (validates UTF-8 only for matched patterns)");
    println!("✓ Binary log support (extracts ASCII from non-UTF-8 data)");
    println!("✓ TLD validation (3.6M+ real TLDs from Public Suffix List)");
    println!();

    println!("=== Common Use Cases ===");
    println!("✓ Security: Extract domains/IPs (IPv4/IPv6) from logs for threat detection");
    println!("✓ Analytics: Count unique domains/IPs in access logs");
    println!("✓ Monitoring: Find email addresses in error logs");
    println!("✓ Compliance: Extract PII from audit logs");
    println!("✓ Forensics: Scan binary logs for ASCII indicators");

    Ok(())
}
