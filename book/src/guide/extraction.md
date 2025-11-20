# Pattern Extraction

Matchy includes a high-performance pattern extractor for finding domains, IP addresses (IPv4 and IPv6), email addresses, and file hashes (MD5, SHA1, SHA256, SHA384) in unstructured text like log files.

## Overview

The `Extractor` uses SIMD-accelerated algorithms to scan text and extract patterns at 200-500 MB/sec. This is useful for:

- **Log scanning**: Find domains/IPs in access logs, firewall logs, etc.
- **Threat detection**: Extract indicators from security logs
- **Analytics**: Count unique domains/IPs in large datasets
- **Compliance**: Find email addresses or PII in audit logs
- **Forensics**: Extract patterns from binary logs

## Quick Start

```rust
use matchy::extractor::Extractor;

let extractor = Extractor::new()?;

let log_line = b"2024-01-15 GET /api evil.example.com 192.168.1.1";

for match_item in extractor.extract_from_line(log_line) {
    println!("Found: {}", match_item.as_str(log_line));
}
// Output:
// Found: evil.example.com
// Found: 192.168.1.1
```

## Supported Patterns

### Domains

Extracts fully qualified domain names with TLD validation:

```rust
let line = b"Visit api.example.com or https://www.github.com/path";

for match_item in extractor.extract_from_line(line) {
    if let ExtractedItem::Domain(domain) = match_item.item {
        println!("Domain: {}", domain);
    }
}
// Output:
// Domain: api.example.com
// Domain: www.github.com
```

**Features:**
- **TLD validation**: 10K+ real TLDs from Public Suffix List
- **Unicode support**: Handles münchen.de, café.fr (both UTF-8 and punycode)
- **Subdomain extraction**: Extracts full domain from URLs
- **Word boundaries**: Avoids false positives in non-domain text

### IPv4 Addresses

Extracts all valid IPv4 addresses:

```rust
let line = b"Traffic from 10.0.0.5 to 172.16.0.10";

for match_item in extractor.extract_from_line(line) {
    if let ExtractedItem::Ipv4(ip) = match_item.item {
        println!("IP: {}", ip);
    }
}
// Output:
// IP: 10.0.0.5
// IP: 172.16.0.10
```

**Features:**
- **SIMD-accelerated**: Uses `memchr` for fast dot detection
- **Validation**: Rejects invalid IPs (256.1.1.1, 999.0.0.1)
- **Word boundaries**: Avoids false matches in version numbers

### IPv6 Addresses

Extracts all valid IPv6 addresses:

```rust
let line = b"Server at 2001:db8::1 responded from fe80::1";

for match_item in extractor.extract_from_line(line) {
    if let ExtractedItem::Ipv6(ip) = match_item.item {
        println!("IPv6: {}", ip);
    }
}
// Output:
// IPv6: 2001:db8::1
// IPv6: fe80::1
```

**Features:**
- **SIMD-accelerated**: Uses `memchr` for fast colon detection
- **Compressed notation**: Handles `::` and full addresses
- **Validation**: Full RFC 4291 compliance via Rust's `Ipv6Addr`
- **Mixed notation**: Supports `::ffff:127.0.0.1` format

### Email Addresses

Extracts RFC 5322-compliant email addresses:

```rust
let line = b"Contact alice@example.com or bob+tag@company.org";

for match_item in extractor.extract_from_line(line) {
    if let ExtractedItem::Email(email) = match_item.item {
        println!("Email: {}", email);
    }
}
// Output:
// Email: alice@example.com
// Email: bob+tag@company.org
```

**Features:**
- **Plus addressing**: Supports user+tag@example.com
- **Subdomain validation**: Checks domain part for valid TLD

### File Hashes

Extracts MD5, SHA1, and SHA256 file hashes:

```rust
use matchy::extractor::{ExtractedItem, HashType};

let line = b"malware.exe MD5=5d41402abc4b2a76b9719d911017c592 detected";

for match_item in extractor.extract_from_line(line) {
    if let ExtractedItem::Hash(hash_type, hash) = match_item.item {
        let type_str = match hash_type {
            HashType::Md5 => "MD5",
            HashType::Sha1 => "SHA1",
            HashType::Sha256 => "SHA256",
        };
        println!("{}: {}", type_str, hash);
    }
}
// Output:
// MD5: 5d41402abc4b2a76b9719d911017c592
```

**Features:**
- **Boundary distance detection**: Finds tokens of exact length (32/40/64 hex chars)
- **SIMD hex validation**: Auto-vectorized lookup table for blazing speed
- **Case insensitive**: Accepts both lowercase and uppercase hex
- **Zero false positives**: Rejects UUIDs (with dashes) and non-hex strings
- **High throughput**: ~1-2 GB/sec processing speed

**Supported hash types:**
- **MD5**: 32 hex characters (e.g., `5d41402abc4b2a76b9719d911017c592`)
- **SHA1**: 40 hex characters (e.g., `2fd4e1c67a2d28fced849ee1bb76e7391b93eb12`)
- **SHA256**: 64 hex characters (e.g., `2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae`)
- **SHA384**: 96 hex characters (e.g., `cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7`)

## Configuration

Customize extraction behavior using the builder pattern:

```rust
use matchy::extractor::Extractor;

let extractor = Extractor::builder()
    .extract_domains(true)        // Enable domain extraction
    .extract_ipv4(true)            // Enable IPv4 extraction
    .extract_ipv6(true)            // Enable IPv6 extraction
    .extract_emails(false)         // Disable email extraction
    .min_domain_labels(3)          // Require 3+ labels (api.test.com)
    .require_word_boundaries(true) // Enforce word boundaries
    .build()?;
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `extract_domains` | `true` | Extract domain names |
| `extract_ipv4` | `true` | Extract IPv4 addresses |
| `extract_ipv6` | `true` | Extract IPv6 addresses |
| `extract_emails` | `true` | Extract email addresses |
| `extract_hashes` | `true` | Extract file hashes (MD5, SHA1, SHA256, SHA384) |
| `min_domain_labels` | `2` | Minimum labels (2 = example.com, 3 = api.example.com) |
| `require_word_boundaries` | `true` | Ensure patterns have word boundaries |

## Unicode and IDN Support

The extractor handles Unicode domains automatically:

```rust
let line = "Visit münchen.de or café.fr".as_bytes();

for match_item in extractor.extract_from_line(line) {
    if let ExtractedItem::Domain(domain) = match_item.item {
        println!("Unicode domain: {}", domain);
    }
}
// Output:
// Unicode domain: münchen.de
// Unicode domain: café.fr
```

**How it works:**
- Extracts Unicode text as-is
- Validates TLD using punycode conversion internally
- Returns original Unicode form (not punycode)

## Binary Log Support

The extractor can find ASCII patterns in binary data:

```rust
let mut binary_log = Vec::new();
binary_log.extend_from_slice(b"Log: ");
binary_log.push(0xFF); // Invalid UTF-8
binary_log.extend_from_slice(b" evil.com ");

for match_item in extractor.extract_from_line(&binary_log) {
    println!("Found in binary: {}", match_item.as_str(&binary_log));
}
// Output:
// Found in binary: evil.com
```

This is useful for scanning:
- Binary protocol logs
- Corrupted text files
- Mixed encoding logs

## Performance

The extractor is highly optimized:

- **Throughput**: 200-500 MB/sec on typical log files
- **SIMD acceleration**: Uses `memchr` for byte scanning
- **Zero-copy**: No string allocation until match
- **Lazy UTF-8 validation**: Only validates matched patterns

### Performance Tips

1. **Disable unused extractors** to reduce overhead:
   ```rust
   let extractor = Extractor::builder()
       .extract_ipv4(true)     // Only extract IPv4
       .extract_ipv6(true)     // Only extract IPv6
       .extract_domains(false)
       .extract_emails(false)
       .build()?;
   ```

2. **Process line-by-line** for better memory usage:
   ```rust
   for line in BufReader::new(file).lines() {
       for match_item in extractor.extract_from_line(line?.as_bytes()) {
           // Process match
       }
   }
   ```

3. **Use byte slices** to avoid UTF-8 conversion:
   ```rust
   // Fast: no UTF-8 validation on whole line
   extractor.extract_from_line(line_bytes)
   
   // Slower: validates entire line as UTF-8 first
   extractor.extract_from_line(line_str.as_bytes())
   ```


## CLI Integration

The `matchy match` command uses the extractor internally:

```bash
# Scan logs for threats (outputs JSON to stdout)
matchy match threats.mxy access.log

# Each match is a JSON line:
# {"timestamp":"123.456","line_number":1,"matched_text":"evil.com","match_type":"pattern",...}
# {"timestamp":"123.789","line_number":2,"matched_text":"1.2.3.4","match_type":"ip",...}

# Show statistics (to stderr)
matchy match threats.mxy access.log --stats

# Statistics output (stderr):
# [INFO] Lines processed: 15,234
# [INFO] Lines with matches: 127 (0.8%)
# [INFO] Throughput: 450.23 MB/s
```

See [matchy match](../commands/matchy-match.md) for CLI details.

## Examples

Complete working examples:

- **`examples/extractor_demo.rs`**: Demonstrates all extraction features
- **`src/bin/matchy.rs`**: See `cmd_match()` for CLI implementation

Run the demo:

```bash
cargo run --release --example extractor_demo
```

## Summary

- **High performance**: 200-500 MB/sec throughput
- **SIMD-accelerated**: Fast pattern finding
- **Unicode support**: Handles international domains
- **Binary logs**: Extracts ASCII from non-UTF-8
- **Zero-copy**: Efficient memory usage
- **Configurable**: Customize extraction behavior

Pattern extraction makes it easy to scan large log files and find security indicators.
