<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="book/src/images/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="book/src/images/logo-light.svg">
    <img alt="Matchy Logo" src="book/src/images/logo-light.svg" width="200">
  </picture>
</p>

# Matchy

[![CI](https://github.com/sethhall/matchy/actions/workflows/ci.yml/badge.svg)](https://github.com/sethhall/matchy/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/matchy.svg)](https://crates.io/crates/matchy)
[![Documentation](https://docs.rs/matchy/badge.svg)](https://docs.rs/matchy)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

**Fast IoC matching against logs, network traffic, and security data.**

Stop using `grep -f` with massive indicator lists. Matchy turns your threat intelligence into a database that matches IPs, domains, file hashes, and patterns in microseconds—not minutes.

```bash
# Build a threat database from your intel feeds
matchy build threats.csv -o threats.mxy

# Scan your logs for matches (JSON output, ~450 MB/s)
matchy match threats.mxy access.log

# Query individual indicators
matchy query threats.mxy 1.2.3.4
```

## What It's For

**Threat Intelligence Matching**: You have threat feeds (IPs, domains, file hashes) and need to search for them in your data. SIEM lookups are slow or complicated. Command-line tools like `grep -f` take forever with 100K+ indicators.

**Use Cases**:
- Scan logs for known-bad IPs, domains, or C2 infrastructure
- Match file hashes from malware feeds against endpoint logs
- Real-time lookups in scripts and pipelines
- Offline analysis when SIEM access is limited
- Pre-filtering before sending to expensive SIEM queries

**Better Than**:
- `grep -f` - Matchy loads in <1ms vs minutes, queries in microseconds vs seconds
- SIEM lookups - Run locally, no query costs, instant results
- Custom scripts - One tool handles IPs, CIDRs, domains, globs, and hashes

## Key Features

- **Unified database**: IPs, CIDRs, exact strings, glob patterns in one file
- **Fast loading**: <1ms regardless of database size (memory-mapped)
- **Fast queries**: Sub-millisecond lookups on 100K+ indicators
- **Log scanning**: Auto-extracts IPs, domains, emails, hashes from unstructured logs
- **Glob patterns**: `*.evil.com` matches subdomains automatically
- **Rich metadata**: Attach threat level, category, source to each indicator
- **MaxMind compatible**: Query GeoIP databases directly - no need for separate libmaxminddb
- **Build MMDB databases**: Create MaxMind-compatible databases from CSVs (libmaxminddb has no builder)
- **Multiple formats**: Import from CSV, JSONL, or read existing MaxMind MMDB files

## Quick Start

### Installation

```bash
cargo install matchy
```

**Requirements**: Rust 1.70+ (or use [pre-built binaries](https://github.com/sethhall/matchy/releases))

### Build a Threat Database

Create a CSV with your indicators:

```csv
entry,threat_level,category,source
1.2.3.4,high,malware,abuse.ch
10.0.0.0/8,low,internal,rfc1918
*.evil.com,critical,phishing,urlhaus
malware.example.com,high,c2,internal
ab5ef3c21d4e...,high,malware,virustotal
```

Build the database:

```bash
matchy build threats.csv -o threats.mxy --format csv

# Build MaxMind-compatible MMDB (IP data only)
matchy build ip-blocklist.csv -o blocklist.mmdb --format csv
# Works with any tool expecting MMDB format!
```

### Scan Logs for Matches

```bash
# Scan access logs (outputs JSON, one match per line)
matchy match threats.mxy /var/log/nginx/access.log

# With statistics
matchy match threats.mxy access.log --stats
# JSON matches to stdout, stats to stderr:
# [INFO] Lines processed: 523,441
# [INFO] Matches found: 127 (0.02%)
# [INFO] Throughput: 450 MB/s

# Scan gzip logs (automatic decompression)
matchy match threats.mxy access.log.gz

# Watch live logs
tail -f /var/log/app.log | matchy match threats.mxy -
```

### Query Individual Indicators

```bash
# Check an IP
matchy query threats.mxy 1.2.3.4
# [{"threat_level":"high","category":"malware","source":"abuse.ch"}]

# Check a domain
matchy query threats.mxy sub.evil.com  
# [{"threat_level":"critical","category":"phishing","source":"urlhaus"}]

# Check a hash
matchy query threats.mxy ab5ef3c21d4e...

# Query MaxMind GeoIP databases (no libmaxminddb needed)
matchy query GeoLite2-City.mmdb 8.8.8.8
# {"city":"Mountain View","country":"US",...}
```

## For Developers

### Rust Library

```bash
cargo add matchy --no-default-features  # Library only, no CLI
```

See **[API docs](https://docs.rs/matchy)** for building databases, querying, and extracting IoCs from text.

### C/C++ Library

```c
#include <matchy/matchy.h>

matchy_t *db = matchy_open("threats.mxy");
matchy_result_t result = matchy_query(db, "1.2.3.4");
matchy_close(db);
```

MaxMind-compatible API also available. See **[The Matchy Book](https://sethhall.github.io/matchy/)** for integration guides.

## Documentation

- **[The Matchy Book](https://sethhall.github.io/matchy/)** - Complete CLI guide and examples
- **[API Reference](https://docs.rs/matchy)** - Rust library documentation  
- **[DEVELOPMENT.md](DEVELOPMENT.md)** - Architecture and performance details

## Workspace Structure

Matchy is organized as a Cargo workspace with focused, reusable crates:

- **matchy** - Main crate with CLI, Database API, C FFI
- **matchy-format** - Unified .mxy file format (orchestrates all components)
- **matchy-paraglob** - Glob pattern matching engine
- **matchy-literal-hash** - O(1) exact string matching
- **matchy-ip-trie** - IP address/CIDR routing
- **matchy-ac** - Aho-Corasick automaton
- **matchy-glob** - Glob pattern parser and matcher
- **matchy-data-format** - MMDB data encoding/decoding
- **matchy-extractor** - IoC extraction from unstructured text
- **matchy-match-mode** - Shared case-sensitivity enum

Each crate has its own README with usage examples and architecture details.

## Project Info

**License**: BSD-2-Clause  
**Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)  
**Status**: Production-ready, 242 tests passing

Matchy extends MaxMind's MMDB format with [Paraglob](https://github.com/zeek/paraglob) glob matching, creating a unified IoC database that's fast enough for real-time lookups and memory-efficient enough to scale to hundreds of worker processes.

