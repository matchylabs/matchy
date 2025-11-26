# matchy match

Scan log files or streams for threats by matching against a database.

## Synopsis

```console
matchy match [OPTIONS] <DATABASE> <INPUT>...
```

## Description

The `matchy match` command processes log files or stdin, automatically extracting IP addresses, domains, and email addresses from each line and checking them against the database. This is designed for operational testing and real-time threat detection in log streams.

**Key features:**
- Automatic extraction of IPs, domains, and emails from unstructured logs
- SIMD-accelerated scanning (200-500 MB/sec typical throughput)
- Outputs JSON (NDJSON format) to stdout for easy parsing
- Statistics and diagnostics to stderr
- Memory-efficient streaming processing

## Arguments

### `<DATABASE>`

Path to the database file to query. Supports:

- **`.mxy` files** - Pre-built matchy database (fastest, recommended for production)
- **`.json` files** - JSON source file (auto-built in memory)
- **`.csv` files** - CSV source file (auto-built in memory)

When a JSON or CSV file is provided, matchy automatically builds the database in-memory before matching. This is convenient for quick testing and ad-hoc analysis, but pre-building with `matchy build` is recommended for repeated use.

### `<INPUT>...`

One or more input files containing log data (one line per entry), or `-` for stdin.

Multiple files can be processed sequentially or in parallel (see `-j, --threads`).

## Options

### `-j, --threads <THREADS>`

Number of worker threads for parallel processing (default: auto-detect).

- `auto` or `0` - Use all available CPU cores (default)
- `1` - Sequential processing (single-threaded)
- `N` - Use N worker threads

```console
$ matchy match threats.mxy *.log -j auto     # Parallel (all cores)
$ matchy match threats.mxy *.log -j 4        # Parallel (4 threads)
$ matchy match threats.mxy *.log -j 1        # Sequential
```

**Parallel processing benefits:**
- 2-8x faster throughput on multi-core systems
- Better CPU utilization for I/O-bound workloads
- Scales with number of CPU cores
- Each worker has its own LRU cache

**When to use sequential mode (`-j 1`):**
- Single small file
- When output order matters
- Debugging/testing

### `-f, --follow`

Follow log file(s) for new data (like `tail -f`).

Watches input files for new content and processes lines as they are appended. Press Ctrl+C to stop.

```console
$ matchy match threats.mxy /var/log/app.log -f --stats
[INFO] Mode: Follow (watch files for new content)
...
```

**Follow mode features:**
- Monitors files for changes using file system notifications
- Processes new lines immediately as they are written
- Supports multiple files simultaneously
- Works with parallel processing (`-j` flag)
- Graceful shutdown on Ctrl+C

### `--batch-bytes <SIZE>`

Batch size in bytes for parallel mode (default: 131072 = 128KB).

Controls how input is divided among worker threads. Larger batches reduce overhead but increase memory usage.

```console
$ matchy match threats.mxy huge.log -j auto --batch-bytes 262144  # 256KB batches
```

### `--format <FORMAT>`

Output format (default: `json`):
- `json` - NDJSON format (one JSON object per match on stdout)
- `summary` - Statistics only (no match output)

```console
$ matchy match threats.mxy access.log --format json
$ matchy match threats.mxy access.log --format summary --stats
```

### `-s, --stats`

Show detailed statistics to stderr including:
- Processing mode (sequential/parallel/follow)
- Lines processed and match rate
- Candidate extraction breakdown (IPv4, IPv6, domains, emails)
- Throughput (MB/s)
- Timing samples (extraction and lookup)
- Cache hit rate
- Number of files processed (in multi-file mode)

```console
$ matchy match threats.mxy access.log --stats
```

### `-p, --progress`

Show live progress updates during processing.

Displays a live 3-line progress indicator showing:
- Lines processed, matches found, hit rate, bytes processed, throughput, elapsed time
- Candidate breakdown (IPv4, IPv6, domains, emails)
- Lookup query rate

On TTY (terminal), progress updates in place. On non-TTY (redirected stderr), prints periodic snapshots.

```console
$ matchy match threats.mxy huge.log -j auto --progress
[PROGRESS] Lines: 1,234,567 | Matches: 4,523 (0.4%) | Processed: 512 MB | Throughput: 450 MB/s | Time: 1.1s
           Candidates: 1,456,789 total (IPv4: 1,234,567, IPv6: 123, Domains: 234,567, Emails: 12,345)
           Lookup rate: 1,324.35K queries/sec
```

### `--cache-size <SIZE>`

Set LRU cache capacity for query results (default: 10000). Use `0` to disable caching.

```console
$ matchy match threats.mxy access.log --cache-size 50000
$ matchy match threats.mxy access.log --cache-size 0  # No cache
```

## Examples

### Scan Apache Access Log

```console
$ matchy match threats.mxy /var/log/apache2/access.log --stats
[INFO] Loaded database: threats.mxy
[INFO] Load time: 12.45ms
[INFO] Cache: 10000 entries
[INFO] Extractor configured for: IPs, strings
[INFO] Processing stdin...

{"timestamp":"1697500800.123","line_number":1,"matched_text":"192.0.2.1","input_line":"192.0.2.1 - - [17/Oct/2024:10:00:00 +0000] \"GET /login HTTP/1.1\" 200 1234","match_type":"ip","prefix_len":32,"cidr":"192.0.2.1/32","data":{"threat_level":"high","category":"malware"}}
{"timestamp":"1697500800.456","line_number":5,"matched_text":"evil.com","input_line":"Request from evil.com blocked","match_type":"pattern","pattern_count":1,"data":[{"threat_level":"critical"}]}

[INFO] Processing complete
[INFO] Lines processed: 15,234
[INFO] Lines with matches: 127 (0.8%)
[INFO] Total matches: 145
[INFO] Candidates tested: 18,456
[INFO]   IPv4: 15,234
[INFO]   Domains: 3,222
[INFO] Throughput: 450.23 MB/s
[INFO] Total time: 0.15s
[INFO] Cache: 10,000 entries (92.3% hit rate)
```

### Process stdin Stream

```console
$ tail -f /var/log/syslog | matchy match threats.mxy - --stats
```

### Parallel Processing (Multiple Files)

```console
$ matchy match threats.mxy /var/log/*.log -j auto --stats --progress
[INFO] Mode: Parallel (8 worker threads)
[INFO] Batch size: 131072 bytes
[INFO] Loaded database: threats.mxy
[INFO] Load time: 12.45ms
[INFO] Cache: 10000 entries per worker
[PROGRESS] Lines: 5,234,123 | Matches: 8,456 (0.2%) | Processed: 2.1 GB | Throughput: 820 MB/s | Time: 12.3s
           Candidates: 6,123,456 (IPv4: 5,000,000, IPv6: 234, Domains: 1,123,222, Emails: 0)
           Lookup rate: 497.85K queries/sec

[INFO] === Processing Complete ===
[INFO] Files processed: 47
[INFO] Lines processed: 5,234,123
[INFO] Lines with matches: 8,456 (0.2%)
[INFO] Throughput: 820.15 MB/s
[INFO] Total time: 12.34s
```

### Follow Mode (Log Tailing)

```console
$ matchy match threats.mxy /var/log/app.log -f --stats
[INFO] Mode: Follow (watch files for new content)
[INFO] Loaded database: threats.mxy
[INFO] Extractor configured for: IPs, strings
[INFO] Watching for changes... (Ctrl+C to stop)

{"timestamp":"1697500850.123","line_number":42,"matched_text":"malware.com", ...}
{"timestamp":"1697500851.456","line_number":43,"matched_text":"192.0.2.50", ...}
^C
[INFO] Shutting down...
[INFO] Lines processed: 89
[INFO] Lines with matches: 2 (2.2%)
```

### Parallel Follow Mode (Multiple Log Files)

```console
$ matchy match threats.mxy /var/log/app*.log -f -j 4 --stats
[INFO] Mode: Follow (watch files for new content)
[INFO] Using parallel follow with 4 worker threads
...
```

### Quick Testing with Source Files (Auto-Build)

Skip the build step for quick ad-hoc analysis:

```console
# JSON source file (builds database in-memory automatically)
$ cat threats.json
[
  {"key": "192.168.1.0/24", "data": {"type": "internal"}},
  {"key": "*.malware.com", "data": {"severity": "high"}},
  {"key": "evil.example.com", "data": {"category": "phishing"}}
]

$ matchy match threats.json access.log --stats
[INFO] Building database from JSON file...
[INFO] Loaded 3 entries from JSON
[INFO] Database: 1 IPs, 1 literals, 1 globs
[INFO] Built database from: threats.json
{"matched_text":"192.168.1.50","match_type":"ip",...}

# CSV source file
$ cat threats.csv
key,type,severity
192.168.1.0/24,internal,low
*.malware.com,malware,high

$ matchy match threats.csv access.log
```

> **Note**: Auto-building is convenient for testing, but pre-building with `matchy build` is faster for repeated use since it avoids rebuilding on every invocation.

### Extract Only Matches

```console
$ matchy match threats.mxy access.log | jq -r '.matched_text'
192.0.2.1
evil.com
phishing.example.com
```

### Count Matches by Type

```console
$ matchy match threats.mxy access.log | jq -r '.match_type' | sort | uniq -c
  89 ip
  38 pattern
```

## Output Format

### JSON Output (NDJSON)

Each match is a JSON object on a single line:

```json
{
  "timestamp": "1697500800.123",
  "line_number": 42,
  "matched_text": "192.0.2.1",
  "input_line": "Original log line containing the match...",
  "match_type": "ip",
  "prefix_len": 24,
  "cidr": "192.0.2.0/24",
  "data": {
    "threat_level": "high",
    "category": "malware"
  }
}
```

**For pattern matches:**
```json
{
  "timestamp": "1697500800.456",
  "line_number": 127,
  "matched_text": "evil.example.com",
  "input_line": "DNS query for evil.example.com",
  "match_type": "pattern",
  "pattern_count": 2,
  "data": [
    {"threat_level": "high"},
    {"category": "phishing"}
  ]
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | Unix timestamp with milliseconds |
| `line_number` | number | Line number in input file |
| `matched_text` | string | The extracted text that matched |
| `input_line` | string | Complete original log line |
| `match_type` | string | `"ip"` or `"pattern"` |
| `prefix_len` | number | IP: CIDR prefix length |
| `cidr` | string | IP: Canonical CIDR notation |
| `pattern_count` | number | Pattern: Number of patterns matched |
| `data` | object/array | Associated metadata from database |

## Pattern Extraction

The command automatically extracts and tests:

- **IPv4 addresses**: 192.0.2.1, 10.0.0.0
- **IPv6 addresses**: 2001:db8::1, ::ffff:192.0.2.1
- **Domain names**: example.com, sub.domain.com
- **Email addresses**: user@example.com

Extraction is context-aware with word boundaries and validates format (TLD checks for domains, etc.).

## Performance

Typical throughput:
- **Sequential mode**: 200-500 MB/s on modern hardware
- **Parallel mode**: 400-2000 MB/s depending on core count and workload

**Parallel performance scaling:**
- 2 cores: ~1.8x speedup
- 4 cores: ~3.2x speedup
- 8 cores: ~5.5x speedup
- 16+ cores: ~8-10x speedup (diminishing returns)

**Best practices for performance:**
- Use parallel mode (`-j auto`) for multiple large files
- Enable caching (default) for repeated patterns
- Increase `--batch-bytes` for very large files (>1GB)
- Use sequential mode for small files (<10MB total)

## Exit Status

- `0` - Success (even if no matches found)
- `1` - Error (file not found, invalid database, etc.)

## See Also

- [matchy query](matchy-query.md) - Single query testing
- [matchy build](matchy-build.md) - Build databases
- [Pattern Extraction Guide](../guide/extraction.md) - Details on extraction
- [Query Result Caching](../guide/caching.md) - Cache optimization
