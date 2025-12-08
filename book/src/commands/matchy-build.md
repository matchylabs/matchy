# matchy build

Build a database from input files.

## Synopsis

```console
matchy build [OPTIONS] <INPUT> --output <OUTPUT>
```

## Description

The `matchy build` command reads entries from input files and builds an optimized
binary database. The input can be CSV, JSON, JSONL, or TSV format.

## Options

### `-o, --output <FILE>`

Specify the output database file path.

```console
$ matchy build threats.csv -o threats.mxy
```

### `--case-sensitive`

Use case-sensitive string matching. By default, matching is case-insensitive.

```console
$ matchy build domains.csv -o domains.mxy --case-sensitive
```

### `--format <FORMAT>`

Explicitly specify input format: `csv`, `json`, `jsonl`, or `tsv`. If not specified,
format is detected from file extension.

```console
$ matchy build data.txt --format csv -o output.mxy
```

### `-t, --database-type <NAME>`

Set the database type in metadata. If you use a known schema name (e.g., `threatdb`),
yield values are validated against the schema during build.

```console
# Enable ThreatDB schema validation
$ matchy build threats.csv -o threats.mxy --database-type threatdb

# Custom type (no validation)
$ matchy build data.csv -o data.mxy --database-type "MyCompany-Intel"
```

See [Schemas Reference](../reference/schemas.md) for available schemas and validation details.

## Examples

### Build from CSV

```console
$ cat threats.csv
key,threat_level,category
192.0.2.1,high,malware
10.0.0.0/8,medium,internal
*.evil.com,high,phishing

$ matchy build threats.csv -o threats.mxy
Building database from threats.csv
  Added 3 entries
Successfully wrote threats.mxy
```

### Build from JSON Lines

```console
$ cat data.jsonl
{"key": "192.0.2.1", "threat": "high"}
{"key": "*.malware.com", "category": "malware"}

$ matchy build data.jsonl -o database.mxy
```

## Entry Type Detection

Matchy automatically detects entry types from the key format:

| Input | Detected As |
|-------|-------------|
| `192.0.2.1` | IP Address |
| `10.0.0.0/8` | CIDR Range |
| `*.example.com` | Pattern (glob) |
| `example.com` | Exact String |

### Explicit Type Control

Use **type prefixes** to override auto-detection:

```console
$ cat entries.txt
literal:*.not-a-glob.txt
glob:simple-string.com
ip:192.168.1.1

$ matchy build entries.txt -o output.mxy
```

| Prefix | Type | Example |
|--------|------|----------|
| `literal:` | Exact String | `literal:file*.txt` matches only "file*.txt" |
| `glob:` | Pattern | `glob:test.com` treated as pattern |
| `ip:` | IP/CIDR | `ip:10.0.0.1` forced as IP |

The prefix is automatically stripped before storage. This is useful when:
- String contains `*`, `?`, or `[` that should be literal
- Forcing pattern matching for consistency
- Disambiguating edge cases

See [Entry Types - Prefix Technique](../guide/entry-types.md#explicit-type-control-prefix-technique) for complete documentation.

## See Also

- [matchy query](matchy-query.md) - Query databases
- [matchy inspect](matchy-inspect.md) - Inspect database contents
- [First Database with CLI](../getting-started/cli-first-database.md) - Tutorial
