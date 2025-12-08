# matchy validate

Validate a database file for safety and correctness.

## Synopsis

```bash
matchy validate [OPTIONS] <DATABASE>
```

## Description

The `validate` command performs comprehensive validation of Matchy database files (`.mxy`) to ensure they are safe to load and use. This is especially important when working with databases from untrusted sources.

Validation checks include:
- **MMDB format structure**: Valid metadata, search tree, and data sections
- **PARAGLOB section integrity**: Pattern automaton structure and consistency
- **Bounds checking**: All offsets point within the file
- **UTF-8 validity**: All strings are valid UTF-8
- **Graph integrity**: No cycles in the failure function
- **Data consistency**: Arrays, maps, and pointers are valid
- **Schema validation**: If `database_type` matches a known schema (e.g., `ThreatDB-v1`), yield values are validated against it

The validator is designed to detect malformed, corrupted, or potentially malicious databases without panicking or causing undefined behavior.

## Options

### `-l, --level <LEVEL>`

Validation strictness level. Default: `strict`

Levels:
- **`standard`**: Basic checks - offsets, UTF-8, structure
- **`strict`**: Deep analysis - cycles, redundancy, consistency (default)
- **`audit`**: Track unsafe code paths and trust assumptions

### `-j, --json`

Output results as JSON instead of human-readable format.

### `-v, --verbose`

Show detailed information including warnings and info messages.

### `-h, --help`

Print help information.

## Arguments

### `<DATABASE>`

Path to the Matchy database file (`.mxy`) to validate.

## Examples

### Basic Validation

Validate with default strict checking:

```bash
matchy validate database.mxy
```

Shows:
- Validation level used (strict by default)
- Database statistics (nodes, patterns, IPs, size)
- Validation time
- Pass/fail status with clear ✅/❌ indicator

### Standard Validation

Use faster standard validation:

```bash
matchy validate --level standard database.mxy
```

### Verbose Output

Show warnings and informational messages:

```bash
matchy validate --verbose database.mxy
```

Adds additional detail:
- **Warnings**: Non-fatal issues (unreferenced patterns, duplicates)
- **Information**: Validation steps completed successfully
- Useful for understanding what was checked and any potential optimizations

### JSON Output

Machine-readable JSON format:

```bash
matchy validate --json database.mxy
```

Provides structured output with:
- `is_valid`: Boolean pass/fail
- `duration_ms`: Validation time
- `errors`, `warnings`, `info`: Categorized messages
- `stats`: Detailed database metrics (node count, pattern count, file size, etc.)

Useful for CI/CD pipelines and automated testing.

### Audit Mode

Track where unsafe code is used and what trust assumptions are made:

```bash
matchy validate --level audit --verbose database.mxy
```

This mode is useful for security audits and understanding the trust model.

## Exit Status

- **0**: Validation passed (no errors)
- **1**: Validation failed (errors found)
- **Other**: Command error (file not found, etc.)

## Validation Levels

### Standard

Fast validation with essential safety checks:
- File format structure
- Offset bounds checking
- UTF-8 string validity
- Basic graph structure

**Use when**: Validating trusted databases for basic integrity

### Strict (Default)

Comprehensive validation including:
- All standard checks
- Cycle detection in automaton
- Redundancy analysis
- Deep consistency checks
- Pattern reachability

**Use when**: Validating databases from untrusted sources (default)

### Audit

All strict checks plus:
- Track all unsafe code locations
- Document trust assumptions
- Report where `--trusted` mode bypasses validation
- Security analysis

**Use when**: Performing security audits

## Common Validation Errors

### Invalid MMDB format

```
ERROR: Invalid MMDB format: metadata marker not found
```

The file is not a valid MMDB database.

### Offset out of bounds

```
ERROR: Node 123 edge offset 45678 exceeds file size 40000
```

The database references data beyond the file size - likely corruption.

### Invalid UTF-8

```
ERROR: String at offset 12345 contains invalid UTF-8
```

A string in the database is not valid UTF-8 text.

### Cycle detected

```
ERROR: Cycle detected in failure function starting at node 56
```

The Aho-Corasick automaton has a cycle, making it unsafe to traverse.

### Invalid magic bytes

```
ERROR: PARAGLOB section magic bytes mismatch: expected "PARAGLOB", found "CORRUPT!"
```

The PARAGLOB section header is corrupted.

## When to Validate

### Always Validate

- Databases from untrusted sources
- Databases downloaded from the internet
- Databases created by third parties
- After file transfer (detect corruption)

### Optional Validation

- Databases built locally with `matchy build`
- Databases from trusted internal sources
- Development/testing environments

### Skip Validation

- After validation has already passed
- In performance-critical hot paths
- When loading the same database repeatedly

## Performance

Validation speed depends on database size and complexity. Standard mode is typically faster than strict mode.

For very large databases (>100MB), consider using `--level standard` for faster validation, or validate once and cache the result.

## Security Considerations

The validator is designed to be safe even with malicious input:

- **No panics**: All errors are caught and reported
- **Bounds checking**: All memory access is validated
- **Safe Rust**: Core validation uses only safe Rust
- **No trust**: Assumes file contents may be adversarial

However, validation is not a substitute for other security measures:

- Always validate before first use
- Use strict mode for untrusted sources
- Combine with file integrity checks (checksums)
- Consider sandboxing if processing user-uploaded files

## Integration with Other Commands

### Validate After Building

```bash
matchy build -i patterns.csv -o database.mxy
matchy validate database.mxy
```

### Validate Before Querying

```bash
matchy validate database.mxy && \
matchy query database.mxy "*.example.com"
```

### Batch Validation

```bash
for db in *.mxy; do
    echo "Validating $db..."
    matchy validate --level standard "$db" || echo "FAILED: $db"
done
```

## Troubleshooting

### False Positives

Some warnings may be benign:
- Unreferenced patterns (intentional padding)
- Duplicate patterns (for testing)

Use `--level standard` to skip these checks if needed.

### Performance Issues

For very large databases (>100MB):
- Use `--level standard` for faster validation
- Validate once and cache the result
- Skip validation for trusted internal databases

### Memory Usage

Validation loads the entire file into memory. For databases larger than available RAM, validation may fail with an out-of-memory error.

## See Also

- [matchy build](matchy-build.md) - Build databases
- [matchy inspect](matchy-inspect.md) - Inspect database structure
- [Validation API](../reference/validation-api.md) - Programmatic validation
- [Schemas Reference](../reference/schemas.md) - Schema validation details
- [Binary Format](../reference/binary-format.md) - Format specification
