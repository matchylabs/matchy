# Matchy Fuzz Targets

This directory contains cargo-fuzz targets for testing matchy's robustness against malformed inputs.

## Running Fuzz Tests

```bash
# Quick start (from project root)
./fuzz/fuzz_quickstart.sh

# Or manually run a specific target
cargo +nightly fuzz run fuzz_database_load

# Run with more iterations
cargo +nightly fuzz run fuzz_database_load -- -runs=1000000

# Run with corpus from previous runs
cargo +nightly fuzz run fuzz_database_load fuzz/corpus/fuzz_database_load
```

## Available Targets

### 1. `fuzz_database_load` - Raw Binary Format Validation
**Purpose:** Tests database loading from arbitrary binary data.

**What it fuzzes:**
- MMDB header parsing
- Binary format validation
- Offset calculations and bounds checking
- Memory safety with malformed structures

**Why it matters:** The most critical safety test. Ensures no crashes or panics when loading untrusted `.mxy` files, even if completely corrupted or maliciously crafted.

**Run with:**
```bash
cargo +nightly fuzz run fuzz_database_load
```

---

### 2. `fuzz_pattern_matching` - End-to-End Pattern Workflow
**Purpose:** Tests the complete pattern matching pipeline from build to query.

**What it fuzzes:**
- Building databases with arbitrary patterns
- Pattern parsing and validation
- Query execution with varied inputs
- Build → Load → Query round-trip

**Why it matters:** Catches issues in the interaction between builder, serializer, and matcher. Tests real-world workflows.

**Run with:**
```bash
cargo +nightly fuzz run fuzz_pattern_matching
```

---

### 3. `fuzz_ip_lookup` - IP Address Parsing Edge Cases
**Purpose:** Tests IP lookup with malformed or edge-case IP addresses.

**What it fuzzes:**
- IP address string parsing
- IPv4/IPv6 handling
- CIDR notation edge cases
- IP tree traversal with various inputs

**Why it matters:** IP parsing is complex and has many edge cases (leading zeros, IPv4-mapped IPv6, malformed octets, etc.). Ensures robust handling.

**Run with:**
```bash
cargo +nightly fuzz run fuzz_ip_lookup
```

---

### 4. `fuzz_glob_patterns` - Glob Syntax Edge Cases
**Purpose:** Tests glob pattern parsing with pathological inputs.

**What it fuzzes:**
- Multiple consecutive wildcards: `****`
- Empty/unclosed character classes: `[]`, `[a-z`
- Negated empty classes: `[!]`
- Backslash at end: `\`
- Very long patterns
- Case-sensitive vs case-insensitive matching

**Why it matters:** Glob parsing is notoriously tricky. This finds edge cases that could cause panics, infinite loops, or incorrect matches.

**Run with:**
```bash
cargo +nightly fuzz run fuzz_glob_patterns
```

---

### 5. `fuzz_data_values` - Data Section Encoding/Decoding
**Purpose:** Tests the serialization/deserialization of rich data values.

**What it fuzzes:**
- Integer encoding (various values)
- Float encoding (including edge cases like NaN, infinity)
- String encoding (UTF-8 validation)
- Nested maps and arrays
- Complex data structures

**Why it matters:** The data section supports JSON-like nested structures. This ensures encoding/decoding is robust against all value types and combinations.

**Run with:**
```bash
cargo +nightly fuzz run fuzz_data_values
```

---

### 6. `fuzz_literal_exact_match` - Literal Hash Table
**Purpose:** Tests the exact string matching hash table implementation.

**What it fuzzes:**
- Hash collisions
- Empty strings
- Very long strings
- UTF-8 edge cases
- Lookup of non-existent keys

**Why it matters:** The literal hash table is a performance-critical O(1) lookup path. This ensures it handles edge cases correctly and doesn't have hash collision vulnerabilities.

**Run with:**
```bash
cargo +nightly fuzz run fuzz_literal_exact_match
```

---

### 7. `fuzz_target_1` - Template/Placeholder
**Purpose:** Generic template for adding new fuzz targets.

**Status:** Currently empty boilerplate. Can be customized for specific test scenarios.

---

## What Each Target Tests

| Target | Binary Format | IP Logic | Pattern Logic | Data Values | Hash Tables |
|--------|--------------|----------|---------------|-------------|-------------|
| `fuzz_database_load` | ✅✅✅ | ✅ | ✅ | ✅ | ✅ |
| `fuzz_pattern_matching` | ✅ | ❌ | ✅✅✅ | ✅ | ❌ |
| `fuzz_ip_lookup` | ✅ | ✅✅✅ | ❌ | ✅ | ❌ |
| `fuzz_glob_patterns` | ✅ | ❌ | ✅✅✅ | ❌ | ❌ |
| `fuzz_data_values` | ✅ | ❌ | ❌ | ✅✅✅ | ❌ |
| `fuzz_literal_exact_match` | ✅ | ❌ | ❌ | ✅ | ✅✅✅ |

✅ = Covered, ✅✅✅ = Primary focus

## Recommended Fuzzing Strategy

### Quick Check (5-10 minutes each)
Run each target for a few minutes to catch obvious issues:
```bash
for target in fuzz_database_load fuzz_pattern_matching fuzz_ip_lookup fuzz_glob_patterns fuzz_data_values fuzz_literal_exact_match; do
    echo "Fuzzing $target for 5 minutes..."
    timeout 300 cargo +nightly fuzz run $target
done
```

### Deep Fuzzing (CI/CD or overnight)
For comprehensive testing, run for hours or days:
```bash
# Run for 24 hours
cargo +nightly fuzz run fuzz_database_load -- -max_total_time=86400

# Or indefinitely until crash found
cargo +nightly fuzz run fuzz_database_load
```

### Parallel Fuzzing
Run multiple targets simultaneously on different cores:
```bash
# Terminal 1
cargo +nightly fuzz run fuzz_database_load

# Terminal 2
cargo +nightly fuzz run fuzz_pattern_matching

# Terminal 3
cargo +nightly fuzz run fuzz_glob_patterns
```

## Corpus Management

Fuzz targets accumulate "interesting" inputs in `fuzz/corpus/<target>/`. These are valuable test cases:

```bash
# View corpus
ls -lh fuzz/corpus/fuzz_database_load/

# Manually test a corpus file
cargo +nightly fuzz run fuzz_database_load fuzz/corpus/fuzz_database_load/some_file

# Minimize corpus (remove redundant cases)
cargo +nightly fuzz cmin fuzz_database_load
```

## When to Add New Targets

Consider adding a new fuzz target when:
1. **New feature added** - Fuzz the new API surface
2. **Bug found** - Create a regression fuzz target
3. **Complex parsing** - Any new parser deserves its own target
4. **Performance path** - Test optimized code paths (like trusted mode)
5. **C FFI changes** - Fuzz the C API boundary

## Integration with CI

Example GitHub Actions snippet:
```yaml
- name: Fuzz for 5 minutes
  run: |
    cargo install cargo-fuzz
    for target in fuzz_database_load fuzz_glob_patterns; do
      timeout 300 cargo +nightly fuzz run $target || true
    done
```

## See Also

- **[FUZZING_GUIDE.md](../.dev/docs/FUZZING_GUIDE.md)** - Comprehensive fuzzing guide (local only)
- **[fuzz_quickstart.sh](fuzz_quickstart.sh)** - Automated fuzzing setup
- **cargo-fuzz docs** - https://rust-fuzz.github.io/book/cargo-fuzz.html
