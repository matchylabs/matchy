# Scripts

Utility scripts for the matchy project.

**Additional Documentation:**
- **[BENCHMARKING.md](BENCHMARKING.md)** - Comprehensive benchmarking guide (includes data persistence setup)

## Benchmark Management Scripts

These scripts help capture, compare, and analyze performance benchmarks using Criterion.

**Note**: Benchmarks are distributed across subcrates (`matchy-paraglob`, `matchy-extractor`) and the main `matchy` crate. The scripts automatically discover and run all workspace benchmarks via `cargo bench`.

### benchmark_baseline.sh

Captures a performance baseline for future comparisons. Creates timestamped backups and optionally tags the commit.

**Usage:**

```bash
./scripts/benchmark_baseline.sh [baseline-name]
```

**Examples:**
```bash
./scripts/benchmark_baseline.sh pre-optimization
./scripts/benchmark_baseline.sh v1.0-release
./scripts/benchmark_baseline.sh before-simd
```

**What it does:**

1. Checks for uncommitted changes (warns if present)
2. Prompts for system preparation (close apps, plug in power, etc.)
3. Performs a clean build (`cargo clean && cargo build --release`)
4. Sets up persistent benchmark storage (symlink to `benchmarks/criterion_data/`)
5. Runs full benchmark suite with `--save-baseline` flag (~5-10 minutes)
6. Creates timestamped backup in `benchmarks/baseline_{name}_{timestamp}/`
7. Saves metadata (git commit, rustc version, CPU info, memory, etc.)
8. Optionally creates a git tag: `baseline-{name}-{commit}`

**Output:**
- Baseline data in `target/criterion/{benchmark}/{baseline-name}/`
- Timestamped backup in `benchmarks/baseline_{name}_{timestamp}/`
- Metadata JSON with system and git information
- HTML report at `target/criterion/report/index.html`

**Important:** Baselines persist across `cargo clean` thanks to symlink setup.

---

### benchmark_compare.sh

Runs benchmarks and compares them against a previously saved baseline.

**Usage:**

```bash
./scripts/benchmark_compare.sh [baseline-name]
```

**Examples:**
```bash
./scripts/benchmark_compare.sh pre-optimization
./scripts/benchmark_compare.sh v1.0-release
```

**What it does:**

1. Verifies the baseline exists (lists available baselines if not found)
2. Performs a clean build (`cargo build --release`)
3. Runs benchmarks with `--baseline {name}` flag
4. Creates comparison report in `benchmarks/comparison_{timestamp}/`
5. Saves comparison metadata (current commit vs baseline)
6. Opens HTML report showing performance differences

**Output:**
- Comparison data in `target/criterion/{benchmark}/change/`
- Metadata in `benchmarks/comparison_{timestamp}/metadata.json`
- HTML report with statistical significance analysis

**Reading results:**
- **Green percentages**: Improvements (faster)
- **Red percentages**: Regressions (slower)
- **p-values < 0.05**: Statistically significant changes
- Look for "No change" vs "Change" indicators

---

### save_current_as_baseline.sh

Saves the most recent benchmark run (the "new" data) as a named baseline. Useful when you've already run `cargo bench` and want to preserve those results.

**Usage:**

```bash
./scripts/save_current_as_baseline.sh <baseline-name>
```

**Examples:**
```bash
# After running: cargo bench
./scripts/save_current_as_baseline.sh post-optimization
./scripts/save_current_as_baseline.sh after-simd-impl
```

**What it does:**

1. Verifies benchmark data exists in `benchmarks/criterion_data/`
2. Finds all `new/` directories (most recent benchmark runs)
3. Copies them to `{baseline-name}/` directories
4. Creates timestamped backup in `benchmarks/baseline_{name}_{timestamp}/`
5. Saves metadata (git commit, system info, etc.)
6. Lists all available baselines

**When to use:**
- You ran `cargo bench` manually and want to save those results
- You want to promote a comparison run to a baseline
- You need to create a baseline retroactively

**Warning:** This overwrites any existing baseline with the same name.

---

### benchmark_report.sh

Shows an overview of all available baselines, recent comparisons, and system information.

**Usage:**

```bash
./scripts/benchmark_report.sh
```

**What it displays:**

1. **Available Baselines**: All captured baselines with metadata
   - Timestamp
   - Git commit and branch
   - Location on disk

2. **Recent Comparisons**: Last 5 comparison runs
   - When they were run
   - Which baseline was used
   - Current commit at comparison time

3. **Current System Info**: 
   - CPU model and core count
   - Memory (GB)
   - Rust/Cargo versions

4. **Git Status**:
   - Current branch and commit
   - Clean vs uncommitted changes

5. **Quick Actions**: Command reminders for common tasks

**Use this to:**
- See what baselines are available before running comparisons
- Check when the last baseline was captured
- Verify system configuration
- Get quick command references

---

## Documentation Generation

### generate_perf_docs.sh

Generates performance documentation by running live benchmarks and parsing the results into markdown.

**Usage:**

```bash
./scripts/generate_perf_docs.sh
```

**What it does:**

1. Runs `matchy bench` for IP, literal, and pattern benchmarks
2. Parses the output to extract performance metrics
3. Generates `book/src/architecture/performance-results.md` with:
   - Current version number from Cargo.toml
   - Today's date
   - Benchmark results in markdown tables
   - Performance characteristics documentation

**Configuration:**

Edit the COUNT variables at the top of the script to adjust benchmark sizes:

```bash
IP_COUNT=100000          # Number of IP addresses (default: 100k)
LITERAL_COUNT=50000      # Number of literals (default: 50k)
PATTERN_COUNT=10000      # Number of patterns (default: 10k)
QUERY_COUNT=50000        # Queries per benchmark (default: 50k)
```

Larger counts = more accurate but slower benchmarks.

**After running:**

1. Review the generated `book/src/architecture/performance-results.md`
2. Run `mdbook build` to update the docs
3. Commit the file if the numbers look good

**Note:** The script runs in release mode for realistic performance numbers. Initial run may take a few minutes while benchmarks complete.

---

## Typical Workflows

### Workflow 1: Before/After Optimization

```bash
# 1. Capture baseline before making changes
./scripts/benchmark_baseline.sh pre-optimization

# 2. Implement your optimization
# ... edit code ...

# 3. Compare against baseline
./scripts/benchmark_compare.sh pre-optimization

# 4. Review HTML report
open target/criterion/report/index.html

# 5. If results are good, save as new baseline
./scripts/save_current_as_baseline.sh post-optimization
```

### Workflow 2: Iterative Optimization

```bash
# Initial baseline
./scripts/benchmark_baseline.sh v1-baseline

# Try optimization A
# ... edit code ...
cargo bench
./scripts/save_current_as_baseline.sh try-optimization-a

# Try optimization B (compare to original)
# ... edit code ...
./scripts/benchmark_compare.sh v1-baseline

# Compare A vs B
./scripts/benchmark_compare.sh try-optimization-a
```

### Workflow 3: Release Benchmarking

```bash
# Before release
./scripts/benchmark_baseline.sh v2.0-candidate

# Tag will be: baseline-v2.0-candidate-{commit}
# Push tag: git push origin baseline-v2.0-candidate-{commit}

# Generate documentation
./scripts/generate_perf_docs.sh

# Update mdbook and commit
(cd book && mdbook build)
git add book/src/architecture/performance-results.md
git commit -m "Update performance docs for v2.0"
```

### Workflow 4: Quick Check

```bash
# See what baselines exist
./scripts/benchmark_report.sh

# Run comparison against latest
./scripts/benchmark_compare.sh v1.0-release

# Quick single benchmark test
cargo bench --bench matchy_bench match/p100_t1000
```

---

## Tips and Best Practices

### System Preparation

For accurate benchmarks:
- **Close unnecessary applications** (browsers, IDEs, Docker, VMs)
- **Plug in power** (disable battery throttling)
- **Disable Wi-Fi/Bluetooth** if possible (reduces background activity)
- **Run multiple times** to verify consistency
- **Don't touch the computer** during benchmark runs

### Baseline Management

- **Use descriptive names**: `pre-simd-opt` not `baseline1`
- **Capture baselines on clean commits**: No uncommitted changes
- **Tag important baselines**: Makes them easy to reference later
- **Keep backups**: The `benchmarks/` directory preserves all historical data
- **Compare on same hardware**: Performance varies across machines

### Interpreting Results

- **Statistical significance matters**: Look for p < 0.05
- **Small changes (< 5%) may be noise**: Multiple runs help verify
- **Watch load times**: Regressions here are critical for mmap use cases
- **Check all benchmarks**: Some optimizations help one area, hurt another
- **Document in commits**: Include benchmark results in commit messages

### Data Persistence

- **Benchmark data persists** across `cargo clean` (stored in `benchmarks/`)
- **Timestamped backups** prevent accidental overwrites
- **Metadata includes**: Git commit, system info, timestamp
- **HTML reports** regenerate from stored data

---

## Troubleshooting

### "Baseline not found" error

```bash
# List available baselines
find benchmarks/criterion_data -type d -maxdepth 3 -mindepth 3 | 
  xargs basename 2>/dev/null | sort | uniq

# Or use the report script
./scripts/benchmark_report.sh
```

### Symlink issues

If `target/criterion` isn't a symlink:

```bash
# Scripts auto-fix this, but manually:
rm -rf target/criterion
mkdir -p benchmarks/criterion_data
ln -s ../benchmarks/criterion_data target/criterion
```

### Inconsistent results

- Close background applications
- Run multiple times and check variance
- Check CPU throttling (thermal or power)
- Verify same optimization level (`--release`)

### Missing jq

Scripts work without `jq` but it helps with JSON parsing:

```bash
brew install jq
```

---

## File Structure

```
benchmarks/
├── criterion_data/              # Live criterion data (symlinked from target/)
│   └── {benchmark-name}/
│       ├── new/                 # Most recent run
│       ├── base/                # Comparison baseline
│       ├── {baseline-name}/     # Named baselines
│       └── report/              # HTML reports
├── baseline_{name}_{timestamp}/ # Timestamped backups
│   ├── metadata.json            # System and git info
│   └── {criterion_data}/        # Full snapshot
└── comparison_{timestamp}/      # Comparison metadata
    └── metadata.json

target/
└── criterion -> ../benchmarks/criterion_data  # Symlink
```
