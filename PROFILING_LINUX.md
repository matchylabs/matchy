# Linux Cache Profiling with `perf`

The `perf` tool on Linux provides detailed CPU performance counter data, including cache miss rates at L1/L2/L3 levels.

## Prerequisites

```bash
# Install perf (Ubuntu/Debian)
sudo apt-get install linux-tools-common linux-tools-generic linux-tools-$(uname -r)

# Install perf (Fedora/RHEL)
sudo dnf install perf

# Install perf (Arch)
sudo pacman -S perf

# Verify installation
perf --version
```

## Quick Start: Cache Miss Analysis

```bash
# Build the profiling binary
cargo build --release --example profile_ac

# Run with cache statistics
sudo perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses \
    target/release/examples/profile_ac

# Or use the shorthand for common cache events
sudo perf stat -d target/release/examples/profile_ac
```

## Understanding the Output

### Example Output:
```
 Performance counter stats for 'target/release/examples/profile_ac':

       45,234,567      cache-references          # 1,245.678 M/sec
        2,345,678      cache-misses              #    5.18 % of all cache refs
      123,456,789      L1-dcache-loads           # 3,401.234 M/sec
        1,234,567      L1-dcache-load-misses     #    1.00 % of all L1-dcache hits
       15,678,901      LLC-loads                 #  432.123 M/sec
          567,890      LLC-load-misses           #    3.62 % of all LL-cache hits

       0.123456789 seconds time elapsed
```

### Interpreting the Metrics:

**Cache Miss Rate** = `(cache-misses / cache-references) × 100%`

- **< 3%**: Excellent - Prefetching and layout are working well
- **3-5%**: Good - Typical for well-optimized code
- **5-10%**: Acceptable - Some room for improvement
- **10-20%**: Poor - Memory layout issues likely
- **> 20%**: Very Poor - Serious cache problems

**L1 Data Cache Miss Rate** = `(L1-dcache-load-misses / L1-dcache-loads) × 100%`

- **< 1%**: Excellent
- **1-3%**: Good  
- **3-10%**: Could be better
- **> 10%**: Poor data locality

**Last Level Cache (LLC/L3) Miss Rate** = `(LLC-load-misses / LLC-loads) × 100%`

- **< 5%**: Excellent
- **5-15%**: Good
- **15-30%**: Acceptable
- **> 30%**: Poor - hitting main memory often

## Detailed Profiling

### 1. All Cache Levels

```bash
sudo perf stat -e \
    L1-dcache-loads,L1-dcache-load-misses,\
    L1-dcache-stores,L1-dcache-store-misses,\
    L1-icache-loads,L1-icache-load-misses,\
    LLC-loads,LLC-load-misses,LLC-stores,LLC-store-misses \
    target/release/examples/profile_ac
```

### 2. Branch Prediction Analysis

```bash
sudo perf stat -e \
    branches,branch-misses,\
    branch-instructions,branch-loads,branch-load-misses \
    target/release/examples/profile_ac
```

### 3. Comprehensive Performance Analysis

```bash
# -d: detailed stats (cache + more)
# -d -d: even more detail
# -d -d -d: maximum detail
sudo perf stat -d -d -d target/release/examples/profile_ac
```

### 4. Record and Analyze Hot Paths

```bash
# Record performance data
sudo perf record -e cache-misses -g target/release/examples/profile_ac

# View the report
sudo perf report

# Or generate a flamegraph-style view
sudo perf report --stdio
```

## Comparing Before/After Optimizations

### Baseline (Before Prefetching):

```bash
# Checkout version without prefetching
git stash
git checkout <commit-before-prefetch>

# Build and profile
cargo build --release --example profile_ac
sudo perf stat -d target/release/examples/profile_ac > baseline.txt 2>&1
```

### After Optimization:

```bash
# Return to current version
git stash pop

# Build and profile
cargo build --release --example profile_ac
sudo perf stat -d target/release/examples/profile_ac > optimized.txt 2>&1

# Compare
diff baseline.txt optimized.txt
```

## Advanced: Annotate Source Code with Cache Misses

Show which lines of code cause cache misses:

```bash
# Record with source annotation
sudo perf record -e cache-misses -g --call-graph dwarf target/release/examples/profile_ac

# Annotate the find_transition function
sudo perf annotate --stdio find_transition

# Or use TUI for interactive exploration
sudo perf annotate
```

## Sampling CPU Events

Get continuous profiling data:

```bash
# Sample at 99 Hz to avoid bias
sudo perf record -F 99 -e cycles,cache-misses \
    target/release/examples/profile_ac

# View results
sudo perf report
```

## Monitoring Specific Functions

Focus on the hot path:

```bash
# Record data
sudo perf record -e cache-misses --call-graph dwarf \
    target/release/examples/profile_ac

# Filter report to specific function
sudo perf report --stdio | grep find_transition
```

## Profiling in Production

For production profiling without sudo:

```bash
# Allow non-root perf (requires root once to set)
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid

# Or for this session only
sudo sysctl -w kernel.perf_event_paranoid=0

# Now can run without sudo
perf stat -e cache-misses target/release/examples/profile_ac
```

## Interpreting Results for AC Automaton

### Expected Baseline (with prefetching):

```
cache-references:       ~50M references/sec
cache-misses:           ~3-5% miss rate
L1-dcache-load-misses:  ~1-2% miss rate
LLC-load-misses:        ~5-10% miss rate
```

### What to Look For:

**If cache-miss rate is high (>10%)**:
- Check if prefetching is working (`perf annotate` should show `prfm`/`prefetch` instructions)
- Consider edge alignment optimization
- Profile with different workloads - maybe pattern structure matters

**If L1 miss rate is high (>5%)**:
- Data structure too large for L1 (32-64 KB typical)
- Poor spatial locality - data not accessed sequentially
- Working set doesn't fit in cache

**If LLC miss rate is high (>30%)**:
- Going to main memory too often (200+ cycle penalty)
- This is where prefetching should help most
- Consider reducing working set size

## Example: Finding the Bottleneck

```bash
# 1. Get overall stats
sudo perf stat -d target/release/examples/profile_ac

# 2. Record cache misses with call graph
sudo perf record -e cache-misses --call-graph dwarf target/release/examples/profile_ac

# 3. Find hot functions
sudo perf report --stdio | head -50

# 4. Annotate the hottest function
sudo perf annotate --stdio <function_name>

# 5. Look for lines with high cache miss %
#    These are your optimization targets!
```

## Automated Comparison Script

Save this as `profile_compare.sh`:

```bash
#!/bin/bash
set -e

echo "=== Building and Profiling ==="
cargo build --release --example profile_ac

echo -e "\n=== Cache Statistics ==="
sudo perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses \
    target/release/examples/profile_ac 2>&1 | grep -E "cache|elapsed"

echo -e "\n=== Branch Prediction ==="
sudo perf stat -e branches,branch-misses \
    target/release/examples/profile_ac 2>&1 | grep -E "branch|elapsed"

echo -e "\n=== Instructions Per Cycle ==="
sudo perf stat -e instructions,cycles \
    target/release/examples/profile_ac 2>&1 | grep -E "insn|IPC|elapsed"
```

Run with:
```bash
chmod +x profile_compare.sh
./profile_compare.sh
```

## Tips for Best Results

1. **Pin to single CPU** to reduce variance:
   ```bash
   taskset -c 0 perf stat -d target/release/examples/profile_ac
   ```

2. **Disable frequency scaling** for consistent results:
   ```bash
   sudo cpupower frequency-set -g performance
   # ... run tests ...
   sudo cpupower frequency-set -g powersave
   ```

3. **Run multiple iterations** and average:
   ```bash
   for i in {1..10}; do 
       perf stat -r 5 target/release/examples/profile_ac
   done
   ```

4. **Use hardware events** for most accurate data (not sampled)

## Common Issues

**"Permission denied" errors**:
```bash
# Temporarily allow perf for users
echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

**Missing symbols in reports**:
```bash
# Make sure debug info is included
cargo build --release
# Release builds include debuginfo by default in Cargo.toml
```

**"Event not supported" errors**:
```bash
# List available events
perf list

# Use only events your CPU supports
```

## Next Steps

1. Run baseline profiling with current code
2. Record cache miss rates for different workloads
3. Compare with/without prefetching
4. Identify if cache or computation is the bottleneck
5. Make data-driven optimization decisions

---

**Remember**: Real data beats intuition. Profile first, optimize second!
