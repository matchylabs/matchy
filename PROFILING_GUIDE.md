# Cache Profiling Guide

This guide shows how to profile the AC automaton to measure actual cache miss rates and identify performance bottlenecks.

## Quick Start

```bash
# 1. Build the profiling binary
cargo build --release --example profile_ac

# 2. Run with timing only (no profiling)
cargo run --release --example profile_ac

# 3. Profile with Instruments (recommended)
# See detailed instructions below
```

## Method 1: Instruments (macOS) - RECOMMENDED

Instruments provides detailed cache statistics and CPU profiling.

### Using Instruments GUI

1. **Build the binary**:
   ```bash
   cargo build --release --example profile_ac
   ```

2. **Open Instruments**:
   ```bash
   open -a Instruments
   ```

3. **Choose a template**:
   - **Time Profiler**: See where CPU time is spent (best for general profiling)
   - **System Trace**: See cache misses, context switches, system calls
   - **Allocations**: See memory allocations (less useful for cache analysis)

4. **Select target**:
   - Click "Choose Target" → "Choose"
   - Navigate to: `target/release/examples/profile_ac`
   - Click "Choose"

5. **Run profiling**:
   - Click the red record button
   - Wait for the program to complete
   - Click stop

6. **Analyze results**:

   **For Time Profiler**:
   - Look at the call tree
   - Find `find_transition` and `find_pattern_ids` 
   - Check "% Self" to see where time is actually spent
   - Look for unexpected hot spots

   **For System Trace**:
   - Click "Events" tab at bottom
   - Select "Memory" section
   - Look for cache miss events
   - High cache miss rate = memory layout issues

### Using Instruments CLI

```bash
# Profile with Time Profiler
instruments -t "Time Profiler" \
    -D ~/Desktop/profile.trace \
    target/release/examples/profile_ac

# Profile with System Trace (shows cache misses)
instruments -t "System Trace" \
    -D ~/Desktop/profile_system.trace \
    target/release/examples/profile_ac

# Open results
open ~/Desktop/profile.trace
```

## Method 2: Activity Monitor (Quick Check)

1. **Open Activity Monitor** (Command + Space, type "Activity Monitor")
2. **Run the profiling binary** in another terminal:
   ```bash
   cargo run --release --example profile_ac
   ```
3. **Find the process** (search for "profile_ac")
4. **Double-click** on the process
5. **Click "Memory" tab** to see:
   - Memory usage
   - Cache activity (if available)
   - Page faults

## Method 3: Manual Instrumentation

For more control, you can add manual instrumentation using the `perf-event` crate or custom timing.

### Install perf-event (optional)

```bash
# Add to Cargo.toml
[dev-dependencies]
perf-event = "0.4"
```

Note: This requires Linux. On macOS, we're limited to Instruments or manual timing.

## What to Look For

### Good Signs:
- ✅ Time spent in `find_transition` is predictable
- ✅ Low cache miss rate (< 5-10%)
- ✅ Most time in actual matching logic, not memory access
- ✅ Prefetching instructions show up in assembly

### Bad Signs:
- ❌ High L1/L2/L3 cache miss rates (> 20%)
- ❌ Time spent waiting on memory
- ❌ Lots of time in bounds checking or validation
- ❌ Unpredictable performance across runs

### Key Metrics to Record

When profiling, record these metrics:

1. **Cache Miss Rate**: (cache misses / cache references) × 100%
   - < 5%: Excellent
   - 5-10%: Good
   - 10-20%: Could be better
   - > 20%: Memory layout issues

2. **Instructions Per Cycle (IPC)**:
   - > 2.0: CPU is busy (good)
   - 1.0-2.0: Some stalls
   - < 1.0: Heavy memory/branch stalls (bad)

3. **Branch Misprediction Rate**:
   - < 2%: Excellent
   - 2-5%: Good
   - > 5%: Branch prediction issues

## Example Workflow

```bash
# 1. Establish baseline with prefetching
cargo build --release --example profile_ac
instruments -t "Time Profiler" -D ~/Desktop/with_prefetch.trace \
    target/release/examples/profile_ac

# 2. Look at the profile - where is time spent?
open ~/Desktop/with_prefetch.trace

# 3. If you want to compare without prefetching:
#    - Comment out prefetch calls in ac_offset.rs
#    - Rebuild and profile again
#    - Compare the two traces

# 4. Check for cache issues in System Trace
instruments -t "System Trace" -D ~/Desktop/cache_analysis.trace \
    target/release/examples/profile_ac
open ~/Desktop/cache_analysis.trace
```

## Interpreting Results

### If Cache Misses Are High (>15%):

Potential optimizations:
1. ✅ **Prefetching** (already implemented!)
2. **Edge alignment** - Align sparse edges to 8-byte boundaries
3. **Better packing** - Group related data together
4. **Smaller structures** - Reduce memory footprint

### If Cache Misses Are Low (<10%):

Focus on other bottlenecks:
1. **Branch prediction** - Already optimized
2. **Algorithm improvements** - Different data structure?
3. **SIMD** - Wider vectorization
4. **Code size** - Ensure hot code fits in instruction cache

### If Time Is Spent in Unexpected Places:

Common issues:
- **Bounds checking**: Consider unsafe with validation
- **String allocation**: Use string slices instead
- **Hashing**: Profile hash table lookups
- **Serialization**: Check zerocopy usage

## Advanced: Custom Counters

For the most accurate data, you can add custom performance counters:

```rust
// In your code
#[cfg(target_arch = "aarch64")]
fn read_cycle_counter() -> u64 {
    let mut count: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, PMCCNTR_EL0",
            out(reg) count
        );
    }
    count
}

// Then time specific sections
let start = read_cycle_counter();
let result = find_transition(offset, ch);
let cycles = read_cycle_counter() - start;
```

## Next Steps After Profiling

1. **Record baseline metrics** from current code
2. **Identify top bottleneck** from profile data
3. **Implement targeted optimization**
4. **Re-profile to measure improvement**
5. **Repeat**

## Questions to Answer

Use profiling to answer:

- [ ] What % of time is spent in `find_transition`?
- [ ] What's the L1/L2/L3 cache miss rate?
- [ ] Are prefetch instructions helping?
- [ ] Where are the unexpected hot spots?
- [ ] Is memory latency or computation the bottleneck?

---

**Pro tip**: Profile with realistic workloads that match your production use case. Synthetic benchmarks can be misleading!
