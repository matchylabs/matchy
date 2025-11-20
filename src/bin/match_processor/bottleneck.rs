//! Automatic bottleneck detection and performance tuning recommendations

use super::stats::ProcessingStats;
use std::time::Duration;

/// Identifies the primary bottleneck in the processing pipeline
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum Bottleneck {
    /// Disk I/O is the limiting factor
    DiskRead { severity: f64 },
    /// Decompression (gzip) is the limiting factor
    Decompression { severity: f64 },
    /// Workers are spending too much time idle (reader can't keep up)
    ReaderStarved { severity: f64 },
    /// Workers are fully utilized (need more workers)
    WorkerSaturated { severity: f64 },
    /// Pattern extraction is consuming most CPU time
    Extraction { severity: f64 },
    /// Database lookups are consuming most CPU time
    Lookup { severity: f64 },
    /// System is well-balanced
    Balanced,
}

impl Bottleneck {
    /// Get severity as percentage (0-100)
    #[allow(dead_code)]
    pub fn severity_percent(&self) -> f64 {
        match self {
            Self::DiskRead { severity } => severity * 100.0,
            Self::Decompression { severity } => severity * 100.0,
            Self::ReaderStarved { severity } => severity * 100.0,
            Self::WorkerSaturated { severity } => severity * 100.0,
            Self::Extraction { severity } => severity * 100.0,
            Self::Lookup { severity } => severity * 100.0,
            Self::Balanced => 0.0,
        }
    }
}

/// Performance analysis and recommendations
#[derive(Debug)]
pub struct PerformanceAnalysis {
    /// Primary bottleneck
    #[allow(dead_code)]
    pub bottleneck: Bottleneck,
    /// Human-readable explanation
    pub explanation: String,
    /// Actionable recommendations
    pub recommendations: Vec<String>,
}

/// Configuration parameters for performance analysis
pub struct AnalysisConfig {
    pub num_workers: usize,
    pub num_files: usize,
    pub cache_hit_rate: f64,
    pub is_auto_tuned: bool,
    pub num_readers: usize,
}

/// Analyze processing statistics to identify bottlenecks
pub fn analyze_performance(
    stats: &ProcessingStats,
    total_time: Duration,
    config: AnalysisConfig,
) -> PerformanceAnalysis {
    // Get available parallelism (more reliable than gdt_cpus, especially on ARM)
    let physical_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let total_secs = total_time.as_secs_f64();

    // Simple ratios for bottleneck detection
    let worker_idle_secs = stats.worker_idle_time.as_secs_f64();
    let worker_busy_secs = stats.worker_busy_time.as_secs_f64();

    // Calculate worker idle percentage (average across workers)
    let worker_idle_pct = if config.num_workers > 0 && total_secs > 0.0 {
        (worker_idle_secs / config.num_workers as f64) / total_secs
    } else {
        0.0
    };

    // Bottleneck detection logic
    // Note: decompress/read times can exceed wall clock when parallel readers are used
    // So check worker idle time as primary indicator
    let (bottleneck, explanation, recommendations) = if worker_idle_pct > 0.6 {
        // Workers are mostly idle - I/O bottleneck
        let mut recs = vec![];
        if !config.is_auto_tuned && config.num_files > 1 {
            recs.push("Use --threads=0 for auto-tune".to_string());
        } else if !config.is_auto_tuned {
            recs.push(format!(
                "Try --threads={} (reduce workers)",
                config.num_workers / 2
            ));
        } else {
            // Already auto-tuned, no obvious fix
            recs.push("I/O is the limiting factor".to_string());
        }

        (
            Bottleneck::ReaderStarved {
                severity: worker_idle_pct,
            },
            format!(
                "Bottleneck: Workers idle {:.0}% of time (I/O can't keep up)",
                worker_idle_pct * 100.0
            ),
            recs,
        )
    } else if worker_idle_pct < 0.1
        && worker_busy_secs > total_secs * config.num_workers as f64 * 0.8
    {
        // Workers are busy, but check if I/O is already saturated
        let io_time_secs = stats.read_time.as_secs_f64() + stats.decompress_time.as_secs_f64();

        // Calculate I/O utilization per reader (times are accumulated across parallel readers)
        // Divide by num_readers to get per-reader utilization
        let io_time_per_reader = if config.num_readers > 0 {
            io_time_secs / config.num_readers as f64
        } else {
            io_time_secs
        };

        // Calculate I/O utilization: how much of wall-clock time is spent in I/O
        // High utilization (>0.8) means I/O is already maxed out
        let io_utilization = if total_secs > 0.0 {
            io_time_per_reader / total_secs
        } else {
            0.0
        };

        // Check throughput efficiency: queries per second per worker
        let qps_per_worker = if config.num_workers > 0 && total_secs > 0.0 {
            (stats.candidates_tested as f64 / total_secs) / config.num_workers as f64
        } else {
            0.0
        };

        // If I/O is saturated (>80% utilization), don't recommend more workers
        // This indicates we're hitting storage/decompression limits
        if io_utilization > 0.8 {
            // Check if decompression is the bottleneck (vs raw disk I/O)
            let decompress_per_reader = if config.num_readers > 0 {
                stats.decompress_time.as_secs_f64() / config.num_readers as f64
            } else {
                stats.decompress_time.as_secs_f64()
            };

            let read_per_reader = if config.num_readers > 0 {
                stats.read_time.as_secs_f64() / config.num_readers as f64
            } else {
                stats.read_time.as_secs_f64()
            };

            // If decompress time is >60% of I/O time, it's a decompression bottleneck
            let is_decompress_bottleneck = decompress_per_reader > read_per_reader * 0.6;

            let mut recs = vec![];

            if is_decompress_bottleneck {
                recs.push("Decompression is the bottleneck".to_string());
                recs.push(
                    "Consider: pre-decompress files, or use parallel decompression (pigz)"
                        .to_string(),
                );
            } else {
                recs.push("Storage I/O is saturated".to_string());
                recs.push(
                    "Consider: faster storage (NVMe), RAID striping, or more readers".to_string(),
                );
            }

            (
                Bottleneck::DiskRead {
                    severity: io_utilization,
                },
                format!(
                    "Bottleneck: I/O saturated ({:.0}% of time in read/decompress)",
                    io_utilization * 100.0
                ),
                recs,
            )
        } else {
            // I/O has headroom - workers are the bottleneck
            // Calculate total thread budget and recommended split
            let current_total = config.num_readers + config.num_workers;
            let recommended_total = (current_total * 2).min(physical_cores);
            let mut recs = vec![];

            if recommended_total > current_total {
                // Recommend increasing total threads (will auto-tune reader/worker split)
                recs.push(format!(
                    "Try --threads={} (will auto-tune to ~{} readers, ~{} workers)",
                    recommended_total,
                    recommended_total / 3,       // Approximate reader count
                    (recommended_total * 2) / 3  // Approximate worker count
                ));
                recs.push(format!(
                    "Current: {:.1}M queries/s per worker",
                    qps_per_worker / 1_000_000.0
                ));
            } else {
                recs.push(format!(
                    "Already at {} cores (hardware limit)",
                    physical_cores
                ));
            }

            (
                Bottleneck::WorkerSaturated { severity: 0.9 },
                "Bottleneck: Workers fully utilized (CPU-bound)".to_string(),
                recs,
            )
        }
    } else if config.cache_hit_rate < 0.5
        && stats.lookup_samples > 10000
        && stats.total_matches > 100
    {
        // Only suggest cache improvements if:
        // 1. Hit rate is low (< 50%)
        // 2. Significant lookup volume (> 10k lookups)
        // 3. Actually finding matches (> 100 matches)
        (
            Bottleneck::Lookup {
                severity: config.cache_hit_rate,
            },
            format!(
                "Bottleneck: Low cache hit rate ({:.0}% with {} lookups)",
                config.cache_hit_rate * 100.0,
                stats.lookup_samples
            ),
            vec!["Try --cache-size=100000 to improve hit rate".to_string()],
        )
    } else {
        (
            Bottleneck::Balanced,
            "Performance: Well-balanced (no obvious bottleneck)".to_string(),
            vec![],
        )
    };

    PerformanceAnalysis {
        bottleneck,
        explanation,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::match_processor::stats::ProcessingStats;

    #[test]
    fn test_io_saturation_detected() {
        // Scenario: Workers are busy BUT I/O is saturated (like your orangepi case)
        // With 4 readers spending 2.5s each on I/O, per-reader time is 2.5s
        // 2.5 / 3.0 = 83% utilization → I/O saturated
        let mut stats = ProcessingStats::new();
        stats.worker_busy_time = Duration::from_secs_f64(15.0); // 5 workers × 3s
        stats.worker_idle_time = Duration::from_secs_f64(0.3); // Minimal idle time
        stats.read_time = Duration::from_secs_f64(4.0); // 4 readers × 1.0s = 4.0s total
        stats.decompress_time = Duration::from_secs_f64(6.0); // 4 readers × 1.5s = 6.0s total
        stats.candidates_tested = 16_507_256;

        let total_time = Duration::from_secs_f64(3.0);

        let config = AnalysisConfig {
            num_workers: 5,
            num_files: 15,
            cache_hit_rate: 0.0,
            is_auto_tuned: true,
            num_readers: 4,
        };

        let analysis = analyze_performance(&stats, total_time, config);

        // Should detect I/O saturation, NOT recommend more workers
        assert!(matches!(analysis.bottleneck, Bottleneck::DiskRead { .. }));
        assert!(analysis.explanation.contains("I/O saturated"));
        assert!(!analysis
            .recommendations
            .iter()
            .any(|r| r.contains("add more workers")));
        assert!(analysis
            .recommendations
            .iter()
            .any(|r| r.contains("pre-decompress")));
    }

    #[test]
    fn test_cpu_bound_with_io_headroom() {
        // Scenario: Workers are busy AND I/O has headroom (should recommend more workers)
        let mut stats = ProcessingStats::new();
        stats.worker_busy_time = Duration::from_secs_f64(6.0); // 2 workers × 3s
        stats.worker_idle_time = Duration::from_secs_f64(0.1); // Minimal idle time
        stats.read_time = Duration::from_secs_f64(0.3); // Light I/O
        stats.decompress_time = Duration::from_secs_f64(0.5); // Light decompression
        stats.candidates_tested = 16_507_256;

        let total_time = Duration::from_secs_f64(3.0);

        let config = AnalysisConfig {
            num_workers: 2,
            num_files: 15,
            cache_hit_rate: 0.0,
            is_auto_tuned: true,
            num_readers: 1,
        };

        let analysis = analyze_performance(&stats, total_time, config);

        // Should detect CPU bottleneck
        assert!(matches!(
            analysis.bottleneck,
            Bottleneck::WorkerSaturated { .. }
        ));
        // On machines with enough cores, should recommend more threads
        // On constrained CI runners, may hit hardware limit instead
        let has_thread_recommendation = analysis
            .recommendations
            .iter()
            .any(|r| r.contains("Try --threads="));
        let at_hardware_limit = analysis
            .recommendations
            .iter()
            .any(|r| r.contains("Already at") && r.contains("hardware limit"));
        assert!(
            has_thread_recommendation || at_hardware_limit,
            "Expected thread recommendation or hardware limit message, got: {:?}",
            analysis.recommendations
        );
    }

    #[test]
    fn test_worker_idle_io_bottleneck() {
        // Scenario: Workers are idle (reader can't keep up)
        let mut stats = ProcessingStats::new();
        stats.worker_busy_time = Duration::from_secs_f64(5.0);
        stats.worker_idle_time = Duration::from_secs_f64(10.0); // Workers idle 66% of time
        stats.read_time = Duration::from_secs_f64(2.5);
        stats.decompress_time = Duration::from_secs_f64(0.5);
        stats.candidates_tested = 5_000_000;

        let total_time = Duration::from_secs_f64(3.0);

        let config = AnalysisConfig {
            num_workers: 5,
            num_files: 15,
            cache_hit_rate: 0.0,
            is_auto_tuned: false,
            num_readers: 2,
        };

        let analysis = analyze_performance(&stats, total_time, config);

        // Should detect reader starvation
        assert!(matches!(
            analysis.bottleneck,
            Bottleneck::ReaderStarved { .. }
        ));
        assert!(analysis.explanation.contains("Workers idle"));
    }
}
