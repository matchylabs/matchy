use std::io::IsTerminal;
use std::time::{Duration, Instant};

/// Statistics for processing a single file or batch
#[derive(Debug, Clone)]
pub struct ProcessingStats {
    pub lines_processed: usize,
    pub candidates_tested: usize,
    pub lines_with_matches: usize,
    pub total_matches: usize,
    pub total_bytes: usize,
    pub extraction_time: Duration,
    pub lookup_time: Duration,
    pub extraction_samples: usize,
    pub lookup_samples: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub domain_count: usize,
    pub email_count: usize,
    // Pipeline stage timings (parallel mode)
    pub read_time: Duration,        // Time spent reading from disk
    pub decompress_time: Duration,  // Time spent decompressing (if .gz)
    pub batch_prep_time: Duration,  // Time spent preparing batches (line splitting)
    pub worker_idle_time: Duration, // Time workers spent waiting for work
    pub worker_busy_time: Duration, // Time workers spent processing
    pub output_time: Duration,      // Time spent in output thread
}

impl ProcessingStats {
    pub fn new() -> Self {
        Self {
            lines_processed: 0,
            candidates_tested: 0,
            lines_with_matches: 0,
            total_matches: 0,
            total_bytes: 0,
            extraction_time: Duration::ZERO,
            lookup_time: Duration::ZERO,
            extraction_samples: 0,
            lookup_samples: 0,
            ipv4_count: 0,
            ipv6_count: 0,
            domain_count: 0,
            email_count: 0,
            read_time: Duration::ZERO,
            decompress_time: Duration::ZERO,
            batch_prep_time: Duration::ZERO,
            worker_idle_time: Duration::ZERO,
            worker_busy_time: Duration::ZERO,
            output_time: Duration::ZERO,
        }
    }

    /// Add another stats object to this one (for aggregation)
    pub fn add(&mut self, other: &ProcessingStats) {
        self.lines_processed += other.lines_processed;
        self.candidates_tested += other.candidates_tested;
        self.lines_with_matches += other.lines_with_matches;
        self.total_matches += other.total_matches;
        self.total_bytes += other.total_bytes;
        self.extraction_time += other.extraction_time;
        self.lookup_time += other.lookup_time;
        self.extraction_samples += other.extraction_samples;
        self.lookup_samples += other.lookup_samples;
        self.ipv4_count += other.ipv4_count;
        self.ipv6_count += other.ipv6_count;
        self.domain_count += other.domain_count;
        self.email_count += other.email_count;
        self.read_time += other.read_time;
        self.decompress_time += other.decompress_time;
        self.batch_prep_time += other.batch_prep_time;
        self.worker_idle_time += other.worker_idle_time;
        self.worker_busy_time += other.worker_busy_time;
        self.output_time += other.output_time;
    }
}

impl Default for ProcessingStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress reporter for displaying live updates
pub struct ProgressReporter {
    last_update: Instant,
    update_interval: Duration,
    is_tty: bool,
}

impl ProgressReporter {
    pub fn new() -> Self {
        // Check if stderr is a TTY for single-line updates
        let is_tty = std::io::stderr().is_terminal();

        Self {
            last_update: Instant::now(),
            update_interval: Duration::from_millis(100),
            is_tty,
        }
    }

    /// Check if it's time to show an update
    pub fn should_update(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_update) >= self.update_interval {
            self.last_update = now;
            true
        } else {
            false
        }
    }

    /// Display progress update
    pub fn show(&self, stats: &ProcessingStats, elapsed: Duration) {
        let throughput = if elapsed.as_secs_f64() > 0.0 {
            (stats.total_bytes as f64 / 1_000_000.0) / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let hit_rate = if stats.lines_processed > 0 {
            (stats.lines_with_matches as f64 / stats.lines_processed as f64) * 100.0
        } else {
            0.0
        };

        if self.is_tty {
            // Multi-line update for TTY (overwrite previous 3 lines)
            eprint!("\r\x1b[2K"); // Clear current line
            eprint!("\x1b[1A\x1b[2K"); // Move up and clear
            eprint!("\x1b[1A\x1b[2K"); // Move up and clear

            eprintln!(
                "[PROGRESS] Lines: {} | Matches: {} ({:.1}%) | Processed: {} | Throughput: {:.2} MB/s | Time: {:.1}s",
                crate::cli_utils::format_number(stats.lines_processed),
                crate::cli_utils::format_number(stats.total_matches),
                hit_rate,
                crate::cli_utils::format_bytes(stats.total_bytes),
                throughput,
                elapsed.as_secs_f64()
            );
            eprintln!(
                "           Candidates: {} total (IPv4: {}, IPv6: {}, Domains: {}, Emails: {})",
                crate::cli_utils::format_number(stats.candidates_tested),
                crate::cli_utils::format_number(stats.ipv4_count),
                crate::cli_utils::format_number(stats.ipv6_count),
                crate::cli_utils::format_number(stats.domain_count),
                crate::cli_utils::format_number(stats.email_count)
            );
            eprint!(
                "           Lookup rate: {:.2}K queries/sec",
                if elapsed.as_secs_f64() > 0.0 {
                    (stats.candidates_tested as f64 / 1000.0) / elapsed.as_secs_f64()
                } else {
                    0.0
                }
            );
        } else {
            // Multi-line update (for non-TTY, like redirected stderr)
            eprintln!(
                "[PROGRESS] Lines: {} | Matches: {} ({:.1}%) | Processed: {} | Throughput: {:.2} MB/s | Time: {:.1}s",
                crate::cli_utils::format_number(stats.lines_processed),
                crate::cli_utils::format_number(stats.total_matches),
                hit_rate,
                crate::cli_utils::format_bytes(stats.total_bytes),
                throughput,
                elapsed.as_secs_f64()
            );
            eprintln!(
                "           Candidates: {} (IPv4: {}, IPv6: {}, Domains: {}, Emails: {})",
                crate::cli_utils::format_number(stats.candidates_tested),
                crate::cli_utils::format_number(stats.ipv4_count),
                crate::cli_utils::format_number(stats.ipv6_count),
                crate::cli_utils::format_number(stats.domain_count),
                crate::cli_utils::format_number(stats.email_count)
            );
        }
    }
}
