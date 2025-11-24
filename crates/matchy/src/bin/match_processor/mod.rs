mod bottleneck;
mod follow;
mod parallel;
mod sequential;
mod stats;
mod thread_utils;

pub use bottleneck::{analyze_performance, AnalysisConfig};
pub use follow::{follow_files, follow_files_parallel};
pub use parallel::{process_parallel, ExtractorConfig};
pub use sequential::process_file_with_aggregate;
pub use stats::{ProcessingStats, ProgressReporter};
