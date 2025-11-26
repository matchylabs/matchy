//! Unified Database API
//!
//! Provides a single interface for querying databases that contain:
//! - IP address data (using binary search tree)
//! - Pattern data (using Aho-Corasick automaton)
//! - Combined databases with both IP and pattern data
//!
//! The database format is automatically detected and the appropriate
//! lookup method is used transparently.

use crate::literal_hash::LiteralHash;
use crate::mmdb::{MmdbError, MmdbHeader, SearchTree};
use arc_swap::ArcSwap;
use lru::LruCache;
use matchy_data_format::DataValue;
use matchy_paraglob::Paraglob;
use memmap2::Mmap;
use std::cell::Cell;
use std::cell::RefCell;
use std::fs::File;
use std::hash::BuildHasherDefault;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// Thread-local query cache with generation tracking
// Each thread gets its own LRU cache for zero-contention queries
// Generation counter is checked to invalidate cache on database reload
type QueryCache = (
    u64,
    LruCache<String, QueryResult, BuildHasherDefault<rustc_hash::FxHasher>>,
);

thread_local! {
    static QUERY_CACHE: RefCell<Option<QueryCache>> = const { RefCell::new(None) };

    // Thread-local cached Arc pointer to current database (for auto-reload)
    // Refreshed when generation counter changes (~1ns atomic check per query)
    static LOCAL_DB: RefCell<Option<Arc<Database>>> = const { RefCell::new(None) };

    // Last seen generation counter (for detecting reloads)
    static LOCAL_GENERATION: Cell<u64> = const { Cell::new(0) };
}

/// Statistics for database queries and cache performance
/// Uses atomic counters for thread-safe access across all threads
#[derive(Debug, Default)]
pub struct DatabaseStats {
    /// Total number of queries executed
    pub total_queries: AtomicU64,
    /// Queries that found a match
    pub queries_with_match: AtomicU64,
    /// Queries that found no match
    pub queries_without_match: AtomicU64,
    /// Cache hits (query served from cache)
    pub cache_hits: AtomicU64,
    /// Cache misses (query required lookup)
    pub cache_misses: AtomicU64,
    /// Number of IP address queries
    pub ip_queries: AtomicU64,
    /// Number of string queries (literal or pattern)
    pub string_queries: AtomicU64,
}

/// Snapshot of database statistics at a point in time
#[derive(Debug, Clone, Copy, Default)]
pub struct DatabaseStatsSnapshot {
    /// Total number of queries executed
    pub total_queries: u64,
    /// Queries that found a match
    pub queries_with_match: u64,
    /// Queries that found no match
    pub queries_without_match: u64,
    /// Cache hits (query served from cache)
    pub cache_hits: u64,
    /// Cache misses (query required lookup)
    pub cache_misses: u64,
    /// Number of IP address queries
    pub ip_queries: u64,
    /// Number of string queries (literal or pattern)
    pub string_queries: u64,
}

impl DatabaseStats {
    /// Take a snapshot of current statistics
    pub fn snapshot(&self) -> DatabaseStatsSnapshot {
        DatabaseStatsSnapshot {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            queries_with_match: self.queries_with_match.load(Ordering::Relaxed),
            queries_without_match: self.queries_without_match.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            ip_queries: self.ip_queries.load(Ordering::Relaxed),
            string_queries: self.string_queries.load(Ordering::Relaxed),
        }
    }
}

impl DatabaseStatsSnapshot {
    /// Calculate cache hit rate (0.0 to 1.0)
    pub fn cache_hit_rate(&self) -> f64 {
        let total_cache_ops = self.cache_hits + self.cache_misses;
        if total_cache_ops == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total_cache_ops as f64
        }
    }

    /// Calculate match rate (0.0 to 1.0)
    pub fn match_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.queries_with_match as f64 / self.total_queries as f64
        }
    }
}

/// Event fired when database is reloaded
#[derive(Debug, Clone)]
pub struct ReloadEvent {
    /// Path to the database file
    pub path: PathBuf,
    /// Whether reload succeeded
    pub success: bool,
    /// Error message if reload failed (None on success)
    pub error: Option<String>,
    /// Generation counter after reload
    pub generation: u64,
}

/// Callback type for reload notifications
pub type ReloadCallback = Arc<dyn Fn(ReloadEvent) + Send + Sync>;

/// Query result from a database lookup
#[derive(Debug, Clone)]
pub enum QueryResult {
    /// IP address lookup result
    Ip {
        /// The data associated with this IP
        data: DataValue,
        /// Network prefix length (CIDR)
        prefix_len: u8,
    },
    /// Pattern match result
    Pattern {
        /// Pattern IDs that matched
        pattern_ids: Vec<u32>,
        /// Optional data for matched patterns
        data: Vec<Option<DataValue>>,
    },
    /// Not found
    NotFound,
}

/// Watcher thread handle and shutdown channel
struct WatcherThread {
    shutdown_tx: mpsc::Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for WatcherThread {
    fn drop(&mut self) {
        // Send shutdown signal
        let _ = self.shutdown_tx.send(());

        // Wait for thread to exit
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Shared state for file watching and auto-reload
/// Uses lock-free Arc swapping for zero-overhead database access
struct WatcherState {
    /// Current database using lock-free atomic Arc pointer
    /// Threads can load this once and cache it thread-locally
    current: Arc<ArcSwap<Database>>,

    /// Generation counter - incremented on each reload to invalidate caches
    /// Threads check this (~1ns) to know when to refresh their local Arc
    generation: Arc<AtomicU64>,

    /// Optional callback for reload notifications
    reload_callback: Option<ReloadCallback>,

    /// Watcher thread handle
    _thread: WatcherThread,

    /// File watcher (must be kept alive!)
    _watcher: notify::RecommendedWatcher,
}

/// Database format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseFormat {
    /// Pure IP database (tree-based)
    IpOnly,
    /// Pure pattern database (.pgb)
    PatternOnly,
    /// Combined IP + pattern database
    Combined,
}

/// Unified database for IP and pattern lookups
///
/// This is the primary public API for querying threat intelligence,
/// GeoIP, or any IP/domain-based data. The database automatically
/// handles both IP addresses and domain patterns.
///
/// # Examples
///
/// ```no_run
/// use matchy::Database;
///
/// let db = Database::from("threats.db").open()?;
///
/// // IP lookup
/// if let Some(result) = db.lookup("1.2.3.4")? {
///     println!("Found threat data: {:?}", result);
/// }
///
/// // Pattern lookup
/// if let Some(result) = db.lookup("evil.com")? {
///     println!("Domain matches patterns: {:?}", result);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
/// Storage for database data - either owned or memory-mapped
enum DatabaseStorage {
    Owned(Vec<u8>),
    Mmap(Mmap),
}

impl DatabaseStorage {
    fn as_slice(&self) -> &[u8] {
        match self {
            DatabaseStorage::Owned(v) => v.as_slice(),
            DatabaseStorage::Mmap(m) => &m[..],
        }
    }
}

/// Lazy pattern data mappings for O(1) load time
/// Stores offset range instead of parsing all mappings eagerly
#[derive(Clone)]
struct PatternDataMappings {
    /// Offset to start of mapping data (after pattern_count u32)
    mappings_offset: usize,
    /// Number of patterns (and thus offsets)
    pattern_count: usize,
}

impl PatternDataMappings {
    /// Get data offset for a specific pattern_id by parsing only that entry
    fn get_offset(&self, pattern_id: u32, data: &[u8]) -> Option<u32> {
        if pattern_id as usize >= self.pattern_count {
            return None;
        }

        let offset_pos = self.mappings_offset + (pattern_id as usize * 4);
        if offset_pos + 4 > data.len() {
            return None;
        }

        Some(u32::from_le_bytes([
            data[offset_pos],
            data[offset_pos + 1],
            data[offset_pos + 2],
            data[offset_pos + 3],
        ]))
    }
}

/// Default LRU cache size for query results
/// ~1-5 MB memory usage depending on result sizes
const DEFAULT_QUERY_CACHE_SIZE: usize = 10_000;

/// Options for opening a database
#[derive(Clone)]
pub struct DatabaseOptions {
    /// Path to the database file (optional for from_bytes)
    pub path: PathBuf,

    /// LRU cache capacity (None = use default, Some(0) = disable)
    pub cache_capacity: Option<usize>,

    /// Optional in-memory bytes (for from_bytes builder)
    pub bytes: Option<Vec<u8>>,

    /// Enable auto-reload on file changes
    pub auto_reload: bool,

    /// Optional callback for reload notifications
    pub reload_callback: Option<ReloadCallback>,
}

impl Default for DatabaseOptions {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            cache_capacity: Some(DEFAULT_QUERY_CACHE_SIZE),
            bytes: None,
            auto_reload: false,
            reload_callback: None,
        }
    }
}

/// Builder for opening databases with custom configuration
///
/// Created via `Database::from(path)`. Use the fluent API to configure
/// options like caching and validation, then call `.open()` to load the database.
///
/// # Examples
///
/// ```no_run
/// use matchy::Database;
///
/// // Simple case with defaults
/// let db = Database::from("threats.mxy").open()?;
///
/// // Custom configuration
/// let db = Database::from("threats.mxy")
///     .cache_capacity(100_000)
///     .open()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct DatabaseOpener {
    options: DatabaseOptions,
}

impl DatabaseOpener {
    /// Create a new database opener for the given path
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            options: DatabaseOptions {
                path: path.into(),
                ..Default::default()
            },
        }
    }

    /// Set LRU cache capacity
    ///
    /// The cache dramatically improves performance for workloads with
    /// repeated queries (80-95% hit rates typical in log analysis).
    ///
    /// Default: 10,000 entries (~1-5 MB memory)
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.options.cache_capacity = Some(capacity);
        self
    }

    /// Disable caching entirely
    ///
    /// Use this for workloads where queries are never repeated
    /// (e.g., sequential IP scans). Saves memory at cost of performance.
    pub fn no_cache(mut self) -> Self {
        self.options.cache_capacity = Some(0);
        self
    }

    /// Enable automatic reload on file changes
    ///
    /// The database will watch its source file and automatically reload
    /// when changes are detected. All queries transparently use the latest
    /// version.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy")
    ///     .auto_reload()
    ///     .open()?;
    ///
    /// // Queries automatically use latest database
    /// let result = db.lookup("1.2.3.4")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn auto_reload(mut self) -> Self {
        self.options.auto_reload = true;
        self
    }

    /// Set callback for reload notifications
    ///
    /// The callback is invoked whenever the database is reloaded (or reload fails).
    /// Only works when auto-reload is enabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy")
    ///     .auto_reload()
    ///     .on_reload(|event| {
    ///         if event.success {
    ///             eprintln!("Database reloaded: {} (generation {})",
    ///                      event.path.display(), event.generation);
    ///         } else {
    ///             eprintln!("Reload failed: {}", event.error.unwrap_or_default());
    ///         }
    ///     })
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn on_reload<F>(mut self, callback: F) -> Self
    where
        F: Fn(ReloadEvent) + Send + Sync + 'static,
    {
        self.options.reload_callback = Some(Arc::new(callback));
        self
    }

    /// Open the database with configured options
    pub fn open(self) -> Result<Database, DatabaseError> {
        Database::open_with_options(self.options)
    }

    /// Create a database opener from bytes (for testing/benchmarking)
    ///
    /// This allows you to configure cache settings before loading.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db_bytes = vec![/* ... */];
    ///
    /// // With cache disabled
    /// let db = Database::from_bytes_builder(db_bytes.clone())
    ///     .no_cache()
    ///     .open()?;
    ///
    /// // With custom cache
    /// let db = Database::from_bytes_builder(db_bytes)
    ///     .cache_capacity(50000)
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_bytes_builder(bytes: Vec<u8>) -> DatabaseOpener {
        DatabaseOpener {
            options: DatabaseOptions {
                bytes: Some(bytes),
                ..Default::default()
            },
        }
    }
}

/// Unified database for IP and pattern lookups
///
/// This struct is Send + Sync and can be wrapped in Arc to share across threads.
/// Each thread maintains its own query cache for zero-contention access.
pub struct Database {
    data: DatabaseStorage,
    format: DatabaseFormat,
    ip_header: Option<MmdbHeader>,
    /// Literal hash table for O(1) exact string lookups
    literal_hash: Option<LiteralHash<'static>>,
    /// Pattern matcher for glob patterns (Combined or PatternOnly databases)
    /// Thread-safe: uses thread-local buffers internally
    pattern_matcher: Option<Paraglob>,
    /// For combined databases: lazy mapping from pattern_id -> data offset in MMDB data section
    /// None for pattern-only databases (which use Paraglob's internal data)
    pattern_data_mappings: Option<PatternDataMappings>,
    /// Cache configuration (capacity)
    cache_capacity: usize,
    /// Whether caching is enabled
    cache_enabled: bool,
    /// Query statistics (thread-safe atomic counters, shared across clones)
    stats: Arc<DatabaseStats>,
    /// File watching state (None if not watching)
    watcher: Option<Arc<WatcherState>>,
    /// Cache generation counter (shared with watcher, incremented on reload)
    cache_generation: Arc<AtomicU64>,
    /// Source file path (None for from_bytes)
    source_path: Option<PathBuf>,
    /// Options used to open this database (for reloading)
    open_options: DatabaseOptions,
}

// Safety: Database is Send + Sync because:
// 1. All data is either owned (DatabaseStorage) or 'static references to mmap
// 2. All components (pattern_matcher, literal_hash, ip_tree) are read-only references to mmap
// 3. Scratch buffers (for pattern matching) use thread-local storage, not shared state
// 4. Caching uses thread-local storage (each thread has its own cache)
// 5. No interior mutability after initialization
unsafe impl Send for Database {}
unsafe impl Sync for Database {}

impl Database {
    /// Helper: Access thread-local cache, initializing if needed
    /// Automatically invalidates cache if generation changed (database reloaded)
    #[inline]
    fn with_cache<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(
            &mut LruCache<String, QueryResult, BuildHasherDefault<rustc_hash::FxHasher>>,
        ) -> R,
    {
        if !self.cache_enabled {
            return None;
        }

        let current_gen = self.cache_generation.load(Ordering::Acquire);

        QUERY_CACHE.with(|cache| {
            let mut cache_borrow = cache.borrow_mut();

            // Check if cache needs initialization or invalidation
            let needs_reset = match *cache_borrow {
                None => true,                                 // Not yet initialized
                Some((gen, _)) if gen != current_gen => true, // Generation mismatch - invalidate!
                _ => false,                                   // Cache is valid
            };

            if needs_reset {
                // Initialize or reset cache with current generation
                *cache_borrow = Some((
                    current_gen,
                    LruCache::with_hasher(
                        NonZeroUsize::new(self.cache_capacity).unwrap(),
                        BuildHasherDefault::<rustc_hash::FxHasher>::default(),
                    ),
                ));
            }

            // Access the cache (guaranteed to be Some after initialization)
            Some(f(&mut cache_borrow.as_mut().unwrap().1))
        })
    }

    /// Create a database opener with fluent builder API
    ///
    /// This is the recommended way to open databases, providing clean
    /// configuration of cache size, validation, and future options.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// // Defaults (cache enabled, validation on)
    /// let db = Database::from("threats.mxy").open()?;
    ///
    /// // Custom cache size
    /// let db = Database::from("threats.mxy")
    ///     .cache_capacity(100_000)
    ///     .open()?;
    ///
    /// // No cache
    /// let db = Database::from("threats.mxy")
    ///     .no_cache()
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from(path: impl Into<PathBuf>) -> DatabaseOpener {
        DatabaseOpener::new(path)
    }

    /// Create a database builder from raw bytes
    ///
    /// Allows configuration of cache settings before loading from memory.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db_bytes = vec![/* ... */];
    ///
    /// // With cache disabled for benchmarking
    /// let db = Database::from_bytes_builder(db_bytes.clone())
    ///     .no_cache()
    ///     .open()?;
    ///
    /// // With custom cache size
    /// let db = Database::from_bytes_builder(db_bytes)
    ///     .cache_capacity(50000)
    ///     .open()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_bytes_builder(bytes: Vec<u8>) -> DatabaseOpener {
        DatabaseOpener::from_bytes_builder(bytes)
    }

    /// Clear the thread-local query cache
    ///
    /// Clears the cache for the current thread only. Useful for benchmarking or
    /// when you want to force fresh lookups.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy").open()?;
    ///
    /// // Do some queries (fills cache)
    /// db.lookup("example.com")?;
    ///
    /// // Clear cache to force fresh lookups
    /// db.clear_cache();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn clear_cache(&self) {
        if self.cache_enabled {
            QUERY_CACHE.with(|cache| {
                if let Some((_, c)) = cache.borrow_mut().as_mut() {
                    c.clear();
                }
            });
        }
    }

    /// Get current thread-local cache size (number of entries)
    ///
    /// Returns the number of query results currently cached in this thread.
    /// Useful for monitoring cache usage.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    ///
    /// let db = Database::from("threats.mxy").open()?;
    ///
    /// // Do some queries
    /// db.lookup("example.com")?;
    /// println!("Cache size: {}", db.cache_size());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn cache_size(&self) -> usize {
        if !self.cache_enabled {
            return 0;
        }
        QUERY_CACHE.with(|cache| cache.borrow().as_ref().map_or(0, |(_, c)| c.len()))
    }

    /// Get database statistics snapshot
    ///
    /// Returns a point-in-time snapshot of query statistics aggregated
    /// across all threads. Uses atomic counters for thread-safe access.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::Database;
    /// use std::sync::Arc;
    ///
    /// let db = Arc::new(Database::from("threats.mxy").open()?);
    ///
    /// // Query from multiple threads...
    ///
    /// // Get aggregated stats
    /// let stats = db.stats();
    /// println!("Total queries: {}", stats.total_queries);
    /// println!("Cache hit rate: {:.1}%", stats.cache_hit_rate() * 100.0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn stats(&self) -> DatabaseStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get the match mode of the database (case-sensitive or case-insensitive)
    ///
    /// Returns the MatchMode for this database, which determines how pattern
    /// matching is performed. Used to optimize query processing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::{Database, MatchMode};
    ///
    /// let db = Database::from("threats.mxy").open()?;
    /// if db.mode() == MatchMode::CaseInsensitive {
    ///     println!("Database uses case-insensitive matching");
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn mode(&self) -> matchy_match_mode::MatchMode {
        // If there's a pattern matcher, use its mode
        if let Some(ref pm) = self.pattern_matcher {
            return pm.mode();
        }
        // If there's a literal hash, use its mode
        if let Some(ref lh) = self.literal_hash {
            return lh.mode();
        }
        // Default to case-sensitive for IP-only databases
        matchy_match_mode::MatchMode::CaseSensitive
    }

    /// Open database with custom options (lower-level API)
    ///
    /// Most users should use `Database::from()` builder instead.
    pub fn open_with_options(options: DatabaseOptions) -> Result<Self, DatabaseError> {
        let cache_capacity = options.cache_capacity;
        let auto_reload = options.auto_reload;
        let path = options.path.clone();
        let is_from_bytes = options.bytes.is_some();
        let options_for_storage = options.clone();

        // Open the database - either from bytes or from file
        let mut db = if let Some(bytes) = options.bytes {
            // Load from bytes
            Self::from_storage(DatabaseStorage::Owned(bytes))?
        } else {
            // Load from file
            Self::open_internal(
                options
                    .path
                    .to_str()
                    .ok_or_else(|| DatabaseError::Io("Invalid path encoding".to_string()))?,
            )?
        };

        // Configure cache size (0 means disable, None means use default)
        if let Some(capacity) = cache_capacity {
            if capacity == 0 {
                // Disable cache completely - skip all cache operations
                db.cache_enabled = false;
            } else {
                db.cache_capacity = capacity;
                db.cache_enabled = true;
            }
        }

        // Store source path and options (for reloading)
        db.source_path = if !is_from_bytes {
            Some(path.clone())
        } else {
            None
        };
        db.open_options = options_for_storage;

        // Spawn watcher thread if auto_reload is enabled
        if auto_reload && !is_from_bytes {
            // Can only watch file-based databases
            // Note: We pass options with auto_reload disabled to prevent nested watchers
            let mut watcher_options = db.open_options.clone();
            watcher_options.auto_reload = false;
            let watcher_state = Self::spawn_watcher_thread(path.clone(), watcher_options)?;

            // Share generation counter with outer database for cache invalidation
            db.cache_generation = Arc::clone(&watcher_state.generation);
            db.watcher = Some(watcher_state);
        }

        Ok(db)
    }

    /// Internal: Open database
    /// Used by database_opener
    pub(crate) fn open_internal(path: &str) -> Result<Self, DatabaseError> {
        let file = File::open(path)
            .map_err(|e| DatabaseError::Io(format!("Failed to open {}: {}", path, e)))?;

        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| DatabaseError::Io(format!("Failed to mmap {}: {}", path, e)))?;

        Self::from_storage(DatabaseStorage::Mmap(mmap))
    }

    /// Create database from raw bytes (for testing)
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, DatabaseError> {
        Self::from_storage(DatabaseStorage::Owned(data))
    }

    /// Internal: Create database from storage
    fn from_storage(storage: DatabaseStorage) -> Result<Self, DatabaseError> {
        // First, create the struct with minimal initialization
        let mut db = Self {
            data: storage,
            format: DatabaseFormat::IpOnly, // Temporary, will be set below
            ip_header: None,
            literal_hash: None,
            pattern_matcher: None,
            pattern_data_mappings: None,
            cache_capacity: DEFAULT_QUERY_CACHE_SIZE,
            cache_enabled: true, // Default: cache enabled
            stats: Arc::new(DatabaseStats::default()),
            watcher: None, // Set by open_with_options if auto_reload enabled
            cache_generation: Arc::new(AtomicU64::new(0)), // Generation 0 for non-watched databases
            source_path: None, // Set by open_with_options
            open_options: DatabaseOptions::default(), // Set by open_with_options
        };

        // Now we can safely get 'static reference since db owns the data
        let data: &'static [u8] = unsafe { std::mem::transmute(db.data.as_slice()) };

        // Detect format
        db.format = Self::detect_format(data)?;

        // Parse based on format
        match db.format {
            DatabaseFormat::IpOnly => {
                db.ip_header = Some(MmdbHeader::from_file(data).map_err(DatabaseError::Format)?);
            }
            DatabaseFormat::PatternOnly => {
                // Pattern-only: load from start of file
                let pg = Self::load_pattern_section(data, 0).map_err(|e| {
                    DatabaseError::Unsupported(format!("Failed to load pattern section: {}", e))
                })?;
                db.pattern_matcher = Some(pg);
            }
            DatabaseFormat::Combined => {
                // Parse IP header first
                db.ip_header = Some(MmdbHeader::from_file(data).map_err(DatabaseError::Format)?);

                // Find and load pattern section after MMDB_PATTERN separator
                if let Some(offset) = Self::find_pattern_section_fast(data) {
                    let (pg, map) =
                        Self::load_combined_pattern_section(data, offset).map_err(|e| {
                            DatabaseError::Unsupported(format!(
                                "Failed to load pattern section: {}",
                                e
                            ))
                        })?;
                    db.pattern_matcher = Some(pg);
                    db.pattern_data_mappings = Some(map);
                }
            }
        }

        // Load literal hash section if present (MMDB_LITERAL marker)
        if let Some(offset) = Self::find_literal_section_fast(data) {
            // Skip the 16-byte marker
            let literal_data = &data[offset + 16..];
            // Read match mode from metadata
            let match_mode = Self::read_match_mode_from_metadata(data);
            db.literal_hash = Some(LiteralHash::from_buffer(literal_data, match_mode).map_err(
                |e| DatabaseError::Unsupported(format!("Failed to load literal hash: {}", e)),
            )?);
        }

        Ok(db)
    }

    /// Look up a query string (IP address or string pattern)
    ///
    /// Automatically determines if the query is an IP address or string
    /// and uses the appropriate lookup method.
    ///
    /// Queries are cached in thread-local storage. Each thread maintains
    /// its own LRU cache for zero-contention access. Cache hit rates
    /// of 80-95% are typical in log processing workloads.
    ///
    /// If auto-reload is enabled, this transparently uses the latest
    /// reloaded database with **zero locks** on the query path.
    ///
    /// ## Auto-Reload Performance
    ///
    /// When auto-reload is enabled:
    /// - **Per-query overhead: ~1-2ns** (atomic generation check)
    /// - No locks acquired on query path
    /// - Thread-local Arc caching eliminates atomic operations after reload check
    /// - Cache invalidation is automatic on database reload
    ///
    /// Returns `Ok(Some(result))` if found, `Ok(None)` if not found.
    pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>, DatabaseError> {
        // If watching is enabled, use lock-free Arc access
        // Each thread caches an Arc pointer locally and refreshes when generation changes
        if let Some(ref watcher) = self.watcher {
            // Check generation (~1ns atomic load with Acquire ordering)
            let current_gen = watcher.generation.load(Ordering::Acquire);

            // Check if database has been reloaded since last query
            let needs_refresh = LOCAL_GENERATION.with(|local_gen| {
                let last_gen = local_gen.get();
                if last_gen != current_gen {
                    local_gen.set(current_gen);
                    true
                } else {
                    false
                }
            });

            if needs_refresh {
                // Database changed - refresh thread-local Arc pointer
                LOCAL_DB.with(|local_db| {
                    *local_db.borrow_mut() = Some(watcher.current.load_full());
                });

                // Clear cache since data changed
                self.with_cache(|cache| cache.clear());
            }

            // Use thread-local cached Arc (zero atomic operations!)
            return LOCAL_DB.with(|local_db| local_db.borrow().as_ref().unwrap().lookup(query));
        }

        // No watching - proceed with normal lookup
        // Check thread-local cache first
        if let Some(Some(result)) = self.with_cache(|cache| cache.get(query).cloned()) {
            self.stats.total_queries.fetch_add(1, Ordering::Relaxed);
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(result));
        }

        // Cache miss (or cache disabled) - perform actual lookup
        let result = if let Ok(addr) = query.parse::<IpAddr>() {
            self.lookup_ip_uncached(addr)?
        } else {
            self.lookup_string_uncached(query)?
        };

        // Update stats
        self.stats.total_queries.fetch_add(1, Ordering::Relaxed);
        if self.cache_enabled {
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        match &result {
            Some(QueryResult::Ip { .. }) => {
                self.stats.ip_queries.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .queries_with_match
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(QueryResult::Pattern { .. }) => {
                self.stats.string_queries.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .queries_with_match
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(QueryResult::NotFound) => {
                self.stats.string_queries.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .queries_without_match
                    .fetch_add(1, Ordering::Relaxed);
            }
            None => {
                self.stats
                    .queries_without_match
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        // Store in cache if found
        if let Some(ref res) = result {
            self.with_cache(|cache| cache.put(query.to_string(), res.clone()));
        }

        Ok(result)
    }

    /// Look up an IP address (uncached internal method)
    ///
    /// Returns data associated with the IP address if found.
    /// This is the internal uncached version used by `lookup()`.
    fn lookup_ip_uncached(&self, addr: IpAddr) -> Result<Option<QueryResult>, DatabaseError> {
        let header = match &self.ip_header {
            Some(h) => h,
            None => return Ok(None), // No IP data in this database
        };

        // Traverse tree
        let tree = SearchTree::new(self.data.as_slice(), header);
        let tree_result = tree.lookup(addr).map_err(DatabaseError::Format)?;

        let tree_result = match tree_result {
            Some(r) => r,
            None => return Ok(Some(QueryResult::NotFound)),
        };

        // Decode data
        let data = self.decode_ip_data(header, tree_result.data_offset)?;

        Ok(Some(QueryResult::Ip {
            data,
            prefix_len: tree_result.prefix_len,
        }))
    }

    /// Look up an IP address (public API, uses thread-local cache)
    ///
    /// Returns data associated with the IP address if found.
    pub fn lookup_ip(&self, addr: IpAddr) -> Result<Option<QueryResult>, DatabaseError> {
        // Convert to string for cache key
        let query = addr.to_string();

        // Check thread-local cache first
        if let Some(Some(result)) = self.with_cache(|cache| cache.get(&query).cloned()) {
            return Ok(Some(result));
        }

        // Cache miss - do actual lookup
        let result = self.lookup_ip_uncached(addr)?;

        // Store in cache if found
        if let Some(ref res) = result {
            self.with_cache(|cache| cache.put(query, res.clone()));
        }

        Ok(result)
    }

    /// Look up an extracted item using the most efficient path
    ///
    /// This method handles the type differences in `ExtractedItem` automatically,
    /// using the optimal lookup strategy for each variant:
    /// - IP addresses use `lookup_ip()` (avoids string parsing)
    /// - Everything else uses `lookup()` (string-based)
    ///
    /// This is the recommended way to query databases after extraction,
    /// as it avoids boilerplate match statements and ensures maximum performance.
    ///
    /// # Arguments
    ///
    /// * `item` - The extracted match to look up
    /// * `input` - The original input buffer (needed to extract string slices)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use matchy::{Database, extractor::Extractor};
    ///
    /// let db = Database::from("threats.mxy").open()?;
    /// let extractor = Extractor::new()?;
    ///
    /// let log_line = b"Connection from 192.168.1.1 to evil.com";
    ///
    /// for item in extractor.extract_from_line(log_line) {
    ///     if let Some(result) = db.lookup_extracted(&item, log_line)? {
    ///         println!("Match: {} -> {:?}", item.as_str(log_line), result);
    ///     }
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn lookup_extracted(
        &self,
        item: &crate::extractor::Match,
        input: &[u8],
    ) -> Result<Option<QueryResult>, DatabaseError> {
        use crate::extractor::ExtractedItem;

        match &item.item {
            ExtractedItem::Ipv4(ip) => self.lookup_ip(IpAddr::V4(*ip)),
            ExtractedItem::Ipv6(ip) => self.lookup_ip(IpAddr::V6(*ip)),
            _ => self.lookup(item.as_str(input)),
        }
    }

    /// Look up a string (literal or glob pattern) - uncached internal method
    ///
    /// Returns matching pattern IDs and associated data.
    /// Checks both:
    /// 1. Literal hash table for O(1) exact matches
    /// 2. Glob patterns for wildcard matches
    ///
    /// A query can match both a literal AND a glob pattern simultaneously.
    fn lookup_string_uncached(&self, pattern: &str) -> Result<Option<QueryResult>, DatabaseError> {
        let mut all_pattern_ids = Vec::new();
        let mut all_data_values = Vec::new();

        // 1. Try literal hash table first (O(1) lookup)
        if let Some(literal_hash) = &self.literal_hash {
            if let Some(pattern_id) = literal_hash.lookup(pattern) {
                // Found an exact match!
                if let Some(data_offset) = literal_hash.get_data_offset(pattern_id) {
                    let header = self.ip_header.as_ref().ok_or_else(|| {
                        DatabaseError::Format(MmdbError::InvalidFormat(
                            "Literal hash present but no IP header".to_string(),
                        ))
                    })?;
                    let data = self.decode_ip_data(header, data_offset)?;
                    all_pattern_ids.push(pattern_id);
                    all_data_values.push(Some(data));
                }
            }
        }

        // 2. Check glob patterns (for wildcard matches)
        if let Some(ref pg) = self.pattern_matcher {
            let glob_pattern_ids = pg.find_all(pattern);

            // Add glob matches
            for &pattern_id in &glob_pattern_ids {
                // For combined databases, use mappings to decode from MMDB data section
                // For pattern-only databases, use Paraglob's internal data cache
                let data = if let Some(mappings) = &self.pattern_data_mappings {
                    // Combined database: decode from MMDB data section using lazy lookup
                    if let Some(data_offset) = mappings.get_offset(pattern_id, self.data.as_slice())
                    {
                        let header = self.ip_header.as_ref().unwrap();
                        Some(self.decode_ip_data(header, data_offset)?)
                    } else {
                        None
                    }
                } else {
                    // Pattern-only database: use Paraglob's lazy data lookup
                    pg.get_pattern_data(pattern_id)
                };
                all_pattern_ids.push(pattern_id);
                all_data_values.push(data);
            }
        }

        // Return results
        if all_pattern_ids.is_empty() {
            // Only return NotFound if we actually have some pattern data
            if self.literal_hash.is_some() || self.pattern_matcher.is_some() {
                Ok(Some(QueryResult::NotFound))
            } else {
                Ok(None) // No pattern data in this database
            }
        } else {
            Ok(Some(QueryResult::Pattern {
                pattern_ids: all_pattern_ids,
                data: all_data_values,
            }))
        }
    }

    /// Look up a string (literal or glob pattern) - public API, uses thread-local cache
    ///
    /// Returns matching pattern IDs and associated data.
    pub fn lookup_string(&self, pattern: &str) -> Result<Option<QueryResult>, DatabaseError> {
        // Check thread-local cache first
        if let Some(Some(result)) = self.with_cache(|cache| cache.get(pattern).cloned()) {
            return Ok(Some(result));
        }

        // Cache miss - do actual lookup
        let result = self.lookup_string_uncached(pattern)?;

        // Store in cache if found
        if let Some(ref res) = result {
            self.with_cache(|cache| cache.put(pattern.to_string(), res.clone()));
        }

        Ok(result)
    }

    /// Decode IP data at a given offset
    /// Decode IP data at a given offset
    fn decode_ip_data(&self, header: &MmdbHeader, offset: u32) -> Result<DataValue, DatabaseError> {
        use matchy_data_format::DataDecoder;

        // Offsets from the tree are relative to the start of the data section (after the 16-byte separator)
        // So we slice the buffer to start at tree_size + 16
        let data_section_start = header.tree_size + 16;
        let data_section = &self.data.as_slice()[data_section_start..];

        // Offsets from tree are relative to data_section, which we've sliced
        // So base_offset is 0 (the decoder will resolve pointers relative to the buffer start)
        let decoder = DataDecoder::new(data_section, 0);

        decoder
            .decode(offset)
            .map_err(|e| DatabaseError::Format(MmdbError::DecodeError(e.to_string())))
    }

    /// Detect database format (optimized to avoid full file scan)
    fn detect_format(data: &[u8]) -> Result<DatabaseFormat, DatabaseError> {
        // Check for paraglob magic at start (pattern-only format)
        let has_paraglob_start = data.len() >= 8 && &data[0..8] == b"PARAGLOB";
        if has_paraglob_start {
            return Ok(DatabaseFormat::PatternOnly);
        }

        // Check for MMDB metadata marker (searches last 128KB only)
        let has_mmdb = crate::mmdb::find_metadata_marker(data).is_ok();
        if !has_mmdb {
            return Err(DatabaseError::Format(MmdbError::InvalidFormat(
                "Unknown database format (no MMDB or PARAGLOB marker)".to_string(),
            )));
        }

        // Fast path: Check metadata for section offsets (new format)
        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                // If pattern_section_offset exists in metadata, use it to determine format
                if let Some(DataValue::Uint32(pattern_offset)) = map.get("pattern_section_offset") {
                    // New format with metadata offsets
                    let has_patterns = *pattern_offset != 0;
                    if let Some(DataValue::Uint32(literal_offset)) =
                        map.get("literal_section_offset")
                    {
                        let has_literals = *literal_offset != 0;
                        if has_patterns || has_literals {
                            return Ok(DatabaseFormat::Combined);
                        } else {
                            return Ok(DatabaseFormat::IpOnly);
                        }
                    }
                }
            }
        }

        // Slow path: Old format without metadata offsets - need to scan
        // Check for MMDB_PATTERN separator (combined format)
        let pattern_separator = b"MMDB_PATTERN\x00\x00\x00\x00";
        let has_pattern_section = data.windows(16).any(|window| window == pattern_separator);

        if has_pattern_section {
            Ok(DatabaseFormat::Combined)
        } else {
            Ok(DatabaseFormat::IpOnly)
        }
    }

    /// Get database format
    pub fn format(&self) -> &str {
        match self.format {
            DatabaseFormat::IpOnly => "IP database",
            DatabaseFormat::PatternOnly => "Pattern database",
            DatabaseFormat::Combined => "Combined IP+Pattern database",
        }
    }

    /// Check if database supports IP lookups
    pub fn has_ip_data(&self) -> bool {
        self.ip_header.is_some()
    }

    /// Check if database supports string lookups (literals or patterns)
    pub fn has_string_data(&self) -> bool {
        self.literal_hash.is_some() || self.pattern_matcher.is_some()
    }

    /// Check if database supports literal (exact string) lookups
    pub fn has_literal_data(&self) -> bool {
        self.literal_hash.is_some()
    }

    /// Check if database supports glob pattern lookups
    pub fn has_glob_data(&self) -> bool {
        self.pattern_matcher.is_some()
    }

    /// Check if database supports pattern lookups (deprecated, use has_literal_data or has_glob_data)
    #[deprecated(
        since = "0.5.0",
        note = "Use has_literal_data or has_glob_data instead"
    )]
    pub fn has_pattern_data(&self) -> bool {
        self.has_string_data()
    }

    /// Get MMDB metadata if available
    ///
    /// Returns the full metadata as a DataValue map, or None if this is not
    /// an MMDB-format database or if metadata cannot be parsed.
    pub fn metadata(&self) -> Option<DataValue> {
        if !self.has_ip_data() {
            return None;
        }

        use crate::mmdb::MmdbMetadata;
        let metadata = MmdbMetadata::from_file(self.data.as_slice()).ok()?;
        metadata.as_value().ok()
    }

    /// Get pattern string by ID
    ///
    /// Returns the pattern string for a given pattern ID.
    /// Returns None if the database has no pattern data or pattern ID is invalid.
    pub fn get_pattern_string(&self, pattern_id: u32) -> Option<String> {
        let pg = self.pattern_matcher.as_ref()?;
        pg.get_pattern(pattern_id)
    }

    /// Get total number of glob patterns
    ///
    /// Returns the number of glob patterns in the database.
    /// Returns 0 if the database has no pattern data.
    pub fn pattern_count(&self) -> usize {
        match &self.pattern_matcher {
            Some(pg) => pg.pattern_count(),
            None => 0,
        }
    }

    /// Get number of glob patterns (alias for pattern_count)
    ///
    /// Returns the number of glob patterns in the database.
    /// Returns 0 if the database has no glob pattern data.
    pub fn glob_count(&self) -> usize {
        // Try to get from metadata first (more accurate)
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(count) = map.get("glob_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return val as usize;
                }
            }
        }
        // Fallback to pattern_count
        self.pattern_count()
    }

    /// Get number of literal patterns
    ///
    /// Returns the number of literal (exact-match) patterns in the database.
    /// Returns 0 if the database has no literal pattern data.
    pub fn literal_count(&self) -> usize {
        // Try to get from metadata first (more accurate)
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(count) = map.get("literal_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return val as usize;
                }
            }
        }
        // Fallback to literal_hash entry count
        match &self.literal_hash {
            Some(lh) => lh.entry_count() as usize,
            None => 0,
        }
    }

    /// Get number of IP address entries
    ///
    /// Returns the number of IP entries in the database.
    /// Returns 0 if the database has no IP data.
    pub fn ip_count(&self) -> usize {
        // Try to get from metadata first (most accurate)
        if let Some(DataValue::Map(map)) = self.metadata() {
            if let Some(count) = map.get("ip_entry_count") {
                if let Some(val) = Self::extract_uint_from_datavalue(count) {
                    return val as usize;
                }
            }
        }
        // No accurate fallback for IP count
        0
    }

    /// Helper to extract unsigned integer from DataValue
    fn extract_uint_from_datavalue(value: &DataValue) -> Option<u64> {
        match value {
            DataValue::Uint16(v) => Some(*v as u64),
            DataValue::Uint32(v) => Some(*v as u64),
            DataValue::Uint64(v) => Some(*v),
            _ => None,
        }
    }

    /// Find the pattern section using fast metadata lookup with fallback to scanning
    /// Returns the offset to the start of pattern data (after MMDB_PATTERN marker)
    fn find_pattern_section_fast(data: &[u8]) -> Option<usize> {
        // Fast path: Try to read offset from metadata
        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                if let Some(DataValue::Uint32(offset)) = map.get("pattern_section_offset") {
                    let offset_val = *offset as usize;
                    // 0 means no pattern section (fast negative result)
                    if offset_val == 0 {
                        return None;
                    }
                    return Some(offset_val);
                }
            }
        }

        // Slow path: Scan for separator (backwards compatibility)
        eprintln!("Warning: Database lacks section offset metadata, falling back to full file scan (slower load time)");
        Self::find_pattern_section_slow(data)
    }

    /// Find the pattern section by scanning (slow, for backwards compatibility)
    /// Returns the offset to the start of pattern data (after MMDB_PATTERN marker)
    fn find_pattern_section_slow(data: &[u8]) -> Option<usize> {
        let separator = b"MMDB_PATTERN\x00\x00\x00\x00";

        // Search for the separator
        for i in 0..data.len().saturating_sub(16) {
            if &data[i..i + 16] == separator {
                // Pattern section starts after the 16-byte separator
                return Some(i + 16);
            }
        }
        None
    }

    /// Find the literal section using fast metadata lookup with fallback to scanning
    /// Returns the offset to the start of MMDB_LITERAL marker
    fn find_literal_section_fast(data: &[u8]) -> Option<usize> {
        // Fast path: Try to read offset from metadata
        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                if let Some(DataValue::Uint32(offset)) = map.get("literal_section_offset") {
                    let offset_val = *offset as usize;
                    // 0 means no literal section (fast negative result)
                    if offset_val == 0 {
                        return None;
                    }
                    // Metadata stores offset to start of data, but we need offset to marker
                    // So subtract 16 bytes for the "MMDB_LITERAL" marker
                    return Some(offset_val - 16);
                }
            }
        }

        // Slow path: Scan for separator (backwards compatibility)
        if data.len() > 1024 * 1024 {
            // Only warn for files > 1MB
            eprintln!("Warning: Database lacks section offset metadata, falling back to full file scan (slower load time)");
        }
        Self::find_literal_section_slow(data)
    }

    /// Find the literal hash section by scanning (slow, for backwards compatibility)
    /// Returns the offset to the start of MMDB_LITERAL marker
    fn find_literal_section_slow(data: &[u8]) -> Option<usize> {
        let separator = b"MMDB_LITERAL\x00\x00\x00\x00";

        // Search for the separator
        (0..data.len().saturating_sub(16)).find(|&i| &data[i..i + 16] == separator)
    }

    /// Load pattern section from data at given offset (for pattern-only databases)
    /// The format at offset is: PARAGLOB magic + data
    /// Uses zero-copy from_mmap for O(1) loading
    fn load_pattern_section(data: &'static [u8], offset: usize) -> Result<Paraglob, String> {
        if offset >= data.len() {
            return Err("Pattern section offset out of bounds".to_string());
        }

        // Try to read match mode from metadata
        let match_mode = Self::read_match_mode_from_metadata(data);

        // For pattern-only databases, data starts with PARAGLOB magic
        if offset == 0 && data.len() >= 8 && &data[0..8] == b"PARAGLOB" {
            // Standard .pgb format - load with zero-copy
            // SAFETY: data is 'static lifetime from mmap, valid for entire Database lifetime
            let result = unsafe { Paraglob::from_mmap(data, match_mode) };
            return result.map_err(|e| format!("Failed to parse pattern-only database: {}", e));
        }

        Err("Invalid pattern-only database format".to_string())
    }

    /// Load combined pattern section from data at given offset
    /// The format at offset is: `[total_size][paraglob_size][PARAGLOB data][pattern_count][data_offsets...]`
    /// Returns (Paraglob matcher, lazy PatternDataMappings)
    /// Uses zero-copy and deferred parsing for O(1) load time
    fn load_combined_pattern_section(
        data: &'static [u8],
        offset: usize,
    ) -> Result<(Paraglob, PatternDataMappings), String> {
        if offset >= data.len() {
            return Err("Pattern section offset out of bounds".to_string());
        }

        // Try to read match mode from metadata
        let match_mode = Self::read_match_mode_from_metadata(data);

        // Read section header
        if offset + 8 > data.len() {
            return Err("Pattern section header truncated".to_string());
        }

        // Read sizes (little-endian u32)
        let _total_size = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let paraglob_size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        // Paraglob data starts at offset + 8
        let paraglob_start = offset + 8;
        let paraglob_end = paraglob_start + paraglob_size;

        if paraglob_end > data.len() {
            return Err(format!(
                "Paraglob section extends beyond file (start={}, size={}, file_len={})",
                paraglob_start,
                paraglob_size,
                data.len()
            ));
        }

        // Extract and load paraglob data with zero-copy
        let paraglob_data = &data[paraglob_start..paraglob_end];
        // SAFETY: data is 'static lifetime from mmap, valid for entire Database lifetime
        let paraglob = unsafe { Paraglob::from_mmap(paraglob_data, match_mode) };
        let paraglob = paraglob.map_err(|e| format!("Failed to parse paraglob section: {}", e))?;

        // Store mapping metadata WITHOUT parsing all offsets (O(1) instead of O(n))
        let mappings_start = paraglob_end;
        if mappings_start + 4 > data.len() {
            return Err("Pattern mappings section truncated".to_string());
        }

        let pattern_count = u32::from_le_bytes([
            data[mappings_start],
            data[mappings_start + 1],
            data[mappings_start + 2],
            data[mappings_start + 3],
        ]) as usize;

        let offsets_start = mappings_start + 4;

        // Validate the mapping section exists, but don't parse it
        let total_mapping_bytes = pattern_count * 4;
        if offsets_start + total_mapping_bytes > data.len() {
            return Err(format!(
                "Pattern mappings section out of bounds (need {} bytes)",
                total_mapping_bytes
            ));
        }

        let mappings = PatternDataMappings {
            mappings_offset: offsets_start,
            pattern_count,
        };

        Ok((paraglob, mappings))
    }

    /// Read match mode from database metadata
    /// Returns CaseSensitive as default if not found or on error
    fn read_match_mode_from_metadata(data: &[u8]) -> matchy_match_mode::MatchMode {
        use matchy_match_mode::MatchMode;

        // Try to read metadata
        if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(data) {
            if let Ok(DataValue::Map(map)) = metadata.as_value() {
                if let Some(DataValue::Uint16(mode_val)) = map.get("match_mode") {
                    return match *mode_val {
                        1 => MatchMode::CaseInsensitive,
                        _ => MatchMode::CaseSensitive, // 0 or unknown = CaseSensitive (default)
                    };
                }
            }
        }

        // Default to case-sensitive for backward compatibility with old databases
        MatchMode::CaseSensitive
    }

    /// Spawn a watcher thread to monitor database file and auto-reload on changes
    fn spawn_watcher_thread(
        path: PathBuf,
        options: DatabaseOptions,
    ) -> Result<Arc<WatcherState>, DatabaseError> {
        use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
        use std::sync::mpsc::RecvTimeoutError;

        // Create channels
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();

        // Canonicalize path to resolve symlinks (important on macOS)
        let canonical_path = path
            .canonicalize()
            .map_err(|e| DatabaseError::Io(format!("Failed to canonicalize path: {}", e)))?;

        // Create watcher - watch the file directly
        // On macOS/FSEvents, this still detects atomic renames (mv new.mxy db.mxy)
        let mut watcher = RecommendedWatcher::new(event_tx, Config::default())
            .map_err(|e| DatabaseError::Io(format!("Failed to create file watcher: {}", e)))?;

        watcher
            .watch(&canonical_path, RecursiveMode::NonRecursive)
            .map_err(|e| DatabaseError::Io(format!("Failed to watch file: {}", e)))?;

        // Open database fresh (not cloned) to get independent mmap
        // This ensures reloads get truly new data, not shared mmap pages
        let initial_db = Database::open_with_options(options.clone())?;

        // Use ArcSwap for lock-free atomic pointer swapping
        let current_db = Arc::new(ArcSwap::from_pointee(initial_db));

        // Create shared generation counter for cache invalidation
        // Starts at 1 (generation 0 is for non-watched databases)
        let generation = Arc::new(AtomicU64::new(1));

        let state = Arc::new(WatcherState {
            current: Arc::clone(&current_db),
            generation: Arc::clone(&generation),
            reload_callback: options.reload_callback.clone(),
            _thread: WatcherThread {
                shutdown_tx: shutdown_tx.clone(),
                handle: None,
            },
            _watcher: watcher,
        });

        // Clone state and path for thread
        let thread_state = Arc::clone(&state);
        let thread_path = canonical_path.clone();

        // Spawn watcher thread
        let handle = thread::spawn(move || {
            let mut last_event_time: Option<Instant> = None;
            const DEBOUNCE_MS: u64 = 200;

            loop {
                // Check shutdown signal
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }

                match event_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(Ok(_event)) => {
                        // Any event on our watched file triggers reload debounce
                        last_event_time = Some(Instant::now());
                    }
                    Ok(Err(_e)) => {
                        // Ignore watcher errors - keep running
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        // Check if file is stable (no events for DEBOUNCE_MS)
                        if let Some(last_time) = last_event_time {
                            if last_time.elapsed() >= Duration::from_millis(DEBOUNCE_MS) {
                                // Attempt reload (with auto_reload disabled to avoid nested watchers)
                                let mut reload_options = options.clone();
                                reload_options.auto_reload = false;
                                let reload_result = Database::open_with_options(reload_options);

                                match reload_result {
                                    Ok(mut new_db) => {
                                        // Increment generation to invalidate all thread-local caches
                                        thread_state.generation.fetch_add(1, Ordering::Release);
                                        let new_generation =
                                            thread_state.generation.load(Ordering::Acquire);

                                        // Share generation counter with reloaded database
                                        new_db.cache_generation =
                                            Arc::clone(&thread_state.generation);

                                        // Atomically swap in new database (lock-free!)
                                        // Old database stays alive until all thread-local Arc refs are dropped
                                        thread_state.current.store(Arc::new(new_db));

                                        // Invoke callback if present
                                        if let Some(ref callback) = thread_state.reload_callback {
                                            callback(ReloadEvent {
                                                path: thread_path.clone(),
                                                success: true,
                                                error: None,
                                                generation: new_generation,
                                            });
                                        }
                                    }
                                    Err(e) => {
                                        // Reload failed - keep old database
                                        // Invoke callback if present
                                        if let Some(ref callback) = thread_state.reload_callback {
                                            let current_generation =
                                                thread_state.generation.load(Ordering::Acquire);
                                            callback(ReloadEvent {
                                                path: thread_path.clone(),
                                                success: false,
                                                error: Some(e.to_string()),
                                                generation: current_generation,
                                            });
                                        }
                                    }
                                }
                                last_event_time = None;
                            }
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        // Store thread handle in WatcherThread
        // Safety: We need to get mutable access to update the handle
        // This is safe because we're the only thread with access at this point
        let state_ptr = Arc::as_ptr(&state) as *mut WatcherState;
        unsafe {
            (*state_ptr)._thread.handle = Some(handle);
        }

        Ok(state)
    }
}

/// Database error type
#[derive(Debug)]
pub enum DatabaseError {
    /// I/O error
    Io(String),
    /// Format error
    Format(MmdbError),
    /// Unsupported operation
    Unsupported(String),
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::Io(msg) => write!(f, "I/O error: {}", msg),
            DatabaseError::Format(err) => write!(f, "Format error: {}", err),
            DatabaseError::Unsupported(msg) => write!(f, "Unsupported: {}", msg),
        }
    }
}

impl std::error::Error for DatabaseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ip_database() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();
        assert_eq!(db.format, DatabaseFormat::IpOnly);
        assert!(db.has_ip_data());
        assert!(!db.has_string_data());
    }

    #[test]
    fn test_lookup_ip_address() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        // Test IP lookup
        let result = db.lookup("1.1.1.1").unwrap();
        assert!(result.is_some());

        if let Some(QueryResult::Ip { data, prefix_len }) = result {
            assert!(prefix_len > 0);
            assert!(prefix_len <= 32);

            // Should have map data
            match data {
                DataValue::Map(map) => {
                    assert!(!map.is_empty());
                }
                _ => panic!("Expected map data"),
            }
        } else {
            panic!("Expected IP result");
        }
    }

    #[test]
    fn test_lookup_ipv6() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        let result = db.lookup("2001:4860:4860::8888").unwrap();
        assert!(result.is_some());

        if let Some(QueryResult::Ip { prefix_len, .. }) = result {
            assert!(prefix_len > 0);
            assert!(prefix_len <= 128);
        }
    }

    #[test]
    fn test_lookup_not_found() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        let result = db.lookup("127.0.0.1").unwrap();
        assert!(matches!(result, Some(QueryResult::NotFound)));
    }

    #[test]
    fn test_auto_detect_query_type() {
        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();

        // Should auto-detect as IP
        let result = db.lookup("8.8.8.8").unwrap();
        assert!(matches!(result, Some(QueryResult::Ip { .. })));

        // Should auto-detect as pattern (but no pattern data in this DB)
        let result = db.lookup("example.com").unwrap();
        assert!(result.is_none() || matches!(result, Some(QueryResult::NotFound)));
    }

    #[test]
    fn test_lookup_extracted() {
        use crate::extractor::Extractor;

        let db = Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .unwrap();
        let extractor = Extractor::new().unwrap();

        // Test with IP addresses (should use efficient typed lookup)
        let log_line = b"Connection from 8.8.8.8 and 2001:4860:4860::8888";
        let matches: Vec<_> = extractor.extract_from_line(log_line).collect();

        assert_eq!(matches.len(), 2, "Should extract 2 IP addresses");

        // First match: IPv4
        let result = db.lookup_extracted(&matches[0], log_line).unwrap();
        assert!(
            matches!(result, Some(QueryResult::Ip { .. })),
            "IPv4 should match via lookup_extracted"
        );

        // Second match: IPv6
        let result = db.lookup_extracted(&matches[1], log_line).unwrap();
        assert!(
            matches!(result, Some(QueryResult::Ip { .. })),
            "IPv6 should match via lookup_extracted"
        );

        // Test with domain (should use string-based lookup)
        let log_line = b"Visit example.com for more info";
        let matches: Vec<_> = extractor.extract_from_line(log_line).collect();

        assert_eq!(matches.len(), 1, "Should extract 1 domain");

        // Domain lookup (no pattern data in this DB, so expect None or NotFound)
        let result = db.lookup_extracted(&matches[0], log_line).unwrap();
        assert!(
            result.is_none() || matches!(result, Some(QueryResult::NotFound)),
            "Domain should not match in IP-only database"
        );
    }

    #[test]
    fn test_reload_callback() {
        use crate::mmdb_builder::DatabaseBuilder;
        use crate::{DataValue, MatchMode};
        use std::collections::HashMap;
        use std::fs;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        // Create a test database file
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        // Build a simple test database with a literal string
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert("test".to_string(), DataValue::String("initial".to_string()));
        builder.add_literal("example.com", data).unwrap();
        let bytes = builder.build().unwrap();
        fs::write(&db_path, bytes).unwrap();

        // Track reload events
        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&events);

        // Open with auto-reload and callback
        let db = Database::from(db_path.clone())
            .auto_reload()
            .on_reload(move |event: ReloadEvent| {
                events_clone.lock().unwrap().push(event);
            })
            .open()
            .unwrap();

        // Verify initial lookup works
        let result = db.lookup("example.com").unwrap();
        assert!(result.is_some(), "Initial lookup should succeed");

        // Modify the database file (trigger reload)
        std::thread::sleep(Duration::from_millis(100));
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "test".to_string(),
            DataValue::String("reloaded".to_string()),
        );
        builder.add_literal("example.org", data).unwrap();
        let bytes = builder.build().unwrap();

        // Use atomic rename to update file (works with active mmap on all platforms)
        let temp_path = db_path.with_extension("tmp");
        fs::write(&temp_path, bytes).unwrap();
        fs::rename(&temp_path, &db_path).unwrap();

        // Wait for reload to complete (file watcher has 200ms debounce + reload time)
        std::thread::sleep(Duration::from_millis(500));

        // Check that callback was invoked
        let events_list = events.lock().unwrap();
        assert!(!events_list.is_empty(), "Callback should have been invoked");

        let last_event = events_list.last().unwrap();
        assert!(last_event.success, "Reload should have succeeded");
        assert!(last_event.error.is_none(), "No error should be present");
        assert!(
            last_event.generation > 0,
            "Generation should have incremented"
        );
        assert_eq!(last_event.path, db_path.canonicalize().unwrap());

        drop(db);
    }
}
