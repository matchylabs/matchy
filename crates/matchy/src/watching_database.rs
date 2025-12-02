//! Auto-reloading database wrapper (native platforms only)
//!
//! Provides [`WatchingDatabase`], a wrapper around [`Database`] that automatically
//! reloads when the underlying file changes. Uses lock-free Arc swapping for
//! zero-overhead query access.
//!
//! # Example
//!
//! ```no_run
//! use matchy::WatchingDatabase;
//!
//! let db = WatchingDatabase::from("threats.mxy")
//!     .on_reload(|event| {
//!         if event.success {
//!             eprintln!("Reloaded: generation {}", event.generation);
//!         }
//!     })
//!     .open()?;
//!
//! // Queries automatically use the latest database version
//! let result = db.lookup("1.2.3.4")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::database::{Database, DatabaseError, DatabaseOptions, QueryResult};
use arc_swap::ArcSwap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

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
struct WatcherState {
    /// File watcher (must be kept alive!)
    _watcher: notify::RecommendedWatcher,
    /// Watcher thread handle
    _thread: WatcherThread,
}

/// Auto-reloading database wrapper
///
/// Wraps a [`Database`] and automatically reloads it when the file changes.
/// Uses lock-free Arc swapping for zero-overhead query access.
///
/// # Thread Safety
///
/// `WatchingDatabase` is `Send + Sync` and can be shared across threads.
/// Each thread caches an Arc pointer locally and refreshes it when the
/// generation counter changes (~1ns check per query).
///
/// # Example
///
/// ```no_run
/// use matchy::WatchingDatabase;
///
/// let db = WatchingDatabase::from("threats.mxy")
///     .on_reload(|event| {
///         println!("Database reloaded: {:?}", event);
///     })
///     .open()?;
///
/// // Queries transparently use latest version
/// if let Some(result) = db.lookup("evil.com")? {
///     println!("Found: {:?}", result);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct WatchingDatabase {
    /// Current database using lock-free atomic Arc pointer
    current: Arc<ArcSwap<Database>>,

    /// Generation counter - incremented on each reload to invalidate caches
    generation: Arc<AtomicU64>,

    /// Optional callback for reload notifications
    reload_callback: Option<ReloadCallback>,

    /// Watcher state (kept alive to maintain file watching)
    _watcher: WatcherState,
}

// Thread-local storage for efficient repeated queries
thread_local! {
    // Cached Arc pointer to current database
    static LOCAL_DB: std::cell::RefCell<Option<Arc<Database>>> = const { std::cell::RefCell::new(None) };

    // Last seen generation counter
    static LOCAL_GENERATION: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

// Safety: WatchingDatabase is Send + Sync because:
// 1. ArcSwap provides atomic, thread-safe access to the current Database
// 2. Generation counter uses atomic operations
// 3. Callback is Arc<dyn ... + Send + Sync>
// 4. WatcherState only holds handles, no shared mutable state
unsafe impl Send for WatchingDatabase {}
unsafe impl Sync for WatchingDatabase {}

impl WatchingDatabase {
    /// Create a new builder for opening a watching database
    pub fn from(path: impl Into<PathBuf>) -> WatchingDatabaseOpener {
        WatchingDatabaseOpener::new(path)
    }

    /// Look up a query string, automatically using the latest database version
    ///
    /// This method is optimized for minimal overhead:
    /// - ~1-2ns per query for generation check (atomic load)
    /// - Thread-local Arc caching eliminates most atomic operations
    /// - No locks on the query path
    pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>, DatabaseError> {
        // Check generation (~1ns atomic load)
        let current_gen = self.generation.load(Ordering::Acquire);

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
                *local_db.borrow_mut() = Some(self.current.load_full());
            });
        }

        // Use thread-local cached Arc (zero atomic operations after refresh!)
        LOCAL_DB.with(|local_db| {
            let db_ref = local_db.borrow();
            // On first call, needs_refresh is always true (generation 0 -> 1)
            let db = db_ref
                .as_ref()
                .expect("LOCAL_DB not initialized: generation check should have triggered refresh");
            db.lookup(query)
        })
    }

    /// Get the current generation counter
    ///
    /// This increments each time the database is reloaded.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Get a snapshot of the current database
    ///
    /// Returns an Arc to the current Database. This is useful when you need
    /// to perform multiple operations on the same database version.
    pub fn snapshot(&self) -> Arc<Database> {
        self.current.load_full()
    }
}

/// Builder for opening a [`WatchingDatabase`]
pub struct WatchingDatabaseOpener {
    path: PathBuf,
    cache_capacity: Option<usize>,
    reload_callback: Option<ReloadCallback>,
}

impl WatchingDatabaseOpener {
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache_capacity: None,
            reload_callback: None,
        }
    }

    /// Set LRU cache capacity for the underlying database
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.cache_capacity = Some(capacity);
        self
    }

    /// Disable caching in the underlying database
    pub fn no_cache(mut self) -> Self {
        self.cache_capacity = Some(0);
        self
    }

    /// Set callback for reload notifications
    ///
    /// The callback is invoked whenever the database is reloaded (or reload fails).
    pub fn on_reload<F>(mut self, callback: F) -> Self
    where
        F: Fn(ReloadEvent) + Send + Sync + 'static,
    {
        self.reload_callback = Some(Arc::new(callback));
        self
    }

    /// Open the watching database
    pub fn open(self) -> Result<WatchingDatabase, DatabaseError> {
        use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
        use std::sync::mpsc::RecvTimeoutError;

        // Build options for opening database
        // Note: We disable the Database's internal cache because WatchingDatabase
        // manages cache invalidation at a higher level via generation counting.
        // The Database's cache is keyed by cache_generation which is 0 for all
        // new instances, leading to stale cache hits after reload.
        let mut db_options = DatabaseOptions::default();
        db_options.path = self.path.clone();
        // Always disable cache on underlying Database when using WatchingDatabase
        db_options.cache_capacity = Some(0);

        // Create channels for watcher thread
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();

        // Canonicalize path to resolve symlinks (important on macOS)
        let canonical_path = self
            .path
            .canonicalize()
            .map_err(|e| DatabaseError::Io(format!("Failed to canonicalize path: {}", e)))?;

        // Create file watcher
        let mut watcher = RecommendedWatcher::new(event_tx, Config::default())
            .map_err(|e| DatabaseError::Io(format!("Failed to create file watcher: {}", e)))?;

        watcher
            .watch(&canonical_path, RecursiveMode::NonRecursive)
            .map_err(|e| DatabaseError::Io(format!("Failed to watch file: {}", e)))?;

        // Open initial database
        let initial_db = Database::open_with_options(db_options.clone())?;
        let current = Arc::new(ArcSwap::from_pointee(initial_db));

        // Generation counter starts at 1 (0 is reserved for non-watched databases)
        let generation = Arc::new(AtomicU64::new(1));

        // Clone for thread
        let thread_current = Arc::clone(&current);
        let thread_generation = Arc::clone(&generation);
        let thread_path = canonical_path.clone();
        let thread_callback = self.reload_callback.clone();
        let thread_options = db_options;

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
                        // Any event triggers reload debounce
                        last_event_time = Some(Instant::now());
                    }
                    Ok(Err(_e)) => {
                        // Ignore watcher errors
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        // Check if file is stable (no events for DEBOUNCE_MS)
                        if let Some(last_time) = last_event_time {
                            if last_time.elapsed() >= Duration::from_millis(DEBOUNCE_MS) {
                                // Attempt reload
                                let reload_result =
                                    Database::open_with_options(thread_options.clone());

                                match reload_result {
                                    Ok(new_db) => {
                                        // Increment generation
                                        thread_generation.fetch_add(1, Ordering::Release);
                                        let new_gen = thread_generation.load(Ordering::Acquire);

                                        // Atomically swap in new database
                                        thread_current.store(Arc::new(new_db));

                                        // Invoke callback
                                        if let Some(ref callback) = thread_callback {
                                            callback(ReloadEvent {
                                                path: thread_path.clone(),
                                                success: true,
                                                error: None,
                                                generation: new_gen,
                                            });
                                        }
                                    }
                                    Err(e) => {
                                        // Reload failed - invoke callback
                                        if let Some(ref callback) = thread_callback {
                                            let gen = thread_generation.load(Ordering::Acquire);
                                            callback(ReloadEvent {
                                                path: thread_path.clone(),
                                                success: false,
                                                error: Some(e.to_string()),
                                                generation: gen,
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

        Ok(WatchingDatabase {
            current,
            generation,
            reload_callback: self.reload_callback,
            _watcher: WatcherState {
                _watcher: watcher,
                _thread: WatcherThread {
                    shutdown_tx,
                    handle: Some(handle),
                },
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatabaseBuilder, DataValue, MatchMode};
    use std::collections::HashMap;
    use std::fs;
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[test]
    fn test_watching_database_basic() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        // Create initial database
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert("value".to_string(), DataValue::String("initial".to_string()));
        builder.add_literal("test.com", data).unwrap();
        let bytes = builder.build().unwrap();
        fs::write(&db_path, bytes).unwrap();

        // Open watching database
        let db = WatchingDatabase::from(&db_path).open().unwrap();

        // Verify initial lookup works
        let result = db.lookup("test.com").unwrap();
        assert!(result.is_some());
        assert_eq!(db.generation(), 1);
    }

    #[test]
    fn test_watching_database_reload_callback() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mxy");

        // Create initial database
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let data = HashMap::new();
        builder.add_literal("example.com", data).unwrap();
        let bytes = builder.build().unwrap();
        fs::write(&db_path, bytes).unwrap();

        // Track reload events
        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&events);

        // Open with callback
        let db = WatchingDatabase::from(&db_path)
            .on_reload(move |event| {
                events_clone.lock().unwrap().push(event);
            })
            .open()
            .unwrap();

        assert_eq!(db.generation(), 1);

        // Modify database (atomic rename)
        std::thread::sleep(Duration::from_millis(100));
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let data = HashMap::new();
        builder.add_literal("example.org", data).unwrap();
        let bytes = builder.build().unwrap();

        let temp_path = db_path.with_extension("tmp");
        fs::write(&temp_path, bytes).unwrap();
        fs::rename(&temp_path, &db_path).unwrap();

        // Wait for reload (debounce + processing)
        std::thread::sleep(Duration::from_millis(500));

        // Verify callback was invoked
        let events_list = events.lock().unwrap();
        assert!(!events_list.is_empty(), "Callback should have been invoked");
        assert!(events_list.last().unwrap().success);
        assert!(events_list.last().unwrap().generation > 1);
    }
}
