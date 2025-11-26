//! Clean Matchy C API
//!
//! This module provides a modern, clean C API for building and querying databases
//! containing IP addresses and patterns. This is the primary public API.

use crate::database::{Database as RustDatabase, QueryResult};
use crate::mmdb_builder::MmdbBuilder;
use matchy_data_format::DataValue;
use matchy_glob::MatchMode;
use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;

// ============================================================================
// ERROR CODES
// ============================================================================

/// Success code
pub const MATCHY_SUCCESS: i32 = 0;
/// File not found error
pub const MATCHY_ERROR_FILE_NOT_FOUND: i32 = -1;
/// Invalid format error
pub const MATCHY_ERROR_INVALID_FORMAT: i32 = -2;
/// Corrupt data error
pub const MATCHY_ERROR_CORRUPT_DATA: i32 = -3;
/// Out of memory error
pub const MATCHY_ERROR_OUT_OF_MEMORY: i32 = -4;
/// Invalid parameter error
pub const MATCHY_ERROR_INVALID_PARAM: i32 = -5;
/// I/O error
pub const MATCHY_ERROR_IO: i32 = -6;

// ============================================================================
// OPAQUE HANDLES
// ============================================================================

/// Opaque database builder handle
#[repr(C)]
pub struct matchy_builder_t {
    _private: [u8; 0],
}

/// Opaque database handle
#[repr(C)]
pub struct matchy_t {
    _private: [u8; 0],
}

/// Query result
#[repr(C)]
pub struct matchy_result_t {
    /// Whether a match was found
    pub found: bool,
    /// Network prefix length (for IP results)
    pub prefix_len: u8,
    /// Internal pointer to cached DataValue (opaque, for structured data access)
    pub _data_cache: *mut (),
    /// Internal database reference (for entry.db population)
    pub _db_ref: *const matchy_t,
}

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

struct MatchyBuilderInternal {
    builder: MmdbBuilder,
}

struct MatchyInternal {
    database: RustDatabase,
}

// Conversion helpers for opaque types
impl matchy_builder_t {
    fn from_internal(internal: Box<MatchyBuilderInternal>) -> *mut Self {
        Box::into_raw(internal) as *mut Self
    }

    unsafe fn into_internal(ptr: *mut Self) -> Box<MatchyBuilderInternal> {
        Box::from_raw(ptr as *mut MatchyBuilderInternal)
    }

    unsafe fn as_internal_mut(ptr: *mut Self) -> &'static mut MatchyBuilderInternal {
        &mut *(ptr as *mut MatchyBuilderInternal)
    }
}

impl matchy_t {
    fn from_internal(internal: Box<MatchyInternal>) -> *mut Self {
        Box::into_raw(internal) as *mut Self
    }

    unsafe fn into_internal(ptr: *mut Self) -> Box<MatchyInternal> {
        Box::from_raw(ptr as *mut MatchyInternal)
    }

    unsafe fn as_internal(ptr: *const Self) -> &'static MatchyInternal {
        &*(ptr as *const MatchyInternal)
    }
}

// ============================================================================
// DATABASE BUILDING API
// ============================================================================

/// Create a new database builder
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on allocation failure
///
/// # Example
/// ```c
/// matchy_builder_t *builder = matchy_builder_new();
/// if (builder == NULL) {
///     fprintf(stderr, "Failed to create builder\n");
///     return 1;
/// }
/// ```
#[no_mangle]
pub extern "C" fn matchy_builder_new() -> *mut matchy_builder_t {
    let builder = MmdbBuilder::new(MatchMode::CaseSensitive);
    let internal = Box::new(MatchyBuilderInternal { builder });
    matchy_builder_t::from_internal(internal)
}

/// Add an entry with associated data (as JSON)
///
/// Automatically detects whether the key is an IP address, CIDR range, or pattern.
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `key` - IP address, CIDR, or pattern (null-terminated C string, must not be NULL)
/// * `json_data` - Associated data as JSON (null-terminated C string, must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `key` must be a valid null-terminated C string
/// * `json_data` must be a valid null-terminated C string containing valid JSON
///
/// # Example
/// ```c
/// matchy_builder_add(builder, "1.2.3.4", "{\"threat_level\": \"high\"}");
/// matchy_builder_add(builder, "10.0.0.0/8", "{\"type\": \"internal\"}");
/// matchy_builder_add(builder, "*.evil.com", "{\"category\": \"malware\"}");
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_add(
    builder: *mut matchy_builder_t,
    key: *const c_char,
    json_data: *const c_char,
) -> i32 {
    if builder.is_null() || key.is_null() || json_data.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let key_str = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    let json_str = match CStr::from_ptr(json_data).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    // Parse JSON to DataValue (supports nested structures)
    let data: DataValue = match serde_json::from_str(json_str) {
        Ok(d) => d,
        Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
    };

    // Wrap in a map if it's not already a map
    let data_map = match data {
        DataValue::Map(m) => m,
        _ => {
            // Single value - wrap it in a map with "value" key
            let mut map = HashMap::new();
            map.insert("value".to_string(), data);
            map
        }
    };

    let internal = matchy_builder_t::as_internal_mut(builder);
    match internal.builder.add_entry(key_str, data_map) {
        Ok(_) => MATCHY_SUCCESS,
        Err(_) => MATCHY_ERROR_INVALID_FORMAT,
    }
}

/// Set database description
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `description` - Description text (null-terminated C string, must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `description` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_set_description(
    builder: *mut matchy_builder_t,
    description: *const c_char,
) -> i32 {
    if builder.is_null() || description.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let desc_str = match CStr::from_ptr(description).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    let internal = matchy_builder_t::as_internal_mut(builder);
    // Create new builder with description
    let old_builder = std::mem::replace(
        &mut internal.builder,
        MmdbBuilder::new(MatchMode::CaseSensitive),
    );
    internal.builder = old_builder.with_description("en", desc_str);

    MATCHY_SUCCESS
}

/// Build and save database to file
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `filename` - Path where file should be written (null-terminated C string, must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `filename` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// if (matchy_builder_save(builder, "threats.db") != MATCHY_SUCCESS) {
///     fprintf(stderr, "Failed to save database\n");
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_save(
    builder: *mut matchy_builder_t,
    filename: *const c_char,
) -> i32 {
    if builder.is_null() || filename.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let path = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    let internal = matchy_builder_t::as_internal_mut(builder);
    // Replace builder with a dummy one to take ownership
    let builder_to_build = std::mem::replace(
        &mut internal.builder,
        MmdbBuilder::new(MatchMode::CaseSensitive),
    );
    let bytes = match builder_to_build.build() {
        Ok(b) => b,
        Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
    };

    match std::fs::write(path, bytes) {
        Ok(_) => MATCHY_SUCCESS,
        Err(_) => MATCHY_ERROR_IO,
    }
}

/// Build and return database in memory
///
/// # Parameters
/// * `builder` - Builder handle (must not be NULL)
/// * `buffer` - Pointer to receive the buffer pointer (must not be NULL)
/// * `size` - Pointer to receive the buffer size (must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS (0) on success
/// * Error code < 0 on failure
///
/// # Safety
/// * `builder` must be a valid pointer from matchy_builder_new
/// * `buffer` and `size` must be valid pointers
/// * Caller must free the returned buffer with libc::free()
///
/// # Example
/// ```c
/// uint8_t *buffer = NULL;
/// size_t size = 0;
/// if (matchy_builder_build(builder, &buffer, &size) == MATCHY_SUCCESS) {
///     // Use buffer...
///     free(buffer);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_build(
    builder: *mut matchy_builder_t,
    buffer: *mut *mut u8,
    size: *mut usize,
) -> i32 {
    if builder.is_null() || buffer.is_null() || size.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let internal = matchy_builder_t::as_internal_mut(builder);
    // Replace builder with a dummy one to take ownership
    let builder_to_build = std::mem::replace(
        &mut internal.builder,
        MmdbBuilder::new(MatchMode::CaseSensitive),
    );
    let bytes = match builder_to_build.build() {
        Ok(b) => b,
        Err(_) => return MATCHY_ERROR_INVALID_FORMAT,
    };

    // Allocate buffer using libc::malloc so C can free it
    let buf_size = bytes.len();
    let buf_ptr = libc::malloc(buf_size) as *mut u8;
    if buf_ptr.is_null() {
        return MATCHY_ERROR_OUT_OF_MEMORY;
    }

    // Copy data
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, buf_size);

    *buffer = buf_ptr;
    *size = buf_size;

    MATCHY_SUCCESS
}

/// Free builder
///
/// # Parameters
/// * `builder` - Builder handle (may be NULL)
///
/// # Safety
/// * `builder` must be NULL or a valid pointer from matchy_builder_new
/// * Must not be used after calling this function
/// * Calling with NULL is safe (no-op)
#[no_mangle]
pub unsafe extern "C" fn matchy_builder_free(builder: *mut matchy_builder_t) {
    if !builder.is_null() {
        let _ = matchy_builder_t::into_internal(builder);
    }
}

// ============================================================================
// DATABASE QUERYING API
// ============================================================================

/// Reload callback event information
///
/// Information passed to reload callbacks when database reloads occur.
#[repr(C)]
pub struct matchy_reload_event_t {
    /// Path to database file (null-terminated C string)
    /// Valid only for duration of callback - copy if needed
    pub path: *const c_char,

    /// Whether reload succeeded
    /// true = successful reload, false = reload failed
    pub success: bool,

    /// Error message if reload failed (null if success)
    /// Valid only for duration of callback - copy if needed
    pub error: *const c_char,

    /// Generation counter (increments on each successful reload)
    /// Can be used to detect if database has changed since last check
    pub generation: u64,
}

/// Reload callback function type
///
/// Called when database reload completes (success or failure).
/// Called from watcher thread - keep processing minimal!
///
/// # Parameters
/// * `event` - Reload event information (valid only during callback)
/// * `user_data` - User-provided context pointer from matchy_open_options_t
///
/// # Safety
/// * Callback must be thread-safe
/// * Do not call matchy_* functions from callback (potential deadlock)
/// * Copy event.path and event.error if you need them after callback returns
/// * user_data must match what was provided in options
///
/// # Example
/// ```c
/// void on_reload(const matchy_reload_event_t *event, void *user_data) {
///     if (event->success) {
///         printf("Database reloaded: %s (generation %lu)\n",
///                event->path, event->generation);
///     } else {
///         fprintf(stderr, "Reload failed: %s - %s\n",
///                 event->path, event->error);
///     }
/// }
/// ```
#[allow(non_camel_case_types)]
pub type matchy_reload_callback_t =
    Option<unsafe extern "C" fn(event: *const matchy_reload_event_t, user_data: *mut c_void)>;

/// Database opening options
///
/// Configure how databases are loaded, including cache settings and validation.
#[repr(C)]
pub struct matchy_open_options_t {
    /// LRU cache capacity
    /// 0 = disable cache, >0 = cache this many entries
    /// Default: 10000
    pub cache_capacity: u32,

    /// Enable automatic reload when database file changes
    /// false = no watching (default), true = auto-reload on file changes
    /// Default: false
    ///
    /// When enabled, the database watches its source file and automatically
    /// reloads when changes are detected. All queries transparently use the
    /// latest version. Adds ~10-20ns overhead per query due to read lock.
    pub auto_reload: bool,

    /// Reload callback function (optional)
    /// Called when database reload completes (success or failure)
    /// Set to NULL to disable callback
    /// Default: NULL
    pub reload_callback: matchy_reload_callback_t,

    /// User data pointer passed to reload callback
    /// Can be any pointer - callback receives it as-is
    /// Default: NULL
    pub reload_callback_user_data: *mut c_void,
}

impl Default for matchy_open_options_t {
    fn default() -> Self {
        Self {
            cache_capacity: 10000,
            auto_reload: false,
            reload_callback: None, // None represents NULL function pointer
            reload_callback_user_data: ptr::null_mut(),
        }
    }
}

/// Initialize database opening options with defaults
///
/// Sets default values:
/// - cache_capacity = 10000
/// - auto_reload = false
///
/// # Parameters
/// * `options` - Pointer to options struct to initialize (must not be NULL)
///
/// # Safety
/// * `options` must be a valid pointer
///
/// # Example
/// ```c
/// matchy_open_options_t opts;
/// matchy_init_open_options(&opts);
/// opts.cache_capacity = 100000;  // Custom size
/// opts.auto_reload = true;        // Enable auto-reload
/// matchy_t *db = matchy_open_with_options("threats.mxy", &opts);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_init_open_options(options: *mut matchy_open_options_t) {
    if options.is_null() {
        return;
    }
    *options = matchy_open_options_t::default();
}

/// Open database with custom options
///
/// Opens a database file with configurable cache size, auto-reload, and validation settings.
///
/// # Parameters
/// * `filename` - Path to database file (null-terminated C string, must not be NULL)
/// * `options` - Opening options (must not be NULL)
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on failure
///
/// # Safety
/// * `filename` must be a valid null-terminated C string
/// * `options` must be a valid pointer
///
/// # Example
/// ```c
/// // High-performance mode with auto-reload
/// matchy_open_options_t opts;
/// matchy_init_open_options(&opts);
/// opts.cache_capacity = 100000; // Large cache
/// opts.auto_reload = true;      // Watch file for changes
///
/// matchy_t *db = matchy_open_with_options("threats.mxy", &opts);
/// if (db == NULL) {
///     fprintf(stderr, "Failed to open database\n");
///     return 1;
/// }
///
/// // Queries automatically use latest database version
/// matchy_result_t result;
/// matchy_lookup(db, "1.2.3.4", &result);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_open_with_options(
    filename: *const c_char,
    options: *const matchy_open_options_t,
) -> *mut matchy_t {
    if filename.is_null() || options.is_null() {
        return ptr::null_mut();
    }

    let path = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let opts = &*options;

    // Build database using fluent API
    let mut opener = RustDatabase::from(path);

    if opts.cache_capacity == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(opts.cache_capacity as usize);
    }

    if opts.auto_reload {
        opener = opener.auto_reload();
    }

    // Set up reload callback if provided (check for non-null function pointer)
    if let Some(callback_fn) = opts.reload_callback {
        // Safety: We trust that the C callback is thread-safe (documented requirement)
        // Cast pointer to usize for Send+Sync (usize is Copy and thread-safe)
        let user_data = opts.reload_callback_user_data as usize;
        opener = opener.on_reload(move |event: crate::database::ReloadEvent| {
            // Convert Rust ReloadEvent to C matchy_reload_event_t
            let c_path = std::ffi::CString::new(event.path.to_string_lossy().as_ref())
                .unwrap_or_else(|_| std::ffi::CString::new("<invalid path>").unwrap());

            let c_error = event.error.as_ref().map(|e| {
                std::ffi::CString::new(e.as_str())
                    .unwrap_or_else(|_| std::ffi::CString::new("<invalid error>").unwrap())
            });

            let c_event = matchy_reload_event_t {
                path: c_path.as_ptr(),
                success: event.success,
                error: c_error.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                generation: event.generation,
            };

            // Call C callback
            // Safety: callback came from C and must be thread-safe (documented requirement)
            unsafe {
                callback_fn(&c_event as *const _, user_data as *mut c_void);
            }

            // c_path and c_error dropped here, so C callback must not retain pointers
        });
    }

    match opener.open() {
        Ok(db) => {
            let internal = Box::new(MatchyInternal { database: db });
            matchy_t::from_internal(internal)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Open database from file (memory-mapped) - SAFE mode
///
/// Opens a database file using memory mapping for optimal performance.
/// The file is not loaded into memory - it's accessed on-demand.
///
/// This validates UTF-8 on pattern string reads. Use for untrusted databases.
///
/// # Parameters
/// * `filename` - Path to database file (null-terminated C string, must not be NULL)
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on failure
///
/// # Safety
/// * `filename` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// matchy_t *db = matchy_open("threats.db");
/// if (db == NULL) {
///     fprintf(stderr, "Failed to open database\n");
///     return 1;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_open(filename: *const c_char) -> *mut matchy_t {
    // Delegate to matchy_open_with_options with default settings
    let opts = matchy_open_options_t::default();
    matchy_open_with_options(filename, &opts)
}

/// Open database from memory buffer (zero-copy)
///
/// Creates a database handle from a memory buffer. No data is copied.
///
/// # Parameters
/// * `buffer` - Pointer to database data (must not be NULL)
/// * `size` - Size of buffer in bytes (must be > 0)
///
/// # Returns
/// * Non-null pointer on success
/// * NULL on failure
///
/// # Safety
/// * `buffer` must be valid for the lifetime of the database handle
/// * Caller must not modify or free buffer while handle exists
#[no_mangle]
pub unsafe extern "C" fn matchy_open_buffer(buffer: *const u8, size: usize) -> *mut matchy_t {
    if buffer.is_null() || size == 0 {
        return ptr::null_mut();
    }

    let slice = slice::from_raw_parts(buffer, size);
    match RustDatabase::from_bytes(slice.to_vec()) {
        Ok(db) => {
            let internal = Box::new(MatchyInternal { database: db });
            matchy_t::from_internal(internal)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Database statistics
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct matchy_stats_t {
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

/// Get database statistics
///
/// Returns statistics about query performance, cache effectiveness,
/// and query distribution.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `stats` - Pointer to stats structure to fill (must not be NULL)
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
/// * `stats` must be a valid pointer to matchy_stats_t
///
/// # Example
/// ```c
/// matchy_stats_t stats;
/// matchy_get_stats(db, &stats);
/// printf("Total queries: %llu\n", stats.total_queries);
///
/// // Calculate hit rate
/// double cache_hit_rate = 0.0;
/// if (stats.cache_hits + stats.cache_misses > 0) {
///     cache_hit_rate = (double)stats.cache_hits /
///                      (stats.cache_hits + stats.cache_misses);
/// }
/// printf("Cache hit rate: %.1f%%\n", cache_hit_rate * 100.0);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_get_stats(db: *const matchy_t, stats: *mut matchy_stats_t) {
    if db.is_null() || stats.is_null() {
        return;
    }

    let internal = matchy_t::as_internal(db);
    let rust_stats = internal.database.stats();

    *stats = matchy_stats_t {
        total_queries: rust_stats.total_queries,
        queries_with_match: rust_stats.queries_with_match,
        queries_without_match: rust_stats.queries_without_match,
        cache_hits: rust_stats.cache_hits,
        cache_misses: rust_stats.cache_misses,
        ip_queries: rust_stats.ip_queries,
        string_queries: rust_stats.string_queries,
    };
}

/// Clear the query cache
///
/// Removes all cached query results. Useful for benchmarking or
/// forcing fresh lookups.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
///
/// # Example
/// ```c
/// // Do some queries (fills cache)
/// matchy_query(db, "example.com");
///
/// // Clear cache to force fresh lookups
/// matchy_clear_cache(db);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_clear_cache(db: *const matchy_t) {
    if db.is_null() {
        return;
    }

    let internal = matchy_t::as_internal(db);
    internal.database.clear_cache();
}

/// Close database
///
/// Closes the database and frees all associated resources.
///
/// # Parameters
/// * `db` - Database handle (may be NULL)
///
/// # Safety
/// * `db` must be NULL or a valid pointer from matchy_open
/// * Must not be used after calling this function
/// * Calling with NULL is safe (no-op)
///
/// # Example
/// ```c
/// matchy_close(db);
/// db = NULL;  // Good practice
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_close(db: *mut matchy_t) {
    if !db.is_null() {
        let _ = matchy_t::into_internal(db);
    }
}

/// Unified query interface - automatically detects IP vs pattern
///
/// Queries the database with an IP address or pattern. The function automatically
/// detects the query type and uses the appropriate lookup method.
///
/// Returns structured data as DataValue (cached internally).
/// Use matchy_result_get_entry() to access structured data,
/// or matchy_result_to_json() to convert to JSON.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `query` - IP address or pattern to search (null-terminated C string, must not be NULL)
///
/// # Returns
/// * matchy_result_t with found=true if match found
/// * matchy_result_t with found=false if no match
/// * Caller must free result with matchy_free_result
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
/// * `query` must be a valid null-terminated C string
///
/// # Example
/// ```c
/// matchy_result_t result = matchy_query(db, "1.2.3.4");
/// if (result.found) {
///     // Option 1: Get as JSON
///     char *json = matchy_result_to_json(&result);
///     printf("Found: %s\n", json);
///     matchy_free_string(json);
///     
///     // Option 2: Access structured data
///     matchy_entry_s entry;
///     matchy_result_get_entry(&result, &entry);
///     // ... use matchy_aget_value()
/// }
/// matchy_free_result(&result);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_query(
    db: *const matchy_t,
    query: *const c_char,
) -> matchy_result_t {
    if db.is_null() || query.is_null() {
        return matchy_result_t {
            found: false,
            prefix_len: 0,
            _data_cache: ptr::null_mut(),
            _db_ref: ptr::null(),
        };
    }

    let query_str = match CStr::from_ptr(query).to_str() {
        Ok(s) => s,
        Err(_) => {
            return matchy_result_t {
                found: false,
                prefix_len: 0,
                _data_cache: ptr::null_mut(),
                _db_ref: ptr::null(),
            }
        }
    };

    let internal = matchy_t::as_internal(db);
    match internal.database.lookup(query_str) {
        Ok(Some(QueryResult::Ip { data, prefix_len })) => {
            // Cache the DataValue for structured access
            let data_cache = Box::new(data);
            let data_cache_ptr = Box::into_raw(data_cache) as *mut ();

            matchy_result_t {
                found: true,
                prefix_len,
                _data_cache: data_cache_ptr,
                _db_ref: db,
            }
        }
        Ok(Some(QueryResult::Pattern {
            pattern_ids: _,
            data,
        })) => {
            // For patterns, return the first match's data
            if let Some(Some(first_data)) = data.first() {
                let data_cache = Box::new(first_data.clone());
                let data_cache_ptr = Box::into_raw(data_cache) as *mut ();

                return matchy_result_t {
                    found: true,
                    prefix_len: 0,
                    _data_cache: data_cache_ptr,
                    _db_ref: db,
                };
            }
            matchy_result_t {
                found: false,
                prefix_len: 0,
                _data_cache: ptr::null_mut(),
                _db_ref: ptr::null(),
            }
        }
        _ => matchy_result_t {
            found: false,
            prefix_len: 0,
            _data_cache: ptr::null_mut(),
            _db_ref: ptr::null(),
        },
    }
}

/// Free query result
///
/// Frees the memory allocated for a query result.
///
/// # Parameters
/// * `result` - Pointer to result from matchy_query (must not be NULL)
///
/// # Safety
/// * `result` must be a valid pointer to a result from matchy_query
/// * Must not be called twice on the same result
#[no_mangle]
pub unsafe extern "C" fn matchy_free_result(result: *mut matchy_result_t) {
    if !result.is_null() && !(*result)._data_cache.is_null() {
        // Free the cached DataValue
        let _ = Box::from_raw((*result)._data_cache as *mut DataValue);
        (*result)._data_cache = ptr::null_mut();
    }
}

/// Free a string returned by matchy
///
/// # Parameters
/// * `string` - String pointer returned by matchy (may be NULL)
///
/// # Safety
/// * `string` must be NULL or a pointer returned by matchy
/// * Must not be called twice on the same pointer
#[no_mangle]
pub unsafe extern "C" fn matchy_free_string(string: *mut c_char) {
    if !string.is_null() {
        let _ = CString::from_raw(string);
    }
}

/// Get library version string
///
/// # Returns
/// * Version string (e.g., "0.4.0")
/// * Pointer is valid for program lifetime, do not free
#[no_mangle]
pub extern "C" fn matchy_version() -> *const c_char {
    // Use the version from Cargo.toml, automatically updated at compile time
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Get database format description
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * Format string ("IP database", "Pattern database", or "Combined IP+Pattern database")
/// * Pointer is valid for database lifetime, do not free
/// * NULL if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_format(db: *const matchy_t) -> *const c_char {
    if db.is_null() {
        return ptr::null();
    }

    let internal = matchy_t::as_internal(db);
    let format_str = internal.database.format();
    format_str.as_ptr() as *const c_char
}

/// Check if database supports IP address lookups
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains IP data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_has_ip_data(db: *const matchy_t) -> bool {
    if db.is_null() {
        return false;
    }

    let internal = matchy_t::as_internal(db);
    internal.database.has_ip_data()
}

/// Check if database supports string lookups (literals or globs)
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains literal or glob data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_has_string_data(db: *const matchy_t) -> bool {
    if db.is_null() {
        return false;
    }

    let internal = matchy_t::as_internal(db);
    internal.database.has_string_data()
}

/// Check if database supports literal (exact string) lookups
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains literal hash data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_has_literal_data(db: *const matchy_t) -> bool {
    if db.is_null() {
        return false;
    }

    let internal = matchy_t::as_internal(db);
    internal.database.has_literal_data()
}

/// Check if database supports glob pattern lookups
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains glob pattern data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_has_glob_data(db: *const matchy_t) -> bool {
    if db.is_null() {
        return false;
    }

    let internal = matchy_t::as_internal(db);
    internal.database.has_glob_data()
}

/// Check if database supports pattern matching (deprecated)
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * true if database contains pattern data
/// * false if not or if db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
///
/// # Deprecated
/// Use matchy_has_literal_data or matchy_has_glob_data instead
#[no_mangle]
#[deprecated(
    since = "0.5.0",
    note = "Use matchy_has_literal_data or matchy_has_glob_data instead"
)]
pub unsafe extern "C" fn matchy_has_pattern_data(db: *const matchy_t) -> bool {
    if db.is_null() {
        return false;
    }

    let internal = matchy_t::as_internal(db);
    internal.database.has_string_data()
}

/// Get database metadata as JSON string
///
/// Returns MMDB metadata if available (for IP or combined databases).
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * JSON string containing metadata (caller must free with matchy_free_string)
/// * NULL if no metadata available or db is NULL
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_metadata(db: *const matchy_t) -> *mut c_char {
    if db.is_null() {
        return ptr::null_mut();
    }

    let internal = matchy_t::as_internal(db);
    match internal.database.metadata() {
        Some(metadata) => {
            // Convert metadata to JSON string
            match serde_json::to_string(&metadata) {
                Ok(json_str) => match CString::new(json_str) {
                    Ok(c_str) => c_str.into_raw(),
                    Err(_) => ptr::null_mut(),
                },
                Err(_) => ptr::null_mut(),
            }
        }
        None => ptr::null_mut(),
    }
}

/// Get pattern string by ID
///
/// Returns the pattern string for a given pattern ID.
/// Only works for pattern or combined databases.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
/// * `pattern_id` - Pattern ID
///
/// # Returns
/// * Pattern string (caller must free with matchy_free_string)
/// * NULL if pattern ID not found or db has no patterns
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_get_pattern_string(
    db: *const matchy_t,
    pattern_id: u32,
) -> *mut c_char {
    if db.is_null() {
        return ptr::null_mut();
    }

    let internal = matchy_t::as_internal(db);

    // Get pattern string from database
    if let Some(pattern_str) = internal.database.get_pattern_string(pattern_id) {
        match CString::new(pattern_str) {
            Ok(c_str) => return c_str.into_raw(),
            Err(_) => return ptr::null_mut(),
        }
    }

    ptr::null_mut()
}

/// Get total number of patterns in database
///
/// Returns the number of patterns in the database.
/// Only works for pattern or combined databases.
///
/// # Parameters
/// * `db` - Database handle (must not be NULL)
///
/// # Returns
/// * Number of patterns (0 if no patterns or db is NULL)
///
/// # Safety
/// * `db` must be a valid pointer from matchy_open
#[no_mangle]
pub unsafe extern "C" fn matchy_pattern_count(db: *const matchy_t) -> usize {
    if db.is_null() {
        return 0;
    }

    let internal = matchy_t::as_internal(db);
    internal.database.pattern_count()
}

// ============================================================================
// ENHANCED API - STRUCTURED DATA ACCESS
// ============================================================================

/// MMDB data type constants (matching libmaxminddb)
/// Extended type marker (internal use)
pub const MATCHY_DATA_TYPE_EXTENDED: u32 = 0;
/// Pointer type for data section references
pub const MATCHY_DATA_TYPE_POINTER: u32 = 1;
/// UTF-8 encoded string
pub const MATCHY_DATA_TYPE_UTF8_STRING: u32 = 2;
/// Double precision float (64-bit)
pub const MATCHY_DATA_TYPE_DOUBLE: u32 = 3;
/// Byte array / binary data
pub const MATCHY_DATA_TYPE_BYTES: u32 = 4;
/// Unsigned 16-bit integer
pub const MATCHY_DATA_TYPE_UINT16: u32 = 5;
/// Unsigned 32-bit integer
pub const MATCHY_DATA_TYPE_UINT32: u32 = 6;
/// Map/dictionary type
pub const MATCHY_DATA_TYPE_MAP: u32 = 7;
/// Signed 32-bit integer
pub const MATCHY_DATA_TYPE_INT32: u32 = 8;
/// Unsigned 64-bit integer
pub const MATCHY_DATA_TYPE_UINT64: u32 = 9;
/// Unsigned 128-bit integer
pub const MATCHY_DATA_TYPE_UINT128: u32 = 10;
/// Array type
pub const MATCHY_DATA_TYPE_ARRAY: u32 = 11;
/// Boolean type
pub const MATCHY_DATA_TYPE_BOOLEAN: u32 = 14;
/// Single precision float (32-bit)
pub const MATCHY_DATA_TYPE_FLOAT: u32 = 15;

/// Additional error codes for structured data API
/// Invalid lookup path specified
pub const MATCHY_ERROR_LOOKUP_PATH_INVALID: i32 = -7;
/// No data available at the specified path
pub const MATCHY_ERROR_NO_DATA: i32 = -8;
/// Failed to parse data value
pub const MATCHY_ERROR_DATA_PARSE: i32 = -9;

/// Entry data union (matches MMDB layout for compatibility)
#[repr(C)]
#[derive(Copy, Clone)]
pub union matchy_entry_data_value_u {
    /// Pointer to data section offset
    pub pointer: u32,
    /// Null-terminated UTF-8 string pointer
    pub utf8_string: *const c_char,
    /// 64-bit floating point value
    pub double_value: f64,
    /// Pointer to byte array
    pub bytes: *const u8,
    /// 16-bit unsigned integer value
    pub uint16: u16,
    /// 32-bit unsigned integer value
    pub uint32: u32,
    /// 32-bit signed integer value
    pub int32: i32,
    /// 64-bit unsigned integer value
    pub uint64: u64,
    /// 128-bit unsigned integer value (as byte array)
    pub uint128: [u8; 16],
    /// Boolean value
    pub boolean: bool,
    /// 32-bit floating point value
    pub float_value: f32,
}

/// Entry data structure (like MMDB_entry_data_s)
#[repr(C)]
pub struct matchy_entry_data_t {
    /// Whether data was found
    pub has_data: bool,
    /// Data type (one of MATCHY_DATA_TYPE_* constants)
    pub type_: u32,
    /// Actual data value
    pub value: matchy_entry_data_value_u,
    /// Size in bytes (for strings, bytes, maps, arrays)
    pub data_size: u32,
    /// Internal offset (for debugging)
    pub offset: u32,
}

/// Entry handle (like MMDB_entry_s)
#[repr(C)]
pub struct matchy_entry_s {
    /// Database handle
    pub db: *const matchy_t,
    /// Cached data pointer (internal)
    pub data_ptr: *const (),
}

/// Entry data list node (like MMDB_entry_data_list_s)
#[repr(C)]
pub struct matchy_entry_data_list_t {
    /// The entry data for this node
    pub entry_data: matchy_entry_data_t,
    /// Pointer to the next node in the list (NULL if last)
    pub next: *mut matchy_entry_data_list_t,
}

impl matchy_entry_data_t {
    /// Create empty entry data
    fn empty() -> Self {
        Self {
            has_data: false,
            type_: 0,
            value: matchy_entry_data_value_u { uint32: 0 },
            data_size: 0,
            offset: 0,
        }
    }

    /// Convert DataValue to entry_data_t
    /// Strings are stored in the cache to keep them alive
    unsafe fn from_data_value(value: &DataValue, string_cache: &mut Vec<CString>) -> Option<Self> {
        let (type_, data_value, data_size) = match value {
            DataValue::Pointer(offset) => (
                MATCHY_DATA_TYPE_POINTER,
                matchy_entry_data_value_u { pointer: *offset },
                0,
            ),
            DataValue::String(s) => {
                let c_str = CString::new(s.as_str()).ok()?;
                let ptr = c_str.as_ptr();
                string_cache.push(c_str);
                (
                    MATCHY_DATA_TYPE_UTF8_STRING,
                    matchy_entry_data_value_u { utf8_string: ptr },
                    s.len() as u32,
                )
            }
            DataValue::Double(d) => (
                MATCHY_DATA_TYPE_DOUBLE,
                matchy_entry_data_value_u { double_value: *d },
                8,
            ),
            DataValue::Bytes(b) => {
                let ptr = b.as_ptr();
                (
                    MATCHY_DATA_TYPE_BYTES,
                    matchy_entry_data_value_u { bytes: ptr },
                    b.len() as u32,
                )
            }
            DataValue::Uint16(n) => (
                MATCHY_DATA_TYPE_UINT16,
                matchy_entry_data_value_u { uint16: *n },
                2,
            ),
            DataValue::Uint32(n) => (
                MATCHY_DATA_TYPE_UINT32,
                matchy_entry_data_value_u { uint32: *n },
                4,
            ),
            DataValue::Map(m) => (
                MATCHY_DATA_TYPE_MAP,
                matchy_entry_data_value_u { uint32: 0 },
                m.len() as u32,
            ),
            DataValue::Int32(n) => (
                MATCHY_DATA_TYPE_INT32,
                matchy_entry_data_value_u { int32: *n },
                4,
            ),
            DataValue::Uint64(n) => (
                MATCHY_DATA_TYPE_UINT64,
                matchy_entry_data_value_u { uint64: *n },
                8,
            ),
            DataValue::Uint128(n) => {
                let bytes = n.to_be_bytes();
                (
                    MATCHY_DATA_TYPE_UINT128,
                    matchy_entry_data_value_u { uint128: bytes },
                    16,
                )
            }
            DataValue::Array(a) => (
                MATCHY_DATA_TYPE_ARRAY,
                matchy_entry_data_value_u { uint32: 0 },
                a.len() as u32,
            ),
            DataValue::Bool(b) => (
                MATCHY_DATA_TYPE_BOOLEAN,
                matchy_entry_data_value_u { boolean: *b },
                1,
            ),
            DataValue::Float(f) => (
                MATCHY_DATA_TYPE_FLOAT,
                matchy_entry_data_value_u { float_value: *f },
                4,
            ),
        };

        Some(Self {
            has_data: true,
            type_,
            value: data_value,
            data_size,
            offset: 0,
        })
    }
}

/// Navigate into DataValue using a path of string keys
fn navigate_path<'a>(mut value: &'a DataValue, path: &[&str]) -> Option<&'a DataValue> {
    for key in path {
        match value {
            DataValue::Map(m) => {
                value = m.get(*key)?;
            }
            DataValue::Array(a) => {
                // Try to parse key as array index
                let idx: usize = key.parse().ok()?;
                value = a.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(value)
}

/// Get entry handle from query result
///
/// This extracts the entry handle which can be used for data navigation.
///
/// # Parameters
/// * `result` - Query result (must not be NULL, must have found=true)
/// * `entry` - Output entry handle (must not be NULL)
///
/// # Returns
/// * MATCHY_SUCCESS on success
/// * MATCHY_ERROR_NO_DATA if result not found
/// * MATCHY_ERROR_INVALID_PARAM if parameters invalid
///
/// # Safety
/// * `result` must be valid result from matchy_query
/// * `entry` must be valid pointer to output struct
/// * Result must not have been freed
///
/// # Example
/// ```c
/// matchy_result_t result = matchy_query(db, "8.8.8.8");
/// if (result.found) {
///     matchy_entry_s entry;
///     matchy_result_get_entry(&result, &entry);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_result_get_entry(
    result: *const matchy_result_t,
    entry: *mut matchy_entry_s,
) -> i32 {
    if result.is_null() || entry.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let res = &*result;
    if !res.found {
        return MATCHY_ERROR_NO_DATA;
    }

    // Populate entry with database reference and result pointer
    (*entry).db = res._db_ref;
    (*entry).data_ptr = result as *const ();

    MATCHY_SUCCESS
}

// Note: Full varargs support (matchy_get_value) should be provided as a C macro
// or wrapper function that calls matchy_aget_value. For now, we provide the
// array-based version which is more portable.

/// Get value using array of strings for path
///
/// Like matchy_get_value but takes an array of strings instead of varargs.
///
/// # Parameters
/// * `entry` - Entry handle
/// * `entry_data` - Output data
/// * `path` - NULL-terminated array of string pointers
///
/// # Returns
/// * Same as matchy_get_value
///
/// # Safety
/// * Same as matchy_get_value
/// * `path` must be NULL-terminated array
///
/// # Example
/// ```c
/// const char *path[] = {"country", "iso_code", NULL};
/// matchy_aget_value(&entry, &data, path);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_aget_value(
    entry: *const matchy_entry_s,
    entry_data: *mut matchy_entry_data_t,
    path: *const *const c_char,
) -> i32 {
    if entry.is_null() || entry_data.is_null() || path.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    // Convert path array to Vec
    let mut path_vec = Vec::new();
    let mut i = 0;
    loop {
        let ptr = *path.offset(i);
        if ptr.is_null() {
            break;
        }
        match CStr::from_ptr(ptr).to_str() {
            Ok(s) => path_vec.push(s),
            Err(_) => return MATCHY_ERROR_INVALID_PARAM,
        }
        i += 1;
    }

    // Get result and access cached DataValue directly
    let result_ptr = (*entry).data_ptr as *const matchy_result_t;
    if result_ptr.is_null() {
        (*entry_data) = matchy_entry_data_t::empty();
        return MATCHY_ERROR_NO_DATA;
    }

    let result = &*result_ptr;
    if result._data_cache.is_null() {
        (*entry_data) = matchy_entry_data_t::empty();
        return MATCHY_ERROR_NO_DATA;
    }

    // Access the cached DataValue directly - no JSON parsing!
    let data = &*(result._data_cache as *const DataValue);

    // Navigate
    let target = match navigate_path(data, &path_vec) {
        Some(v) => v,
        None => {
            (*entry_data) = matchy_entry_data_t::empty();
            return MATCHY_ERROR_LOOKUP_PATH_INVALID;
        }
    };

    // Convert
    let mut string_cache = Vec::new();
    match matchy_entry_data_t::from_data_value(target, &mut string_cache) {
        Some(data) => {
            (*entry_data) = data;
            std::mem::forget(string_cache);
            MATCHY_SUCCESS
        }
        None => {
            (*entry_data) = matchy_entry_data_t::empty();
            MATCHY_ERROR_DATA_PARSE
        }
    }
}

/// Get full entry data as linked list (tree traversal)
///
/// This function traverses the entire data structure and returns it as
/// a flattened linked list. Maps and arrays are expanded recursively.
///
/// # Parameters
/// * `entry` - Entry handle
/// * `entry_data_list` - Output list pointer
///
/// # Returns
/// * MATCHY_SUCCESS on success
/// * Error code on failure
///
/// # Safety
/// * `entry` must be valid
/// * `entry_data_list` must be valid pointer
/// * Caller must free result with matchy_free_entry_data_list
///
/// # Example
/// ```c
/// matchy_entry_data_list_t *list = NULL;
/// if (matchy_get_entry_data_list(&entry, &list) == MATCHY_SUCCESS) {
///     for (matchy_entry_data_list_t *p = list; p != NULL; p = p->next) {
///         // Process p->entry_data
///     }
///     matchy_free_entry_data_list(list);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_get_entry_data_list(
    entry: *const matchy_entry_s,
    entry_data_list: *mut *mut matchy_entry_data_list_t,
) -> i32 {
    if entry.is_null() || entry_data_list.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    // Get result and access cached DataValue (same as aget_value)
    let result_ptr = (*entry).data_ptr as *const matchy_result_t;
    if result_ptr.is_null() {
        return MATCHY_ERROR_NO_DATA;
    }

    let result = &*result_ptr;
    if result._data_cache.is_null() {
        return MATCHY_ERROR_NO_DATA;
    }

    let data = &*(result._data_cache as *const DataValue);

    // Build a flat list by traversing the data structure
    let mut string_cache = Vec::new();
    let mut list_head: *mut matchy_entry_data_list_t = ptr::null_mut();
    let mut list_tail: *mut matchy_entry_data_list_t = ptr::null_mut();

    // Helper to add a node to the list
    let mut add_node = |entry_data: matchy_entry_data_t| {
        let node = Box::new(matchy_entry_data_list_t {
            entry_data,
            next: ptr::null_mut(),
        });
        let node_ptr = Box::into_raw(node);

        if list_head.is_null() {
            list_head = node_ptr;
            list_tail = node_ptr;
        } else {
            (*list_tail).next = node_ptr;
            list_tail = node_ptr;
        }
    };

    // Flatten the data structure recursively
    fn flatten_data(
        value: &DataValue,
        string_cache: &mut Vec<CString>,
        add_node: &mut impl FnMut(matchy_entry_data_t),
    ) {
        // Add the current node
        if let Some(entry_data) =
            unsafe { matchy_entry_data_t::from_data_value(value, string_cache) }
        {
            add_node(entry_data);
        }

        // Recursively add children
        match value {
            DataValue::Map(m) => {
                for (_key, val) in m.iter() {
                    flatten_data(val, string_cache, add_node);
                }
            }
            DataValue::Array(a) => {
                for val in a.iter() {
                    flatten_data(val, string_cache, add_node);
                }
            }
            _ => {}
        }
    }

    flatten_data(data, &mut string_cache, &mut add_node);

    // Leak the string cache so pointers remain valid
    std::mem::forget(string_cache);

    *entry_data_list = list_head;
    MATCHY_SUCCESS
}

/// Free entry data list
///
/// Frees the linked list returned by matchy_get_entry_data_list.
///
/// # Parameters
/// * `list` - List to free (may be NULL)
///
/// # Safety
/// * `list` must be from matchy_get_entry_data_list or NULL
/// * Must not be freed twice
#[no_mangle]
pub unsafe extern "C" fn matchy_free_entry_data_list(list: *mut matchy_entry_data_list_t) {
    if list.is_null() {
        return;
    }

    let mut current = list;
    while !current.is_null() {
        let next = (*current).next;
        let _ = Box::from_raw(current);
        current = next;
    }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Convert query result data to JSON string
///
/// This is a convenience function to convert the structured DataValue
/// to a JSON string for simple use cases.
///
/// # Parameters
/// * `result` - Query result (must not be NULL, must have found=true)
///
/// # Returns
/// * JSON string (caller must free with matchy_free_string)
/// * NULL if result is NULL, not found, or conversion fails
///
/// # Safety
/// * `result` must be a valid pointer to a result from matchy_query
/// * Result must not have been freed
///
/// # Example
/// ```c
/// matchy_result_t result = matchy_query(db, "8.8.8.8");
/// if (result.found) {
///     char *json = matchy_result_to_json(&result);
///     if (json) {
///         printf("Data: %s\n", json);
///         matchy_free_string(json);
///     }
/// }
/// matchy_free_result(&result);
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_result_to_json(result: *const matchy_result_t) -> *mut c_char {
    if result.is_null() || !(*result).found || (*result)._data_cache.is_null() {
        return ptr::null_mut();
    }

    // Get the cached DataValue
    let data = &*((*result)._data_cache as *const DataValue);

    // Convert to JSON
    let json_str = match serde_json::to_string(data) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    // Convert to C string
    match CString::new(json_str) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// VALIDATION API
// ============================================================================

/// Standard validation level - all offsets, UTF-8, basic structure
pub const MATCHY_VALIDATION_STANDARD: i32 = 0;
/// Strict validation level - standard plus deep graph analysis and consistency checks (default)
pub const MATCHY_VALIDATION_STRICT: i32 = 1;

/// Validate a database file
///
/// Validates a .mxy database file to ensure it's safe to use.
/// Returns MATCHY_SUCCESS if the database is valid, or an error code if invalid.
///
/// # Parameters
/// * `filename` - Path to database file (null-terminated C string, must not be NULL)
/// * `level` - Validation level (MATCHY_VALIDATION_STANDARD or _STRICT)
/// * `error_message` - Pointer to receive error message (may be NULL if not needed)
///   If non-NULL and validation fails, receives a string that must be freed with matchy_free_string
///
/// # Returns
/// * MATCHY_SUCCESS (0) if database is valid
/// * Error code < 0 if validation failed or parameters invalid
///
/// # Safety
/// * `filename` must be a valid null-terminated C string
/// * If `error_message` is non-NULL, caller must free the returned string
///
/// # Example
/// ```c
/// char *error = NULL;
/// int result = matchy_validate("/path/to/database.mxy", MATCHY_VALIDATION_STRICT, &error);
/// if (result != MATCHY_SUCCESS) {
///     fprintf(stderr, "Validation failed: %s\n", error ? error : "unknown error");
///     if (error) matchy_free_string(error);
///     return 1;
/// }
/// printf("Database is valid and safe to use!\n");
/// ```
#[no_mangle]
pub unsafe extern "C" fn matchy_validate(
    filename: *const c_char,
    level: i32,
    error_message: *mut *mut c_char,
) -> i32 {
    use crate::validation::{validate_database, ValidationLevel};
    use std::path::Path;

    if filename.is_null() {
        return MATCHY_ERROR_INVALID_PARAM;
    }

    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return MATCHY_ERROR_INVALID_PARAM,
    };

    let validation_level = match level {
        MATCHY_VALIDATION_STANDARD => ValidationLevel::Standard,
        MATCHY_VALIDATION_STRICT => ValidationLevel::Strict,
        _ => return MATCHY_ERROR_INVALID_PARAM,
    };

    match validate_database(Path::new(path_str), validation_level) {
        Ok(report) => {
            if report.is_valid() {
                MATCHY_SUCCESS
            } else {
                // Validation failed - populate error message if requested
                if !error_message.is_null() {
                    let error_text = if report.errors.is_empty() {
                        "Validation failed (no error details)".to_string()
                    } else {
                        report.errors.join("; ")
                    };

                    if let Ok(c_str) = CString::new(error_text) {
                        *error_message = c_str.into_raw();
                    } else {
                        *error_message = ptr::null_mut();
                    }
                }
                MATCHY_ERROR_CORRUPT_DATA
            }
        }
        Err(_) => {
            if !error_message.is_null() {
                if let Ok(c_str) = CString::new("Failed to validate database") {
                    *error_message = c_str.into_raw();
                }
            }
            MATCHY_ERROR_IO
        }
    }
}
