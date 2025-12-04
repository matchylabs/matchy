//! C API for Matchy
//!
//! Provides stable C FFI bindings for building and querying databases from C/C++
//! and other languages. The API uses opaque handles and integer error codes for
//! maximum compatibility across language boundaries.
//!
//! # API Modules
//!
//! - [`matchy`] - Core database building and querying API  
//! - [`maxminddb_compat`] - MaxMind DB compatibility layer (drop-in replacement for libmaxminddb)
//!
//! # Safety Guarantees
//!
//! All C functions follow these safety rules:
//! - Null pointer checks on all inputs
//! - Panic catching at FFI boundaries  
//! - Opaque handles for resource management
//! - Integer error codes (no exceptions)
//! - Memory ownership clearly documented
//!
//! # Basic Usage Pattern
//!
//! **Note**: Databases are **immutable** once built. To update, rebuild entirely.
//!
//! ```c
//! #include <matchy/matchy.h>
//!
//! // ============ BUILD PHASE (create new database) ============
//!
//! // 1. Create a builder
//! matchy_builder_t *builder = matchy_builder_new();
//! if (builder == NULL) { /* handle error */ }
//!
//! // 2. Add entries with JSON data
//! matchy_builder_add(builder, "1.2.3.4",
//!     "{\"threat_level\": \"high\", \"score\": 95}");
//! matchy_builder_add(builder, "10.0.0.0/8",
//!     "{\"type\": \"internal\"}");
//! matchy_builder_add(builder, "*.evil.com",
//!     "{\"category\": \"malware\"}");
//!
//! // 3. Set optional metadata
//! matchy_builder_set_description(builder, "Threat intelligence database");
//!
//! // 4. Save to file
//! int err = matchy_builder_save(builder, "threats.mxy");
//! if (err != MATCHY_SUCCESS) { /* handle error */ }
//!
//! // 5. Cleanup builder
//! matchy_builder_free(builder);
//!
//! // ============ QUERY PHASE (read-only access) ============
//!
//! // 6. Open database (memory-mapped for fast loading)
//! matchy_t *db = matchy_open("threats.mxy");
//! if (db == NULL) { /* handle error */ }
//!
//! // 7. Query database
//! // Option A: Return by value (standard C)
//! matchy_result_t result = matchy_query(db, "1.2.3.4");
//! // Option B: Write into pointer (FFI-friendly for Java JNA, etc.)
//! // matchy_result_t result;
//! // matchy_query_into(db, "1.2.3.4", &result);
//! if (result.found) {
//!     // Option A: Get data as JSON string
//!     char *json = matchy_result_to_json(&result);
//!     printf("Found: %s\n", json);
//!     matchy_free_string(json);
//!     
//!     // Option B: Access structured data (MMDB-compatible API)
//!     matchy_entry_s entry;
//!     matchy_result_get_entry(&result, &entry);
//!     
//!     matchy_entry_data_t data;
//!     const char *path[] = {"threat_level", NULL};
//!     if (matchy_aget_value(&entry, &data, path) == MATCHY_SUCCESS) {
//!         if (data.type_ == MATCHY_DATA_TYPE_UTF8_STRING) {
//!             printf("Threat level: %s\n", data.value.utf8_string);
//!         }
//!     }
//! }
//! matchy_free_result(&result);
//!
//! // 8. Close database
//! matchy_close(db);
//! ```
//!
//! # Extractor API
//!
//! High-performance pattern extraction from text:
//!
//! ```c
//! // Create extractor (bitmask of what to extract)
//! matchy_extractor_t *ext = matchy_extractor_create(
//!     MATCHY_EXTRACT_DOMAINS | MATCHY_EXTRACT_IPV4
//! );
//!
//! // Extract from data
//! matchy_matches_t matches;
//! matchy_extractor_extract_chunk(ext, data, len, &matches);
//!
//! // Process results
//! for (size_t i = 0; i < matches.count; i++) {
//!     printf("%s: %s\n",
//!            matchy_item_type_name(matches.items[i].item_type),
//!            matches.items[i].value);
//! }
//!
//! // Cleanup
//! matchy_matches_free(&matches);
//! matchy_extractor_free(ext);
//! ```
//!
//! # Memory Management
//!
//! - **Builder**: Call `matchy_builder_free()` when done building
//! - **Database**: Call `matchy_close()` to unmap file and release resources
//! - **Results**: Call `matchy_free_result()` after processing query results
//! - **Strings**: Call `matchy_free_string()` for strings returned by matchy functions
//! - **Data lists**: Call `matchy_free_entry_data_list()` for full data traversals
//! - **Extractor**: Call `matchy_extractor_free()` when done extracting
//! - **Matches**: Call `matchy_matches_free()` after processing extraction results
//!
//! # Thread Safety
//!
//! - **Database handles**: Safe for concurrent reads from multiple threads
//! - **Extractor handles**: Safe for concurrent extraction from multiple threads
//! - **Builders**: NOT thread-safe, use one builder per thread
//! - **Results/Matches**: Thread-local, don't share between threads
//!
//! # Database Update Strategy
//!
//! Databases are **immutable** once built. To update:
//!
//! 1. Create new builder
//! 2. Add all entries (old + new + modified)
//! 3. Build new database
//! 4. Atomically replace old file (e.g., rename)
//! 5. Reopen database handles
//!
//! This ensures readers always see consistent state.
//!
//! # Error Handling
//!
//! All functions return error codes. Common values:
//! - `MATCHY_SUCCESS` (0) - Success
//! - `MATCHY_ERROR_INVALID_PARAM` - Null pointer or invalid argument  
//! - `MATCHY_ERROR_FILE_NOT_FOUND` - Database file doesn't exist
//! - `MATCHY_ERROR_INVALID_FORMAT` - Corrupted or invalid database
//! - `MATCHY_ERROR_IO` - File I/O error during save
//! - `MATCHY_ERROR_OUT_OF_MEMORY` - Memory allocation failed

pub mod matchy;
pub mod maxminddb_compat;
