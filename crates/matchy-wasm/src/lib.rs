//! WebAssembly bindings for matchy
//!
//! This crate provides JavaScript/TypeScript bindings for matchy's core functionality:
//! - **Database**: Load and query matchy databases
//! - **DatabaseBuilder**: Create databases with IPs, domains, and patterns
//! - **Extractor**: Extract IPs, domains, emails, and hashes from text
//!
//! # Example (JavaScript)
//!
//! ```javascript
//! import init, { Database, DatabaseBuilder, Extractor } from 'matchy-wasm';
//!
//! await init();
//!
//! // Build a database
//! const builder = new DatabaseBuilder(true); // case-sensitive
//! builder.addEntry("1.2.3.4", { threat: "high" });
//! builder.addEntry("*.evil.com", { category: "malware" });
//! const dbBytes = builder.build();
//!
//! // Query the database
//! const db = new Database(dbBytes);
//! const result = db.lookup("malware.evil.com");
//! console.log(result); // { category: "malware" }
//!
//! // Extract entities from text
//! const extractor = new Extractor();
//! const entities = extractor.extract("Contact admin@example.com or visit evil.com");
//! console.log(entities);
//! // [{ type: "Email", value: "admin@example.com", start: 8, end: 25 },
//! //  { type: "Domain", value: "evil.com", start: 35, end: 43 }]
//! ```

use matchy::extractor::{ExtractedItem, Extractor as MatchyExtractor, HashType};
use matchy::{
    DataValue, Database as MatchyDatabase, DatabaseBuilder as MatchyDatabaseBuilder, MatchMode,
    QueryResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

/// Initialize the WASM module with better panic messages
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Get the matchy library version
#[wasm_bindgen]
pub fn version() -> String {
    matchy::MATCHY_VERSION.to_string()
}

// ============================================================================
// Database
// ============================================================================

/// A matchy database loaded from bytes
///
/// Use this to query IP addresses, domains, and patterns against a pre-built database.
#[wasm_bindgen]
pub struct Database {
    inner: MatchyDatabase,
}

#[wasm_bindgen]
impl Database {
    /// Create a new Database from raw bytes (Uint8Array)
    ///
    /// @param bytes - Database file contents as Uint8Array
    /// @throws Error if the database format is invalid
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Database, JsError> {
        let inner = MatchyDatabase::from_bytes(bytes.to_vec())
            .map_err(|e| JsError::new(&format!("Invalid database: {}", e)))?;
        Ok(Database { inner })
    }

    /// Look up a key in the database
    ///
    /// Automatically detects whether the key is an IP address or pattern and
    /// performs the appropriate lookup.
    ///
    /// @param key - IP address (e.g., "1.2.3.4") or string to match patterns
    /// @returns The associated data as a JavaScript object, or null if not found
    #[wasm_bindgen]
    pub fn lookup(&self, key: &str) -> Result<JsValue, JsError> {
        let result = self
            .inner
            .lookup(key)
            .map_err(|e| JsError::new(&format!("Lookup error: {}", e)))?;

        match result {
            Some(QueryResult::Ip { data, prefix_len }) => {
                let js_data = query_result_to_js(&data, Some(prefix_len))?;
                Ok(js_data)
            }
            Some(QueryResult::Pattern { data, .. }) => {
                // Return first pattern's data if available
                if let Some(Some(d)) = data.first() {
                    let js_data = data_value_to_js_value(d)?;
                    Ok(js_data)
                } else {
                    Ok(JsValue::NULL)
                }
            }
            Some(QueryResult::NotFound) | None => Ok(JsValue::NULL),
        }
    }

    /// Look up an IP address specifically
    ///
    /// Use this when you know the input is an IP address for slightly better performance.
    ///
    /// @param ip - IPv4 or IPv6 address string
    /// @returns The associated data as a JavaScript object, or null if not found
    #[wasm_bindgen(js_name = lookupIp)]
    pub fn lookup_ip(&self, ip: &str) -> Result<JsValue, JsError> {
        let ip_addr: std::net::IpAddr = ip
            .parse()
            .map_err(|e| JsError::new(&format!("Invalid IP address: {}", e)))?;

        let result = self
            .inner
            .lookup_ip(ip_addr)
            .map_err(|e| JsError::new(&format!("Lookup error: {}", e)))?;

        match result {
            Some(QueryResult::Ip { data, prefix_len }) => {
                let js_data = query_result_to_js(&data, Some(prefix_len))?;
                Ok(js_data)
            }
            Some(QueryResult::NotFound) | None => Ok(JsValue::NULL),
            _ => Ok(JsValue::NULL), // Shouldn't happen for IP lookup
        }
    }

    /// Look up a string against patterns only
    ///
    /// Skips IP address parsing and only checks against glob patterns.
    ///
    /// @param text - String to match against patterns
    /// @returns The associated data as a JavaScript object, or null if not found
    #[wasm_bindgen(js_name = lookupPattern)]
    pub fn lookup_pattern(&self, text: &str) -> Result<JsValue, JsError> {
        let result = self
            .inner
            .lookup_string(text)
            .map_err(|e| JsError::new(&format!("Lookup error: {}", e)))?;

        match result {
            Some(QueryResult::Pattern { data, .. }) => {
                if let Some(Some(d)) = data.first() {
                    let js_data = data_value_to_js_value(d)?;
                    Ok(js_data)
                } else {
                    Ok(JsValue::NULL)
                }
            }
            Some(QueryResult::NotFound) | None => Ok(JsValue::NULL),
            _ => Ok(JsValue::NULL), // Shouldn't happen for pattern lookup
        }
    }

    /// Get database query statistics
    ///
    /// @returns Object with query statistics (total_queries, cache_hits, etc.)
    #[wasm_bindgen]
    pub fn stats(&self) -> Result<JsValue, JsError> {
        let stats = self.inner.stats();
        let obj = StatsResult {
            total_queries: stats.total_queries,
            queries_with_match: stats.queries_with_match,
            queries_without_match: stats.queries_without_match,
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
        };
        serde_wasm_bindgen::to_value(&obj).map_err(|e| JsError::new(&e.to_string()))
    }
}

#[derive(Serialize)]
struct StatsResult {
    total_queries: u64,
    queries_with_match: u64,
    queries_without_match: u64,
    cache_hits: u64,
    cache_misses: u64,
}

// ============================================================================
// DatabaseBuilder
// ============================================================================

/// Builder for creating matchy databases
///
/// Use this to create new databases that can be saved and loaded later.
#[wasm_bindgen]
pub struct DatabaseBuilder {
    inner: MatchyDatabaseBuilder,
}

#[wasm_bindgen]
impl DatabaseBuilder {
    /// Create a new DatabaseBuilder
    ///
    /// @param case_sensitive - Whether pattern matching should be case-sensitive
    #[wasm_bindgen(constructor)]
    pub fn new(case_sensitive: bool) -> DatabaseBuilder {
        let mode = if case_sensitive {
            MatchMode::CaseSensitive
        } else {
            MatchMode::CaseInsensitive
        };
        DatabaseBuilder {
            inner: MatchyDatabaseBuilder::new(mode),
        }
    }

    /// Add an entry (auto-detects IP vs pattern)
    ///
    /// The key is automatically classified:
    /// - IP addresses (1.2.3.4, 192.168.0.0/16, ::1) go to IP tree
    /// - Patterns with wildcards (*.example.com) go to pattern matcher
    /// - Plain strings go to literal hash table
    ///
    /// @param key - IP address, CIDR, pattern, or literal string
    /// @param data - Associated data as a JavaScript object
    #[wasm_bindgen(js_name = addEntry)]
    pub fn add_entry(&mut self, key: &str, data: JsValue) -> Result<(), JsError> {
        let data_map = js_to_data_map(data)?;
        self.inner
            .add_entry(key, data_map)
            .map_err(|e| JsError::new(&format!("Failed to add entry: {}", e)))
    }

    /// Add an IP address or CIDR explicitly
    ///
    /// @param ip - IPv4/IPv6 address or CIDR (e.g., "1.2.3.4", "192.168.0.0/16")
    /// @param data - Associated data as a JavaScript object
    #[wasm_bindgen(js_name = addIp)]
    pub fn add_ip(&mut self, ip: &str, data: JsValue) -> Result<(), JsError> {
        let data_map = js_to_data_map(data)?;
        self.inner
            .add_ip(ip, data_map)
            .map_err(|e| JsError::new(&format!("Failed to add IP: {}", e)))
    }

    /// Add a glob pattern explicitly
    ///
    /// @param pattern - Glob pattern (e.g., "*.evil.com", "malware-*")
    /// @param data - Associated data as a JavaScript object
    #[wasm_bindgen(js_name = addPattern)]
    pub fn add_pattern(&mut self, pattern: &str, data: JsValue) -> Result<(), JsError> {
        let data_map = js_to_data_map(data)?;
        self.inner
            .add_glob(pattern, data_map)
            .map_err(|e| JsError::new(&format!("Failed to add pattern: {}", e)))
    }

    /// Add a literal string explicitly
    ///
    /// @param literal - Exact string to match
    /// @param data - Associated data as a JavaScript object
    #[wasm_bindgen(js_name = addLiteral)]
    pub fn add_literal(&mut self, literal: &str, data: JsValue) -> Result<(), JsError> {
        let data_map = js_to_data_map(data)?;
        self.inner
            .add_literal(literal, data_map)
            .map_err(|e| JsError::new(&format!("Failed to add literal: {}", e)))
    }

    /// Build the database and return as bytes
    ///
    /// @returns Uint8Array containing the database that can be saved or loaded
    #[wasm_bindgen]
    pub fn build(self) -> Result<Vec<u8>, JsError> {
        self.inner
            .build()
            .map_err(|e| JsError::new(&format!("Failed to build database: {}", e)))
    }
}

// ============================================================================
// Extractor
// ============================================================================

/// Extract structured entities from text
///
/// Finds IP addresses, domains, emails, and cryptographic hashes in text.
#[wasm_bindgen]
pub struct Extractor {
    inner: MatchyExtractor,
}

/// Extracted entity from text
#[derive(Serialize)]
struct ExtractedEntity {
    /// Entity type: "IPv4", "IPv6", "Domain", "Email", "MD5", "SHA1", "SHA256", etc.
    #[serde(rename = "type")]
    entity_type: String,
    /// The extracted value
    value: String,
    /// Start byte offset in the input text
    start: usize,
    /// End byte offset in the input text (exclusive)
    end: usize,
}

#[wasm_bindgen]
impl Extractor {
    /// Create a new Extractor
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Extractor, JsError> {
        let inner = MatchyExtractor::new()
            .map_err(|e| JsError::new(&format!("Failed to create: {}", e)))?;
        Ok(Extractor { inner })
    }

    /// Extract all entities from text
    ///
    /// @param text - Input text to search
    /// @returns Array of extracted entities with type, value, start, and end
    #[wasm_bindgen]
    pub fn extract(&self, text: &str) -> Result<JsValue, JsError> {
        let matches = self.inner.extract_from_chunk(text.as_bytes());
        let entities: Vec<ExtractedEntity> = matches
            .iter()
            .map(|m| {
                let entity_type = match &m.item {
                    ExtractedItem::Ipv4(_) => "IPv4",
                    ExtractedItem::Ipv6(_) => "IPv6",
                    ExtractedItem::Domain(_) => "Domain",
                    ExtractedItem::Email(_) => "Email",
                    ExtractedItem::Hash(hash_type, _) => match hash_type {
                        HashType::Md5 => "MD5",
                        HashType::Sha1 => "SHA1",
                        HashType::Sha256 => "SHA256",
                        HashType::Sha384 => "SHA384",
                        HashType::Sha512 => "SHA512",
                    },
                    ExtractedItem::Bitcoin(_) => "Bitcoin",
                    ExtractedItem::Ethereum(_) => "Ethereum",
                    ExtractedItem::Monero(_) => "Monero",
                };
                ExtractedEntity {
                    entity_type: entity_type.to_string(),
                    value: m.as_str(text.as_bytes()).to_string(),
                    start: m.span.0,
                    end: m.span.1,
                }
            })
            .collect();

        serde_wasm_bindgen::to_value(&entities).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Extract only IP addresses from text
    ///
    /// @param text - Input text to search
    /// @returns Array of extracted IP addresses
    #[wasm_bindgen(js_name = extractIps)]
    pub fn extract_ips(&self, text: &str) -> Result<JsValue, JsError> {
        let matches = self.inner.extract_from_chunk(text.as_bytes());
        let ips: Vec<ExtractedEntity> = matches
            .iter()
            .filter(|m| matches!(m.item, ExtractedItem::Ipv4(_) | ExtractedItem::Ipv6(_)))
            .map(|m| {
                let entity_type = match &m.item {
                    ExtractedItem::Ipv4(_) => "IPv4",
                    ExtractedItem::Ipv6(_) => "IPv6",
                    _ => unreachable!(),
                };
                ExtractedEntity {
                    entity_type: entity_type.to_string(),
                    value: m.as_str(text.as_bytes()).to_string(),
                    start: m.span.0,
                    end: m.span.1,
                }
            })
            .collect();

        serde_wasm_bindgen::to_value(&ips).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Extract only domains from text
    ///
    /// @param text - Input text to search
    /// @returns Array of extracted domains
    #[wasm_bindgen(js_name = extractDomains)]
    pub fn extract_domains(&self, text: &str) -> Result<JsValue, JsError> {
        let matches = self.inner.extract_from_chunk(text.as_bytes());
        let domains: Vec<ExtractedEntity> = matches
            .iter()
            .filter(|m| matches!(m.item, ExtractedItem::Domain(_)))
            .map(|m| ExtractedEntity {
                entity_type: "Domain".to_string(),
                value: m.as_str(text.as_bytes()).to_string(),
                start: m.span.0,
                end: m.span.1,
            })
            .collect();

        serde_wasm_bindgen::to_value(&domains).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Extract only emails from text
    ///
    /// @param text - Input text to search
    /// @returns Array of extracted email addresses
    #[wasm_bindgen(js_name = extractEmails)]
    pub fn extract_emails(&self, text: &str) -> Result<JsValue, JsError> {
        let matches = self.inner.extract_from_chunk(text.as_bytes());
        let emails: Vec<ExtractedEntity> = matches
            .iter()
            .filter(|m| matches!(m.item, ExtractedItem::Email(_)))
            .map(|m| ExtractedEntity {
                entity_type: "Email".to_string(),
                value: m.as_str(text.as_bytes()).to_string(),
                start: m.span.0,
                end: m.span.1,
            })
            .collect();

        serde_wasm_bindgen::to_value(&emails).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Extract only hashes from text
    ///
    /// @param text - Input text to search
    /// @returns Array of extracted hashes (MD5, SHA1, SHA256, etc.)
    #[wasm_bindgen(js_name = extractHashes)]
    pub fn extract_hashes(&self, text: &str) -> Result<JsValue, JsError> {
        let matches = self.inner.extract_from_chunk(text.as_bytes());
        let hashes: Vec<ExtractedEntity> = matches
            .iter()
            .filter(|m| matches!(m.item, ExtractedItem::Hash(_, _)))
            .map(|m| {
                let entity_type = match &m.item {
                    ExtractedItem::Hash(hash_type, _) => match hash_type {
                        HashType::Md5 => "MD5",
                        HashType::Sha1 => "SHA1",
                        HashType::Sha256 => "SHA256",
                        HashType::Sha384 => "SHA384",
                        HashType::Sha512 => "SHA512",
                    },
                    _ => unreachable!(),
                };
                ExtractedEntity {
                    entity_type: entity_type.to_string(),
                    value: m.as_str(text.as_bytes()).to_string(),
                    start: m.span.0,
                    end: m.span.1,
                }
            })
            .collect();

        serde_wasm_bindgen::to_value(&hashes).map_err(|e| JsError::new(&e.to_string()))
    }
}

impl Default for Extractor {
    fn default() -> Self {
        Self::new().expect("Failed to create default Extractor")
    }
}

// ============================================================================
// Helper functions for JS <-> Rust data conversion
// ============================================================================

/// Convert a single DataValue to a JsValue
fn data_value_to_js_value(value: &DataValue) -> Result<JsValue, JsError> {
    let json = data_value_to_json(value);
    serde_wasm_bindgen::to_value(&json).map_err(|e| JsError::new(&e.to_string()))
}

/// Convert an IP query result with prefix_len to a JavaScript object
fn query_result_to_js(data: &DataValue, prefix_len: Option<u8>) -> Result<JsValue, JsError> {
    // If the data is a Map, include prefix_len as "_prefix_len" field
    match data {
        DataValue::Map(map) => {
            let mut json_map: HashMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), data_value_to_json(v)))
                .collect();
            if let Some(prefix) = prefix_len {
                json_map.insert("_prefix_len".to_string(), serde_json::json!(prefix));
            }
            serde_wasm_bindgen::to_value(&json_map).map_err(|e| JsError::new(&e.to_string()))
        }
        _ => data_value_to_js_value(data),
    }
}

/// Convert DataValue to serde_json::Value
fn data_value_to_json(value: &DataValue) -> serde_json::Value {
    match value {
        DataValue::String(s) => serde_json::Value::String(s.clone()),
        DataValue::Int32(i) => serde_json::Value::Number((*i).into()),
        DataValue::Uint16(u) => serde_json::Value::Number((*u).into()),
        DataValue::Uint32(u) => serde_json::Value::Number((*u).into()),
        DataValue::Uint64(u) => serde_json::json!(*u), // May exceed JSON number precision
        DataValue::Uint128(u) => serde_json::Value::String(u.to_string()), // Too large for JSON number
        DataValue::Double(d) => serde_json::json!(*d),
        DataValue::Float(f) => serde_json::json!(*f),
        DataValue::Bool(b) => serde_json::Value::Bool(*b),
        DataValue::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(data_value_to_json).collect())
        }
        DataValue::Map(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), data_value_to_json(v)))
                .collect();
            serde_json::Value::Object(obj)
        }
        DataValue::Bytes(b) => {
            // Encode bytes as base64
            use base64::{engine::general_purpose::STANDARD, Engine};
            serde_json::Value::String(STANDARD.encode(b))
        }
        DataValue::Pointer(_) => serde_json::Value::Null, // Internal type, shouldn't appear in user data
    }
}

/// Input data for adding entries (from JavaScript)
#[derive(Deserialize)]
#[serde(untagged)]
enum JsDataValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Array(Vec<JsDataValue>),
    Object(HashMap<String, JsDataValue>),
    Null,
}

/// Convert a JavaScript object to a Rust DataValue map
fn js_to_data_map(js_value: JsValue) -> Result<HashMap<String, DataValue>, JsError> {
    if js_value.is_null() || js_value.is_undefined() {
        return Ok(HashMap::new());
    }

    let json: HashMap<String, JsDataValue> =
        serde_wasm_bindgen::from_value(js_value).map_err(|e| JsError::new(&e.to_string()))?;

    let mut result = HashMap::new();
    for (key, value) in json {
        result.insert(key, js_data_value_to_data_value(value));
    }
    Ok(result)
}

/// Convert JsDataValue to DataValue
fn js_data_value_to_data_value(value: JsDataValue) -> DataValue {
    match value {
        JsDataValue::String(s) => DataValue::String(s),
        JsDataValue::Int(i) => {
            // Choose appropriate integer type based on value
            if i >= 0 {
                if i <= u32::MAX as i64 {
                    DataValue::Uint32(i as u32)
                } else {
                    DataValue::Uint64(i as u64)
                }
            } else if i >= i32::MIN as i64 {
                DataValue::Int32(i as i32)
            } else {
                DataValue::Double(i as f64)
            }
        }
        JsDataValue::Float(f) => DataValue::Double(f),
        JsDataValue::Bool(b) => DataValue::Bool(b),
        JsDataValue::Array(arr) => {
            DataValue::Array(arr.into_iter().map(js_data_value_to_data_value).collect())
        }
        JsDataValue::Object(obj) => {
            let map: HashMap<String, DataValue> = obj
                .into_iter()
                .map(|(k, v)| (k, js_data_value_to_data_value(v)))
                .collect();
            DataValue::Map(map)
        }
        JsDataValue::Null => DataValue::String(String::new()), // No null in DataValue, use empty string
    }
}

// ============================================================================
// Tests (run with: wasm-pack test --node)
// ============================================================================

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_database_builder_and_query() {
        use super::*;

        let mut builder = DatabaseBuilder::new(true);

        // Add IP entry
        let ip_data = serde_wasm_bindgen::to_value(&serde_json::json!({
            "threat": "high"
        }))
        .unwrap();
        builder.add_ip("1.2.3.4", ip_data).unwrap();

        // Build and load
        let bytes = builder.build().unwrap();
        let db = Database::new(&bytes).unwrap();

        // Query
        let result = db.lookup("1.2.3.4").unwrap();
        assert!(!result.is_null());
    }

    #[wasm_bindgen_test]
    fn test_extractor() {
        use super::*;

        let extractor = Extractor::new().unwrap();
        let result = extractor.extract("Check 1.2.3.4 and evil.com").unwrap();
        // Result should be a JS array, we just verify it doesn't error
        assert!(!result.is_null());
    }
}
