//! Data section encoding and decoding for Paraglob v2
//!
//! Provides full MMDB-compatible data encoding for storing pattern-associated data.
//! Implements the complete MaxMind DB data type specification.
//!
//! # Supported Types
//!
//! Complete MMDB type support:
//! - **Pointer**: Reference to another data item (with base handling)
//! - **String**: UTF-8 text data
//! - **Double**: 64-bit floating point (IEEE 754)
//! - **Bytes**: Raw byte arrays
//! - **Uint16**: Unsigned 16-bit integers
//! - **Uint32**: Unsigned 32-bit integers
//! - **Map**: Key-value pairs (string keys)
//! - **Int32**: Signed 32-bit integers
//! - **Uint64**: Unsigned 64-bit integers
//! - **Uint128**: Unsigned 128-bit integers
//! - **Array**: Ordered lists of values
//! - **Bool**: Boolean values
//! - **Float**: 32-bit floating point (IEEE 754)
//!
//! # Format
//!
//! Uses MMDB encoding: control byte(s) followed by data.
//! Control byte encodes type (3 bits) and size/payload (5 bits).
//!
//! See: <https://maxmind.github.io/MaxMind-DB/>

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

mod validation;
pub use validation::{
    validate_data_section, validate_data_value_pointers, validate_data_value_utf8,
    validate_value_strings_utf8, DataFormatStats, DataFormatValidationResult,
    PointerValidationError, PointerValidationResult, PointerValidationStats,
    MAX_POINTER_DEPTH, MAX_TOTAL_DEPTH,
};

/// Data value that can be stored in the data section
///
/// This enum represents all MMDB data types and can be used
/// for both standalone .pgb files and MMDB-embedded data.
///
/// Note: `Pointer` is excluded from JSON serialization/deserialization as it's
/// an internal MMDB format detail (data section offset), not a user-facing type.
#[derive(Debug, Clone, PartialEq)]
pub enum DataValue {
    /// Pointer to another data item (offset) - internal use only, not for JSON
    #[allow(dead_code)]
    Pointer(u32),
    /// UTF-8 string
    String(String),
    /// IEEE 754 double precision float
    Double(f64),
    /// Raw byte array
    Bytes(Vec<u8>),
    /// Unsigned 16-bit integer
    Uint16(u16),
    /// Unsigned 32-bit integer
    Uint32(u32),
    /// Key-value map (string keys only per MMDB spec)
    Map(HashMap<String, DataValue>),
    /// Signed 32-bit integer
    Int32(i32),
    /// Unsigned 64-bit integer
    Uint64(u64),
    /// Unsigned 128-bit integer
    Uint128(u128),
    /// Array of values
    Array(Vec<DataValue>),
    /// Boolean value
    Bool(bool),
    /// IEEE 754 single precision float
    Float(f32),
}

// Custom serialization that excludes Pointer (internal format detail)
impl serde::Serialize for DataValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            DataValue::Pointer(_) => Err(serde::ser::Error::custom(
                "Pointer is an internal type and cannot be serialized to JSON",
            )),
            DataValue::String(s) => serializer.serialize_str(s),
            DataValue::Double(d) => serializer.serialize_f64(*d),
            DataValue::Bytes(b) => serializer.serialize_bytes(b),
            DataValue::Uint16(n) => serializer.serialize_u16(*n),
            DataValue::Uint32(n) => serializer.serialize_u32(*n),
            DataValue::Map(m) => m.serialize(serializer),
            DataValue::Int32(n) => serializer.serialize_i32(*n),
            DataValue::Uint64(n) => serializer.serialize_u64(*n),
            DataValue::Uint128(n) => serializer.serialize_u128(*n),
            DataValue::Array(a) => a.serialize(serializer),
            DataValue::Bool(b) => serializer.serialize_bool(*b),
            DataValue::Float(f) => serializer.serialize_f32(*f),
        }
    }
}

// Custom deserialization that properly handles JSON numbers
impl<'de> serde::Deserialize<'de> for DataValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DataValueVisitor;

        impl<'de> serde::de::Visitor<'de> for DataValueVisitor {
            type Value = DataValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a valid MMDB data value")
            }

            fn visit_bool<E>(self, v: bool) -> Result<DataValue, E> {
                Ok(DataValue::Bool(v))
            }

            fn visit_i32<E>(self, v: i32) -> Result<DataValue, E> {
                Ok(DataValue::Int32(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<DataValue, E> {
                // Choose appropriate integer type based on value
                if v >= 0 {
                    if v <= u16::MAX as i64 {
                        Ok(DataValue::Uint16(v as u16))
                    } else if v <= u32::MAX as i64 {
                        Ok(DataValue::Uint32(v as u32))
                    } else {
                        Ok(DataValue::Uint64(v as u64))
                    }
                } else if v >= i32::MIN as i64 {
                    Ok(DataValue::Int32(v as i32))
                } else {
                    // For very large negative numbers, store as Double
                    Ok(DataValue::Double(v as f64))
                }
            }

            fn visit_u64<E>(self, v: u64) -> Result<DataValue, E> {
                // Choose appropriate unsigned integer type
                if v <= u16::MAX as u64 {
                    Ok(DataValue::Uint16(v as u16))
                } else if v <= u32::MAX as u64 {
                    Ok(DataValue::Uint32(v as u32))
                } else {
                    Ok(DataValue::Uint64(v))
                }
            }

            fn visit_f32<E>(self, v: f32) -> Result<DataValue, E> {
                Ok(DataValue::Float(v))
            }

            fn visit_f64<E>(self, v: f64) -> Result<DataValue, E> {
                Ok(DataValue::Double(v))
            }

            fn visit_str<E>(self, v: &str) -> Result<DataValue, E> {
                Ok(DataValue::String(v.to_string()))
            }

            fn visit_string<E>(self, v: String) -> Result<DataValue, E> {
                Ok(DataValue::String(v))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<DataValue, E> {
                Ok(DataValue::Bytes(v.to_vec()))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<DataValue, E> {
                Ok(DataValue::Bytes(v))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<DataValue, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut array = Vec::new();
                while let Some(value) = seq.next_element()? {
                    array.push(value);
                }
                Ok(DataValue::Array(array))
            }

            fn visit_map<A>(self, mut map: A) -> Result<DataValue, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut hash_map = HashMap::new();
                while let Some((key, value)) = map.next_entry()? {
                    hash_map.insert(key, value);
                }
                Ok(DataValue::Map(hash_map))
            }
        }

        deserializer.deserialize_any(DataValueVisitor)
    }
}

// Implement Hash for DataValue to enable fast deduplication
impl Hash for DataValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the discriminant first
        std::mem::discriminant(self).hash(state);

        match self {
            DataValue::Pointer(v) => v.hash(state),
            DataValue::String(v) => v.hash(state),
            DataValue::Double(v) => {
                // For floats, hash the bit representation to handle NaN consistently
                v.to_bits().hash(state);
            }
            DataValue::Bytes(v) => v.hash(state),
            DataValue::Uint16(v) => v.hash(state),
            DataValue::Uint32(v) => v.hash(state),
            DataValue::Map(m) => {
                // Hash maps require sorted keys for deterministic hashing
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort_unstable();
                keys.len().hash(state);
                for key in keys {
                    key.hash(state);
                    m[key].hash(state);
                }
            }
            DataValue::Int32(v) => v.hash(state),
            DataValue::Uint64(v) => v.hash(state),
            DataValue::Uint128(v) => v.hash(state),
            DataValue::Array(v) => {
                v.len().hash(state);
                for item in v {
                    item.hash(state);
                }
            }
            DataValue::Bool(v) => v.hash(state),
            DataValue::Float(v) => {
                // For floats, hash the bit representation to handle NaN consistently
                v.to_bits().hash(state);
            }
        }
    }
}

/// Data section encoder
///
/// Builds a data section by encoding values and tracking offsets.
/// Supports deduplication - identical values get the same offset.
/// Also supports string interning - duplicate strings are replaced with pointers.
pub struct DataEncoder {
    /// Encoded data buffer
    buffer: Vec<u8>,
    /// Map from serialized value to offset (for deduplication)
    dedup_map: HashMap<Vec<u8>, u32>,
    /// Map from string content to its first occurrence offset (for string interning)
    string_cache: HashMap<String, u32>,
    /// Enable string interning (default: true)
    intern_strings: bool,
}

impl DataEncoder {
    /// Create a new encoder with string interning enabled
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            dedup_map: HashMap::new(),
            string_cache: HashMap::new(),
            intern_strings: true,
        }
    }

    /// Create a new encoder without string interning (legacy behavior)
    pub fn new_without_interning() -> Self {
        Self {
            buffer: Vec::new(),
            dedup_map: HashMap::new(),
            string_cache: HashMap::new(),
            intern_strings: false,
        }
    }

    /// Encode a value and return its offset
    ///
    /// If the value was previously encoded, returns the existing offset.
    /// This enables automatic deduplication at the value level.
    /// String interning happens during encoding for sub-strings within maps/arrays.
    pub fn encode(&mut self, value: &DataValue) -> u32 {
        // For whole-value deduplication, we still use the temp buffer approach
        // But we need to be careful about string interning during serialization

        // Temporarily disable interning for the dedup check
        let saved_intern = self.intern_strings;
        self.intern_strings = false;

        let mut temp = Vec::new();
        Self::encode_to_buffer(value, &mut temp);

        // Restore interning setting
        self.intern_strings = saved_intern;

        // Check deduplication map
        if let Some(&offset) = self.dedup_map.get(&temp) {
            return offset;
        }

        // New value - encode with interning
        let offset = self.buffer.len() as u32;
        self.encode_value_interned(value);
        self.dedup_map.insert(temp, offset);
        offset
    }

    /// Get the final encoded data section
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Get current buffer size
    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    /// Encode a value with string interning
    ///
    /// This is the main entry point that handles interning.
    fn encode_value_interned(&mut self, value: &DataValue) {
        match value {
            DataValue::String(s) if self.intern_strings => {
                // Check if we've seen this string before
                if let Some(&existing_offset) = self.string_cache.get(s) {
                    // Use a pointer to the existing string
                    Self::encode_pointer(existing_offset, &mut self.buffer);
                } else {
                    // First occurrence - encode the string and cache its offset
                    let offset = self.buffer.len() as u32;
                    Self::encode_string(s, &mut self.buffer);
                    self.string_cache.insert(s.clone(), offset);
                }
            }
            DataValue::Map(m) => self.encode_map_interned(m),
            DataValue::Array(a) => self.encode_array_interned(a),
            // All other types use the static encoding
            _ => Self::encode_to_buffer(value, &mut self.buffer),
        }
    }

    /// Encode a value to a buffer (static version, no interning)
    fn encode_to_buffer(value: &DataValue, buffer: &mut Vec<u8>) {
        match value {
            DataValue::Pointer(offset) => Self::encode_pointer(*offset, buffer),
            DataValue::String(s) => Self::encode_string(s, buffer),
            DataValue::Double(d) => Self::encode_double(*d, buffer),
            DataValue::Bytes(b) => Self::encode_bytes(b, buffer),
            DataValue::Uint16(n) => Self::encode_uint16(*n, buffer),
            DataValue::Uint32(n) => Self::encode_uint32(*n, buffer),
            DataValue::Map(m) => Self::encode_map(m, buffer),
            DataValue::Int32(n) => Self::encode_int32(*n, buffer),
            DataValue::Uint64(n) => Self::encode_uint64(*n, buffer),
            DataValue::Uint128(n) => Self::encode_uint128(*n, buffer),
            DataValue::Array(a) => Self::encode_array(a, buffer),
            DataValue::Bool(b) => Self::encode_bool(*b, buffer),
            DataValue::Float(f) => Self::encode_float(*f, buffer),
        }
    }

    // Type 1: Pointer
    fn encode_pointer(offset: u32, buffer: &mut Vec<u8>) {
        let size = if offset < 2048 {
            0 // 11 bits (0-2047)
        } else if offset < 2048 + 524288 {
            1 // 19 bits (2048-526335)
        } else if offset < 2048 + 524288 + 134217728 {
            2 // 27 bits (526336-134744063)
        } else {
            3 // 32 bits
        };

        match size {
            0 => {
                // 11 bits: 3 bits in control byte (high bits) + 8 bits in next byte (low bits)
                // Decode reconstructs as: (low_3_bits << 8) | next_byte
                let high_3_bits = ((offset >> 8) & 0x7) as u8;
                let low_8_bits = (offset & 0xFF) as u8;
                let ctrl = 0x20 | high_3_bits; // Type 1, size 0, high 3 bits
                buffer.push(ctrl);
                buffer.push(low_8_bits);
            }
            1 => {
                // 19 bits: 3 bits in control byte + 16 bits in next 2 bytes, offset by 2048
                // Decode reconstructs as: 2048 + ((low_3_bits << 16) | (b0 << 8) | b1)
                let adjusted = offset - 2048;
                let high_3_bits = ((adjusted >> 16) & 0x7) as u8;
                let mid_8_bits = ((adjusted >> 8) & 0xFF) as u8;
                let low_8_bits = (adjusted & 0xFF) as u8;
                let ctrl = 0x20 | (1 << 3) | high_3_bits; // Type 1, size 1, high 3 bits
                buffer.push(ctrl);
                buffer.push(mid_8_bits);
                buffer.push(low_8_bits);
            }
            2 => {
                // 27 bits: 3 bits in control byte + 24 bits in next 3 bytes, offset by 526336
                // Decode reconstructs as: 526336 + ((low_3_bits << 24) | (b0 << 16) | (b1 << 8) | b2)
                let adjusted = offset - 526336;
                let high_3_bits = ((adjusted >> 24) & 0x7) as u8;
                let b0 = ((adjusted >> 16) & 0xFF) as u8;
                let b1 = ((adjusted >> 8) & 0xFF) as u8;
                let b2 = (adjusted & 0xFF) as u8;
                let ctrl = 0x20 | (2 << 3) | high_3_bits; // Type 1, size 2, high 3 bits
                buffer.push(ctrl);
                buffer.push(b0);
                buffer.push(b1);
                buffer.push(b2);
            }
            _ => {
                // 32 bits: payload bits ignored, full 32 bits in next 4 bytes
                let ctrl = 0x20 | (3 << 3); // Type 1, size 3, payload bits unused
                buffer.push(ctrl);
                buffer.extend_from_slice(&offset.to_be_bytes());
            }
        }
    }

    // Type 2: String (UTF-8)
    fn encode_string(s: &str, buffer: &mut Vec<u8>) {
        let bytes = s.as_bytes();
        Self::encode_with_size(2, bytes.len(), buffer);
        buffer.extend_from_slice(bytes);
    }

    // Type 3: Double (IEEE 754, 64-bit)
    fn encode_double(d: f64, buffer: &mut Vec<u8>) {
        buffer.push(0x68); // Type 3 << 5, size 8
        buffer.extend_from_slice(&d.to_be_bytes());
    }

    // Type 4: Bytes (raw binary)
    fn encode_bytes(b: &[u8], buffer: &mut Vec<u8>) {
        Self::encode_with_size(4, b.len(), buffer);
        buffer.extend_from_slice(b);
    }

    // Type 5: Uint16
    fn encode_uint16(n: u16, buffer: &mut Vec<u8>) {
        buffer.push(0xA2); // Type 5 << 5, size 2
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 6: Uint32
    fn encode_uint32(n: u32, buffer: &mut Vec<u8>) {
        buffer.push(0xC4); // Type 6 << 5, size 4
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 7: Map (with interning)
    fn encode_map_interned(&mut self, m: &HashMap<String, DataValue>) {
        Self::encode_with_size(7, m.len(), &mut self.buffer);

        // Encode key-value pairs (sorted by key for deterministic output)
        let mut pairs: Vec<_> = m.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);

        for (key, value) in pairs {
            // Intern the map key
            if self.intern_strings {
                if let Some(&existing_offset) = self.string_cache.get(key) {
                    Self::encode_pointer(existing_offset, &mut self.buffer);
                } else {
                    let offset = self.buffer.len() as u32;
                    Self::encode_string(key, &mut self.buffer);
                    self.string_cache.insert(key.clone(), offset);
                }
            } else {
                Self::encode_string(key, &mut self.buffer);
            }

            // Recursively encode value with interning
            self.encode_value_interned(value);
        }
    }

    // Type 7: Map (static version, no interning)
    fn encode_map(m: &HashMap<String, DataValue>, buffer: &mut Vec<u8>) {
        Self::encode_with_size(7, m.len(), buffer);

        // Encode key-value pairs (sorted by key for deterministic output)
        let mut pairs: Vec<_> = m.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);

        for (key, value) in pairs {
            Self::encode_string(key, buffer);
            Self::encode_to_buffer(value, buffer);
        }
    }

    // Extended types (type 0)

    // Type 8: Int32 (extended type 1)
    fn encode_int32(n: i32, buffer: &mut Vec<u8>) {
        buffer.push(0x04); // Type 0 << 5, size 4
        buffer.push(0x01); // Extended type: 8 - 7 = 1
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 9: Uint64 (extended type 2)
    fn encode_uint64(n: u64, buffer: &mut Vec<u8>) {
        buffer.push(0x08); // Type 0 << 5, size 8
        buffer.push(0x02); // Extended type: 9 - 7 = 2
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 10: Uint128 (extended type 3)
    fn encode_uint128(n: u128, buffer: &mut Vec<u8>) {
        buffer.push(0x10); // Type 0 << 5, size 16
        buffer.push(0x03); // Extended type: 10 - 7 = 3
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 11: Array (with interning)
    fn encode_array_interned(&mut self, a: &[DataValue]) {
        let size = a.len();

        // Control byte: type 0 << 5 | size bits
        if size < 29 {
            self.buffer.push(size as u8);
        } else if size < 29 + 256 {
            self.buffer.push(29);
            self.buffer.push((size - 29) as u8);
        } else if size < 29 + 256 + 65536 {
            self.buffer.push(30);
            let adjusted = size - 29 - 256;
            self.buffer
                .extend_from_slice(&(adjusted as u16).to_be_bytes());
        } else {
            self.buffer.push(31);
            let adjusted = size - 29 - 256 - 65536;
            self.buffer
                .extend_from_slice(&(adjusted as u32).to_be_bytes()[1..]);
        }

        // Extended type byte
        self.buffer.push(0x04); // 11 - 7 = 4

        // Recursively encode each element with interning
        for value in a {
            self.encode_value_interned(value);
        }
    }

    // Type 11: Array (static version, no interning)
    fn encode_array(a: &[DataValue], buffer: &mut Vec<u8>) {
        // Extended type encoding:
        // First byte: control byte with type 0 and size
        // Second byte: raw extended type number (11 - 7 = 4)
        let size = a.len();

        // Control byte: type 0 << 5 | size bits
        if size < 29 {
            buffer.push(size as u8); // Type 0, size in lower 5 bits
        } else if size < 29 + 256 {
            buffer.push(29); // Type 0, size = 29
            buffer.push((size - 29) as u8);
        } else if size < 29 + 256 + 65536 {
            buffer.push(30); // Type 0, size = 30
            let adjusted = size - 29 - 256;
            buffer.extend_from_slice(&(adjusted as u16).to_be_bytes());
        } else {
            buffer.push(31); // Type 0, size = 31
            let adjusted = size - 29 - 256 - 65536;
            buffer.extend_from_slice(&(adjusted as u32).to_be_bytes()[1..]); // 3 bytes
        }

        // Extended type byte
        buffer.push(0x04); // 11 - 7 = 4

        for value in a {
            Self::encode_to_buffer(value, buffer);
        }
    }

    // Type 14: Bool (extended type 7)
    fn encode_bool(b: bool, buffer: &mut Vec<u8>) {
        if b {
            buffer.push(0x01); // Type 0 << 5, size 1
        } else {
            buffer.push(0x00); // Type 0 << 5, size 0
        }
        buffer.push(0x07); // Extended type: 14 - 7 = 7
    }

    // Type 15: Float (IEEE 754, 32-bit) (extended type 8)
    fn encode_float(f: f32, buffer: &mut Vec<u8>) {
        buffer.push(0x04); // Type 0 << 5, size 4
        buffer.push(0x08); // Extended type: 15 - 7 = 8
        buffer.extend_from_slice(&f.to_be_bytes());
    }

    /// Encode control byte with size for standard types
    fn encode_with_size(type_id: u8, size: usize, buffer: &mut Vec<u8>) {
        let type_bits = type_id << 5;

        if size < 29 {
            buffer.push(type_bits | (size as u8));
        } else if size < 29 + 256 {
            buffer.push(type_bits | 29);
            buffer.push((size - 29) as u8);
        } else if size < 29 + 256 + 65536 {
            buffer.push(type_bits | 30);
            let adjusted = size - 29 - 256;
            buffer.extend_from_slice(&(adjusted as u16).to_be_bytes());
        } else {
            buffer.push(type_bits | 31);
            let adjusted = size - 29 - 256 - 65536;
            buffer.extend_from_slice(&(adjusted as u32).to_be_bytes()[1..]); // 3 bytes
        }
    }
}

impl Default for DataEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Data section decoder
///
/// Decodes values from an encoded data section buffer.
/// Fully compatible with MMDB format.
pub struct DataDecoder<'a> {
    buffer: &'a [u8],
    base_offset: usize,
}

impl<'a> DataDecoder<'a> {
    /// Create a decoder for a data section
    ///
    /// # Arguments
    /// * `buffer` - The encoded data buffer
    /// * `base_offset` - Base offset for pointer calculations (0 for standalone data)
    pub fn new(buffer: &'a [u8], base_offset: usize) -> Self {
        Self {
            buffer,
            base_offset,
        }
    }

    /// Decode a value at the given offset
    pub fn decode(&self, offset: u32) -> Result<DataValue, &'static str> {
        let mut cursor = offset as usize;
        if cursor < self.base_offset {
            return Err("Offset before base");
        }
        cursor -= self.base_offset;
        let value = self.decode_at(&mut cursor)?;
        // Recursively resolve pointers in the returned value
        self.resolve_pointers(value)
    }

    fn decode_at(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor >= self.buffer.len() {
            return Err("Cursor out of bounds");
        }

        let ctrl = self.buffer[*cursor];
        *cursor += 1;

        let type_id = ctrl >> 5;
        let payload = ctrl & 0x1F;

        match type_id {
            0 => self.decode_extended(cursor, payload),
            1 => self.decode_pointer(cursor, payload),
            2 => self.decode_string(cursor, payload),
            3 => self.decode_double(cursor),
            4 => self.decode_bytes(cursor, payload),
            5 => self.decode_uint16(cursor, payload),
            6 => self.decode_uint32(cursor, payload),
            7 => self.decode_map(cursor, payload),
            _ => Err("Invalid type"),
        }
    }

    fn decode_extended(
        &self,
        cursor: &mut usize,
        size_from_ctrl: u8,
    ) -> Result<DataValue, &'static str> {
        if *cursor >= self.buffer.len() {
            return Err("Extended type truncated");
        }

        // The next byte contains the raw extended type number
        // Actual type = 7 + raw_ext_type (per libmaxminddb)
        let raw_ext_type = self.buffer[*cursor];
        let type_id = 7 + raw_ext_type;
        *cursor += 1;

        match type_id {
            8 => self.decode_int32(cursor, size_from_ctrl), // Extended type 1
            9 => self.decode_uint64(cursor, size_from_ctrl), // Extended type 2
            10 => self.decode_uint128(cursor, size_from_ctrl), // Extended type 3
            11 => self.decode_array(cursor, size_from_ctrl), // Extended type 4
            14 => Ok(DataValue::Bool(size_from_ctrl != 0)), // Extended type 7
            15 => self.decode_float(cursor, size_from_ctrl), // Extended type 8
            _ => {
                eprintln!(
                    "Unknown extended type: raw_ext_type={}, type_id={}, size_from_ctrl={}, offset={}",
                    raw_ext_type, type_id, size_from_ctrl, *cursor - 1
                );
                Err("Unknown extended type")
            }
        }
    }

    fn decode_pointer(&self, cursor: &mut usize, payload: u8) -> Result<DataValue, &'static str> {
        let size_bits = (payload >> 3) & 0x3; // Extract bits 3-4
        let offset = match size_bits {
            0 => {
                // 11 bits: 3 bits from payload + 8 bits from next byte
                if *cursor >= self.buffer.len() {
                    return Err("Pointer data truncated");
                }
                let low_3_bits = (payload & 0x7) as u32;
                let next_byte = self.buffer[*cursor] as u32;
                *cursor += 1;
                (low_3_bits << 8) | next_byte
            }
            1 => {
                // 19 bits: 3 bits from payload + 16 bits from next 2 bytes, offset by 2048
                if *cursor + 1 >= self.buffer.len() {
                    return Err("Pointer data truncated");
                }
                let low_3_bits = (payload & 0x7) as u32;
                let b0 = self.buffer[*cursor] as u32;
                let b1 = self.buffer[*cursor + 1] as u32;
                *cursor += 2;
                2048 + ((low_3_bits << 16) | (b0 << 8) | b1)
            }
            2 => {
                // 27 bits: 3 bits from payload + 24 bits from next 3 bytes, offset by 526336
                if *cursor + 2 >= self.buffer.len() {
                    return Err("Pointer data truncated");
                }
                let low_3_bits = (payload & 0x7) as u32;
                let b0 = self.buffer[*cursor] as u32;
                let b1 = self.buffer[*cursor + 1] as u32;
                let b2 = self.buffer[*cursor + 2] as u32;
                *cursor += 3;
                526336 + ((low_3_bits << 24) | (b0 << 16) | (b1 << 8) | b2)
            }
            3 => {
                // 32 bits: payload bits ignored, full 32 bits from next 4 bytes
                if *cursor + 3 >= self.buffer.len() {
                    return Err("Pointer data truncated");
                }
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 4]);
                *cursor += 4;
                u32::from_be_bytes(bytes)
            }
            _ => return Err("Invalid pointer size"),
        };

        Ok(DataValue::Pointer(offset))
    }

    fn decode_string(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let len = self.decode_size(cursor, size_bits)?;

        if *cursor + len > self.buffer.len() {
            return Err("String data out of bounds");
        }

        let s = std::str::from_utf8(&self.buffer[*cursor..*cursor + len])
            .map_err(|_| "Invalid UTF-8")?;
        *cursor += len;

        Ok(DataValue::String(s.to_string()))
    }

    fn decode_double(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor + 8 > self.buffer.len() {
            return Err("Double data out of bounds");
        }

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 8]);
        *cursor += 8;

        Ok(DataValue::Double(f64::from_be_bytes(bytes)))
    }

    fn decode_bytes(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let len = self.decode_size(cursor, size_bits)?;

        if *cursor + len > self.buffer.len() {
            return Err("Bytes data out of bounds");
        }

        let bytes = self.buffer[*cursor..*cursor + len].to_vec();
        *cursor += len;

        Ok(DataValue::Bytes(bytes))
    }

    fn decode_uint16(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let size = self.decode_size(cursor, size_bits)?;

        if size > 2 {
            return Err("Uint16 size too large");
        }

        if *cursor + size > self.buffer.len() {
            return Err("Uint16 data out of bounds");
        }

        // Read variable number of bytes and convert to u16
        let mut value = 0u16;
        for i in 0..size {
            value = (value << 8) | (self.buffer[*cursor + i] as u16);
        }
        *cursor += size;

        Ok(DataValue::Uint16(value))
    }

    fn decode_uint32(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let size = self.decode_size(cursor, size_bits)?;

        if size > 4 {
            return Err("Uint32 size too large");
        }

        if *cursor + size > self.buffer.len() {
            return Err("Uint32 data out of bounds");
        }

        // Read variable number of bytes and convert to u32
        let mut value = 0u32;
        for i in 0..size {
            value = (value << 8) | (self.buffer[*cursor + i] as u32);
        }
        *cursor += size;

        Ok(DataValue::Uint32(value))
    }

    fn decode_map(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let count = self.decode_size(cursor, size_bits)?;
        let mut map = HashMap::new();

        for _ in 0..count {
            // Decode key - can be String or Pointer (MMDB uses pointers for deduplication)
            let key_value = self.decode_at(cursor)?;
            let key = match key_value {
                DataValue::String(s) => s,
                DataValue::Pointer(offset) => {
                    // Follow pointer to get the actual key string
                    match self.decode(offset)? {
                        DataValue::String(s) => s,
                        _ => return Err("Pointer in map key must point to string"),
                    }
                }
                _ => return Err("Map key must be string or pointer to string"),
            };

            let value = self.decode_at(cursor)?;
            map.insert(key, value);
        }

        Ok(DataValue::Map(map))
    }

    fn decode_int32(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let size = self.decode_size(cursor, size_bits)?;

        if size > 4 {
            return Err("Int32 size too large");
        }

        if *cursor + size > self.buffer.len() {
            return Err("Int32 data out of bounds");
        }

        // Read variable number of bytes and convert to i32 with sign extension
        let mut value = 0i32;
        if size > 0 {
            // Check if the high bit is set (negative number)
            let is_negative = (self.buffer[*cursor] & 0x80) != 0;

            if is_negative {
                // Start with all 1s for sign extension
                value = -1;
            }

            for i in 0..size {
                value = (value << 8) | (self.buffer[*cursor + i] as i32);
            }
        }
        *cursor += size;

        Ok(DataValue::Int32(value))
    }

    fn decode_uint64(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let size = self.decode_size(cursor, size_bits)?;

        if size > 8 {
            return Err("Uint64 size too large");
        }

        if *cursor + size > self.buffer.len() {
            return Err("Uint64 data out of bounds");
        }

        // Read variable number of bytes and convert to u64
        let mut value = 0u64;
        for i in 0..size {
            value = (value << 8) | (self.buffer[*cursor + i] as u64);
        }
        *cursor += size;

        Ok(DataValue::Uint64(value))
    }

    fn decode_uint128(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let size = self.decode_size(cursor, size_bits)?;

        if size > 16 {
            return Err("Uint128 size too large");
        }

        if *cursor + size > self.buffer.len() {
            return Err("Uint128 data out of bounds");
        }

        // Read variable number of bytes and convert to u128
        let mut value = 0u128;
        for i in 0..size {
            value = (value << 8) | (self.buffer[*cursor + i] as u128);
        }
        *cursor += size;

        Ok(DataValue::Uint128(value))
    }

    fn decode_array(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let count = self.decode_size(cursor, size_bits)?;
        let mut array = Vec::with_capacity(count);

        for _ in 0..count {
            array.push(self.decode_at(cursor)?);
        }

        Ok(DataValue::Array(array))
    }

    fn decode_float(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        // Float should always be 4 bytes
        if size_bits != 4 {
            return Err("Float must be 4 bytes");
        }

        if *cursor + 4 > self.buffer.len() {
            return Err("Float data out of bounds");
        }

        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 4]);
        *cursor += 4;

        Ok(DataValue::Float(f32::from_be_bytes(bytes)))
    }

    fn decode_size(&self, cursor: &mut usize, size_bits: u8) -> Result<usize, &'static str> {
        match size_bits {
            0..=28 => Ok(size_bits as usize),
            29 => {
                if *cursor >= self.buffer.len() {
                    return Err("Size byte out of bounds");
                }
                let size = self.buffer[*cursor] as usize;
                *cursor += 1;
                Ok(29 + size)
            }
            30 => {
                if *cursor + 2 > self.buffer.len() {
                    return Err("Size bytes out of bounds");
                }
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 2]);
                *cursor += 2;
                Ok(29 + 256 + u16::from_be_bytes(bytes) as usize)
            }
            31 => {
                if *cursor + 3 > self.buffer.len() {
                    return Err("Size bytes out of bounds");
                }
                let b0 = self.buffer[*cursor] as usize;
                let b1 = self.buffer[*cursor + 1] as usize;
                let b2 = self.buffer[*cursor + 2] as usize;
                *cursor += 3;
                Ok(29 + 256 + 65536 + ((b0 << 16) | (b1 << 8) | b2))
            }
            _ => Err("Invalid size encoding"),
        }
    }

    /// Recursively resolve all pointers in a decoded value
    fn resolve_pointers(&self, value: DataValue) -> Result<DataValue, &'static str> {
        match value {
            DataValue::Pointer(offset) => {
                // Follow the pointer and recursively resolve
                let mut cursor = offset as usize;
                if cursor < self.base_offset {
                    return Err("Pointer offset before base");
                }
                cursor -= self.base_offset;
                let pointed_value = self.decode_at(&mut cursor)?;
                self.resolve_pointers(pointed_value)
            }
            DataValue::Map(entries) => {
                // Recursively resolve pointers in map values
                let mut resolved_map = HashMap::new();
                for (key, val) in entries {
                    resolved_map.insert(key, self.resolve_pointers(val)?);
                }
                Ok(DataValue::Map(resolved_map))
            }
            DataValue::Array(items) => {
                // Recursively resolve pointers in array elements
                let mut resolved_array = Vec::new();
                for item in items {
                    resolved_array.push(self.resolve_pointers(item)?);
                }
                Ok(DataValue::Array(resolved_array))
            }
            // All other types have no pointers to resolve
            other => Ok(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_all_types() {
        let mut encoder = DataEncoder::new();

        // Test each type
        let string_val = DataValue::String("hello".to_string());
        let uint16_val = DataValue::Uint16(12345);
        let uint32_val = DataValue::Uint32(0xDEADBEEF);
        let uint64_val = DataValue::Uint64(0x123456789ABCDEF0);
        let uint128_val = DataValue::Uint128(0x0123456789ABCDEF0123456789ABCDEF);
        let int32_val = DataValue::Int32(-42);
        let double_val = DataValue::Double(std::f64::consts::PI);
        let float_val = DataValue::Float(std::f32::consts::E);
        let bool_val = DataValue::Bool(true);
        let bytes_val = DataValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let offsets = [
            encoder.encode(&string_val),
            encoder.encode(&uint16_val),
            encoder.encode(&uint32_val),
            encoder.encode(&uint64_val),
            encoder.encode(&uint128_val),
            encoder.encode(&int32_val),
            encoder.encode(&double_val),
            encoder.encode(&float_val),
            encoder.encode(&bool_val),
            encoder.encode(&bytes_val),
        ];

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);

        let values = vec![
            string_val,
            uint16_val,
            uint32_val,
            uint64_val,
            uint128_val,
            int32_val,
            double_val,
            float_val,
            bool_val,
            bytes_val,
        ];

        for (offset, expected) in offsets.iter().zip(values.iter()) {
            let decoded = decoder.decode(*offset).unwrap();
            assert_eq!(&decoded, expected);
        }
    }

    #[test]
    fn test_encode_decode_map() {
        let mut encoder = DataEncoder::new();
        let mut map = HashMap::new();
        map.insert("country".to_string(), DataValue::String("US".to_string()));
        map.insert("asn".to_string(), DataValue::Uint32(13335));
        map.insert("score".to_string(), DataValue::Double(0.95));

        let value = DataValue::Map(map.clone());
        let offset = encoder.encode(&value);

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);
        let decoded = decoder.decode(offset).unwrap();

        assert_eq!(decoded, value);
    }

    #[test]
    fn test_encode_decode_array() {
        let mut encoder = DataEncoder::new();
        let value = DataValue::Array(vec![
            DataValue::String("tag1".to_string()),
            DataValue::String("tag2".to_string()),
            DataValue::Uint32(123),
            DataValue::Bool(false),
        ]);
        let offset = encoder.encode(&value);

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);
        let decoded = decoder.decode(offset).unwrap();

        assert_eq!(decoded, value);
    }

    #[test]
    fn test_deduplication() {
        let mut encoder = DataEncoder::new();

        // Encode same value multiple times
        let value = DataValue::String("test".to_string());
        let offset1 = encoder.encode(&value);
        let offset2 = encoder.encode(&value);
        let offset3 = encoder.encode(&value);

        // Should get same offset (deduplicated)
        assert_eq!(offset1, offset2);
        assert_eq!(offset2, offset3);

        // Different value gets different offset
        let value2 = DataValue::String("different".to_string());
        let offset4 = encoder.encode(&value2);
        assert_ne!(offset1, offset4);
    }

    #[test]
    fn test_complex_nested_structure() {
        let mut encoder = DataEncoder::new();

        // Build threat intelligence data structure
        let mut threat_data = HashMap::new();
        threat_data.insert(
            "threat_level".to_string(),
            DataValue::String("high".to_string()),
        );
        threat_data.insert(
            "category".to_string(),
            DataValue::String("malware".to_string()),
        );
        threat_data.insert("confidence".to_string(), DataValue::Float(0.98));
        threat_data.insert("first_seen".to_string(), DataValue::Uint64(1704067200));

        let mut indicators = HashMap::new();
        indicators.insert("ip_count".to_string(), DataValue::Uint32(42));
        indicators.insert("domain_count".to_string(), DataValue::Uint32(15));

        threat_data.insert("indicators".to_string(), DataValue::Map(indicators));
        threat_data.insert(
            "tags".to_string(),
            DataValue::Array(vec![
                DataValue::String("botnet".to_string()),
                DataValue::String("c2".to_string()),
            ]),
        );
        threat_data.insert("active".to_string(), DataValue::Bool(true));

        let value = DataValue::Map(threat_data);
        let offset = encoder.encode(&value);

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);
        let decoded = decoder.decode(offset).unwrap();

        assert_eq!(decoded, value);
    }

    #[test]
    fn test_large_strings() {
        let mut encoder = DataEncoder::new();

        // Test string size encodings
        let short = "x".repeat(28); // < 29
        let medium = "x".repeat(100); // 29..285
        let long = "x".repeat(1000); // > 285

        let offset1 = encoder.encode(&DataValue::String(short.clone()));
        let offset2 = encoder.encode(&DataValue::String(medium.clone()));
        let offset3 = encoder.encode(&DataValue::String(long.clone()));

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);

        assert_eq!(decoder.decode(offset1).unwrap(), DataValue::String(short));
        assert_eq!(decoder.decode(offset2).unwrap(), DataValue::String(medium));
        assert_eq!(decoder.decode(offset3).unwrap(), DataValue::String(long));
    }

    #[test]
    fn test_string_interning() {
        // Test that repeated strings within structures are interned
        let mut encoder = DataEncoder::new();

        // Create multiple maps with repeated string values
        let mut map1 = HashMap::new();
        map1.insert(
            "threat_level".to_string(),
            DataValue::String("high".to_string()),
        );
        map1.insert(
            "category".to_string(),
            DataValue::String("malware".to_string()),
        );
        map1.insert("score".to_string(), DataValue::Uint32(95));

        let mut map2 = HashMap::new();
        map2.insert(
            "threat_level".to_string(),
            DataValue::String("high".to_string()),
        ); // Repeated
        map2.insert(
            "category".to_string(),
            DataValue::String("phishing".to_string()),
        );
        map2.insert("score".to_string(), DataValue::Uint32(88));

        let mut map3 = HashMap::new();
        map3.insert(
            "threat_level".to_string(),
            DataValue::String("high".to_string()),
        ); // Repeated
        map3.insert(
            "category".to_string(),
            DataValue::String("malware".to_string()),
        ); // Repeated
        map3.insert("score".to_string(), DataValue::Uint32(92));

        // Encode all three maps
        let offset1 = encoder.encode(&DataValue::Map(map1.clone()));
        let offset2 = encoder.encode(&DataValue::Map(map2.clone()));
        let offset3 = encoder.encode(&DataValue::Map(map3.clone()));

        let bytes_with_interning = encoder.into_bytes();

        // Now encode WITHOUT interning to compare size
        let mut encoder_no_intern = DataEncoder::new_without_interning();
        encoder_no_intern.encode(&DataValue::Map(map1.clone()));
        encoder_no_intern.encode(&DataValue::Map(map2.clone()));
        encoder_no_intern.encode(&DataValue::Map(map3.clone()));
        let bytes_no_interning = encoder_no_intern.into_bytes();

        // Interned version should be smaller
        println!("With interning: {} bytes", bytes_with_interning.len());
        println!("Without interning: {} bytes", bytes_no_interning.len());
        println!(
            "Savings: {} bytes ({:.1}%)",
            bytes_no_interning.len() - bytes_with_interning.len(),
            100.0 * (bytes_no_interning.len() - bytes_with_interning.len()) as f64
                / bytes_no_interning.len() as f64
        );
        assert!(bytes_with_interning.len() < bytes_no_interning.len());

        // Verify decoding still works correctly
        let decoder = DataDecoder::new(&bytes_with_interning, 0);
        let decoded1 = decoder.decode(offset1).unwrap();
        let decoded2 = decoder.decode(offset2).unwrap();
        let decoded3 = decoder.decode(offset3).unwrap();

        assert_eq!(decoded1, DataValue::Map(map1));
        assert_eq!(decoded2, DataValue::Map(map2));
        assert_eq!(decoded3, DataValue::Map(map3));
    }

    #[test]
    fn test_string_interning_in_arrays() {
        // Test interning within arrays
        let mut encoder = DataEncoder::new();

        let array = DataValue::Array(vec![
            DataValue::String("botnet".to_string()),
            DataValue::String("c2".to_string()),
            DataValue::String("botnet".to_string()), // Repeated
            DataValue::String("malware".to_string()),
            DataValue::String("c2".to_string()), // Repeated
        ]);

        let offset = encoder.encode(&array);
        let bytes = encoder.into_bytes();

        // Decode and verify
        let decoder = DataDecoder::new(&bytes, 0);
        let decoded = decoder.decode(offset).unwrap();
        assert_eq!(decoded, array);
    }

    #[test]
    fn test_pointer_encoding() {
        // Test pointer resolution with actual data that pointers reference
        let mut encoder = DataEncoder::new();

        // First encode some actual data that we'll point to
        let target_data = DataValue::String("shared_value".to_string());
        let target_offset = encoder.encode(&target_data);

        // Now create a map that uses a pointer to reference that data (simulating deduplication)
        // In MMDB format, pointers are typically used within maps for deduplicated keys/values
        let mut map = HashMap::new();
        map.insert(
            "direct".to_string(),
            DataValue::String("direct_value".to_string()),
        );
        // Manually insert pointer (in real MMDB, encoder would do this for deduplication)
        map.insert("ptr_ref".to_string(), DataValue::Pointer(target_offset));

        let map_offset = encoder.encode(&DataValue::Map(map));

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);

        // Decode the map - pointers should be automatically resolved
        let decoded = decoder.decode(map_offset).unwrap();

        if let DataValue::Map(decoded_map) = decoded {
            // The pointer should have been resolved to the actual string value
            assert_eq!(
                decoded_map.get("direct"),
                Some(&DataValue::String("direct_value".to_string()))
            );
            assert_eq!(
                decoded_map.get("ptr_ref"),
                Some(&DataValue::String("shared_value".to_string()))
            );
        } else {
            panic!("Expected Map, got {:?}", decoded);
        }
    }
}
