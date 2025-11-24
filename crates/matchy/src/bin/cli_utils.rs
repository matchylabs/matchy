use anyhow::Result;
use matchy::DataValue;
use serde_json::json;
use std::collections::HashMap;
use std::io;

/// Zero-copy line scanner using memchr for SIMD-accelerated scanning.
/// Reuses a provided buffer to avoid allocations. Handles partial lines at buffer boundaries.
pub struct LineScanner<R: io::BufRead> {
    reader: R,
    partial: Vec<u8>,
    eof: bool,
}

impl<R: io::BufRead> LineScanner<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            partial: Vec::new(),
            eof: false,
        }
    }

    /// Trim ASCII whitespace from both ends of a byte slice
    fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
        while !bytes.is_empty() && bytes[0].is_ascii_whitespace() {
            bytes = &bytes[1..];
        }
        while !bytes.is_empty() && bytes[bytes.len() - 1].is_ascii_whitespace() {
            bytes = &bytes[..bytes.len() - 1];
        }
        bytes
    }

    /// Read next line into the provided buffer (zero-copy when possible).
    /// Returns Ok(true) if a line was read, Ok(false) on EOF, Err on I/O error.
    pub fn read_line(&mut self, line_buf: &mut Vec<u8>) -> io::Result<bool> {
        line_buf.clear();

        loop {
            if self.eof {
                // Handle final partial line if any
                if !self.partial.is_empty() {
                    let trimmed = Self::trim_ascii(&self.partial);
                    if !trimmed.is_empty() {
                        line_buf.extend_from_slice(trimmed);
                        self.partial.clear();
                        return Ok(true);
                    }
                    self.partial.clear();
                }
                return Ok(false);
            }

            let buffer = self.reader.fill_buf()?;

            if buffer.is_empty() {
                self.eof = true;
                continue;
            }

            // Scan for newline using memchr
            if let Some(newline_pos) = memchr::memchr(b'\n', buffer) {
                // Found complete line
                if self.partial.is_empty() {
                    // Fast path: line is entirely in buffer, no allocation
                    let trimmed = Self::trim_ascii(&buffer[..newline_pos]);
                    if !trimmed.is_empty() {
                        line_buf.extend_from_slice(trimmed);
                        self.reader.consume(newline_pos + 1);
                        return Ok(true);
                    }
                } else {
                    // Append to partial line from previous chunk
                    self.partial.extend_from_slice(&buffer[..newline_pos]);
                    let trimmed = Self::trim_ascii(&self.partial);
                    if !trimmed.is_empty() {
                        line_buf.extend_from_slice(trimmed);
                    }
                    self.partial.clear();
                    self.reader.consume(newline_pos + 1);
                    if !line_buf.is_empty() {
                        return Ok(true);
                    }
                }

                // Empty line, consume and continue
                self.reader.consume(newline_pos + 1);
            } else {
                // No newline in buffer - accumulate and continue
                self.partial.extend_from_slice(buffer);
                let consumed = buffer.len();
                self.reader.consume(consumed);
            }
        }
    }
}

/// Helper function to format IP and prefix length as CIDR
pub fn format_cidr(ip_str: &str, prefix_len: u8) -> String {
    let mut buf = String::with_capacity(64);
    format_cidr_into(ip_str, prefix_len, &mut buf);
    buf
}

/// Format IP and prefix length as CIDR into provided buffer (zero-allocation)
pub fn format_cidr_into(ip_str: &str, prefix_len: u8, buf: &mut String) {
    use std::fmt::Write;
    use std::net::IpAddr;

    buf.clear();

    if let Ok(addr) = ip_str.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(ipv4) => {
                let ip_int = u32::from(ipv4);
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                let network_int = ip_int & mask;
                let network = std::net::Ipv4Addr::from(network_int);
                let _ = write!(buf, "{}/{}", network, prefix_len);
            }
            IpAddr::V6(ipv6) => {
                let ip_int = u128::from(ipv6);
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                let network_int = ip_int & mask;
                let network = std::net::Ipv6Addr::from(network_int);
                let _ = write!(buf, "{}/{}", network, prefix_len);
            }
        }
    } else {
        let _ = write!(buf, "{}/{}", ip_str, prefix_len);
    }
}

pub fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

pub fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn format_qps(qps: f64) -> String {
    if qps >= 1_000_000.0 {
        format!("{:.2}M", qps / 1_000_000.0)
    } else if qps >= 1_000.0 {
        format!("{:.2}K", qps / 1_000.0)
    } else {
        format!("{:.2}", qps)
    }
}

pub fn data_value_to_json(data: &DataValue) -> serde_json::Value {
    match data {
        DataValue::String(s) => json!(s),
        DataValue::Double(d) => json!(d),
        DataValue::Bytes(b) => json!(b),
        DataValue::Uint16(u) => json!(u),
        DataValue::Uint32(u) => json!(u),
        DataValue::Uint64(u) => json!(u),
        DataValue::Uint128(u) => json!(u.to_string()),
        DataValue::Int32(i) => json!(i),
        DataValue::Bool(b) => json!(b),
        DataValue::Float(f) => json!(f),
        DataValue::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                map.insert(k.clone(), data_value_to_json(v));
            }
            json!(map)
        }
        DataValue::Array(items) => {
            json!(items.iter().map(data_value_to_json).collect::<Vec<_>>())
        }
        DataValue::Pointer(_) => json!("<pointer>"),
    }
}

pub fn json_to_data_map(json: &serde_json::Value) -> Result<HashMap<String, DataValue>> {
    match json {
        serde_json::Value::Object(obj) => obj
            .iter()
            .map(|(k, v)| Ok((k.clone(), json_to_data_value(v)?)))
            .collect::<Result<HashMap<_, _>>>(),
        _ => anyhow::bail!("Expected JSON object for data field"),
    }
}

pub fn json_to_data_value(json: &serde_json::Value) -> Result<DataValue> {
    match json {
        serde_json::Value::Null => Ok(DataValue::Bytes(vec![])),
        serde_json::Value::Bool(b) => Ok(DataValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(DataValue::Int32(i as i32))
            } else if let Some(u) = n.as_u64() {
                Ok(DataValue::Uint64(u))
            } else if let Some(f) = n.as_f64() {
                Ok(DataValue::Double(f))
            } else {
                anyhow::bail!("Unsupported number type")
            }
        }
        serde_json::Value::String(s) => Ok(DataValue::String(s.clone())),
        serde_json::Value::Array(arr) => {
            let items = arr
                .iter()
                .map(json_to_data_value)
                .collect::<Result<Vec<_>>>()?;
            Ok(DataValue::Array(items))
        }
        serde_json::Value::Object(obj) => {
            let entries = obj
                .iter()
                .map(|(k, v)| Ok((k.clone(), json_to_data_value(v)?)))
                .collect::<Result<HashMap<_, _>>>()?;
            Ok(DataValue::Map(entries))
        }
    }
}

pub fn extract_uint_from_datavalue(data: &DataValue) -> Option<u64> {
    match data {
        DataValue::Uint16(u) => Some(*u as u64),
        DataValue::Uint32(u) => Some(*u as u64),
        DataValue::Uint64(u) => Some(*u),
        _ => None,
    }
}

pub fn format_unix_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let duration = Duration::from_secs(timestamp);
    let datetime = UNIX_EPOCH + duration;

    // Convert to a formatted string using the system's local time
    // We'll format it manually since we don't have external dependencies
    match datetime.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let total_secs = d.as_secs();
            let days = total_secs / 86400;
            let remaining = total_secs % 86400;
            let hours = remaining / 3600;
            let remaining = remaining % 3600;
            let minutes = remaining / 60;
            let seconds = remaining % 60;

            // Calculate date from days since epoch (1970-01-01)
            let (year, month, day) = days_to_ymd(days);

            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                year, month, day, hours, minutes, seconds
            )
        }
        Err(_) => format!("Invalid timestamp: {}", timestamp),
    }
}

// Convert days since Unix epoch to year/month/day
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;
    (year, month, day)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

pub fn format_data_value(data: &DataValue, indent: &str) -> String {
    match data {
        DataValue::String(s) => format!("\"{}\"", s),
        DataValue::Double(d) => format!("{}", d),
        DataValue::Bytes(b) => format!("{:?}", b),
        DataValue::Uint16(u) => format!("{}", u),
        DataValue::Uint32(u) => format!("{}", u),
        DataValue::Uint64(u) => format!("{}", u),
        DataValue::Uint128(u) => format!("{}", u),
        DataValue::Int32(i) => format!("{}", i),
        DataValue::Bool(b) => format!("{}", b),
        DataValue::Float(f) => format!("{}", f),
        DataValue::Map(entries) => {
            if entries.is_empty() {
                "{}".to_string()
            } else {
                let mut result = "{\n".to_string();
                for (k, v) in entries {
                    result.push_str(&format!(
                        "{}  {}: {},\n",
                        indent,
                        k,
                        format_data_value(v, &format!("{}  ", indent))
                    ));
                }
                result.push_str(&format!("{}}}", indent));
                result
            }
        }
        DataValue::Array(items) => {
            if items.is_empty() {
                "[]".to_string()
            } else {
                let items_str: Vec<_> = items
                    .iter()
                    .map(|item| format_data_value(item, indent))
                    .collect();
                format!("[{}]", items_str.join(", "))
            }
        }
        DataValue::Pointer(_) => "<pointer>".to_string(),
    }
}
