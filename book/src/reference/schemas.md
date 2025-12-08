# Schemas Reference

Built-in JSON schemas for validating database yield values.

## Overview

Matchy includes built-in schemas that define the structure of yield values for common database types. When you specify a known schema type during `matchy build`, yield values are validated against the schema, catching errors early.

### Available Schemas

| Name | Metadata Type | Description |
|------|---------------|-------------|
| `threatdb` | `ThreatDB-v1` | Threat intelligence with MISP/STIX-compatible fields |

## Using Schemas

### CLI

Enable schema validation with `--database-type`:

```bash
# Use the short name - enables ThreatDB schema validation
matchy build --database-type threatdb threats.csv -o threats.mxy

# Custom names skip validation
matchy build --database-type "MyCompany-Intel" data.csv -o custom.mxy
```

When you use a known schema name like `threatdb`:
1. Yield values are validated against the schema during build
2. The canonical `database_type` (`ThreatDB-v1`) is set in metadata
3. Validation errors stop the build with helpful messages

### Rust API

```rust
use matchy::schemas::{get_schema_info, is_known_database_type};

// Check if a type has built-in validation
if is_known_database_type("threatdb") {
    let info = get_schema_info("threatdb").unwrap();
    println!("Canonical type: {}", info.database_type); // "ThreatDB-v1"
}
```

## ThreatDB Schema

The ThreatDB schema (`threatdb`) is designed for threat intelligence databases, with fields compatible with MISP and STIX 2.1 concepts.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `threat_level` | string | Severity: `critical`, `high`, `medium`, `low`, `unknown` |
| `category` | string | Threat type (lowercase): `malware`, `c2`, `phishing`, etc. |
| `source` | string | Origin feed or organization |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `confidence` | integer | Score 0-100 (STIX 2.1 compatible) |
| `first_seen` | string | ISO 8601 datetime |
| `last_seen` | string | ISO 8601 datetime |
| `description` | string | Human-readable notes |
| `tags` | array | List of strings for classification |
| `reference` | string | URL to external documentation |
| `tlp` | string | Traffic Light Protocol: `clear`, `green`, `amber`, `amber+strict`, `red` |
| `indicator_type` | string | What the key represents: `ip-src`, `domain`, `url`, `sha256`, etc. |

### Threat Levels

| Value | MISP Equivalent | Use Case |
|-------|-----------------|----------|
| `critical` | - | Active campaigns, zero-days |
| `high` | 1 | Known active threats |
| `medium` | 2 | Suspicious activity |
| `low` | 3 | Low confidence or historical |
| `unknown` | 4 | Insufficient data |

### Common Categories

```
malware      c2           phishing     botnet       ransomware
spam         scanner      proxy        cryptomining dropper
apt          tor-exit     vpn          bruteforce   exploit
rat          stealer      ddos
```

### TLP (Traffic Light Protocol)

| Value | Sharing |
|-------|---------|
| `clear` | Unrestricted (formerly WHITE) |
| `green` | Community-wide |
| `amber` | Limited distribution |
| `amber+strict` | Organization only |
| `red` | Named recipients only |

### Example: CSV Input

```csv
key,threat_level,category,source,confidence,tags
192.0.2.1,high,c2,abuse.ch,95,"emotet,banking"
*.evil.com,medium,phishing,internal,75,
10.0.0.0/8,low,scanner,honeypot,50,
```

### Example: JSON Input

```json
{
  "192.0.2.1": {
    "threat_level": "high",
    "category": "c2",
    "source": "abuse.ch",
    "confidence": 95,
    "first_seen": "2024-01-15T10:30:00Z",
    "tags": ["emotet", "banking-trojan"],
    "tlp": "amber"
  },
  "*.evil.com": {
    "threat_level": "medium",
    "category": "phishing",
    "source": "internal",
    "description": "Phishing campaign targeting employees"
  }
}
```

### Example: Build with Validation

```bash
$ matchy build --database-type threatdb -f json threats.json -o threats.mxy
Schema validation: enabled (ThreatDB-v1)
Building database from threats.json
  Added 2 entries
Successfully wrote threats.mxy
```

### Validation Errors

Invalid data produces clear error messages:

```bash
$ cat bad.csv
key,threat_level,category,source
192.0.2.1,critical,malware,abuse.ch
10.0.0.1,extreme,badcat,

$ matchy build --database-type threatdb bad.csv -o out.mxy
Schema validation failed for entry "10.0.0.1"

Validation errors:
  - /threat_level: "extreme" is not one of ["critical","high","medium","low","unknown"]
  - /source: string length 0 is less than minLength 1

Use a custom --database-type name if you don't want schema validation.
```

## Validating Existing Databases

The `matchy validate` command checks schema compliance for databases with known `database_type`:

```bash
# Validates structure AND schema if database_type is "ThreatDB-v1"
matchy validate threats.mxy
```

Validation detects the schema from the `database_type` metadata field.

## Custom Schemas (Future)

Currently, only built-in schemas are supported. Custom schema support via `--schema <file>` may be added in future versions.

For now, use a custom `--database-type` name to skip schema validation:

```bash
# No validation - your own structure
matchy build --database-type "MyCompany-ThreatFeed-v2" data.json -o custom.mxy
```

## Schema API Reference

### Functions

```rust
use matchy::schemas::{
    get_schema,
    get_schema_info,
    schema_database_type,
    detect_schema_from_database_type,
    available_schemas,
    is_known_database_type,
};
```

#### `get_schema(name: &str) -> Option<&'static str>`

Returns the raw JSON schema string for a schema name or database_type.

```rust
let schema_json = get_schema("threatdb").unwrap();
// or
let schema_json = get_schema("ThreatDB-v1").unwrap();
```

#### `get_schema_info(name: &str) -> Option<&'static SchemaInfo>`

Returns full schema metadata.

```rust
let info = get_schema_info("threatdb").unwrap();
println!("{}: {}", info.name, info.description);
// threatdb: Threat intelligence database with MISP/STIX-compatible fields
```

#### `schema_database_type(name: &str) -> Option<&'static str>`

Maps short name to canonical database_type.

```rust
assert_eq!(schema_database_type("threatdb"), Some("ThreatDB-v1"));
```

#### `detect_schema_from_database_type(db_type: &str) -> Option<&'static str>`

Maps database_type back to schema name.

```rust
assert_eq!(detect_schema_from_database_type("ThreatDB-v1"), Some("threatdb"));
```

#### `available_schemas() -> impl Iterator<Item = &'static str>`

Lists all available schema names.

```rust
for name in available_schemas() {
    println!("  - {}", name);
}
```

#### `is_known_database_type(name: &str) -> bool`

Checks if a name is a known schema (short name or database_type).

```rust
assert!(is_known_database_type("threatdb"));
assert!(is_known_database_type("ThreatDB-v1"));
assert!(!is_known_database_type("Custom-Type"));
```

### SchemaInfo Struct

```rust
pub struct SchemaInfo {
    /// Short name used in CLI (e.g., "threatdb")
    pub name: &'static str,
    /// Database type string set in metadata (e.g., "ThreatDB-v1")
    pub database_type: &'static str,
    /// Raw JSON Schema content
    pub schema_json: &'static str,
    /// Human-readable description
    pub description: &'static str,
}
```

## See Also

- [matchy build](../commands/matchy-build.md) - Building with schema validation
- [matchy validate](../commands/matchy-validate.md) - Validating databases
- [Data Types Reference](data-types-ref.md) - Supported yield value types
- [Input Formats](input-formats.md) - CSV/JSON input format details
