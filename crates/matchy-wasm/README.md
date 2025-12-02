# matchy-wasm

WebAssembly bindings for [matchy](https://github.com/matchylabs/matchy) - fast IP and pattern matching database.

## Features

- **Database**: Load and query matchy databases from `Uint8Array`
- **DatabaseBuilder**: Create databases with IPs, domains, and glob patterns
- **Extractor**: Extract IPs, domains, emails, and hashes from text

## Installation

```bash
npm install matchy-wasm
```

Or build from source:

```bash
wasm-pack build crates/matchy-wasm --target web
```

## Usage

### JavaScript/TypeScript

```javascript
import init, { Database, DatabaseBuilder, Extractor } from 'matchy-wasm';

async function main() {
  // Initialize the WASM module
  await init();

  // Build a threat intelligence database
  const builder = new DatabaseBuilder(true); // case-sensitive
  builder.addEntry("1.2.3.4", { threat: "high", category: "botnet" });
  builder.addEntry("192.168.0.0/16", { category: "private" });
  builder.addEntry("*.evil.com", { category: "malware" });
  builder.addEntry("bad-actor.org", { threat: "medium" });
  
  const dbBytes = builder.build();

  // Query the database
  const db = new Database(dbBytes);
  
  // IP lookup
  const ipResult = db.lookup("1.2.3.4");
  console.log(ipResult); // { threat: "high", category: "botnet", _prefix_len: 32 }
  
  // Pattern matching
  const patternResult = db.lookup("malware.evil.com");
  console.log(patternResult); // { category: "malware" }
  
  // Extract entities from text
  const extractor = new Extractor();
  const entities = extractor.extract(
    "Contact admin@example.com, check 192.168.1.1 and malware.evil.com"
  );
  console.log(entities);
  // [
  //   { type: "Email", value: "admin@example.com", start: 8, end: 25 },
  //   { type: "IPv4", value: "192.168.1.1", start: 33, end: 44 },
  //   { type: "Domain", value: "malware.evil.com", start: 49, end: 65 }
  // ]
}

main();
```

### Loading from File (Browser)

```javascript
// Fetch a pre-built database
const response = await fetch('/threats.mxy');
const bytes = new Uint8Array(await response.arrayBuffer());
const db = new Database(bytes);

const result = db.lookup("suspicious.domain.com");
```

### Selective Extraction

```javascript
const extractor = new Extractor();

// Extract only IPs
const ips = extractor.extractIps("Server 10.0.0.1 and 8.8.8.8");

// Extract only domains
const domains = extractor.extractDomains("Visit example.com or test.org");

// Extract only emails
const emails = extractor.extractEmails("Contact alice@example.com");

// Extract only hashes (MD5, SHA1, SHA256, etc.)
const hashes = extractor.extractHashes("Hash: d41d8cd98f00b204e9800998ecf8427e");
```

## API Reference

### `Database`

```typescript
class Database {
  constructor(bytes: Uint8Array);
  lookup(key: string): object | null;
  lookupIp(ip: string): object | null;
  lookupPattern(text: string): object | null;
  stats(): { total_queries: number, cache_hits: number, ... };
}
```

### `DatabaseBuilder`

```typescript
class DatabaseBuilder {
  constructor(caseSensitive: boolean);
  addEntry(key: string, data: object): void;
  addIp(ip: string, data: object): void;
  addPattern(pattern: string, data: object): void;
  addLiteral(literal: string, data: object): void;
  build(): Uint8Array;
}
```

### `Extractor`

```typescript
class Extractor {
  constructor();
  extract(text: string): ExtractedEntity[];
  extractIps(text: string): ExtractedEntity[];
  extractDomains(text: string): ExtractedEntity[];
  extractEmails(text: string): ExtractedEntity[];
  extractHashes(text: string): ExtractedEntity[];
}

interface ExtractedEntity {
  type: "IPv4" | "IPv6" | "Domain" | "Email" | "MD5" | "SHA1" | "SHA256" | ...;
  value: string;
  start: number;
  end: number;
}
```

## Building

```bash
# Build for web (ES modules)
wasm-pack build crates/matchy-wasm --target web

# Build for Node.js
wasm-pack build crates/matchy-wasm --target nodejs

# Build for bundlers (webpack, etc.)
wasm-pack build crates/matchy-wasm --target bundler

# Run tests (requires Node.js)
wasm-pack test --node crates/matchy-wasm
```

## License

Apache-2.0
