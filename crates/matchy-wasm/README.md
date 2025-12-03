# matchy-wasm

WebAssembly bindings for [matchy](https://github.com/matchylabs/matchy) - fast IP and pattern matching database.

## Features

- **Database**: Load and query matchy databases from `Uint8Array`
- **DatabaseBuilder**: Create databases with IPs, domains, and glob patterns
- **ExtractorBuilder**: Configure and build extractors for IPs, domains, emails, hashes, and crypto addresses

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
import init, { Database, DatabaseBuilder, ExtractorBuilder } from 'matchy-wasm';

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
  
  // Extract entities from text (all types enabled by default)
  const extractor = new ExtractorBuilder().build();
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

### Selective Extraction (Efficient)

Configure extractors to only extract what you need - this is more efficient than extracting everything:

```javascript
// Extract only IPs (skips domain/email/hash extraction work)
const ipExtractor = new ExtractorBuilder()
    .extractDomains(false)
    .extractEmails(false)
    .extractHashes(false)
    .extractBitcoin(false)
    .extractEthereum(false)
    .extractMonero(false)
    .build();
const ips = ipExtractor.extract("Server 10.0.0.1 and 8.8.8.8");

// Extract only domains
const domainExtractor = new ExtractorBuilder()
    .extractIpv4(false)
    .extractIpv6(false)
    .extractEmails(false)
    .extractHashes(false)
    .extractBitcoin(false)
    .extractEthereum(false)
    .extractMonero(false)
    .build();
const domains = domainExtractor.extract("Visit example.com or test.org");
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

### `ExtractorBuilder`

```typescript
class ExtractorBuilder {
  constructor();  // All extractors enabled by default
  extractDomains(enable: boolean): ExtractorBuilder;
  extractEmails(enable: boolean): ExtractorBuilder;
  extractIpv4(enable: boolean): ExtractorBuilder;
  extractIpv6(enable: boolean): ExtractorBuilder;
  extractHashes(enable: boolean): ExtractorBuilder;
  extractBitcoin(enable: boolean): ExtractorBuilder;
  extractEthereum(enable: boolean): ExtractorBuilder;
  extractMonero(enable: boolean): ExtractorBuilder;
  minDomainLabels(min: number): ExtractorBuilder;
  build(): Extractor;
}

class Extractor {
  extract(text: string): ExtractedEntity[];
}

interface ExtractedEntity {
  type: "IPv4" | "IPv6" | "Domain" | "Email" | "MD5" | "SHA1" | "SHA256" | "SHA384" | "SHA512" | "Bitcoin" | "Ethereum" | "Monero";
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
