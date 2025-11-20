# Building from Source

Build Matchy from source code.

## Prerequisites

- Rust 1.70 or later
- C compiler (for examples)

## Quick Build

```bash
# Clone
git clone https://github.com/sethhall/matchy.git
cd matchy

# Build
cargo build --release

# Test
cargo test

# Install CLI
cargo install --path .
```

## Build Profiles

### Debug Build

```bash
cargo build
# Output: target/debug/
```

- Fast compilation
- Includes debug symbols
- No optimizations

### Release Build

```bash
cargo build --release
# Output: target/release/
```

- Slow compilation
- Full optimizations
- LTO enabled
- Single codegen unit

## Build Options

```bash
# Check without building
cargo check

# Build with all features
cargo build --all-features

# Build examples
cargo build --examples

# Build documentation
cargo doc --no-deps
```

## C Header Generation

The C header is auto-generated on release builds:

```bash
cargo build --release
# Generates: include/matchy.h
```

## Cross-Compilation

```bash
# Install target
rustup target add x86_64-unknown-linux-gnu

# Build for target
cargo build --release --target x86_64-unknown-linux-gnu
```

## Development Tools

Matchy includes development-only tools in the `examples/` directory that are not installed with `cargo install`.

### Updating the Public Suffix List

The TLD matching feature uses a hash-based lookup table built from the [Public Suffix List](https://publicsuffix.org). To refresh this data:

```bash
# Download latest PSL and generate punycode versions
cd tools/update-psl
cargo run

# Verify everything works
cd ../..
cargo test

# Commit the updated data
git add src/data/public_suffix_list.dat
git commit -m "Update Public Suffix List"
```

The update tool:
- Downloads the latest PSL from publicsuffix.org
- Generates punycode versions of non-ASCII entries (e.g., "公司.cn" → "xn--55qx5d.cn")
- Saves both UTF-8 and punycode versions to `src/data/public_suffix_list.dat`
- This ensures domains work whether logs contain UTF-8 or punycode

**Note:** This is only needed when updating TLD patterns. The PSL data is embedded at compile time, so end users never need to run this.

## See Also

- [Development Guide](../development.md)
- [Testing](testing.md)
