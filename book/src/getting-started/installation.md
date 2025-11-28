# Installation

[![Crate](https://img.shields.io/crates/v/matchy.svg)](https://crates.io/crates/matchy)

Current version: **{{version}}**

## Prerequisites

- **Rust** 1.70 or later
- **Cargo** (comes with Rust)
- **C compiler** (optional, for C API usage)

## Installing Rust

If you don't have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Verify installation:

```bash
rustc --version
cargo --version
```

## Using as a Rust Dependency

### Full Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
matchy = "{{version_minor}}"
```

### Library Only (Minimal Dependencies)

If you're embedding Matchy in your application and don't need CLI components:

```toml
[dependencies]
matchy = { version = "{{version_minor}}", default-features = false }
```

This saves ~40 transitive dependencies by excluding CLI-only features (`clap`, `notify`, `ctrlc`, `csv`).

Then run:

```bash
cargo build
```

## Building from Source

Clone and build the repository:

```bash
git clone https://github.com/matchylabs/matchy
cd matchy
cargo build --release
```

The build produces:
- `target/release/libmatchy.a` - Static library
- `target/release/libmatchy.{so,dylib,dll}` - Dynamic library
- `target/release/matchy` - Command-line tool

## Installing the CLI Tool

### From crates.io

```bash
cargo install matchy
```

### From source

```bash
cargo install --path .
```

Verify:

```bash
matchy --version
# matchy {{version}}
```

## C/C++ Integration

### Option 1: Using cargo-c (Recommended)

Install the C library system-wide:

```bash
# Install cargo-c
cargo install cargo-c

# Build and install
cargo cinstall --release --prefix=/usr/local
```

This installs:
- Headers: `/usr/local/include/matchy/`
- Libraries: `/usr/local/lib/`
- pkg-config: `/usr/local/lib/pkgconfig/matchy.pc`

Then in your C project:

```bash
# Using pkg-config
gcc myapp.c $(pkg-config --cflags --libs matchy) -o myapp

# Or manually
gcc myapp.c -I/usr/local/include -lmatchy -o myapp
```

### Option 2: Manual Installation

1. Build the release version:

```bash
cargo build --release
```

2. Copy files:

```bash
# Copy library
sudo cp target/release/libmatchy.* /usr/local/lib/

# Copy headers
sudo mkdir -p /usr/local/include/matchy
sudo cp include/matchy/*.h /usr/local/include/matchy/

# Update library cache (Linux)
sudo ldconfig
```

3. Compile your C project:

```bash
gcc myapp.c -I/usr/local/include -L/usr/local/lib -lmatchy -o myapp
```

See the [C Installation Guide](../reference/c-installation.md) for platform-specific details.

## Verifying Installation

### Run tests

```bash
cargo test
```

Expected: **79/79 tests passing**

### Run benchmarks

```bash
cargo bench
```

### Try examples

```bash
# Production workload test
cargo run --release --example production_test

# Glob pattern demonstrations
cargo run --release --example glob_demo

# Combined IP + pattern database
cargo run --release --example combined_query
```

## Platform-Specific Notes

### Linux

Works out of the box. Both static and dynamic linking supported.

### macOS

Standard system allocator used. Link with:

```bash
-lmatchy
```

### Windows

Requires Windows 10+. Ensure runtime library compatibility (MT/MD).

## Troubleshooting

### Dynamic library not found

**Linux:**
```bash
export LD_LIBRARY_PATH=/path/to/matchy/target/release:$LD_LIBRARY_PATH
```

**macOS:**
```bash
export DYLD_LIBRARY_PATH=/path/to/matchy/target/release:$DYLD_LIBRARY_PATH
```

**Windows:**
Add `target\release` to your PATH or copy the DLL next to your executable.

### cbindgen not found

The C header is auto-generated during build. If you see errors:

```bash
cargo install cbindgen
```

### Outdated dependencies

Update all dependencies:

```bash
cargo update
cargo build --release
```

## Next Steps

- [First Steps with Matchy](first-steps.md) - Build your first database
- [Rust API Guide](../reference/rust-api.md) - Complete API documentation
- [C API Guide](../reference/c-api.md) - C/C++ integration guide
- [Examples](../reference/examples.md) - More code examples
