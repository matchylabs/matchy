# Installing as a Library

## For Rust Projects

Add Matchy to your `Cargo.toml`:

### Full Installation (includes CLI dependencies)

```toml
[dependencies]
matchy = "{{version_minor}}"
```

### Library Only (minimal dependencies)

If you're only using Matchy as a library and don't need CLI components, save ~40 transitive dependencies:

```toml
[dependencies]
matchy = { version = "{{version_minor}}", default-features = false }
```

This excludes CLI-only dependencies (`clap`, `notify`, `ctrlc`, `csv`) while keeping all core functionality.

Then run `cargo build`:

```console
$ cargo build
    Updating crates.io index
   Downloading matchy v{{version_minor}}
     Compiling matchy v{{version_minor}}
     Compiling your-project v0.1.0
```

That's it! You can now use Matchy in your Rust code.

## For C/C++ Projects

### Option 1: Using cargo-c (Recommended)

Install the system-wide C library:

```console
$ cargo install cargo-c
$ git clone https://github.com/matchylabs/matchy
$ cd matchy
$ cargo cinstall --release --prefix=/usr/local
```

This installs:
- Headers to `/usr/local/include/matchy/`
- Library to `/usr/local/lib/`
- pkg-config file to `/usr/local/lib/pkgconfig/`

Compile your project:

```console
$ gcc myapp.c $(pkg-config --cflags --libs matchy) -o myapp
```

### Option 2: Manual Installation

1. Build the library:

```console
$ git clone https://github.com/matchylabs/matchy
$ cd matchy
$ cargo build --release
```

2. Copy files:

```console
$ sudo cp target/release/libmatchy.* /usr/local/lib/
$ sudo cp include/matchy.h /usr/local/include/
```

3. Update library cache (Linux):

```console
$ sudo ldconfig
```

4. Compile your project:

```console
$ gcc myapp.c -I/usr/local/include -L/usr/local/lib -lmatchy -o myapp
```

## For Other Languages

Matchy provides a C API that can be called from any language with C FFI support:

- **Python**: Use `ctypes` or `cffi`
- **Go**: Use `cgo`
- **Node.js**: Use `node-ffi` or `napi`
- **Ruby**: Use `fiddle` or `ffi`

See the [C API Reference](../reference/c-api.md) for the full API specification.

## Next Steps

Choose your language:

* [First Database with Rust](api-rust-first.md)
* [First Database with C](api-c-first.md)
