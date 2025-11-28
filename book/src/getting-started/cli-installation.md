# Installing the CLI

## Prerequisites

The Matchy CLI requires Rust to build. If you don't have Rust installed:

```console
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Verify installation:

```console
$ rustc --version
rustc 1.70.0 (or later)
```

## Installing from crates.io

The easiest way to install the Matchy CLI is from crates.io:

```console
$ cargo install matchy
    Updating crates.io index
  Downloaded matchy v{{version}}
   Compiling matchy v{{version}}
    Finished release [optimized] target(s) in 2m 15s
  Installing ~/.cargo/bin/matchy
```

Verify the installation:

```console
$ matchy --version
matchy {{version}}
```

## Installing from source

To install the latest development version:

```console
$ git clone https://github.com/matchylabs/matchy
$ cd matchy
$ cargo install --path .
```

## Using without installation

You can also run Matchy directly from the source repository without installing:

```console
$ git clone https://github.com/matchylabs/matchy
$ cd matchy
$ cargo run --release -- --version
matchy {{version}}
```

Use `cargo run --release --` instead of `matchy` for all commands.

## Next Steps

Now that you have the CLI installed, let's build your first database:

* [First Database with CLI](cli-first-database.md)

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
