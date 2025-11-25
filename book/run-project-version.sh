#!/usr/bin/env bash
# Wrapper script that ensures mdbook-project-version is built before running

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREPROCESSOR_DIR="$SCRIPT_DIR/mdbook-project-version"
BINARY="$PREPROCESSOR_DIR/target/release/mdbook-project-version"

# Build if binary doesn't exist or source is newer
if [ ! -f "$BINARY" ] || [ "$PREPROCESSOR_DIR/src/main.rs" -nt "$BINARY" ]; then
    (cd "$PREPROCESSOR_DIR" && cargo build --release --quiet) >&2
fi

# Run the preprocessor with all arguments
exec "$BINARY" "$@"
