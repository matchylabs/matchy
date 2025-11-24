#!/bin/bash
# Wrapper script for mdbook-cmdrun preprocessor
# Ensures matchy is in PATH when commands execute

set -e

# Add cargo bin to PATH if not already present
export PATH="$HOME/.cargo/bin:$PATH"

# Check if mdbook-cmdrun is available
if ! command -v mdbook-cmdrun &> /dev/null; then
    echo "Error: mdbook-cmdrun not found in PATH" >&2
    echo "PATH=$PATH" >&2
    exit 1
fi

# Run mdbook-cmdrun with all arguments
exec mdbook-cmdrun "$@"
