#!/bin/bash
# Build and serve the matchy-wasm demo locally

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WASM_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building matchy-wasm..."
cd "$WASM_DIR"

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack not found. Install with: cargo install wasm-pack"
    exit 1
fi

# Build the WASM package
wasm-pack build --target web --out-dir demo/pkg

echo ""
echo "Build complete! Starting local server..."
echo ""
echo "Open http://localhost:8080 in your browser"
echo "Press Ctrl+C to stop"
echo ""

cd demo

# Try python3 first, then python
if command -v python3 &> /dev/null; then
    python3 -m http.server 8080
elif command -v python &> /dev/null; then
    python -m http.server 8080
else
    echo "Python not found. Please serve the demo directory manually."
    echo "For example: npx serve ."
    exit 1
fi
