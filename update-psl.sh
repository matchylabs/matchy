#!/bin/bash
# Update Public Suffix List from publicsuffix.org
#
# Usage: ./update-psl.sh

set -e

PSL_URL="https://publicsuffix.org/list/public_suffix_list.dat"
OUTPUT_FILE="src/data/public_suffix_list.dat"

echo "Downloading latest Public Suffix List..."
curl -fsSL "$PSL_URL" -o "$OUTPUT_FILE"

echo "✓ Downloaded to $OUTPUT_FILE"
echo ""
echo "File size: $(wc -c < "$OUTPUT_FILE" | xargs) bytes"
echo "Lines: $(wc -l < "$OUTPUT_FILE" | xargs)"
echo "TLD entries: $(grep -v '^//' "$OUTPUT_FILE" | grep -v '^$' | wc -l | xargs)"
echo ""
echo "Next steps:"
echo "  1. cargo test    # Verify everything still works"
echo "  2. git add $OUTPUT_FILE"
echo "  3. git commit -m \"Update Public Suffix List\""
