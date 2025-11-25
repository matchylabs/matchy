# Update PSL Tool

Simple tool to download the Public Suffix List and generate punycode versions of non-ASCII entries.

## Purpose

The extractor uses hash-based TLD validation from the PSL. This tool:
1. Downloads latest PSL from publicsuffix.org
2. Keeps all original entries (UTF-8 and ASCII)
3. For each non-ASCII entry, generates the punycode equivalent
4. Saves both versions to `src/data/public_suffix_list.dat`

This ensures domains work whether they appear in logs as UTF-8 ("公司.cn") or punycode ("xn--55qx5d.cn").

## Usage

```bash
cd crates/matchy-extractor/tools/update-psl
cargo run
```

The tool will:
- Download latest PSL
- Process ~10K entries
- Generate punycode for ~1.5K UTF-8 entries
- Save to `../../src/data/public_suffix_list.dat`

## Example Output

```
Downloading Public Suffix List from https://publicsuffix.org/list/public_suffix_list.dat...
Processing entries and generating punycode versions...
Found 1543 UTF-8 entries
Generated 1543 punycode entries
Total unique entries: 11490

✓ Saved to ../../src/data/public_suffix_list.dat

Next steps:
  1. cd ../../.. && cargo test -p matchy-extractor    # Verify everything works
  2. git add src/data/public_suffix_list.dat
  3. git commit -m "Update Public Suffix List with punycode"
```

## Dependencies

- `idna` - Unicode domain name to punycode conversion
- `ureq` - HTTP client for downloading PSL

Total: ~15 dependencies (much lighter than the old 74+ dep AC tool!)

## Why Separate?

The `idna` crate pulls in Unicode normalization tables. Keeping this as a dev-only tool prevents bloating matchy's production dependencies.
