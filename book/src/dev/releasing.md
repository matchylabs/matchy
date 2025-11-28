# Release Process

This guide covers how to release a new version of Matchy to crates.io using automated GitHub Actions workflows with trusted publishing.

## Overview

Matchy uses **trusted publishing** to securely publish releases to crates.io without managing API tokens. When you push a version tag (like `v1.0.0`), GitHub Actions automatically:

1. Creates a GitHub release
2. Builds binaries for multiple platforms
3. Publishes to crates.io using OIDC authentication

## Prerequisites

### One-Time Setup: Configure Trusted Publishing

Before your first release, you must configure trusted publishing on crates.io:

1. Go to https://crates.io/crates/matchy/settings
2. Navigate to the "Trusted Publishing" section
3. Click "Add" and fill in:
   - **Repository owner:** `matchylabs`
   - **Repository name:** `matchy`
   - **Workflow filename:** `release.yml`
   - **Environment:** `release`
4. Click "Save"

This tells crates.io to trust releases from your GitHub Actions workflow.

> **Note:** The GitHub `release` environment has already been created in your repository.

## Release Checklist

Before releasing, ensure:

- [ ] All tests pass: `cargo test`
- [ ] Benchmarks run successfully: `cargo bench`
- [ ] Documentation builds: `cargo doc --no-deps`
- [ ] CHANGELOG.md is updated with version changes
- [ ] README.md reflects current features
- [ ] No uncommitted changes

## Creating a Release

### 1. Update the Version

Update the version in `Cargo.toml`:

```toml
[package]
name = "matchy"
version = "1.0.0"  # Update this
```

### 2. Commit the Version Bump

```bash
git add Cargo.toml CHANGELOG.md
git commit -m "Release version 1.0.0"
git push origin main
```

### 3. Create and Push the Tag

```bash
# Create an annotated tag
git tag -a v1.0.0 -m "Release version 1.0.0"

# Push the tag (this triggers the release workflow)
git push origin v1.0.0
```

> **Important:** The tag version must match the `Cargo.toml` version. The workflow will fail if they don't match (e.g., tag `v1.0.0` requires `version = "1.0.0"` in Cargo.toml).

## What Happens Automatically

When you push the tag, the GitHub Actions workflow (`.github/workflows/release.yml`) runs three jobs:

### Job 1: Create Release
- Creates a GitHub release for the tag
- Sets the release name and description

### Job 2: Build CLI Binaries
Builds the `matchy` CLI for multiple platforms:
- Linux x86_64 (`.tar.gz`)
- Linux ARM64 (`.tar.gz`) - cross-compiled
- macOS x86_64 (`.tar.gz`)
- macOS ARM64 (`.tar.gz`)
- Windows x86_64 (`.zip`)

All archives are attached to the GitHub release for users who want pre-built binaries.

### Job 3: Publish to crates.io
- Verifies the tag version matches `Cargo.toml`
- Uses the `rust-lang/crates-io-auth-action` to authenticate via OIDC
- Runs `cargo publish` with a short-lived token
- No API tokens are stored in the repository!

## Monitoring a Release

### Watch the Workflow

Monitor the release progress:
```bash
# Open in browser
gh run watch
```

Or visit: https://github.com/matchylabs/matchy/actions

### Verify Publication

After the workflow completes:

1. **Check crates.io:** https://crates.io/crates/matchy
2. **Check GitHub release:** https://github.com/matchylabs/matchy/releases
3. **Test installation:**
   ```bash
   cargo install matchy --force
   matchy --version
   ```

## Troubleshooting

### "Trusted publishing not configured"

**Problem:** The workflow fails with an authentication error.

**Solution:** Follow the [Prerequisites](#prerequisites) section to configure trusted publishing on crates.io.

### "Version mismatch"

**Problem:** The workflow fails with "Tag version does not match Cargo.toml version."

**Solution:** Ensure the tag (e.g., `v1.0.0`) matches the version in `Cargo.toml` (e.g., `version = "1.0.0"`). Delete the tag, fix the version, and re-tag:

```bash
# Delete local and remote tag
git tag -d v1.0.0
git push origin :refs/tags/v1.0.0

# Fix Cargo.toml, commit, then re-tag
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

### "Permission denied" or OIDC errors

**Problem:** The workflow can't authenticate with crates.io.

**Solution:** Verify that:
1. The `release` environment exists in your repository
2. The workflow has `id-token: write` permission (already set)
3. Trusted publishing is configured on crates.io with the correct repository and workflow name

### Build failures

**Problem:** The build or tests fail during the workflow.

**Solution:** Test locally first:

```bash
# Run all checks locally
cargo test
cargo clippy -- -D warnings
cargo build --release

# Test cross-compilation (if needed)
cargo build --release --target x86_64-unknown-linux-gnu
```

## Semantic Versioning

Matchy follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0 → 2.0.0): Breaking API changes
- **MINOR** (1.0.0 → 1.1.0): New features, backwards compatible
- **PATCH** (1.0.0 → 1.0.1): Bug fixes, backwards compatible

### When to Bump

- **Major:** Binary format changes, API removals, behavior changes
- **Minor:** New features, new APIs, performance improvements
- **Patch:** Bug fixes, documentation updates, internal refactoring

## Pre-Releases

For testing before an official release:

```bash
# Use a pre-release version
version = "1.0.0-beta.1"

# Tag with the same format
git tag -a v1.0.0-beta.1 -m "Beta release"
git push origin v1.0.0-beta.1
```

Pre-release versions are published to crates.io but not marked as the "latest" version.

## Yanking a Release

If you discover a critical issue after publishing:

```bash
# Yank the problematic version
cargo yank --vers 1.0.0

# Fix the issue, then release a new version
# Bump to 1.0.1 and follow the normal release process
```

Yanked versions remain available for existing users but won't be installed for new users.

## How Trusted Publishing Works

Under the hood:

1. GitHub Actions generates an **OIDC token** that cryptographically proves:
   - The workflow is running from the `matchylabs/matchy` repository
   - It's using the `release.yml` workflow
   - It's deploying to the `release` environment

2. The `rust-lang/crates-io-auth-action` exchanges this OIDC token for a **short-lived crates.io token** (expires in 30 minutes)

3. `cargo publish` uses this temporary token to upload the crate

4. The token expires automatically - no cleanup needed!

This is more secure than API tokens because:
- No long-lived secrets to manage or rotate
- Tokens are scoped to specific repositories and workflows
- Cryptographic proof of workflow identity
- Automatic expiration prevents token reuse

## See Also

- [Testing](testing.md) - Run tests before releasing
- [CI Checks](ci-checks.md) - What CI validates
- [Benchmarking](benchmarking.md) - Performance validation
- [GitHub Actions Workflows](https://github.com/matchylabs/matchy/tree/main/.github/workflows)
- [crates.io Trusted Publishing Docs](https://crates.io/docs/trusted-publishing)
