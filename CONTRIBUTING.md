# Contributing to matchy

Thank you for your interest in contributing to matchy! This document provides guidelines and information for contributors.

## Code of Conduct

Be respectful and constructive. We're all here to make matchy better.

## Getting Started

### Prerequisites

- Rust 1.70+ (stable toolchain)
- Git
- Familiarity with Rust, glob patterns, or the Aho-Corasick algorithm (helpful but not required)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/matchylabs/matchy.git
cd matchy

# Build the project
cargo build

# Run tests
cargo test

# Run clippy for linting
cargo clippy

# Format code
cargo fmt
```

## Development Workflow

### Before You Start

1. Check existing issues and PRs to avoid duplicate work
2. For significant changes, open an issue first to discuss the approach
3. Fork the repository and create a feature branch

### Making Changes

1. **Write Tests**: All new functionality should include tests
2. **Follow Style Guidelines**: Run `cargo fmt` before committing
3. **Pass Clippy**: Run `cargo clippy` and address warnings
4. **Document**: Add doc comments (`///`) for public APIs
5. **Update Documentation**: Update README.md or DEVELOPMENT.md if needed

### Testing

```bash
# Run all tests
cargo test

# Run with output visible
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run integration tests
cargo test --test integration_tests

# Run benchmarks (compile only)
cargo bench --no-run

# Run benchmark smoke test
cargo bench -- --test
```

### Code Quality

```bash
# Format code (required)
cargo fmt

# Check formatting without modifying
cargo fmt -- --check

# Run clippy (required to pass)
cargo clippy --all-targets --all-features -- -D warnings

# Check documentation builds
cargo doc --no-deps
```

## Pull Request Process

1. **Create a Feature Branch**: `git checkout -b feature/your-feature-name`
2. **Make Your Changes**: Follow the guidelines above
3. **Commit with Clear Messages**: 
   ```
   Add feature: brief description
   
   More detailed explanation of what and why.
   ```
4. **Push to Your Fork**: `git push origin feature/your-feature-name`
5. **Open a Pull Request**: 
   - Describe what your PR does
   - Reference any related issues
   - Explain any breaking changes

### PR Checklist

Before submitting a PR, ensure:

- [ ] All tests pass: `cargo test`
- [ ] Code is formatted: `cargo fmt`
- [ ] Clippy passes: `cargo clippy -- -D warnings`
- [ ] Documentation builds: `cargo doc --no-deps`
- [ ] New features have tests
- [ ] Public APIs have doc comments
- [ ] CHANGELOG.md is updated (if applicable)

## Architecture Guidelines

### Memory Safety

- **Core algorithms must be safe Rust** - Unsafe code only at FFI boundaries
- Document all `unsafe` blocks with safety invariants
- Validate all assumptions before dereferencing

### Binary Format Compatibility

- All binary format structures use `#[repr(C)]`
- Changes to binary format require version bump
- Test compatibility with C++ implementation

### Performance

- Use `cargo bench` to measure performance impact
- Document performance characteristics in doc comments
- Keep O(n) complexity for matching operations

## Types of Contributions

### Bug Fixes

- Include a test that reproduces the bug
- Explain the root cause in the PR description
- Reference the issue number

### New Features

- Discuss the design in an issue first
- Consider impact on binary format
- Add examples in `examples/` directory
- Update relevant documentation

### Performance Improvements

- Include benchmark results showing improvement
- Explain the optimization technique
- Ensure correctness is maintained

### Documentation

- Fix typos, unclear explanations, or outdated info
- Add examples for complex features
- Improve error messages

## Project Structure

```
matchy/
├── src/                    # Rust source code
│   ├── lib.rs              # Public API
│   ├── ac_offset.rs        # Aho-Corasick automaton
│   ├── paraglob_offset.rs  # Main Paraglob implementation
│   ├── glob.rs             # Glob pattern matching
│   ├── binary/             # Binary format
│   └── c_api/              # C FFI layer
├── tests/                  # Integration tests
├── benches/                # Benchmarks
├── examples/               # Example programs
└── .github/workflows/      # CI configuration
```

## Getting Help

- **Questions**: Open a GitHub issue with the "question" label
- **Bugs**: Open a GitHub issue with the "bug" label and reproduction steps
- **Feature Requests**: Open a GitHub issue with the "enhancement" label

## License

By contributing, you agree that your contributions will be licensed under the BSD-2-Clause License.

## Recognition

Contributors are recognized in the project's commit history and will be acknowledged in release notes for significant contributions.
