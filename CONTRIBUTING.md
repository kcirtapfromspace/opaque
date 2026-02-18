# Contributing to Opaque

Thank you for your interest in contributing to Opaque.

## Prerequisites

- Rust 1.80+ (edition 2024)
- macOS or Linux
- Git

## Getting Started

```bash
git clone https://github.com/anthropics/opaque.git
cd opaque
cargo build --workspace
cargo test --workspace
```

## Development Workflow

### Code Quality

Before submitting a PR, ensure:

```bash
# All tests pass
cargo test --workspace

# No clippy warnings
cargo clippy --workspace -- -D warnings

# Code is formatted
cargo fmt --check
```

### Running Locally

```bash
# Build all binaries
cargo build --release

# Initialize config
./target/release/opaque init

# Start daemon
./target/release/opaqued

# In another terminal
./target/release/opaque ping
./target/release/opaque execute test.noop
```

## Pull Request Expectations

- **Tests**: Add or update tests for any new functionality
- **Clippy**: Zero warnings with `cargo clippy --workspace -- -D warnings`
- **Format**: Run `cargo fmt` before committing
- **Docs**: Update documentation if behavior changes
- **Scope**: Keep PRs focused on a single concern
- **Commits**: Use clear, descriptive commit messages

## Architecture

See `docs/architecture.md` for an overview. Key principles:

- **Deny-by-default**: Nothing is permitted without an explicit policy rule
- **Fail closed**: Errors and unavailable backends result in denial, never in secret disclosure
- **Typestate sanitization**: Response types enforce that secrets are scrubbed before reaching clients
- **Audit everything**: Every operation request, policy decision, and approval is logged

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
