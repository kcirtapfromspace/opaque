# Contributing to Opaque

Thank you for your interest in contributing to Opaque.

## Prerequisites

- Rust 1.80+ (edition 2024)
- macOS or Linux
- Git

## Getting Started

```bash
git clone https://github.com/kcirtapfromspace/opaque.git
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

## The Site

The docs and the landing page are one MkDocs build:

```sh
uv venv && source .venv/bin/activate
uv pip install -r docs/requirements.txt
mkdocs serve            # http://127.0.0.1:8000
mkdocs build --strict   # what CI and both deploys run
```

`--strict` is not optional in a deploy: a dead internal link or an unknown
config key fails the build rather than shipping a broken site. Package versions
are pinned in `docs/requirements.txt` and Python in `.python-version`, so the
build resolves identically everywhere.

It publishes to two places:

| Target | Where | How |
|---|---|---|
| **opaque.info** (canonical) | Cloudflare Pages | Builds from `main`; output directory comes from `wrangler.toml`, build command from the Pages dashboard |
| kcirtapfromspace.github.io/opaque | GitHub Pages | `.github/workflows/pages.yml` |

Canonical URLs and the sitemap point at `opaque.info` (`site_url` in
`mkdocs.yml`), so the mirror never competes with it in search results. Asset
paths are relative, so one build serves correctly both at a domain root and
under a subpath.

Brand decisions — the slogan, the redaction motif, palette, type, and voice —
live in [BRAND.md](BRAND.md). Read it before changing the landing page.

## Architecture

See [Architecture](docs/architecture.md) for an overview. Key principles:

- **Deny-by-default**: Nothing is permitted without an explicit policy rule
- **Fail closed**: Errors and unavailable backends result in denial, never in secret disclosure
- **Typestate sanitization**: Response types enforce that secrets are scrubbed before reaching clients
- **Audit everything**: Every operation request, policy decision, and approval is logged

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
