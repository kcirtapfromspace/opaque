#!/bin/sh
# install.sh — download and install Opaque binaries
# Usage: curl -fsSL https://raw.githubusercontent.com/kcirtapfromspace/opaque/main/install.sh | sh
#
# Environment variables:
#   OPAQUE_VERSION   — version to install (default: latest)
#   OPAQUE_INSTALL   — install directory (default: /usr/local/bin)
#   GITHUB_TOKEN     — optional, for private repos or rate-limited API calls
set -eu

REPO="kcirtapfromspace/opaque"
INSTALL_DIR="${OPAQUE_INSTALL:-/usr/local/bin}"
BINARIES="opaqued opaque opaque-mcp opaque-approve-helper"

# --- helpers ----------------------------------------------------------------

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# --- detect platform --------------------------------------------------------

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os_part="unknown-linux-gnu" ;;
        Darwin) os_part="apple-darwin" ;;
        *)      die "unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64)   arch_part="x86_64" ;;
        aarch64|arm64)   arch_part="aarch64" ;;
        *)               die "unsupported architecture: $arch" ;;
    esac

    printf '%s-%s' "$arch_part" "$os_part"
}

# --- resolve version --------------------------------------------------------

resolve_version() {
    if [ -n "${OPAQUE_VERSION:-}" ]; then
        printf '%s' "$OPAQUE_VERSION"
        return
    fi

    need_cmd curl

    auth_header=""
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        auth_header="Authorization: token ${GITHUB_TOKEN}"
    fi

    # Fetch latest release tag from GitHub API
    if [ -n "$auth_header" ]; then
        latest="$(curl -fsSL -H "$auth_header" \
            "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)" \
            || die "failed to fetch latest release (API). Set OPAQUE_VERSION to install a specific version."
    else
        latest="$(curl -fsSL \
            "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)" \
            || die "failed to fetch latest release (API). Set OPAQUE_VERSION to install a specific version."
    fi

    # Parse tag_name from JSON without jq (POSIX sed)
    tag="$(printf '%s' "$latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
    [ -n "$tag" ] || die "could not determine latest version from GitHub API response"

    # Strip leading "v" prefix
    printf '%s' "${tag#v}"
}

# --- download & verify ------------------------------------------------------

download_and_install() {
    version="$1"
    target="$2"

    archive="opaque-${version}-${target}.tar.gz"
    url="https://github.com/${REPO}/releases/download/v${version}/${archive}"
    checksum_url="${url}.sha256"

    tmpdir="$(mktemp -d)" || die "failed to create temporary directory"
    trap 'rm -r -- "$tmpdir"' EXIT INT TERM

    printf 'Downloading opaque %s for %s...\n' "$version" "$target"

    # Download archive
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fSL -H "Authorization: token ${GITHUB_TOKEN}" \
            -o "${tmpdir}/${archive}" "$url" \
            || die "download failed: ${url}"
    else
        curl -fSL -o "${tmpdir}/${archive}" "$url" \
            || die "download failed: ${url}"
    fi

    # Download and verify checksum
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" \
            -o "${tmpdir}/${archive}.sha256" "$checksum_url" 2>/dev/null
    else
        curl -fsSL -o "${tmpdir}/${archive}.sha256" "$checksum_url" 2>/dev/null
    fi

    if [ -f "${tmpdir}/${archive}.sha256" ]; then
        verify_checksum "${tmpdir}" "${archive}"
    else
        printf 'warning: checksum file not available, skipping verification\n' >&2
    fi

    # Extract
    need_cmd tar
    tar xzf "${tmpdir}/${archive}" -C "${tmpdir}" \
        || die "failed to extract archive"

    # Install binaries
    printf 'Installing to %s...\n' "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR" || die "failed to create install directory: ${INSTALL_DIR}"

    for bin in $BINARIES; do
        if [ -f "${tmpdir}/${bin}" ]; then
            install -m 755 "${tmpdir}/${bin}" "${INSTALL_DIR}/${bin}" \
                || die "failed to install ${bin} to ${INSTALL_DIR}"
        else
            printf 'warning: binary %s not found in archive (may not be built for this platform)\n' "$bin" >&2
        fi
    done

    printf 'Successfully installed opaque %s to %s\n' "$version" "$INSTALL_DIR"
    printf 'Binaries: %s\n' "$BINARIES"
}

# --- checksum verification --------------------------------------------------

verify_checksum() {
    dir="$1"
    archive="$2"

    expected="$(awk '{print $1}' "${dir}/${archive}.sha256")"
    [ -n "$expected" ] || die "checksum file is empty or malformed"

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "${dir}/${archive}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "${dir}/${archive}" | awk '{print $1}')"
    else
        printf 'warning: neither sha256sum nor shasum found, skipping checksum verification\n' >&2
        return 0
    fi

    if [ "$expected" != "$actual" ]; then
        die "checksum mismatch: expected ${expected}, got ${actual}"
    fi

    printf 'Checksum verified.\n'
}

# --- main -------------------------------------------------------------------

main() {
    need_cmd curl
    need_cmd tar
    need_cmd mktemp
    need_cmd install

    target="$(detect_target)"
    version="$(resolve_version)"

    download_and_install "$version" "$target"
}

main
