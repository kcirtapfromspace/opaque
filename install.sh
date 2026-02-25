#!/bin/sh
# install.sh — download and install Opaque binaries
# Usage: curl -fsSL https://raw.githubusercontent.com/kcirtapfromspace/opaque/main/install.sh | sh
#   or:  sh install.sh [--no-verify]
#
# Flags:
#   --no-verify  Skip checksum verification when the .sha256 file is unavailable.
#                This does NOT skip verification when a checksum is downloaded but
#                does not match — mismatches always abort. Intended for air-gapped
#                environments where release checksums are not reachable.
#
# Environment variables:
#   OPAQUE_VERSION   — version to install (default: latest)
#   OPAQUE_INSTALL   — install directory (default: /usr/local/bin)
#   GITHUB_TOKEN     — optional, for private repos or rate-limited API calls
set -eu

REPO="kcirtapfromspace/opaque"
INSTALL_DIR="${OPAQUE_INSTALL:-/usr/local/bin}"
BINARIES="opaqued opaque opaque-mcp opaque-approve-helper"
NO_VERIFY=0

# --- flag parsing -----------------------------------------------------------

usage() {
    printf 'Usage: sh install.sh [--no-verify]\n'
    printf '\n'
    printf 'Flags:\n'
    printf '  --no-verify  Skip checksum verification when the .sha256 file is\n'
    printf '               unavailable. Mismatches still abort. For air-gapped\n'
    printf '               environments.\n'
    printf '\n'
    printf 'Environment variables:\n'
    printf '  OPAQUE_VERSION   version to install (default: latest)\n'
    printf '  OPAQUE_INSTALL   install directory  (default: /usr/local/bin)\n'
    printf '  GITHUB_TOKEN     optional, for private repos or rate-limited API\n'
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-verify)
                NO_VERIFY=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown flag: $1 (see --help)"
                ;;
        esac
        shift
    done
}

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

    # Download checksum file
    checksum_ok=0
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        if curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" \
            -o "${tmpdir}/${archive}.sha256" "$checksum_url" 2>/dev/null; then
            checksum_ok=1
        fi
    else
        if curl -fsSL -o "${tmpdir}/${archive}.sha256" "$checksum_url" 2>/dev/null; then
            checksum_ok=1
        fi
    fi

    # Verify checksum (fail-closed by default)
    if [ "$checksum_ok" = 1 ] && [ -f "${tmpdir}/${archive}.sha256" ]; then
        verify_checksum "${tmpdir}" "${archive}"
    else
        if [ "$NO_VERIFY" = 1 ]; then
            printf 'warning: checksum file not available, skipping verification (--no-verify)\n' >&2
        else
            die "checksum file not available for ${archive}; refusing to install without verification. Use --no-verify to skip checksum verification for air-gapped environments."
        fi
    fi

    # Opportunistic cosign signature verification
    verify_cosign_signature "${tmpdir}" "${archive}" "$url"

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
        die "neither sha256sum nor shasum found; cannot verify archive integrity. Install one of these tools or use --no-verify."
    fi

    if [ "$expected" != "$actual" ]; then
        die "checksum mismatch for ${archive}: expected ${expected}, got ${actual}. The archive may be corrupt or tampered with."
    fi

    printf 'Checksum verified.\n'
}

# --- cosign signature verification (opportunistic) --------------------------

verify_cosign_signature() {
    dir="$1"
    archive="$2"
    base_url="$3"

    if ! command -v cosign >/dev/null 2>&1; then
        return 0
    fi

    sig_url="${base_url}.sig"

    printf 'cosign detected, attempting signature verification...\n'

    # Download the .sig file
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        if ! curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" \
            -o "${dir}/${archive}.sig" "$sig_url" 2>/dev/null; then
            printf 'warning: signature file not available at %s, skipping cosign verification\n' "$sig_url" >&2
            return 0
        fi
    else
        if ! curl -fsSL -o "${dir}/${archive}.sig" "$sig_url" 2>/dev/null; then
            printf 'warning: signature file not available at %s, skipping cosign verification\n' "$sig_url" >&2
            return 0
        fi
    fi

    if cosign verify-blob \
        --signature "${dir}/${archive}.sig" \
        --certificate-identity-regexp ".*github\\.com/${REPO}.*" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${dir}/${archive}" 2>/dev/null; then
        printf 'Cosign signature verified.\n'
    else
        die "cosign signature verification failed for ${archive}. The archive may be tampered with."
    fi
}

# --- main -------------------------------------------------------------------

main() {
    parse_args "$@"

    need_cmd curl
    need_cmd tar
    need_cmd mktemp
    need_cmd install

    target="$(detect_target)"
    version="$(resolve_version)"

    download_and_install "$version" "$target"
}

main "$@"
