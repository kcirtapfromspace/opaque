#!/bin/sh
# Opaque installer — POSIX-compatible shell script.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/anthropics/opaque/main/install.sh | sh
#
# Environment variables:
#   OPAQUE_VERSION  — version to install (default: latest)
#   INSTALL_DIR     — installation directory (default: ~/.local/bin)

set -eu

REPO="anthropics/opaque"
GITHUB="https://github.com/${REPO}"
BINARIES="opaqued opaque opaque-mcp opaque-approve-helper opaque-web"

# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

err() {
    printf "error: %s\n" "$1" >&2
    exit 1
}

info() {
    printf "  %s\n" "$1"
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        err "need '$1' (command not found)"
    fi
}

# --------------------------------------------------------------------------- #
# Platform detection                                                          #
# --------------------------------------------------------------------------- #

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS="unknown-linux-gnu" ;;
        Darwin) OS="apple-darwin" ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            err "Windows is not supported. Please use WSL2 and re-run this script inside the Linux environment."
            ;;
        *)
            err "unsupported operating system: $OS"
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="x86_64" ;;
        aarch64|arm64)   ARCH="aarch64" ;;
        *)
            err "unsupported architecture: $ARCH"
            ;;
    esac

    TARGET="${ARCH}-${OS}"
}

# --------------------------------------------------------------------------- #
# Version resolution                                                          #
# --------------------------------------------------------------------------- #

resolve_version() {
    if [ -n "${OPAQUE_VERSION:-}" ]; then
        VERSION="$OPAQUE_VERSION"
        return
    fi

    need_cmd curl

    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/')" \
        || err "failed to determine latest release version — set OPAQUE_VERSION and retry"

    if [ -z "$VERSION" ]; then
        err "could not parse latest release version from GitHub API"
    fi
}

# --------------------------------------------------------------------------- #
# Download and verify                                                         #
# --------------------------------------------------------------------------- #

download_and_install() {
    TARBALL="opaque-v${VERSION}-${TARGET}.tar.gz"
    URL="${GITHUB}/releases/download/v${VERSION}/${TARBALL}"
    CHECKSUM_URL="${GITHUB}/releases/download/v${VERSION}/${TARBALL}.sha256"

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    info "downloading ${TARBALL} ..."
    curl -fsSL -o "${TMPDIR}/${TARBALL}" "$URL" \
        || err "download failed — does release v${VERSION} exist for ${TARGET}?"

    info "downloading checksum ..."
    if curl -fsSL -o "${TMPDIR}/${TARBALL}.sha256" "$CHECKSUM_URL" 2>/dev/null; then
        info "verifying SHA256 checksum ..."
        EXPECTED="$(awk '{print $1}' "${TMPDIR}/${TARBALL}.sha256")"
        if command -v sha256sum > /dev/null 2>&1; then
            ACTUAL="$(sha256sum "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
        elif command -v shasum > /dev/null 2>&1; then
            ACTUAL="$(shasum -a 256 "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
        else
            info "warning: no sha256sum or shasum found — skipping verification"
            ACTUAL="$EXPECTED"
        fi

        if [ "$EXPECTED" != "$ACTUAL" ]; then
            err "checksum mismatch (expected ${EXPECTED}, got ${ACTUAL})"
        fi
        info "checksum OK"
    else
        info "warning: checksum file not found — skipping verification"
    fi

    info "extracting ..."
    tar xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

    # The tarball contains a directory named opaque-v<version>-<target>/
    EXTRACT_DIR="${TMPDIR}/opaque-v${VERSION}-${TARGET}"
    if [ ! -d "$EXTRACT_DIR" ]; then
        # Fallback: binaries may be at the root of the tarball
        EXTRACT_DIR="$TMPDIR"
    fi

    # Determine install directory
    INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"

    if [ -w "$INSTALL_DIR" ] 2>/dev/null || mkdir -p "$INSTALL_DIR" 2>/dev/null; then
        SUDO=""
    elif [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
        SUDO=""
    else
        INSTALL_DIR="/usr/local/bin"
        SUDO="sudo"
        info "installing to ${INSTALL_DIR} (requires sudo) ..."
    fi

    $SUDO mkdir -p "$INSTALL_DIR" 2>/dev/null || true

    for BIN in $BINARIES; do
        if [ -f "${EXTRACT_DIR}/${BIN}" ]; then
            $SUDO install -m 755 "${EXTRACT_DIR}/${BIN}" "${INSTALL_DIR}/${BIN}"
        fi
    done

    info "installed to ${INSTALL_DIR}"
}

# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #

main() {
    printf "\n  Opaque Installer\n\n"

    need_cmd curl
    need_cmd tar
    need_cmd uname

    detect_platform
    info "detected platform: ${TARGET}"

    resolve_version
    info "version: ${VERSION}"

    download_and_install

    printf "\n"
    info "Installation complete!"
    printf "\n"

    # Check if install dir is in PATH
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            info "Add ${INSTALL_DIR} to your PATH:"
            info "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            printf "\n"
            ;;
    esac

    info "Get started:"
    info "  opaque init"
    printf "\n"
}

main
