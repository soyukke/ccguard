#!/bin/bash
# ensure-binary.sh — Download ccguard binary for the current platform.
# Called by SessionStart hook. Skips download if binary is already up-to-date.
set -euo pipefail

REPO="soyukke/ccguard"
DATA_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.local/share/ccguard}"
BIN_DIR="${DATA_DIR}/bin"
BIN_PATH="${BIN_DIR}/ccguard"
VERSION_FILE="${DATA_DIR}/.version"
CHECK_FILE="${DATA_DIR}/.last_check"
EXPECTED_VERSION="${CCGUARD_VERSION:-}"

# Read expected version from plugin.json if not set
if [ -z "$EXPECTED_VERSION" ]; then
  PLUGIN_JSON="${CLAUDE_PLUGIN_ROOT:-.}/.claude-plugin/plugin.json"
  if [ -f "$PLUGIN_JSON" ]; then
    EXPECTED_VERSION=$(grep '"version"' "$PLUGIN_JSON" | head -1 | sed 's/.*: *"\(.*\)".*/\1/')
  fi
fi

# Skip if binary exists and version matches
if [ -x "$BIN_PATH" ] && [ -f "$VERSION_FILE" ]; then
  INSTALLED=$(cat "$VERSION_FILE")
  if [ "$INSTALLED" = "$EXPECTED_VERSION" ]; then
    exit 0
  fi
fi

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin) OS_TAG="macos" ;;
  linux)  OS_TAG="linux" ;;
  *)
    echo "ccguard: unsupported OS: $OS" >&2
    exit 0  # Don't block session start
    ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH_TAG="x86_64" ;;
  arm64|aarch64) ARCH_TAG="aarch64" ;;
  *)
    echo "ccguard: unsupported architecture: $ARCH" >&2
    exit 0
    ;;
esac

ASSET="ccguard-${ARCH_TAG}-${OS_TAG}.tar.gz"

# Determine download URL
if [ -n "$EXPECTED_VERSION" ]; then
  URL="https://github.com/${REPO}/releases/download/v${EXPECTED_VERSION}/${ASSET}"
else
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
fi

# Download and install
mkdir -p "$BIN_DIR"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "ccguard: downloading ${ASSET}..." >&2
if curl -fsSL "$URL" -o "${TMPDIR}/${ASSET}"; then
  tar xzf "${TMPDIR}/${ASSET}" -C "$TMPDIR"
  mv "${TMPDIR}/ccguard" "$BIN_PATH"
  chmod +x "$BIN_PATH"
  echo "$EXPECTED_VERSION" > "$VERSION_FILE"
  echo "ccguard: installed v${EXPECTED_VERSION} (${ARCH_TAG}-${OS_TAG})" >&2
else
  echo "ccguard: download failed (${URL}), using existing binary if available" >&2
  exit 0  # Don't block session start on download failure
fi
