#!/usr/bin/env bash
# GHOST Phase 12 — fetch the loopback harness's pinned Tor (expert bundle).
#
# Downloads the pinned tarball of ghost/third_party/tor-expert/pins.env from
# archive.torproject.org, verifies its SHA-256 against the pin BEFORE anything is
# extracted (the monero-pin discipline), and unpacks it under .cache/ (git-ignored).
# Idempotent: a cached, hash-verified extract is reused.
#
# The harness (client-core/net/tests/pt_loopback.rs) resolves tor from
#   $GHOST_PT_TOR  >  .cache/tor-expert/tor/tor.exe (windows) or .../tor/tor (linux).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"         # ghost/third_party/tor-expert
CACHE="$HERE/.cache"
source "$HERE/pins.env"

case "$(uname -s)" in
  *_NT | MINGW* | MSYS* | CYGWIN*)
    TARBALL="$TOR_EXPERT_WINDOWS_TARBALL"
    SHA256="$TOR_EXPERT_WINDOWS_TARBALL_SHA256"
    TOR_BIN="tor/tor.exe"
    ;;
  *)
    TARBALL="$TOR_EXPERT_LINUX_TARBALL"
    SHA256="$TOR_EXPERT_LINUX_TARBALL_SHA256"
    TOR_BIN="tor/tor"
    ;;
esac

BASE="https://archive.torproject.org/tor-package-archive/torbrowser/$TOR_EXPERT_VERSION"
DEST="$CACHE/tor-expert"

# Reuse a cached extract only when the binary inside reports the pinned version, so a
# half-finished or wrong-tree extract can never satisfy a later run silently.
version_ok() {
  [ -x "$DEST/$TOR_BIN" ] || return 1
  "$DEST/$TOR_BIN" --version 2>/dev/null | grep -q "Tor version $TOR_EXPERT_TOR_VERSION"
}

if version_ok; then
  echo "[tor-expert] cached $TARBALL ($DEST/$TOR_BIN)"
else
  mkdir -p "$CACHE"
  echo "[tor-expert] fetching $BASE/$TARBALL"
  curl -fsSL -o "$CACHE/$TARBALL" "$BASE/$TARBALL"
  echo "$SHA256  $CACHE/$TARBALL" | sha256sum -c -
  rm -rf "$DEST" "$CACHE/extract.tmp"
  mkdir -p "$CACHE/extract.tmp"
  tar -xzf "$CACHE/$TARBALL" -C "$CACHE/extract.tmp"
  mv "$CACHE/extract.tmp" "$DEST"
  version_ok || { echo "[tor-expert] FAIL: extracted tor does not report $TOR_EXPERT_TOR_VERSION" >&2; exit 1; }
  echo "[tor-expert] extracted and version-verified ($DEST/$TOR_BIN)"
fi

echo "[tor-expert] tor: $DEST/$TOR_BIN"
"$DEST/$TOR_BIN" --version | head -1
