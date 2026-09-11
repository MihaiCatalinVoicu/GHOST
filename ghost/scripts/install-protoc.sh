#!/usr/bin/env bash
# Installs a pinned protoc (FR-8.1): tonic-prost-build runs it at build time and its output is
# compiled into the relay and into libghost_client_net.so, so it is a build tool of the release.
# Usage: install-protoc.sh <install-dir>   (then add <install-dir>/bin to PATH). Linux x86_64 only.
set -euo pipefail
VERSION="36.1"
SHA256="c4bc672d9d49214dc8cafdceadf4df92182d6ca8e3ec65a56b2d7de5602669b4"
DEST="${1:?usage: install-protoc.sh <install-dir>}"
zip="$(mktemp)"
trap 'rm -f "$zip"' EXIT
curl -sSfL -o "$zip" "https://github.com/protocolbuffers/protobuf/releases/download/v$VERSION/protoc-$VERSION-linux-x86_64.zip"
echo "$SHA256  $zip" | sha256sum -c --quiet -
mkdir -p "$DEST"
unzip -q -o "$zip" -d "$DEST"
"$DEST/bin/protoc" --version
