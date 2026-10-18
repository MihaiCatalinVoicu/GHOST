#!/usr/bin/env bash
# fixture: a "build" that is not reproducible
set -euo pipefail
OUT="$(cd "$(dirname "$0")" && pwd)/out"
mkdir -p "$OUT"
echo "built lyrebird-linux-amd64 (fake)"
head -c 32 /dev/urandom | sha256sum | cut -d' ' -f1 > "$OUT/SHA256SUMS.har.new"
echo "  lyrebird-linux-amd64" >> "$OUT/SHA256SUMS.har.new"
mv "$OUT/SHA256SUMS.har.new" "$OUT/SHA256SUMS.har"
