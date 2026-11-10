#!/usr/bin/env bash
# monero-regtest.sh — the local equivalent of the legacy .github/workflows/monero-regtest.yml
# (Phase 8 design §13.3/§13.6/§14.2, §19.17 point 7; ADR-26; ADR-58: CI is local). The pinned
# monerod and monero-wallet-rpc on regtest, driven by the issuer's production rail and handlers
# (ghost/issuer/crates/service/tests/monero_regtest.rs). Runs on Linux only (the pinned archive
# is linux-x64) — locally that means the ghost-runner WSL distro.
#
# Steps, unchanged from the workflow: read the pin (infra/issuer/monero-release.pin, linux-x64
# row), download the archive if not already cached, sha256sum -c against the pin before every
# extraction (a cache hit included), extract monerod + monero-wallet-rpc, build the operator
# tools (ghost-issuer-ops), run the regtest scenario on the release profile with
# MONERO_RANDOMX_FULL_MEM=1 (the WSL2 light-mode RandomX hash rate measured in the workflow's
# comment) and --test-threads=1.
#
# Usage: monero-regtest.sh [--work <dir>]
#   --work  cache/report directory (default: <repo>/t2-reports/monero-regtest; the archive cache
#           lives in <work>/monero-archive, the binaries in <work>/monero-bin)
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
PIN="$GHOST/infra/issuer/monero-release.pin"
WORK="$GHOST/t2-reports/monero-regtest"
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    *) echo "monero-regtest: unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$(uname -s)" in
  Linux) ;;
  *) echo "monero-regtest: the pinned archive is linux-x64; run this in the ghost-runner WSL distro" >&2; exit 2 ;;
esac

read -r _ platform file sha mdir < <(awk '$1 == "archive" && $2 == "linux-x64"' "$PIN")
url="$(awk '$1 == "url" {print $2}' "$PIN")"
[ "$platform" = linux-x64 ] && [ -n "$file" ] && [ -n "$sha" ] && [ -n "$mdir" ] && [ -n "$url" ] || \
  { echo "monero-regtest: $PIN has no usable linux-x64 archive row" >&2; exit 2; }

mkdir -p "$WORK/monero-archive" "$WORK/monero-bin"
( cd "$WORK/monero-archive" && \
  [ -f "$file" ] || curl -fsSL --retry 3 -o "$file" "$url$file"; \
  echo "$sha  $file" | sha256sum -c - && \
  tar -xjf "$file" -C "$WORK/monero-bin" --strip-components=1 "$mdir/monerod" "$mdir/monero-wallet-rpc" ) || \
  { echo "monero-regtest: download/digest/extract failed against the pin" >&2; exit 1; }
"$WORK/monero-bin/monerod" --version

( cd "$GHOST" && cargo build -p ghost-issuer-ops --release --locked ) || \
  { echo "monero-regtest: the operator tools build failed" >&2; exit 1; }

( cd "$GHOST" && \
  GHOST_MONERO_BIN="$WORK/monero-bin" MONERO_RANDOMX_FULL_MEM=1 \
  GHOST_ISSUER_OPS="$GHOST/target/release/ghost-issuer-ops" \
    cargo test -p ghost-issuer --release --locked --test monero_regtest -- --ignored --test-threads=1 ) \
  2>&1 | tee "$WORK/monero-regtest.txt"
rc=${PIPESTATUS[0]}
[ "$rc" = 0 ] && echo "monero-regtest: PASS" || echo "monero-regtest: FAIL (report: $WORK/monero-regtest.txt)" >&2
exit "$rc"
