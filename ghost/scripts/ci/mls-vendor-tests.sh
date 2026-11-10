#!/usr/bin/env bash
# mls-vendor-tests.sh — the local equivalent of the legacy
# .github/workflows/mls-vendor-tests.yml (ADR-58: CI is local). Its two steps call scripts that
# already exist locally; this wrapper runs both and keeps their reports:
#   1. vendor-tests.sh openmls <work> — the pinned crates.io package checked against the lock's
#      checksum, its .cargo_vcs_info.json against the commit, every checkout blob id, then the
#      openmls lib suite at its pinned features;
#   2. mls-advisories.sh <work> — the dev-dependency advisories the vendored checkouts cannot
#      reach from cargo-deny/cargo-audit, queried at the pins.
#
# Usage: mls-vendor-tests.sh [--work <dir>]
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
WORK="$GHOST/t2-reports/mls-vendor-tests"
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    *) echo "mls-vendor-tests: unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"
rc=0

( cd "$GHOST" && bash scripts/ci/vendor-tests.sh openmls "$WORK/openmls" ) \
  2>&1 | tee "$WORK/openmls-summary.txt"
[ "${PIPESTATUS[0]}" = 0 ] || rc=1

( cd "$GHOST" && bash scripts/ci/mls-advisories.sh "$WORK/advisories" ) \
  2>&1 | tee "$WORK/advisories.txt"
[ "${PIPESTATUS[0]}" = 0 ] || rc=1

[ "$rc" = 0 ] && echo "mls-vendor-tests: PASS (reports in $WORK)" || \
  echo "mls-vendor-tests: FAIL (reports in $WORK)" >&2
exit "$rc"
