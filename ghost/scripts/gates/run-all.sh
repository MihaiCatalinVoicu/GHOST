#!/usr/bin/env bash
# Runs every static gate (fast; no SDK required). Build-dependent gates run in their own CI jobs.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0
for g in anti-placeholder no-logging manifest-lint dependency-allowlist proto-check sync-no-catch-all; do
  bash "$DIR/$g.sh" || rc=1
done
exit $rc
