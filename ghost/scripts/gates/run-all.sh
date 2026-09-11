#!/usr/bin/env bash
# Runs every static gate (fast; no SDK required). Build-dependent gates run in their own CI jobs.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0
# merged-manifest-lint.sh (T15m) needs the release build; the CI android job runs it after the build.
for g in anti-placeholder no-logging manifest-lint dependency-allowlist proto-check sync-no-catch-all kotlin-clearnet; do
  bash "$DIR/$g.sh" || rc=1
done
exit $rc
