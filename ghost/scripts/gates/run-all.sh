#!/usr/bin/env bash
# Runs every static gate (fast; no SDK required). Build-dependent gates run in their own CI jobs.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0
# merged-manifest-lint.sh (T15m) needs the release build; the CI android job runs it after the build.
# The licence gates that read build outputs run where those exist (Phase 9 design §22.8.10 point 10):
# license-notices.sh rust, rust-license-headers.sh (G-R5) and mpl-sources.sh (G-L4) in the rust job
# (rust-gates.sh); license-notices.sh android (G-L1, G-L2) and apk-notices.sh (G-L3) in the android job.
for g in anti-placeholder no-logging issuer-output monero-pin manifest-lint dependency-allowlist proto-check sync-no-catch-all kotlin-clearnet no-public-binaries; do
  bash "$DIR/$g.sh" || rc=1
done
exit $rc
