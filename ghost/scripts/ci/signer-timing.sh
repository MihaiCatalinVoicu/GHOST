#!/usr/bin/env bash
# signer-timing.sh — the local equivalent of the legacy .github/workflows/signer-timing.yml
# (Phase 8 design §2.8 point 6, §13.7, §19.27/§19.30, S12 CR-CT-1; ADR-58: CI is local). The
# dudect-style Welch t-test of ghost/issuer/crates/service/tests/signer_timing.rs: 10^5 samples,
# a fixed blinded value against random ones, each stage of
# CheckedSigner<ReferenceSigner>::blind_sign timed separately; |t| > 4.5 on the private-key
# operation fails. Not a gate: a noisy machine can fail it too — the report is where a human
# reruns and reads the numbers (the workflow opened a GitHub issue on failure; locally the
# failing exit code and the kept report play that role).
#
# Usage: signer-timing.sh [--work <dir>]
#   --work  report directory (default: <repo>/t2-reports/signer-timing)
# Requires: protoc reachable (install-protoc.sh is what CI used) or PROTOC set.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
WORK="$GHOST/t2-reports/signer-timing"
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    *) echo "signer-timing: unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$WORK"

( cd "$GHOST" && cargo test -p ghost-issuer --release --locked --test signer_timing --no-run ) || \
  { echo "signer-timing: the release build of the timing test failed" >&2; exit 1; }

( cd "$GHOST" && cargo test -p ghost-issuer --release --locked --test signer_timing \
    -- --ignored --exact blind_sign_time_does_not_depend_on_the_blinded_value --nocapture ) \
  2>&1 | tee "$WORK/signer-timing.txt"
rc=${PIPESTATUS[0]}

grep -E 'Welch t|samples|above' "$WORK/signer-timing.txt" | head -n 10 || true
if [ "$rc" = 0 ]; then
  echo "signer-timing: PASS (report: $WORK/signer-timing.txt)"
else
  echo "signer-timing: FAIL (report kept at $WORK/signer-timing.txt — rerun on a quiet machine and read the numbers)" >&2
fi
exit "$rc"
