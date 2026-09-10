#!/usr/bin/env bash
# Proves each gate actually fails on a known-bad tree (ADR-10: "demonstrated to fail on
# counter-examples"). The fixtures live in test-harness/gates/negative and mirror the layout of
# ghost/ so the gates scan them unchanged via GHOST_ROOT.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEG="$(cd "$DIR/../../test-harness/gates/negative" && pwd)"
rc=0
expect_fail() {
  local gate="$1"
  if GHOST_ROOT="$NEG" bash "$DIR/$gate.sh" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: $gate passed on the negative fixture" >&2; rc=1
  else
    echo "self-test ok: $gate rejects the negative fixture"
  fi
}
for g in anti-placeholder no-logging manifest-lint dependency-allowlist; do expect_fail "$g"; done
exit $rc
