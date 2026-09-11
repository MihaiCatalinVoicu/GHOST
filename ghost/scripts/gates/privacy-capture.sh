#!/usr/bin/env bash
# Gate T1: the relay-capture validator accepts the positive fixture and rejects every line of the
# negative fixture. From Phase 5 the same validator runs on real captures produced by relays in
# capture mode.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$GHOST_ROOT"
SCHEMA="test-harness/privacy/allowed-observables.json"
cargo run -q --locked -p ghost-capture-check -- --schema "$SCHEMA" --capture test-harness/privacy/fixtures/capture-ok.ndjson || fail "positive capture fixture rejected"
if cargo run -q --locked -p ghost-capture-check -- --schema "$SCHEMA" --capture test-harness/privacy/fixtures/capture-bad.ndjson 2>/dev/null; then
  fail "negative capture fixture was accepted"
fi
finish privacy-capture
