#!/usr/bin/env bash
# Gate T1: the relay-capture validator accepts the positive fixture and rejects every line of
# the negative fixture. From Phase 5 the same validator runs on real captures produced by relays
# in capture mode.
# Phase 12 (PT-P2, design faza12-transports.md §12.5): the PT rows — the relay-shape fixtures
# recorded by the pt_loopback harness (the relay-visible byte class on the PT path must equal
# the direct path). The positive fixture's `pt` and `direct` signatures must be identical and
# non-trivial; a drifted negative fixture must be rejected. A missing or empty positive
# fixture fails (D28: a vacuous scan is not evidence).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$GHOST_ROOT"
SCHEMA="test-harness/privacy/allowed-observables.json"
cargo run -q --locked -p ghost-capture-check -- --schema "$SCHEMA" --capture test-harness/privacy/fixtures/capture-ok.ndjson || fail "positive capture fixture rejected"
if cargo run -q --locked -p ghost-capture-check -- --schema "$SCHEMA" --capture test-harness/privacy/fixtures/capture-bad.ndjson 2>/dev/null; then
  fail "negative capture fixture was accepted"
fi

# --- PT-P2: the relay-shape fixtures of the pt_loopback harness ---------------------------
PT_FIX="test-harness/privacy/fixtures/pt-relay-shape.txt"
[ -s "$PT_FIX" ] || fail "pt-relay-shape.txt missing or empty (record it from a pt_loopback run; D28: a vacuous scan is not evidence)"
shape_line() { # $1 = tag (pt|direct): prints "handshake=<...> alphabet=<...>"
  grep -E "^$1[[:space:]]" "$PT_FIX" | sed -n '1p'
}
pt_line="$(shape_line pt)"
dir_line="$(shape_line direct)"
[ -n "$pt_line" ] || fail "pt-relay-shape.txt has no 'pt' row"
[ -n "$dir_line" ] || fail "pt-relay-shape.txt has no 'direct' row"
pt_hand="$(sed -n 's/.*handshake=\(\[.*\)\] alphabet=.*/\1]/p' <<< "$pt_line")"
pt_alpha="$(sed -n 's/.*alphabet=\(\[.*\]\).*/\1/p' <<< "$pt_line")"
dir_hand="$(sed -n 's/.*handshake=\(\[.*\)\] alphabet=.*/\1]/p' <<< "$dir_line")"
dir_alpha="$(sed -n 's/.*alphabet=\(\[.*\]\).*/\1/p' <<< "$dir_line")"
[ -n "$pt_hand" ] && [ -n "$pt_alpha" ] && [ -n "$dir_hand" ] && [ -n "$dir_alpha" ] \
  || fail "pt-relay-shape.txt rows do not carry handshake/alphabet signatures"
[ "$pt_hand" != "[]" ] || fail "the pt row's handshake signature is empty (not a TLS record parse?)"
[ "$pt_hand" = "$dir_hand" ] || fail "PT-P2: the relay-visible handshake choreography differs between the PT and the direct path:\n  pt:     $pt_hand\n  direct: $dir_hand"
[ "$pt_alpha" = "$dir_alpha" ] || fail "PT-P2: the record alphabet differs:\n  pt:     $pt_alpha\n  direct: $dir_alpha"
grep -q '^# pt path:' "$PT_FIX" || fail "pt-relay-shape.txt carries no byte-size comment (not a harness record?)"

# The drifted twin must be rejected.
PT_NEG="test-harness/privacy/fixtures/pt-relay-shape-negative.txt"
if [ -f "$PT_NEG" ]; then
  neg_hand="$(grep -E '^pt[[:space:]]' "$PT_NEG" | sed -n '1p' | sed -n 's/.*handshake=\(\[.*\)\] alphabet=.*/\1]/p')"
  [ -n "$neg_hand" ] && [ "$neg_hand" != "$dir_hand" ] || fail "the negative PT shape fixture no longer drifts (it would pass vacuously)"
else
  fail "pt-relay-shape-negative.txt missing (the PT rows' negative fixture)"
fi

finish privacy-capture
