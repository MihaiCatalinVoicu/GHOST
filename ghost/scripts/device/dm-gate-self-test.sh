#!/usr/bin/env bash
# Self-test of scripts/device/dm-gate.sh (Phase 9 design §21.13 point 4: "the gate build type,
# scripts/device/dm-gate.sh, the digest export and a host re-store tool, each with a self-test";
# slice S12). The orchestrator runs against test-harness/device/fake-adb, which answers as two
# phones, once honestly and once per way a phone could lie; every lie must fail the step that
# checks it, and nothing the orchestrator writes may carry a contact card.
#
# The re-store tool's own self-test is client-core/net/tests/dm_restore.rs; the gate variant's
# digest export is exercised on the devices (it needs Android) and its pure half, OrderDigests, by
# the same digests this script compares.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAKE="$(cd "$DIR/../../test-harness/device" && pwd)/fake-adb"
rc=0
ok() { echo "self-test ok: dm-gate $1"; }
bad() { echo "SELF-TEST FAIL: dm-gate $1" >&2; rc=1; }

run() { # bug step... -> exit status; the output directory is $work/out
  local bug="$1"
  shift
  env GHOST_ADB="$FAKE" FAKE_ADB_DIR="$work/phones" FAKE_ADB_BUG="$bug" GHOST_GATE_A=A GHOST_GATE_B=B \
    GHOST_GATE_OUT="$work/out" GHOST_GATE_WAIT=5 GHOST_GATE_POLL=0 GHOST_GATE_AIRPLANE=0 \
    bash "$DIR/dm-gate.sh" "$@" > "$work/stdout" 2> "$work/stderr"
}

fresh() { work="$(mktemp -d)"; }

# The honest pair: establishment, a reorder burst, a restart run and the key change all pass, and
# the log records digests and no card.
fresh
if run "" establish && run "" reorder 6 && run "" restart 7 && run "" keychange && run "" digest; then
  ok "passes an honest pair of phones through steps 1, 2, 3 and 5"
else
  bad "fails an honest pair: $(tail -n 2 "$work/stderr")"
fi
grep -q '^.* step1 safety digests equal: [0-9a-f]\{64\}$' "$work/out/dm-gate.log" && ok "records the safety digest" || bad "does not record the safety digest"
grep -q 'step2 order=[0-9a-f]\{64\} multiset=[0-9a-f]\{64\} count=' "$work/out/dm-gate.log" && ok "records the order and multiset digests" || bad "does not record the digests"
grep -q 'step5 held message released once after acknowledgement' "$work/out/dm-gate.log" && ok "records the key change's release" || bad "does not record the key change's release"
card="$(env FAKE_ADB_DIR="$work/phones" "$FAKE" -s A shell am instrument -w -e cmd card x | sed -n 's/^INSTRUMENTATION_RESULT: card=//p')"
if [ -n "$card" ] && ! grep -rqF "$card" "$work/out" "$work/stdout"; then ok "writes no contact card anywhere"; else bad "wrote a contact card"; fi
rm -rf "$work"

# Each lie fails its step.
lie() { # bug expected-text steps...
  local bug="$1" want="$2"
  shift 2
  fresh
  run "$bug" establish > /dev/null 2>&1 || true
  if [ "$1" = establish ]; then shift; fi
  if [ $# -gt 0 ] && run "$bug" "$@"; then
    bad "passes a phone that lies ($bug)"
  elif [ $# -eq 0 ] && run "$bug" establish; then
    bad "passes a phone that lies ($bug)"
  elif grep -qF "$want" "$work/stderr" "$work/out/dm-gate.log" 2>/dev/null; then
    ok "refuses a phone that lies ($bug): $want"
  else
    bad "refuses the $bug lie for another reason: $(tail -n 1 "$work/stderr")"
  fi
  rm -rf "$work"
}
lie reorder "the order digests differ" reorder 4
lie duplicate "duplicates rendered" restart 3
lie safety "safety number digests differ" establish
lie nochange "A never showed the key change" keychange

# The leak bug adds a second copy of the card to the card command's answer: the orchestrator reads
# only the key it asked for, so the log still carries no card.
fresh
run leak establish > /dev/null 2>&1
card="$(env FAKE_ADB_DIR="$work/phones" FAKE_ADB_BUG=leak "$FAKE" -s B shell am instrument -w -e cmd card x | sed -n 's/^INSTRUMENTATION_RESULT: card=//p')"
if ! grep -rqF "$card" "$work/out" "$work/stdout" "$work/stderr"; then ok "keeps an over-answering phone's card out of its output"; else bad "logged a card"; fi
rm -rf "$work"

# A usage error is not a pass.
if env GHOST_ADB="$FAKE" GHOST_GATE_A=A GHOST_GATE_B=B bash "$DIR/dm-gate.sh" no-such-step > /dev/null 2>&1; then
  bad "accepts an unknown step"
else
  ok "refuses an unknown step"
fi
exit $rc
