#!/usr/bin/env bash
# Self-test of scripts/device/dm-gate.sh (Phase 9 design §21.13 point 4: "the gate build type,
# scripts/device/dm-gate.sh, the digest export and a host re-store tool, each with a self-test";
# slice S12). The orchestrator runs against test-harness/device/fake-adb, which answers as two
# phones, and test-harness/device/fake-restore in place of the re-store tool: once honestly through
# every step it drives, and once per way a phone or the relay could lie; every lie must fail the
# step that checks it, and nothing the orchestrator writes may carry a contact card, a deposit
# credential or a message tag.
#
# What is tested elsewhere, and what is not tested at all:
#   - the re-store tool itself: client-core/net/tests/dm_restore.rs, against a real relay;
#   - the digest export's pure half (`OrderDigests`): the JVM test `OrderDigestsTest` pins it
#     against independently computed SHA-256 values. The fake phones compute digests of their own,
#     and the orchestrator only compares the two phones' digests with each other;
#   - the gate instrumentation (`GateInstrumentation`) needs Android and has never run: nothing on a
#     host exercises it (design §22.17).
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="$(cd "$DIR/../../test-harness/device" && pwd)"
FAKE="$HARNESS/fake-adb"
RESTORE="$HARNESS/fake-restore"
rc=0
ok() { echo "self-test ok: dm-gate $1"; }
bad() { echo "SELF-TEST FAIL: dm-gate $1" >&2; rc=1; }

run() { # bug step args... -> exit status; the output directory is $work/out
  local bug="$1"
  shift
  env GHOST_ADB="$FAKE" GHOST_RESTORE="$RESTORE" FAKE_ADB_DIR="$work/phones" FAKE_ADB_BUG="$bug" \
    GHOST_GATE_A=A GHOST_GATE_B=B GHOST_GATE_OUT="$work/out" GHOST_GATE_WAIT=5 GHOST_GATE_POLL=0 \
    GHOST_GATE_AIRPLANE=0 GHOST_GATE_SESSION=1 GHOST_GATE_KILL_AFTER=0 GHOST_GATE_BOOT=5 \
    ${FAKE_RESTORE_LIVE:+FAKE_RESTORE_LIVE="$FAKE_RESTORE_LIVE"} \
    bash "$DIR/dm-gate.sh" "$@" > "$work/stdout" 2> "$work/stderr"
}

# Runs steps in order, each a separate invocation as on the real phones; stops at the first failure.
steps() { # bug step [step ...]; a step with an argument is written "reorder:6"
  local bug="$1" s
  shift
  for s in "$@"; do
    # shellcheck disable=SC2086
    run "$bug" ${s//:/ } || return 1
  done
}

fresh() { work="$(mktemp -d)"; }

# The honest pair, through every step the orchestrator drives.
fresh
apk="$work/app-gate.apk"
printf 'not an apk' > "$apk"
if steps "" "install:$apk" establish reorder:6 restart:20 replay replay-restore keychange t25:0 digest; then
  ok "passes an honest pair of phones through install and steps 1, 2, 3, 4 (both parts), 5 and 6"
else
  bad "fails an honest pair: $(tail -n 2 "$work/stderr")"
fi
log="$work/out/dm-gate.log"
grep -q 'step1 both contacts VERIFIED' "$log" && ok "checks that both contacts are verified" || bad "does not check verification"
grep -q '^.* step1 safety digests equal: [0-9a-f]\{64\}$' "$log" && ok "records the safety digest" || bad "does not record the safety digest"
grep -q 'step2 order=[0-9a-f]\{64\} multiset=[0-9a-f]\{64\} count=' "$log" && ok "records the order and multiset digests" || bad "does not record the digests"
grep -q '^A pass HIGH$' "$work/phones/events" && grep -q 'step2 every session on A ran in HIGH mode' "$log" \
  && ok "runs A's step-2 sessions in HIGH mode" || bad "does not run A's sessions in HIGH mode"
grep -q '^A reboot$' "$work/phones/events" && grep -q '^B reboot$' "$work/phones/events" && ok "reboots both phones in step 3" || bad "does not reboot both phones"
grep -q '^A am force-stop$' "$work/phones/events" && grep -q '^A am kill$' "$work/phones/events" && grep -q '^B am force-stop$' "$work/phones/events" \
  && ok "kills the phones in the middle of their sessions with am kill and am force-stop" || bad "does not kill the phones"
grep -q 'step4 dm-restore: 5 blobs, 5 re-stored as new listings, 0 still live at the relay' "$log" && ok "records the re-store as new listings" || bad "does not record the re-store"
[ ! -e "$work/out/state/replay-capture" ] && ok "deletes the capture after the re-store" || bad "kept the capture"
grep -q 'step5 both directions deliver after the acknowledgement' "$log" && ok "records the key change's release and both directions" || bad "does not record the key change's release"
grep -q 'step6 the timed messages are gone on both phones' "$log" && grep -q 'the message tag is in none of them' "$log" \
  && ok "checks step 6's expiry and scans the export for the tag" || bad "does not check step 6"
card="$(env FAKE_ADB_DIR="$work/phones" "$FAKE" -s A shell am instrument -w -e cmd card x | sed -n 's/^INSTRUMENTATION_RESULT: card=//p')"
if [ -n "$card" ] && ! grep -rqF "$card" "$work/out" "$work/stdout"; then ok "writes no contact card anywhere"; else bad "wrote a contact card"; fi
credential="$(printf credential | sha256sum | cut -d' ' -f1)"
if ! grep -rqF "$credential" "$work/out" "$work/stdout"; then ok "leaves no deposit credential behind"; else bad "left a deposit credential behind"; fi
tag="$(cat "$work/phones/tag")"
if [ -n "$tag" ] && ! grep -qF "$tag" "$log" "$work/stdout"; then ok "logs no message tag"; else bad "logged the message tag"; fi
rm -rf "$work"

# Each lie fails its step.
lie() { # bug expected-text step... (the phones are established first)
  local bug="$1" want="$2"
  shift 2
  fresh
  if [ "$1" != establish ]; then run "$bug" establish > /dev/null 2>&1 || true; fi
  if steps "$bug" "$@"; then
    bad "passes a phone that lies ($bug)"
  elif grep -qF "$want" "$work/stderr" "$work/out/dm-gate.log" 2>/dev/null; then
    ok "refuses a phone that lies ($bug): $want"
  else
    bad "refuses the $bug lie for another reason: $(tail -n 1 "$work/stderr")"
  fi
  rm -rf "$work"
}
lie reorder "the order digests differ" reorder:4
lie duplicate "duplicates rendered" restart:3
lie safety "safety number digests differ" establish
lie unverified "not VERIFIED" establish
lie nohigh "did not run in HIGH mode" reorder:4
lie nochange "A never showed the key change" keychange
lie stale-identity "B's key change answered ALREADY_ACTIVE" keychange
lie replayed "B shows a replayed message" replay replay-restore
lie noexpiry "the timed messages are still shown" t25:0
lie leak-tag "the message tag is in an exported database file" t25:0

# A relay that still holds the originals: step 4 refuses to call the no-op a replay, stores
# nothing, and keeps the capture for a later run.
fresh
run "" establish > /dev/null 2>&1
run "" replay > /dev/null 2>&1
if FAKE_RESTORE_LIVE=1 run "" replay-restore; then
  bad "passes a replay the relay answered as a no-op"
elif grep -qF "the relay still holds 5 of the 5 originals" "$work/stderr" && [ -s "$work/out/state/replay-capture" ] && [ ! -e "$work/phones/restored" ]; then
  ok "refuses a replay of blobs the relay still holds, stores nothing and keeps the capture"
else
  bad "handles a live relay wrongly: $(tail -n 1 "$work/stderr")"
fi
rm -rf "$work"

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
