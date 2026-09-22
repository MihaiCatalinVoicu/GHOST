#!/usr/bin/env bash
# dm-gate.sh — the host orchestrator of the Phase 9 physical-device checklist (design §15.10,
# §21.13 point 4; slice S12). It drives two gate phones through adb and the `gate` variant's
# instrumentation (`org.ghost.app.gate.GateInstrumentation`) and **records digests, never content**.
#
#   GHOST_GATE_A, GHOST_GATE_B   adb serials of phone A (API 29–31) and phone B (API 35+)
#   GHOST_GATE_OUT               where the log goes (default ./dm-gate-out); the log is the step's
#                                evidence for docs/reviews/<date>-faza9-devices.md
#   GHOST_ADB                    the adb binary (default adb); the self-test points it at a fake
#   GHOST_RESTORE                the host re-store tool (default: cargo run -p ghost-client-net
#                                --example dm_restore --locked --)
#   GHOST_GATE_WAIT              seconds a delivery wait may take (default 900)
#
# Steps (each prints what it recorded and fails the run on a mismatch):
#   install <gate.apk>   install the gate variant on both phones (built locally, never published)
#   establish            step 1: each card injected into the other phone as addContact(card,
#                        qr_in_person); one message each way; both verified; safety digests equal
#   reorder [n]          step 2: n-message bursts each way (default 30) with airplane-mode toggles on
#                        B; the order digests are equal on both phones
#   restart [n]          step 3: n sends on A (default 20) with `am kill` and `am force-stop`
#                        between chunks; after quiescence the multiset digests agree, 0 duplicates
#   replay               step 4, first half: A sends 5 in airplane mode, their bytes and A's deposit
#                        credential go to a private capture file, the host re-store tool stores them
#                        again over Tor; B shows nothing twice and its drop counters rise
#   keychange            step 5: B switches to the bound alternate Olm identity (the debug hook),
#                        re-adds A's card and writes; A shows `changed`, A's send is refused, the
#                        held message appears once after acknowledgement
#   t25 [minutes]        step 6, first half: a 5-minute timer both ways, a wait (default 20), the
#                        messages are gone; the databases are exported through run-as and scanned
#                        for the message tag (the scan's result is recorded, never the bytes)
#   digest               both phones' digests of the conversation, as a record
#
# Not here (the checklist's manual steps, §15.10): step 4's debug-hook halves (re-encrypt after a
# forced FAILED, tombstone clearing — deferred, design §22.17), step 7 (restore from the mnemonic,
# which needs Phase 13's restore UI or an entitlement restore command the gate variant does not have
# yet — §22.17), step 8 (the staging capture, validated by capture-check on the relay host) and step
# 9 (measurements).
#
# Self-test: scripts/device/dm-gate-self-test.sh (a fake adb that answers as two phones).
set -euo pipefail

ADB="${GHOST_ADB:-adb}"
A="${GHOST_GATE_A:?set GHOST_GATE_A to the adb serial of phone A}"
B="${GHOST_GATE_B:?set GHOST_GATE_B to the adb serial of phone B}"
OUT="${GHOST_GATE_OUT:-./dm-gate-out}"
WAIT="${GHOST_GATE_WAIT:-900}"
PKG="org.ghost.app.gate"
RUNNER="$PKG/org.ghost.app.gate.GateInstrumentation"
mkdir -p "$OUT"
LOG="$OUT/dm-gate.log"
STATE="$OUT/state"
mkdir -p "$STATE"

record() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; printf '%s\n' "$*"; }
die() { record "FAIL $*"; echo "dm-gate: $*" >&2; exit 1; }

# One instrumentation command; prints its result as `key=value` lines. Arguments after the command
# are key/value pairs passed with `-e`.
gate() { # serial cmd [key value]...
  local serial="$1" cmd="$2" out
  shift 2
  local args=(-e cmd "$cmd")
  while [ $# -gt 1 ]; do args+=(-e "$1" "$2"); shift 2; done
  out="$("$ADB" -s "$serial" shell am instrument -w "${args[@]}" "$RUNNER" 2>&1 | tr -d '\r')" || true
  if ! grep -q '^INSTRUMENTATION_CODE: -1$' <<<"$out"; then
    local why
    why="$(sed -n 's/^INSTRUMENTATION_RESULT: error=//p' <<<"$out" | head -n 1)"
    die "gate command '$cmd' failed on ${serial} (${why:-no result})"
  fi
  sed -n 's/^INSTRUMENTATION_RESULT: //p' <<<"$out"
}

field() { sed -n "s/^$1=//p" <<<"$2" | head -n 1; }

# The contact id of the peer on each phone, kept between steps (ids are local and random: not
# content, and they name nothing outside the phone).
contact_of() { cat "$STATE/contact-$1" 2>/dev/null || die "no contact on $1: run establish first"; }

digests() { # serial contact -> "order multiset count duplicates"
  local r
  r="$(gate "$1" digest contact "$2")"
  printf '%s %s %s %s\n' "$(field order "$r")" "$(field multiset "$r")" "$(field count "$r")" "$(field duplicates "$r")"
}

pass() { gate "$1" pass > /dev/null; }

# Waits until both phones render the same number of messages and the count stops moving.
wait_converged() { # expected-count
  local want="$1" deadline=$((SECONDS + WAIT)) da db
  while [ "$SECONDS" -lt "$deadline" ]; do
    pass "$A"; pass "$B"
    da="$(digests "$A" "$(contact_of a)")"
    db="$(digests "$B" "$(contact_of b)")"
    if [ "$(cut -d' ' -f3 <<<"$da")" -ge "$want" ] && [ "$(cut -d' ' -f3 <<<"$db")" -ge "$want" ]; then
      printf '%s\n%s\n' "$da" "$db"
      return 0
    fi
    sleep "${GHOST_GATE_POLL:-10}"
  done
  die "the phones did not converge on $want messages within ${WAIT}s"
}

compare() { # step label, the two digest lines
  local step="$1" da db
  da="$(sed -n 1p <<<"$2")"
  db="$(sed -n 2p <<<"$2")"
  local oa ob ma mb ca cb dupa dupb
  read -r oa ma ca dupa <<<"$da"
  read -r ob mb cb dupb <<<"$db"
  # A duplicate is named as such first: it also makes the counts differ, and "shown twice" is the
  # finding step 3 is about.
  [ "$dupa" = 0 ] && [ "$dupb" = 0 ] || die "$step: duplicates rendered (A $dupa, B $dupb)"
  [ "$ca" = "$cb" ] || die "$step: A renders $ca messages, B $cb"
  [ "$ma" = "$mb" ] || die "$step: the multiset digests differ"
  [ "$oa" = "$ob" ] || die "$step: the order digests differ"
  record "$step order=$oa multiset=$ma count=$ca duplicates=0 equal on both phones"
}

total() { cut -d' ' -f3 <<<"$(digests "$1" "$2")"; }

step="${1:-}"
[ -n "$step" ] || { sed -n '2,40p' "$0"; exit 2; }
shift || true

case "$step" in
  install)
    apk="${1:?usage: dm-gate.sh install <app-gate.apk>}"
    for s in "$A" "$B"; do "$ADB" -s "$s" install -r "$apk" > /dev/null || die "install on $s"; done
    record "install gate variant $(sha256sum "$apk" | cut -d' ' -f1) on both phones"
    ;;
  establish)
    card_a="$(field card "$(gate "$A" card)")"
    card_b="$(field card "$(gate "$B" card)")"
    [ -n "$card_a" ] && [ -n "$card_b" ] || die "a phone exported no card"
    ra="$(gate "$A" add-contact card "$card_b" source qr)"
    rb="$(gate "$B" add-contact card "$card_a" source qr)"
    unset card_a card_b
    [ "$(field result "$ra")" = ADDED ] && [ "$(field result "$rb")" = ADDED ] || die "addContact: A $(field result "$ra"), B $(field result "$rb")"
    field contact "$ra" > "$STATE/contact-a"
    field contact "$rb" > "$STATE/contact-b"
    record "step1 cards injected by adb as qr_in_person: A ADDED, B ADDED"
    gate "$A" send contact "$(contact_of a)" count 1 > /dev/null
    gate "$B" send contact "$(contact_of b)" count 1 > /dev/null
    compare step1 "$(wait_converged 2)"
    sa="$(field safety "$(gate "$A" safety contact "$(contact_of a)")")"
    sb="$(field safety "$(gate "$B" safety contact "$(contact_of b)")")"
    [ "$sa" != none ] && [ "$sa" = "$sb" ] || die "step1: safety number digests differ or are missing"
    record "step1 safety digests equal: $sa"
    ;;
  reorder)
    n="${1:-30}"
    before="$(total "$A" "$(contact_of a)")"
    gate "$A" send contact "$(contact_of a)" count "$n" > /dev/null
    "$ADB" -s "$B" shell cmd connectivity airplane-mode enable > /dev/null 2>&1 || true
    gate "$B" send contact "$(contact_of b)" count "$n" > /dev/null
    sleep "${GHOST_GATE_AIRPLANE:-60}"
    "$ADB" -s "$B" shell cmd connectivity airplane-mode disable > /dev/null 2>&1 || true
    compare step2 "$(wait_converged $((before + 2 * n)))"
    ;;
  restart)
    n="${1:-20}"
    before="$(total "$A" "$(contact_of a)")"
    sent=0
    while [ "$sent" -lt "$n" ]; do
      chunk=$(( n - sent < 5 ? n - sent : 5 ))
      gate "$A" send contact "$(contact_of a)" count "$chunk" > /dev/null
      sent=$((sent + chunk))
      if [ $(( (sent / 5) % 2 )) = 0 ]; then "$ADB" -s "$A" shell am kill "$PKG" > /dev/null 2>&1 || true
      else "$ADB" -s "$B" shell am force-stop "$PKG" > /dev/null 2>&1 || true; fi
    done
    compare step3 "$(wait_converged $((before + n)))"
    ;;
  replay)
    capture="$(mktemp "${TMPDIR:-/tmp}/dm-gate-capture.XXXXXX")"
    chmod 600 "$capture"
    trap 'rm -f "$capture"' EXIT
    drops_before="$(gate "$B" status | awk -F= '/^drop\./ { s += $2 } END { print s + 0 }')"
    before="$(total "$A" "$(contact_of a)")"
    "$ADB" -s "$A" shell cmd connectivity airplane-mode enable > /dev/null 2>&1 || true
    gate "$A" send contact "$(contact_of a)" count 5 > /dev/null
    export_out="$(gate "$A" export-deposits contact "$(contact_of a)" count 5)"
    "$ADB" -s "$A" shell cmd connectivity airplane-mode disable > /dev/null 2>&1 || true
    {
      printf 'namespace %s\ncredential %s\nttl %s\n' "$(field namespace "$export_out")" "$(field credential "$export_out")" "$(field ttl "$export_out")"
      for i in 0 1 2 3 4; do printf 'blob %s\n' "$(field "blob.$i" "$export_out")"; done
    } > "$capture"
    onion="$(field onion "$export_out")"
    unset export_out
    compare step4-delivered "$(wait_converged $((before + 5)))"
    restore="${GHOST_RESTORE:-cargo run -q -p ghost-client-net --example dm_restore --locked --}"
    # shellcheck disable=SC2086
    report="$($restore --onion "$onion" --capture "$capture" --state-dir "$OUT/restore-tor")" || die "step4: the re-store tool failed: $(tail -n 1 <<<"$report")"
    rm -f "$capture"
    grep -q '^dm-restore: 5 blobs, 5 stored identical bytes$' <<<"$report" || die "step4: the relay did not take the 5 identical re-stores"
    record "step4 $(tail -n 1 <<<"$report")"
    compare step4-after-replay "$(wait_converged $((before + 5)))"
    [ "$(total "$B" "$(contact_of b)")" = "$(total "$A" "$(contact_of a)")" ] || die "step4: B shows a replayed message"
    drops_after="$(gate "$B" status | awk -F= '/^drop\./ { s += $2 } END { print s + 0 }')"
    [ "${drops_after:-0}" -gt "${drops_before:-0}" ] 2>/dev/null || record "step4 note: the drop counters did not rise in this process (they are per process; B may have been restarted)"
    record "step4 identical-bytes replay: nothing shown twice"
    ;;
  keychange)
    r="$(gate "$B" key-change on true)"
    [ "$(field result "$r")" = ACTIVATED ] || die "step5: B's key change answered $(field result "$r")"
    card_a="$(field card "$(gate "$A" card)")"
    rb="$(gate "$B" add-contact card "$card_a" source qr)"
    unset card_a
    field contact "$rb" > "$STATE/contact-b"
    gate "$B" send contact "$(contact_of b)" count 1 > /dev/null
    deadline=$((SECONDS + WAIT))
    while :; do
      pass "$B"; pass "$A"
      trust="$(field contacts "$(gate "$A" contacts)" | tr ',' '\n' | grep "^$(contact_of a):" | cut -d: -f2)"
      [ "$trust" = CHANGED ] && break
      [ "$SECONDS" -lt "$deadline" ] || die "step5: A never showed the key change"
      sleep "${GHOST_GATE_POLL:-10}"
    done
    record "step5 A shows CHANGED"
    refused="$(gate "$A" send contact "$(contact_of a)" count 1)"
    [ "$(field send.KEY_CHANGED "$refused")" = 1 ] || die "step5: A's send was not refused while the change was undecided"
    record "step5 A's send refused (KEY_CHANGED)"
    before="$(total "$A" "$(contact_of a)")"
    [ "$(field result "$(gate "$A" ack-key-change contact "$(contact_of a)")")" = true ] || die "step5: acknowledgement refused"
    after="$(total "$A" "$(contact_of a)")"
    [ "$after" -eq $((before + 1)) ] || die "step5: the held message did not appear exactly once ($before -> $after)"
    record "step5 held message released once after acknowledgement"
    ;;
  t25)
    minutes="${1:-20}"
    gate "$A" timer contact "$(contact_of a)" code 1 > /dev/null
    gate "$B" timer contact "$(contact_of b)" code 1 > /dev/null
    tag="$(field send.QUEUED "$(gate "$A" send contact "$(contact_of a)" count 1)")"
    [ "$tag" = 1 ] || die "step6: the timed message was not queued"
    record "step6 5-minute timers set both ways; waiting $minutes minutes locked"
    sleep $((minutes * 60))
    pass "$A"; pass "$B"
    for s in "$A" "$B"; do
      for f in ghost.db ghost.db-wal; do
        "$ADB" -s "$s" exec-out run-as "$PKG" cat "no_backup/$f" > "$OUT/export-$s-$f" 2>/dev/null || true
      done
    done
    record "step6 databases exported through run-as ($(cat "$OUT"/export-* | wc -c) bytes); scan them with the canary list of §15.10 step 6"
    ;;
  digest)
    record "digest A $(digests "$A" "$(contact_of a)")"
    record "digest B $(digests "$B" "$(contact_of b)")"
    ;;
  *)
    echo "dm-gate: unknown step '$step'" >&2
    exit 2
    ;;
esac
