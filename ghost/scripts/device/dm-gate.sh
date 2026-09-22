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
#   GHOST_GATE_SESSION           seconds each `pass` holds a foreground relay session (default 30)
#   GHOST_GATE_BOOT              seconds a reboot may take until `sys.boot_completed` (default 300)
#
# **How traffic moves** (S12 review). Every gate command is an `am instrument` run, which restarts
# the app's process with no activity: no foreground session, and the periodic job's next run is
# minutes away in a process the next command replaces. So nothing crosses the network unless the
# orchestrator asks for it: `pass` holds a foreground relay session for GHOST_GATE_SESSION seconds —
# what the app does while the user has it open — and every wait below is a loop of passes on both
# phones. HIGH privacy mode is in memory only, so step 2 sets it on A in every pass A runs.
#
# **Setup the script assumes:** both phones plugged in and awake (`install` sets `svc power stayon
# usb`), no screen lock (step 3 reboots them, and the app's credential-encrypted storage opens
# without a user unlock only then), and the gate variant installed by `install`.
#
# Steps (each prints what it recorded and fails the run on a mismatch):
#   install <gate.apk>   install the gate variant on both phones (built locally, never published)
#   establish            step 1: each card injected into the other phone as addContact(card,
#                        qr_in_person); one message each way; both contacts VERIFIED on both phones;
#                        safety digests equal
#   reorder [n]          step 2: n-message bursts each way (default 30), HIGH mode on A in every
#                        session A runs, airplane-mode toggles on B; the order digests are equal
#   restart [n]          step 3: n sends on A (default 20) in chunks of 5; after each chunk a
#                        session runs on both phones and one of them is killed in the middle of it
#                        (`am kill` and `am force-stop`, alternating), and both phones are rebooted
#                        once while their sessions run; after quiescence the multiset digests agree
#                        and nothing is shown twice
#   replay               step 4, first half, part 1: a one-hour timer (the relay's 1-hour TTL
#                        bucket) on A; A sends 5 in airplane mode; their bytes and A's deposit
#                        credential go to a private capture file (mode 600) in the state directory;
#                        delivery is waited for. The capture is kept for part 2
#   replay-restore       part 2, run once the relay has let the originals expire (about two hours):
#                        the re-store tool checks the relay first and refuses while it still holds
#                        any of them — an identical store of a live blob is a no-op no phone ever
#                        sees — then stores all 5 again as new listings; B shows nothing new and
#                        nothing twice. The capture is deleted as soon as the tool has run. D1 is
#                        :sync's `(namespace, blob_hash)` tombstone, which has no counter (T33), so
#                        the DM drop counters the passes report are recorded, not required to rise:
#                        "the drop counters rise" is the evidence of step 4's D2/D3 halves
#   keychange            step 5: B switches to the bound alternate Olm identity (the debug hook,
#                        answered ACTIVATED because B's old DM rows are cleared), re-adds A's card
#                        and writes; A shows CHANGED, A's send is refused, the held message appears
#                        once after acknowledgement, then a message each way is delivered
#   t25 [minutes]        step 6, the part a host can check: a 5-minute timer both ways and one
#                        tagged message each way; both screens off for `minutes` (default 20); then
#                        the timed messages are gone on both phones, and the database and WAL
#                        exported through run-as do not contain the tag. Not here: the app lock
#                        (Phase 13's; the screen lock stands for it) and the `body_env` and canary
#                        scan, which needs the database decrypted with its key (§22.17)
#   digest               both phones' digests of the conversation, as a record
#
# Not here (the checklist's manual steps, §15.10): step 4's debug-hook halves (re-encrypt after a
# forced FAILED, tombstone clearing — deferred, design §22.17), step 7 (restore from the mnemonic,
# which needs Phase 13's restore UI or an entitlement restore command the gate variant does not have
# yet — §22.17), step 8 (the staging capture, validated by capture-check on the relay host) and step
# 9 (measurements).
#
# Self-test: scripts/device/dm-gate-self-test.sh (a fake adb that answers as two phones, and a fake
# re-store tool).
set -euo pipefail

ADB="${GHOST_ADB:-adb}"
A="${GHOST_GATE_A:?set GHOST_GATE_A to the adb serial of phone A}"
B="${GHOST_GATE_B:?set GHOST_GATE_B to the adb serial of phone B}"
OUT="${GHOST_GATE_OUT:-./dm-gate-out}"
WAIT="${GHOST_GATE_WAIT:-900}"
SESSION="${GHOST_GATE_SESSION:-30}"
BOOT="${GHOST_GATE_BOOT:-300}"
PKG="org.ghost.app.gate"
RUNNER="$PKG/org.ghost.app.gate.GateInstrumentation"
mkdir -p "$OUT"
LOG="$OUT/dm-gate.log"
STATE="$OUT/state"
mkdir -p "$STATE"

record() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; printf '%s\n' "$*"; }
die() { record "FAIL $*"; echo "dm-gate: $*" >&2; exit 1; }

# The instrumentation arguments of one command: `-e cmd <cmd>` and `-e key value` pairs.
instrument_args() { # cmd [key value]...
  local cmd="$1"
  shift
  local args=(-e cmd "$cmd")
  while [ $# -gt 1 ]; do args+=(-e "$1" "$2"); shift 2; done
  printf '%s\0' "${args[@]}"
}

# One instrumentation command; prints its result as `key=value` lines. Arguments after the command
# are key/value pairs passed with `-e`.
gate() { # serial cmd [key value]...
  local serial="$1" cmd="$2" out
  shift
  local args=()
  while IFS= read -r -d '' a; do args+=("$a"); done < <(instrument_args "$@")
  out="$("$ADB" -s "$serial" shell am instrument -w "${args[@]}" "$RUNNER" 2>&1 | tr -d '\r')" || true
  if ! grep -q '^INSTRUMENTATION_CODE: -1$' <<<"$out"; then
    local why
    why="$(sed -n 's/^INSTRUMENTATION_RESULT: error=//p' <<<"$out" | head -n 1)"
    die "gate command '$cmd' failed on ${serial} (${why:-no result})"
  fi
  sed -n 's/^INSTRUMENTATION_RESULT: //p' <<<"$out"
}

# The same command, run for its side effects only and allowed to die with the process: step 3
# kills the phones in the middle of these.
gate_interruptible() { # serial cmd [key value]...
  local serial="$1"
  shift
  local args=()
  while IFS= read -r -d '' a; do args+=("$a"); done < <(instrument_args "$@")
  "$ADB" -s "$serial" shell am instrument -w "${args[@]}" "$RUNNER" > /dev/null 2>&1 || true
}

field() { sed -n "s/^$1=//p" <<<"$2" | head -n 1; }
drops() { awk -F= '/^drop\./ { s += $2 } END { print s + 0 }' <<<"$1"; }

# The contact id of the peer on each phone, kept between steps (ids are local and random: not
# content, and they name nothing outside the phone).
contact_of() { cat "$STATE/contact-$1" 2>/dev/null || die "no contact on $1: run establish first"; }

digests() { # serial contact -> "order multiset count duplicates"
  local r
  r="$(gate "$1" digest contact "$2")"
  printf '%s %s %s %s\n' "$(field order "$r")" "$(field multiset "$r")" "$(field count "$r")" "$(field duplicates "$r")"
}

# A foreground relay session on one phone for GHOST_GATE_SESSION seconds; prints its answer. A
# second argument names the privacy mode the session runs in, which the answer must confirm.
pass() { # serial [privacy]
  local r
  if [ -n "${2:-}" ]; then
    r="$(gate "$1" pass seconds "$SESSION" privacy "$2")"
    [ "$(field privacy "$r")" = "$2" ] || die "the session on $1 did not run in $2 mode"
  else
    r="$(gate "$1" pass seconds "$SESSION")"
  fi
  printf '%s\n' "$r"
}

total() { cut -d' ' -f3 <<<"$(digests "$1" "$2")"; }

# Waits until both phones render the same number of messages and at least `want`; prints the two
# digest lines. A second argument is the privacy mode of A's sessions.
wait_converged() { # expected-count [privacy of A]
  local want="$1" privacy="${2:-}" deadline=$((SECONDS + WAIT)) da db
  while [ "$SECONDS" -lt "$deadline" ]; do
    pass "$A" "$privacy" > /dev/null; pass "$B" > /dev/null
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

# Waits until A renders at least `a` messages and B at least `b` (their conversations differ after
# step 5, where B's tables were cleared).
wait_counts() { # a b label
  local wa="$1" wb="$2" label="$3" deadline=$((SECONDS + WAIT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    pass "$A" > /dev/null; pass "$B" > /dev/null
    if [ "$(total "$A" "$(contact_of a)")" -ge "$wa" ] && [ "$(total "$B" "$(contact_of b)")" -ge "$wb" ]; then return 0; fi
    sleep "${GHOST_GATE_POLL:-10}"
  done
  die "$label: A did not reach $wa messages or B $wb within ${WAIT}s"
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

# wait_converged, then compare; a wait that failed ends the run with its own message (inside a
# command substitution its `die` would only end the subshell, and compare would report empty digests).
converge() { # step label, expected count, [privacy of A]
  local d
  d="$(wait_converged "$2" "${3:-}")" || exit 1
  compare "$1" "$d"
}

awake() { # serial: screen on, keyguard (none on a gate phone) dismissed, kept on while plugged in
  "$ADB" -s "$1" shell input keyevent KEYCODE_WAKEUP > /dev/null 2>&1 || true
  "$ADB" -s "$1" shell wm dismiss-keyguard > /dev/null 2>&1 || true
  "$ADB" -s "$1" shell svc power stayon usb > /dev/null 2>&1 || true
}

reboot() { # serial
  local deadline=$((SECONDS + BOOT))
  "$ADB" -s "$1" reboot > /dev/null 2>&1 || die "step3: adb reboot of $1"
  "$ADB" -s "$1" wait-for-device > /dev/null 2>&1 || die "step3: $1 did not come back"
  until [ "$("$ADB" -s "$1" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
    [ "$SECONDS" -lt "$deadline" ] || die "step3: $1 did not finish booting within ${BOOT}s"
    sleep "${GHOST_GATE_POLL:-10}"
  done
  awake "$1"
}

verified_on() { # serial contact
  local c
  c="$(field contacts "$(gate "$1" contacts)" | tr ',' '\n' | grep "^$2:" | cut -d: -f2 || true)"
  [ "$c" = VERIFIED ] || die "step1: the contact on $1 is ${c:-missing}, not VERIFIED"
}

step="${1:-}"
[ -n "$step" ] || { sed -n '2,80p' "$0"; exit 2; }
shift || true

case "$step" in
  install)
    apk="${1:?usage: dm-gate.sh install <app-gate.apk>}"
    for s in "$A" "$B"; do "$ADB" -s "$s" install -r "$apk" > /dev/null || die "install on $s"; awake "$s"; done
    record "install gate variant $(sha256sum "$apk" | cut -d' ' -f1) on both phones; screens kept on while plugged in"
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
    converge step1 2
    verified_on "$A" "$(contact_of a)"
    verified_on "$B" "$(contact_of b)"
    record "step1 both contacts VERIFIED"
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
    # A's burst goes out in HIGH mode while B is offline; B's waits for the network.
    pass "$A" HIGH > /dev/null
    sleep "${GHOST_GATE_AIRPLANE:-60}"
    "$ADB" -s "$B" shell cmd connectivity airplane-mode disable > /dev/null 2>&1 || true
    converge step2 $((before + 2 * n)) HIGH
    record "step2 every session on A ran in HIGH mode"
    ;;
  restart)
    n="${1:-20}"
    before="$(total "$A" "$(contact_of a)")"
    sent=0
    chunk_no=0
    rebooted_a="" rebooted_b=""
    while [ "$sent" -lt "$n" ]; do
      chunk=$(( n - sent < 5 ? n - sent : 5 ))
      gate "$A" send contact "$(contact_of a)" count "$chunk" > /dev/null
      sent=$((sent + chunk))
      chunk_no=$((chunk_no + 1))
      # A session on both phones — A sending, B receiving — and one of them killed in the middle.
      gate_interruptible "$A" pass seconds "$SESSION" &
      pa=$!
      gate_interruptible "$B" pass seconds "$SESSION" &
      pb=$!
      sleep "${GHOST_GATE_KILL_AFTER:-8}"
      case $(( chunk_no % 4 )) in
        1) "$ADB" -s "$A" shell am kill "$PKG" > /dev/null 2>&1 || true; what="am kill on A while sending" ;;
        2) "$ADB" -s "$B" shell am force-stop "$PKG" > /dev/null 2>&1 || true; what="am force-stop on B while receiving" ;;
        3) "$ADB" -s "$A" shell am force-stop "$PKG" > /dev/null 2>&1 || true; what="am force-stop on A while sending" ;;
        0) "$ADB" -s "$B" shell am kill "$PKG" > /dev/null 2>&1 || true; what="am kill on B while receiving" ;;
      esac
      # One reboot of each phone, in the middle of the run, while its session runs.
      if [ -z "$rebooted_a" ] && [ $((sent * 2)) -ge "$n" ]; then reboot "$A"; rebooted_a=1; what="$what; A rebooted"
      elif [ -n "$rebooted_a" ] && [ -z "$rebooted_b" ]; then reboot "$B"; rebooted_b=1; what="$what; B rebooted"; fi
      wait "$pa" "$pb" 2>/dev/null || true
      record "step3 chunk $chunk_no ($chunk sends): $what"
    done
    [ -n "$rebooted_a" ] || { reboot "$A"; record "step3 A rebooted"; }
    [ -n "$rebooted_b" ] || { reboot "$B"; record "step3 B rebooted"; }
    converge step3 $((before + n))
    ;;
  replay)
    capture="$STATE/replay-capture"
    [ ! -e "$capture" ] || die "step4: a capture from an earlier run is still in $STATE; run replay-restore or delete it"
    gate "$A" timer contact "$(contact_of a)" code 2 > /dev/null
    converge step4-timer "$(total "$A" "$(contact_of a)")"
    before="$(total "$A" "$(contact_of a)")"
    "$ADB" -s "$A" shell cmd connectivity airplane-mode enable > /dev/null 2>&1 || true
    gate "$A" send contact "$(contact_of a)" count 5 > /dev/null
    export_out="$(gate "$A" export-deposits contact "$(contact_of a)" count 5)"
    "$ADB" -s "$A" shell cmd connectivity airplane-mode disable > /dev/null 2>&1 || true
    ( umask 077
      { printf 'namespace %s\ncredential %s\nttl %s\n' "$(field namespace "$export_out")" "$(field credential "$export_out")" "$(field ttl "$export_out")"
        for i in 0 1 2 3 4; do printf 'blob %s\n' "$(field "blob.$i" "$export_out")"; done
      } > "$capture"
      field onion "$export_out" > "$STATE/replay-onion" )
    ttl="$(field ttl "$export_out")"
    unset export_out
    [ "$ttl" = 3600 ] || die "step4: the captured ops carry TTL $ttl, not the one-hour bucket"
    converge step4-delivered $((before + 5))
    record "step4 5 messages with a one-hour timer delivered; the capture is kept (mode 600) for replay-restore, to be run once the relay has let them expire (about two hours)"
    ;;
  replay-restore)
    capture="$STATE/replay-capture"
    [ -s "$capture" ] || die "step4: no capture in $STATE: run replay first"
    onion="$(cat "$STATE/replay-onion")"
    restore="${GHOST_RESTORE:-cargo run -q -p ghost-client-net --example dm_restore --locked --}"
    # shellcheck disable=SC2086
    check="$($restore --onion "$onion" --capture "$capture" --state-dir "$OUT/restore-tor" --check-only)" || die "step4: the re-store tool's check failed: $(tail -n 1 <<<"$check")"
    live="$(sed -n 's/^dm-restore: [0-9]* blobs, [0-9]* re-stored as new listings, \([0-9]*\) still live at the relay$/\1/p' <<<"$check")"
    [ "$live" = 0 ] || die "step4: the relay still holds ${live:-?} of the 5 originals; an identical re-store of a live blob is a no-op no phone sees (D1 is not reached). Run replay-restore again once they expire; the capture stays in $STATE"
    before_a="$(total "$A" "$(contact_of a)")"
    before_b="$(total "$B" "$(contact_of b)")"
    # shellcheck disable=SC2086
    report="$($restore --onion "$onion" --capture "$capture" --state-dir "$OUT/restore-tor")" || { rm -f "$capture" "$STATE/replay-onion"; die "step4: the re-store tool failed: $(tail -n 1 <<<"$report")"; }
    rm -f "$capture" "$STATE/replay-onion"
    grep -q '^dm-restore: 5 blobs, 5 re-stored as new listings, 0 still live at the relay$' <<<"$report" || die "step4: the relay did not take the 5 identical re-stores as new listings"
    record "step4 $(tail -n 1 <<<"$report")"
    # Sessions on B fetch the new listings; nothing may appear, and nothing twice.
    seen=0
    for _ in 1 2 3; do seen=$((seen + $(drops "$(pass "$B")"))); pass "$A" > /dev/null; done
    after="$(printf '%s\n%s\n' "$(digests "$A" "$(contact_of a)")" "$(digests "$B" "$(contact_of b)")")"
    # The timed originals may expire on both phones meanwhile, so B is held to A, which never
    # sees a replay addressed to B, and to its own count before the re-store.
    ca="$(sed -n 1p <<<"$after" | cut -d' ' -f3)"
    cb="$(sed -n 2p <<<"$after" | cut -d' ' -f3)"
    [ "$cb" -le "$ca" ] && [ "$cb" -le "$before_b" ] || die "step4: B shows a replayed message (A renders $ca, B $cb, B before the re-store $before_b)"
    [ "$ca" -le "$before_a" ] || die "step4: A's count grew during the replay"
    compare step4-after-replay "$after"
    record "step4 identical-bytes replay as new listings: nothing shown, nothing twice; DM drop counters in B's sessions: $seen (D1 is :sync's tombstone and counts nothing, T33)"
    gate "$A" timer contact "$(contact_of a)" code 4 > /dev/null
    ;;
  keychange)
    r="$(gate "$B" key-change on true)"
    [ "$(field result "$r")" = ACTIVATED ] || die "step5: B's key change answered $(field result "$r")"
    card_a="$(field card "$(gate "$A" card)")"
    rb="$(gate "$B" add-contact card "$card_a" source qr)"
    unset card_a
    [ "$(field result "$rb")" = ADDED ] || die "step5: B re-adding A answered $(field result "$rb")"
    field contact "$rb" > "$STATE/contact-b"
    gate "$B" send contact "$(contact_of b)" count 1 > /dev/null
    deadline=$((SECONDS + WAIT))
    while :; do
      pass "$B" > /dev/null; pass "$A" > /dev/null
      trust="$(field contacts "$(gate "$A" contacts)" | tr ',' '\n' | grep "^$(contact_of a):" | cut -d: -f2 || true)"
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
    a0="$after"
    b0="$(total "$B" "$(contact_of b)")"
    gate "$A" send contact "$(contact_of a)" count 1 > /dev/null
    gate "$B" send contact "$(contact_of b)" count 1 > /dev/null
    wait_counts $((a0 + 2)) $((b0 + 2)) step5
    record "step5 both directions deliver after the acknowledgement"
    ;;
  t25)
    minutes="${1:-20}"
    ta="$(total "$A" "$(contact_of a)")"
    tb="$(total "$B" "$(contact_of b)")"
    gate "$A" timer contact "$(contact_of a)" code 1 > /dev/null
    gate "$B" timer contact "$(contact_of b)" code 1 > /dev/null
    # Each timer change is a row on both phones.
    wait_counts $((ta + 2)) $((tb + 2)) step6-timers
    tag="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    a0="$(total "$A" "$(contact_of a)")"
    b0="$(total "$B" "$(contact_of b)")"
    [ "$(field send.QUEUED "$(gate "$A" send contact "$(contact_of a)" count 1 tag "$tag")")" = 1 ] || die "step6: A's timed message was not queued"
    [ "$(field send.QUEUED "$(gate "$B" send contact "$(contact_of b)" count 1 tag "$tag")")" = 1 ] || die "step6: B's timed message was not queued"
    wait_counts $((a0 + 2)) $((b0 + 2)) step6-delivery
    record "step6 5-minute timers set both ways, one timed message each way delivered; screens off for $minutes minutes"
    for s in "$A" "$B"; do "$ADB" -s "$s" shell input keyevent KEYCODE_SLEEP > /dev/null 2>&1 || true; done
    sleep $((minutes * 60))
    for s in "$A" "$B"; do awake "$s"; done
    pass "$A" > /dev/null; pass "$B" > /dev/null
    ga="$(total "$A" "$(contact_of a)")"
    gb="$(total "$B" "$(contact_of b)")"
    [ "$ga" -eq "$a0" ] && [ "$gb" -eq "$b0" ] || die "step6: the timed messages are still shown (A $a0 -> $ga, B $b0 -> $gb)"
    record "step6 the timed messages are gone on both phones"
    for s in "$A" "$B"; do
      for f in ghost.db ghost.db-wal; do
        "$ADB" -s "$s" exec-out run-as "$PKG" cat "databases/$f" > "$OUT/export-$s-$f" 2>/dev/null || true
      done
      [ -s "$OUT/export-$s-ghost.db" ] || die "step6: nothing exported from $s through run-as"
    done
    bytes="$(cat "$OUT"/export-* | wc -c | tr -d ' ')"
    if LC_ALL=C grep -aqF -e "$tag" "$OUT"/export-*; then die "step6: the message tag is in an exported database file"; fi
    unset tag
    record "step6 databases and WALs exported through run-as ($bytes bytes): the message tag is in none of them; the body_env and canary scan needs the decrypted database and is done by hand (§22.17)"
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
