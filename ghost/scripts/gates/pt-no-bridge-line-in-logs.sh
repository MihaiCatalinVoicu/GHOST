#!/usr/bin/env bash
# Gate G-T7 (design faza12-transports.md §13, §7.4, T58): no bridge line ever reaches a log.
# Two halves:
#   1. Static: the :network and :sync production source sets carry no logging primitive at
#      all — today they log nothing (verified), so "no log statement formats a bridge-line
#      variable" pins at its strongest: the first logging call lands here and forces the
#      index-not-text review the design requires.
#   2. Fixture: the PT harness's captured logs (a committed, scrubbed record of a real
#      pt_loopback run: the relay and lyrebird-server children plus the harness's own phase
#      output) contain the run's proof markers but no bridge line: neither the full grammar
#      shape (`obfs4 ip:port FINGERPRINT`) nor `cert=` material. A bare 40-hex scan is NOT
#      part of the rule — the relay legitimately announces its own identity fingerprint in
#      its log, and that identity is the bridge's; the canary is the *line-shaped* leak. An
#      empty fixture fails (D28's rule: a vacuous scan is not evidence).
#      (GHOST's own code never formats a line into anything; arti's *debug*-level internals
#      do dump configured lines — upstream behaviour the product's log plumbing never
#      enables, §7.4 — so the fixture records the children and the harness output, not an
#      arti debug trace.)
# A separate negative fixture (test-harness/privacy/fixtures/pt-logs-negative/) carries one
# injected line and must be rejected — self-test.sh proves both directions.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
FIX="$GHOST_ROOT/test-harness/privacy/fixtures/pt-logs"
LINE_REGEX='(obfs4|webtunnel)[[:space:]]+[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}[[:space:]]+[0-9A-Fa-f]{40}'
CERT_REGEX='cert=[A-Za-z0-9+/]{20,}={0,2}'

# 1. Static half over :network and :sync production sources.
count=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  count=$((count + 1))
  if hits="$(grep -nE '(^|[^A-Za-z0-9_])(android\.util\.Log|System\.out\.print|println[[:space:]]*\(|Timber\.)' "$f" || true)"; [ -n "$hits" ]; then
    while IFS= read -r line; do
      fail "${f#"$GHOST_ROOT"/}:${line}: a logging call in :network/:sync (T58: a bridge line must never be formatted into a log)"
    done <<< "$hits"
  fi
done < <(find "$GHOST_ROOT/android/network/src" "$GHOST_ROOT/android/sync/src" -path '*/build' -prune \
           -o -type f \( -name '*.kt' -o -name '*.java' \) \( -path '*/src/main/*' -o -path '*/src/release/*' -o -path '*/src/gate/*' \) -print 2>/dev/null || true)
[ "$count" -gt 0 ] || fail "the static half read no :network/:sync production file (the scan would pass vacuously)"

# 2. The fixture half: run log present, non-empty, marked, clean.
LOG="$FIX/harness-run.log"
[ -f "$LOG" ] || fail "test-harness/privacy/fixtures/pt-logs/harness-run.log missing (the PT fixtures' captured logs)"
[ -s "$LOG" ] || fail "harness-run.log is empty (D28: an empty scan is not evidence)"
grep -q 'pt-loopback' "$LOG" || fail "harness-run.log carries no pt-loopback marker (not a PT harness log?)"
lines=$(grep -c . "$LOG")
[ "$lines" -ge 20 ] || fail "harness-run.log has $lines lines: too thin to be the fixtures' log record"
while IFS= read -r n; do
  [ -n "$n" ] || continue
  fail "harness-run.log:$n: a bridge-line shape in the PT fixtures' logs"
done < <(grep -nE "$LINE_REGEX" "$LOG" || true)
while IFS= read -r n; do
  [ -n "$n" ] || continue
  fail "harness-run.log:$n: cert= material in the PT fixtures' logs"
done < <(grep -nE "$CERT_REGEX" "$LOG" || true)

finish pt-no-bridge-line-in-logs
