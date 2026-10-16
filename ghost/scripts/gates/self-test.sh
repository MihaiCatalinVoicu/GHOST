#!/usr/bin/env bash
# Proves each gate actually fails on a known-bad tree (ADR-10: "demonstrated to fail on
# counter-examples"). The fixtures live in test-harness/gates/negative* and mirror the layout of
# ghost/ so the gates scan them unchanged via GHOST_ROOT.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="$(cd "$DIR/../../test-harness/gates" && pwd)"
rc=0
# A case that calls a command this shell does not have is a case that never ran (the review of S4, Phase 10 design
# §19.38: eight G-M5 cases called `evasion_count` and `evasion_named` before their definition, printed "command not
# found" and counted nothing). Bash runs this handler in a subshell, so it records the name in a file, and the end of
# the script turns every record into a failure. A gate's own commands run in its own `bash`, which does not inherit it.
NOT_FOUND_LOG="$(mktemp)"
command_not_found_handle() {
  printf '%s\n' "$1" >> "$NOT_FOUND_LOG"
  echo "SELF-TEST FAIL: command not found in the self-test: $1" >&2
  return 127
}
# Output checks use here-strings (grep ... <<<"$out"), never `printf '%s\n' "$out" | grep -q`: under
# pipefail that pipeline fails whenever grep -q stops reading before printf has flushed everything
# (EPIPE; the static-gates self-test of run 35473735223 reported a present message as missing).
expect_fail() {
  local gate="$1" root="$2"
  if GHOST_ROOT="$root" bash "$DIR/$gate.sh" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: $gate passed on fixture $(basename "$root")" >&2; rc=1
  else
    echo "self-test ok: $gate rejects fixture $(basename "$root")"
  fi
}
# The evasion helpers (Phase 9 design §22.33 item 16), defined before any case uses them (§19.38).
EVASION_OUT=""
evasion_count() { # $1 = gate, $2 = fixture under test-harness/gates, $3 = expected violation count
  local hits
  EVASION_OUT="$(GHOST_ROOT="$HARNESS/$2" bash "$DIR/$1.sh" 2>&1 || true)"
  hits="$(grep -c '^GATE-FAIL' <<<"$EVASION_OUT" || true)"
  if [ "$hits" = "$3" ]; then
    echo "self-test ok: $1 reports exactly $3 violation(s) in $2"
  else
    echo "SELF-TEST FAIL: $1 reported $hits of $3 violations in $2" >&2
    printf '%s\n' "$EVASION_OUT" | tail -5 >&2; rc=1
  fi
}
evasion_named() { # $1 = gate, $2 = expected text of one violation, $3 = description (reads EVASION_OUT)
  if grep -qF -- "$2" <<<"$EVASION_OUT"; then
    echo "self-test ok: $1 $3"
  else
    echo "SELF-TEST FAIL: $1 $3: no violation reads '$2'" >&2; rc=1
  fi
}
near_misses() { # $1 = gate, $2 = fixture under test-harness/gates
  if GHOST_ROOT="$HARNESS/$2" bash "$DIR/$1.sh" >/dev/null 2>&1; then
    echo "self-test ok: $1 accepts the near misses of $2"
  else
    echo "SELF-TEST FAIL: $1 rejects the near misses of $2" >&2; rc=1
  fi
}
for g in anti-placeholder no-logging manifest-lint dependency-allowlist; do
  expect_fail "$g" "$HARNESS/negative"
done
# workflow-yaml: a workflow that is not valid YAML never starts (the DM exit gate missed three merges to
# main that way). The good fixture must pass, and each negative must fail **for the reason it names**,
# so a missing parser can never stand in for a rejection. `bad-comment` is the real defect: a wrapped
# comment line that lost its `#`.
wfy_case() { # $1 = expect pass|fail, $2 = fixture directory, $3 = expected text ("" for pass), $4 = description
  local out got
  if out="$(GHOST_WORKFLOWS_DIR="$HARNESS/workflow-yaml/$2" bash "$DIR/workflow-yaml.sh" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" = "$1" ] && { [ -z "$3" ] || grep -qF "$3" <<<"$out"; }; then
    echo "self-test ok: workflow-yaml $4"
  else
    echo "SELF-TEST FAIL: workflow-yaml $4 ($got)" >&2; printf '%s\n' "$out" | tail -2 >&2; rc=1
  fi
}
wfy_case pass good "" "accepts a valid workflow"
wfy_case fail bad-comment "unparseable" "rejects a comment line that lost its # (the defect that stopped messaging-exit-gate)"
wfy_case fail bad-no-jobs "no jobs" "rejects a workflow with no jobs"
wfy_case fail bad-job-shape "has neither runs-on nor uses" "rejects a job with no runner"
wfy_case fail bad-step "has neither uses nor run" "rejects a step that does nothing"
wfy_case fail empty "no workflow file found" "refuses a directory with no workflow (a gate that scans nothing passes)"
# Phase 9 review GATES-2: the release-only source set ships beside `src/main`, and five gates read
# only `src/main`. One fixture file there breaks all five; each must name it.
for g in no-logging kotlin-clearnet anti-placeholder dm-enqueue-callers dm-no-fts; do
  rel_out="$(GHOST_ROOT="$HARNESS/negative-release-source-set" bash "$DIR/$g.sh" 2>&1 || true)"
  if grep -q '^GATE-FAIL' <<<"$rel_out" && grep -qF "src/release/kotlin/org/ghost/app/ReleaseOnly.kt" <<<"$rel_out"; then
    echo "self-test ok: $g reads the release-only source set"
  else
    echo "SELF-TEST FAIL: $g does not report the release-only source set's violations" >&2; rc=1
  fi
done
# G-M7 (Phase 11 design faza11-media.md §13.1, §16.1 G-M7; slice S1): the media crate is pure. Each
# fixture of media-purity/ breaks one rule and must fail for that rule's reason alone (every GATE-FAIL
# line of the run names it); the good fixture, with the near misses (banned names in comments and
# strings, core::time, a 'static lifetime, a use of std::collections, the registry's static in
# src/registry.rs, crate-type rlib), passes. The fixtures after build-script are the evasions the
# review of S1 found in the first version (each passed it). A logging macro in the crate is
# no-logging.sh's, which reads every client-core crate.
MPUR="$HARNESS/media-purity"
if GHOST_ROOT="$MPUR/good" bash "$DIR/media-crate-purity.sh" >/dev/null 2>&1; then
  echo "self-test ok: media-crate-purity accepts the near misses"
else
  echo "SELF-TEST FAIL: media-crate-purity rejects the good fixture" >&2; rc=1
fi
for mp_case in \
  "clock|a clock (the media crate reads no clock" \
  "io|I/O (the media crate does no I/O" \
  "state|state (the media crate keeps none" \
  "random|randomness (the caller passes K_f and object_id" \
  "unsafe|unsafe code (forbidden in the media crate)" \
  "forbid-missing|no #![forbid(unsafe_code)]" \
  "jni|JNI (the media crate has none" \
  "extern-crate|dependency 'base64' (an external crate" \
  "target-dependency|no build or target-specific dependency" \
  "feature|feature 'simd' = [] (a feature" \
  "build-script|a build script" \
  "io-nested-import|I/O (the media crate does no I/O" \
  "io-glob-import|I/O (the media crate does no I/O" \
  "io-extern-crate|I/O (the media crate does no I/O" \
  "io-std-path|I/O (the media crate does no I/O" \
  "state-alias|state (the media crate keeps none" \
  "state-once|state (the media crate keeps none" \
  "path-attribute|a source outside src/ (#[path] or include!" \
  "include-macro|a source outside src/ (#[path] or include!" \
  "forbid-in-string|no #![forbid(unsafe_code)]" \
  "package-build|package.build = \"gen.rs\" (a build script or a native library" \
  "package-links|package.links = \"native\" (a build script or a native library" \
  "spaced-features|feature 'simd' = [] (a feature" \
  "spaced-dependencies|dependency 'base64' (an external crate" \
  "crate-type|lib.crate-type = [\"rlib\",\"cdylib\"] (the crate is one rlib" \
  "bin-target|[[bin]] (a target other than the library"; do
  mp_name="${mp_case%%|*}"
  mp_want="${mp_case#*|}"
  if mp_out="$(GHOST_ROOT="$MPUR/$mp_name" bash "$DIR/media-crate-purity.sh" 2>&1)"; then
    echo "SELF-TEST FAIL: media-crate-purity passed fixture $mp_name" >&2; rc=1
  elif [ "$(grep -c '^GATE-FAIL' <<<"$mp_out" || true)" -lt 1 ] \
    || [ "$(grep '^GATE-FAIL' <<<"$mp_out" | grep -cvF -- "$mp_want" || true)" != 0 ]; then
    echo "SELF-TEST FAIL: media-crate-purity does not fail fixture $mp_name for its own reason ($mp_want)" >&2
    printf '%s\n' "$mp_out" | grep '^GATE-FAIL' | head -4 >&2; rc=1
  else
    echo "self-test ok: media-crate-purity rejects $mp_name for its own reason"
  fi
done

# G-M1 (Phase 11 design faza11-media.md §16.1 G-M1; slice S7): the no-plaintext-io gate, sink
# and writer halves. The good fixture carries an empty writer allowlist (its tree is clean);
# the negatives each break one rule.
if GHOST_ROOT="$HARNESS/media-no-plaintext/good" GHOST_WRITER_ALLOWLIST=/dev/null bash "$DIR/media-no-plaintext-io.sh" >/dev/null 2>&1; then
  echo "self-test ok: media-no-plaintext-io accepts the clean fixture"
else
  echo "SELF-TEST FAIL: media-no-plaintext-io rejects the clean fixture" >&2; rc=1
fi
expect_fail media-no-plaintext-io "$HARNESS/media-no-plaintext/negative-simple-cache"
expect_fail media-no-plaintext-io "$HARNESS/media-no-plaintext/negative-cache-dir"
expect_fail media-no-plaintext-io "$HARNESS/media-no-plaintext/negative-mediastore"
expect_fail media-no-plaintext-io "$HARNESS/media-no-plaintext/negative-writer"
expect_fail media-no-plaintext-io "$HARNESS/media-no-plaintext/negative-transformer"
# The PM-M10 fixture is the sink half's shape: the player wrapped over a caching data source.
pm10_out="$(GHOST_WRITER_ALLOWLIST=/dev/null GHOST_ROOT="$HARNESS/media-no-plaintext/negative-simple-cache" bash "$DIR/media-no-plaintext-io.sh" 2>&1 || true)"
if grep -qF "(G-M1 sink: simple-cache)" <<<"$pm10_out"; then
  echo "self-test ok: media-no-plaintext-io names the simple-cache sink (PM-M10's fixture)"
else
  echo "SELF-TEST FAIL: media-no-plaintext-io does not report the simple-cache sink" >&2; rc=1
fi

# G-M2 (faza11-media.md §16.1 G-M2; slice S7): the Media3 artifact allowlist.
if GHOST_ROOT="$HARNESS/media3-dependency/good" bash "$DIR/media3-dependency-allowlist.sh" >/dev/null 2>&1; then
  echo "self-test ok: media3-dependency-allowlist accepts the clean fixture"
else
  echo "SELF-TEST FAIL: media3-dependency-allowlist rejects the clean fixture" >&2; rc=1
fi
expect_fail media3-dependency-allowlist "$HARNESS/media3-dependency/negative-session"
expect_fail media3-dependency-allowlist "$HARNESS/media3-dependency/negative-ui"

# G-M3 (faza11-media.md §16.1 G-M3; slice S7): decoder confinement's source and configuration
# halves, plus the shape assertions (the no-mfra fixture is MC-M24's source shape).
if GHOST_ROOT="$HARNESS/media-decoder-confinement/good" bash "$DIR/media-decoder-confinement.sh" >/dev/null 2>&1; then
  echo "self-test ok: media-decoder-confinement accepts the clean fixture"
else
  echo "SELF-TEST FAIL: media-decoder-confinement rejects the clean fixture" >&2; rc=1
fi
expect_fail media-decoder-confinement "$HARNESS/media-decoder-confinement/negative-image-decoder"
expect_fail media-decoder-confinement "$HARNESS/media-decoder-confinement/negative-default-renderers"
expect_fail media-decoder-confinement "$HARNESS/media-decoder-confinement/negative-player-builder"
mfra_out="$(GHOST_ROOT="$HARNESS/media-decoder-confinement/negative-no-mfra" bash "$DIR/media-decoder-confinement.sh" 2>&1 || true)"
if grep -qF "FLAG_READ_MFRA_FOR_SEEK_MAP" <<<"$mfra_out"; then
  echo "self-test ok: media-decoder-confinement catches MC-M24's shape (the seek-map flag gone)"
else
  echo "SELF-TEST FAIL: media-decoder-confinement does not catch the no-mfra fixture" >&2; rc=1
fi

# G-M4 (faza11-media.md §16.1 G-M4; slice S7): manifest-lint's isolated-service and binding
# halves over source manifests and sources.
if GHOST_ROOT="$HARNESS/media-manifest/good" bash "$DIR/manifest-lint.sh" >/dev/null 2>&1; then
  echo "self-test ok: manifest-lint accepts the clean G-M4 fixture"
else
  echo "SELF-TEST FAIL: manifest-lint rejects the clean G-M4 fixture" >&2; rc=1
fi
expect_fail manifest-lint "$HARNESS/media-manifest/negative-no-isolated"
expect_fail manifest-lint "$HARNESS/media-manifest/negative-binding"

# G-M10 (faza11-media.md §16.1 G-M10, S0-10; slice S7): the release-dex absence check over
# synthetic R8 outputs (a kept ImageRenderer is the design's negative fixture).
MRD="$HARNESS/media-release-dex"
if bash "$DIR/media-release-dex.sh" "$MRD/good/mapping.txt" "$MRD/good/usage.txt" >/dev/null 2>&1; then
  echo "self-test ok: media-release-dex accepts the clean fixture"
else
  echo "SELF-TEST FAIL: media-release-dex rejects the clean fixture" >&2; rc=1
fi
if bash "$DIR/media-release-dex.sh" "$MRD/bad-kept/mapping.txt" "$MRD/bad-kept/usage.txt" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: media-release-dex passed the kept-ImageRenderer fixture" >&2; rc=1
else
  echo "self-test ok: media-release-dex rejects a kept ImageRenderer (G-M10's negative fixture)"
fi
if bash "$DIR/media-release-dex.sh" "$MRD/bad-usage/mapping.txt" "$MRD/bad-usage/usage.txt" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: media-release-dex passed the not-a-usage-report fixture" >&2; rc=1
else
  echo "self-test ok: media-release-dex refuses a usage.txt that reports no removable class"
fi
media_log_out="$(GHOST_ROOT="$HARNESS/negative-media-logging" bash "$DIR/no-logging.sh" 2>&1 || true)"
if [ "$(grep -c '^GATE-FAIL' <<<"$media_log_out" || true)" = 2 ] \
  && grep -qF "client-core/media/src/lib.rs:3:    log::info!" <<<"$media_log_out" \
  && grep -qF "client-core/media/src/lib.rs:4:    println!" <<<"$media_log_out"; then
  echo "self-test ok: no-logging reports a logging and a print macro in the media crate (G-M7)"
else
  echo "SELF-TEST FAIL: no-logging does not report exactly the media crate's two logging lines" >&2; rc=1
fi
# Phase 9 §21.13 point 7 (slice S12): anti-placeholder reads the `gate` source sets. The fixture holds
# a gate source and nothing else, so only that reading can fail it.
expect_fail anti-placeholder "$HARNESS/negative-gate-placeholder"
gate_ph_out="$(GHOST_ROOT="$HARNESS/negative-gate-placeholder" bash "$DIR/anti-placeholder.sh" 2>&1 || true)"
if [ "$(grep -c '^GATE-FAIL' <<<"$gate_ph_out" || true)" = "1" ] && grep -qF "src/gate/kotlin/org/ghost/app/gate/GateStandIn.kt:6:" <<<"$gate_ph_out"; then
  echo "self-test ok: anti-placeholder reports the gate source set's stand-in"
else
  echo "SELF-TEST FAIL: anti-placeholder does not report exactly the gate source set's stand-in" >&2; rc=1
fi
# Phase 7 crash fidelity: every catch-all form in the fixture is reported, one line each. Phase 8
# (design §11.1): the fixture's entitlement module adds 3 lines, each reported by its file name, and
# a tree without android/entitlement/src/main fails for that reason alone.
expect_fail sync-no-catch-all "$HARNESS/negative-sync"
sync_out="$(GHOST_ROOT="$HARNESS/negative-sync" bash "$DIR/sync-no-catch-all.sh" 2>&1 || true)"
sync_hits="$(printf '%s\n' "$sync_out" | grep -c '^GATE-FAIL' || true)"
if [ "$sync_hits" = "12" ]; then echo "self-test ok: sync-no-catch-all reports all 12 fixture lines"; else echo "SELF-TEST FAIL: sync-no-catch-all reported $sync_hits of 12 fixture lines" >&2; rc=1; fi
for want in CatchAllParticipant.kt:6: CatchAllParticipant.kt:10: CatchAllParticipant.kt:13:; do
  if grep -qF "android/entitlement/src/main/kotlin/org/ghost/entitlement/bad/$want" <<<"$sync_out"; then
    echo "self-test ok: sync-no-catch-all reports entitlement $want"
  else
    echo "SELF-TEST FAIL: sync-no-catch-all does not report entitlement $want" >&2; rc=1
  fi
done
expect_fail sync-no-catch-all "$HARNESS/negative-sync-no-entitlement"
out="$(GHOST_ROOT="$HARNESS/negative-sync-no-entitlement" bash "$DIR/sync-no-catch-all.sh" 2>&1 || true)"
if [ "$(printf '%s\n' "$out" | grep -c '^GATE-FAIL' || true)" = "1" ] && grep -qF "android/entitlement/src/main: missing" <<<"$out"; then
  echo "self-test ok: sync-no-catch-all reports a missing entitlement module"
else
  echo "SELF-TEST FAIL: sync-no-catch-all does not report exactly a missing entitlement module" >&2; rc=1
fi
# Phase 7 T6 (Kotlin side): every clearnet primitive in the fixture is reported, one line each.
expect_fail kotlin-clearnet "$HARNESS/negative-clearnet"
clearnet_hits="$(GHOST_ROOT="$HARNESS/negative-clearnet" bash "$DIR/kotlin-clearnet.sh" 2>&1 | grep -c '^GATE-FAIL' || true)"
if [ "$clearnet_hits" = "12" ]; then echo "self-test ok: kotlin-clearnet reports all 12 fixture lines"; else echo "SELF-TEST FAIL: kotlin-clearnet reported $clearnet_hits of 12 fixture lines" >&2; rc=1; fi
# Phase 7 T15m on fixture files: the negative merged manifest reports each of its 15 violations, and
# the merged release manifest as built at Phase 7 passes (a gate failing on everything is caught).
# Phase 7 T15m on fixture files: the negative merged manifest reports each of its 17 violations
# (16 of Phase 7's fixture plus G-M4's missing MediaDecodeService, slice S7), and the merged
# release manifest as built at Phase 7 passes (a gate failing on everything is caught).
MERGED_FIXTURES="$HARNESS/negative-merged-manifest"
merged_hits="$(bash "$DIR/merged-manifest-lint.sh" "$MERGED_FIXTURES/AndroidManifest.xml" 2>&1 | grep -c '^GATE-FAIL' || true)"
if [ "$merged_hits" = "17" ]; then echo "self-test ok: merged-manifest-lint reports all 17 violations of the negative fixture"; else echo "SELF-TEST FAIL: merged-manifest-lint reported $merged_hits of 17 violations" >&2; rc=1; fi
# G-DM7 (Phase 9 design §16.1; slice S12): the DM alarm receiver exported with an intent filter is
# three lines (two G-DM7 clauses and T15m's unlisted export), and the missing receiver is V16 above.
# The fixture predates Phase 11, so G-M4's missing MediaDecodeService adds a fourth line (slice S7).
dmrecv_out="$(bash "$DIR/merged-manifest-lint.sh" "$MERGED_FIXTURES/dm-receiver/AndroidManifest.xml" 2>&1 || true)"
dmrecv_hits="$(grep -c '^GATE-FAIL' <<<"$dmrecv_out" || true)"
if [ "$dmrecv_hits" = "4" ] && grep -qF 'must declare android:exported="false" (G-DM7)' <<<"$dmrecv_out" \
   && grep -qF 'must have no intent filter (G-DM7)' <<<"$dmrecv_out"; then
  echo "self-test ok: merged-manifest-lint reports the exported DM alarm receiver (G-DM7)"
else
  echo "SELF-TEST FAIL: merged-manifest-lint reported $dmrecv_hits of 4 violations (3 G-DM7 + G-M4's missing service)" >&2; rc=1
fi
if grep -qF 'ExpiryAlarmReceiver: missing' <<<"$(bash "$DIR/merged-manifest-lint.sh" "$MERGED_FIXTURES/AndroidManifest.xml" 2>&1 || true)"; then
  echo "self-test ok: merged-manifest-lint reports a missing DM alarm receiver (G-DM7)"
else
  echo "SELF-TEST FAIL: merged-manifest-lint does not report a missing DM alarm receiver" >&2; rc=1
fi
# ADR-06, FR-7.11 (Phase 9 review A-3): an androidx.startup initializer that is not allowlisted is
# one line — emoji2's, which called Google Play Services' font provider at every UI start. The
# Phase 7 fixture has no MediaDecodeService, so G-M4 adds a second line (slice S7).
startup_out="$(bash "$DIR/merged-manifest-lint.sh" "$MERGED_FIXTURES/startup/AndroidManifest.xml" 2>&1 || true)"
startup_hits="$(grep -c '^GATE-FAIL' <<<"$startup_out" || true)"
if [ "$startup_hits" = "2" ] && grep -qF 'androidx.startup initializer not allowlisted: androidx.emoji2.text.EmojiCompatInitializer' <<<"$startup_out"; then
  echo "self-test ok: merged-manifest-lint reports a startup initializer that is not allowlisted (A-3)"
else
  echo "SELF-TEST FAIL: merged-manifest-lint reported $startup_hits of 2 violations (the startup initializer + G-M4's missing service)" >&2; rc=1
fi
if bash "$DIR/merged-manifest-lint.sh" "$MERGED_FIXTURES/positive/AndroidManifest.xml" >/dev/null 2>&1; then
  echo "self-test ok: merged-manifest-lint accepts the Phase 7 merged release manifest"
else
  echo "SELF-TEST FAIL: merged-manifest-lint rejects the Phase 7 merged release manifest" >&2; rc=1
fi
# Phase 8 T2 (design §13.4, §13.6, §19.31): the report check accepts only a complete PASS report of
# the right scale (A1, the FR-6′.7 amount uniformity, included), and all 26 privacy mutants detected.
T2R="$HARNESS/t2-report"
# A negative case names the T2-REPORT-FAIL text it must fail with ($5): a fixture that fails for
# another reason (a second, unintended change) does not show the requirement it names (Phase 9
# design §22.24 item 10).
t2r_case() { # $1 = expect pass|fail, $2 = report, $3 = kind, $4 = description, $5 = the failure text (fail only)
  local err fails
  if err="$(bash "$DIR/t2-report-check.sh" "$T2R/$2" "$3" 2>&1 >/dev/null)"; then got=pass; else got=fail; fi
  fails="$(grep -E '^T2-REPORT-FAIL: ' <<<"$err" || true)"
  if [ "$got" != "$1" ]; then
    echo "SELF-TEST FAIL: t2-report-check $4 ($got)" >&2; rc=1
  elif [ "$1" = fail ] && { [ -z "${5:-}" ] || ! grep -qF -- "$5" <<<"$fails"; }; then
    echo "SELF-TEST FAIL: t2-report-check $4 (failed, but not with \"${5:-<no failure text named>}\")" >&2; rc=1
  else
    echo "self-test ok: t2-report-check $4"
  fi
}
# base-gate.txt is the made-up gate report ("PASS fixture" lines) every negative gate fixture below
# was made from: each is one change from it (a line removed, replaced or, for a failed check, the
# check's line and the result line), and the base itself passes — so each negative fails for the one
# requirement it names. pass-gate.txt is a measured report, not a made-up one: seed pair 0 at the
# gate scale after §4.9 (Phase 9 design §22.24), its dm_owner_namespaces field included; its scale
# is the gate's only. Its namespace counts are the Phase 11 design §5.2 T2 shift of the §22.24
# measurement (×1.5, "3 per activated client"), extrapolated by slice S4-owner because the gate
# scale cannot run locally; the CI gate job re-measures it.
t2r_case pass base-gate.txt gate "accepts the made-up base every negative gate fixture is one change from"
t2r_case pass pass-gate.txt gate "accepts the measured gate report (seed pair 0, Phase 9 §4.9, §22.24)"
t2r_case fail pass-gate.txt pr "rejects the measured gate report as the PR variant's" "the report is not of the pr scale"
t2r_case pass pass-pr.txt pr "accepts a complete PR-variant report"
t2r_case fail missing-check.txt gate "rejects a report without a check (NI-1d)" "no PASS line for NI-1d"
t2r_case fail failed-check.txt gate "rejects a report with a failed check" "S1 failed"
t2r_case fail wrong-scale.txt gate "rejects a PR-scale report as the gate's" "the report is not of the gate scale"
t2r_case fail vacuous.txt gate "rejects a check that passed on an empty sample (S3d, n=0)" "a check passed on an empty sample"
t2r_case fail missing-e30.txt gate "rejects a report without the E30 redeem-hold line" "no E30 line"
t2r_case fail vacuous-e30.txt gate "rejects an E30 line that measured no held session" "E30 measured no held session"
t2r_case fail vacuous-reads.txt gate "rejects an NI-2 line whose twin moved no drop read by an hour" "NI-2 or NI-3 passed with no drop read moved by an hour or more"
t2r_case fail exempt-twin.txt gate "rejects an NI-2 line that compared an inviter only before a horizon (no exemption, §19.29)" "NI-2 passed without identical views and no exemption"
t2r_case fail no-such-report.txt gate "rejects a missing report" "no report at"
t2r_case fail missing-a1.txt gate "rejects a report without the A1 amount-uniformity line (FR-6′.7, §19.31)" "no PASS line for A1"
t2r_case fail vacuous-a1.txt gate "rejects an A1 line that checked no wallet transfer" "A1 passed with no XMR invoice answer or no wallet transfer"
# Phase 9 design §4.9 point 3 (slice S11), extended to three namespaces per owner by Phase 11
# design §5.2's T2 bullet (slice S4-owner): the population line names the DM owner namespaces, and
# a world whose relays answered none of their registrations OK did not model them.
t2r_case fail missing-dm-namespaces.txt gate "rejects a population line without dm_owner_namespaces (Phase 9 §4.9)" "the population line names no dm_owner_namespaces"
t2r_case fail vacuous-dm-registrations.txt gate "rejects DM owner namespaces with no registration answered OK" "DM owner namespaces with no registration answered OK"
t2r_case fail failed-dm-registrations.txt gate "rejects DM registrations the loopback failed" "14 DM registrations failed on the loopback"
t2r_case fail dm-namespaces-per-owner.txt gate "rejects DM owner namespaces that are not three per activated client (Phase 11 §5.2)" "not three per activated client (Phase 11 design §5.2)"
# "One change from the base": every negative gate fixture differs from base-gate.txt in at most two
# lines (diff's `<` and `>` lines, a replaced line counting twice).
for neg in missing-check failed-check wrong-scale vacuous missing-e30 vacuous-e30 vacuous-reads exempt-twin \
  missing-a1 vacuous-a1 missing-dm-namespaces vacuous-dm-registrations failed-dm-registrations dm-namespaces-per-owner; do
  changed="$(diff "$T2R/base-gate.txt" "$T2R/$neg.txt" | grep -cE '^[<>]' || true)"
  if [ "$changed" -ge 1 ] && [ "$changed" -le 4 ]; then
    echo "self-test ok: t2-report fixture $neg.txt is one change from base-gate.txt ($changed diff lines)"
  else
    echo "SELF-TEST FAIL: t2-report fixture $neg.txt is not one change from base-gate.txt ($changed diff lines)" >&2; rc=1
  fi
done
t2r_case pass mutants-ok.txt mutants "accepts 26 detected mutants"
t2r_case pass mutants-interleaved.txt mutants "accepts a detected mutant whose ok line another test's output ran into"
t2r_case fail mutants-short.txt mutants "rejects 25 detected mutants" "25 of 26 mutants detected"
# Phase 10 EM-3 (design faza10-forum.md §12.3, §19.34, §19.34.1): the report check accepts only a
# complete report of its scale — every control scenario with at least its pinned states, its flows
# reached and its premises live, every registered mutant killed by its named check site, every check
# site broken by a registered run, every finding reproduced (and corrected where a correction is
# proposed), the corrections' rerun clean. pass-pr.txt and pass-full.txt are measured reports (the
# `EM-3` lines and libtest's result of a PR-bound and a full-bound run); every negative fixture is
# one change from its base, and each case names the CH-STATE-MODELS-FAIL text it must fail with.
CHSM="$HARNESS/ch-state-models"
chsm_case() { # $1 = expect pass|fail, $2 = report, $3 = scale, $4 = description, $5 = the failure text (fail only)
  local err fails
  if err="$(bash "$DIR/ch-state-models-check.sh" "$CHSM/$2" "$3" 2>&1 >/dev/null)"; then got=pass; else got=fail; fi
  fails="$(grep -E '^CH-STATE-MODELS-FAIL: ' <<<"$err" || true)"
  if [ "$got" != "$1" ]; then
    echo "SELF-TEST FAIL: ch-state-models-check $4 ($got)" >&2; rc=1
  elif [ "$1" = fail ] && { [ -z "${5:-}" ] || ! grep -qF -- "$5" <<<"$fails"; }; then
    echo "SELF-TEST FAIL: ch-state-models-check $4 (failed, but not with \"${5:-<no failure text named>}\")" >&2; rc=1
  else
    echo "self-test ok: ch-state-models-check $4"
  fi
}
chsm_case pass pass-pr.txt pr "accepts a measured PR-bound report"
chsm_case pass pass-full.txt full "accepts a measured full-bound report"
chsm_case fail pass-pr.txt full "rejects a PR-bound report as the full bound's" "no 'EM-3 controls (full): 20 scenarios' line"
chsm_case fail pass-full.txt pr "rejects a full-bound report as the PR bound's" "no 'EM-3 controls (pr): 19 scenarios' line"
chsm_case fail missing-control.txt pr "rejects a report without a control (SC-REMOVE)" "no line for the control SC-REMOVE"
chsm_case fail failed-control.txt pr "rejects a failed control (SC-GOV)" "the report names a failed control or a surviving mutant"
chsm_case fail unreached-flow.txt pr "rejects a control with an unreached flow (SC-JOIN, 1 of 2)" "SC-JOIN reached 1 of its 2 flows"
chsm_case fail vacuous-control.txt pr "rejects a control with no reachability query (SC-ADV, 0 of 0)" "SC-ADV names no reachability query"
chsm_case fail dead-premise.txt pr "rejects a control whose property never had its premise (SC-CONC's P-CONC)" "SC-CONC: P-CONC never had its premise"
chsm_case fail shrunk-control.txt pr "rejects a control that explored fewer states than pinned (SC-LATE)" "SC-LATE explored 1000 states, fewer than the"
chsm_case fail missing-bounds.txt pr "rejects a report without the bounds line" "no 'EM-3 bounds (pr)' line"
chsm_case fail survived-mutant.txt pr "rejects a surviving mutant (NoHold)" "the mutant NoHold was not killed"
chsm_case fail missing-mutant.txt pr "rejects a report without a registered mutant (OwnAnchorAtPass)" "the mutant OwnAnchorAtPass was not killed"
chsm_case fail uncovered-site.txt pr "rejects a check site no registered run breaks" "no 'EM-3 sites: … 0 by none' line"
chsm_case fail missing-finding.txt pr "rejects a report without a finding's correction line (F-5)" "no line 'EM-3 finding F-5 corrected'"
chsm_case fail corrections-failed.txt pr "rejects a corrections rerun with a failure" "no 'EM-3 corrections: 19 controls rerun"
chsm_case fail missing-arithmetic.txt pr "rejects a report without the arithmetic line" "no 'EM-3 arithmetic: 7 checks hold' line"
chsm_case fail no-result.txt pr "rejects a report without libtest's result" "no 'test result: ok. 10 passed; 0 failed'"
chsm_case fail no-such-report.txt pr "rejects a missing report" "no report at"
chsm_case fail full-no-mm2.txt full "rejects a full-bound report without MM-2's rerun" "no line 'EM-3 finding F-5 leaves MM-2 equivalent'"
chsm_case fail full-beacons-failed.txt full "rejects a full-bound report whose beacons rerun failed" "19 with F-2's beacons too (pr)"
# A report captured with CRLF line ends (on Windows) is the same report (§19.34.1 item 19).
chsm_crlf="$(mktemp -d)"
sed 's/$/\r/' "$CHSM/pass-pr.txt" > "$chsm_crlf/pass-pr-crlf.txt"
if bash "$DIR/ch-state-models-check.sh" "$chsm_crlf/pass-pr-crlf.txt" pr >/dev/null 2>&1; then
  echo "self-test ok: ch-state-models-check accepts the PR-bound report with CRLF line ends"
else
  echo "SELF-TEST FAIL: ch-state-models-check rejects the PR-bound report with CRLF line ends" >&2; rc=1
fi
rm -rf "$chsm_crlf"
# "One change from the base": every negative fixture differs from its base in at most two lines.
for neg in missing-control failed-control unreached-flow vacuous-control dead-premise shrunk-control \
  missing-bounds survived-mutant missing-mutant uncovered-site missing-finding corrections-failed \
  missing-arithmetic no-result full-no-mm2 full-beacons-failed; do
  base=pass-pr.txt
  [[ $neg == full-* ]] && base=pass-full.txt
  changed="$(diff "$CHSM/$base" "$CHSM/$neg.txt" | grep -cE '^[<>]' || true)"
  if [ "$changed" -ge 1 ] && [ "$changed" -le 4 ]; then
    echo "self-test ok: ch-state-models fixture $neg.txt is one change from $base ($changed diff lines)"
  else
    echo "SELF-TEST FAIL: ch-state-models fixture $neg.txt is not one change from $base ($changed diff lines)" >&2; rc=1
  fi
done
# Phase 9 S10 (design §15.3, §15.4, §15.6, §15.7): the DM exit-gate report check accepts only a
# complete report of the right scale. Every negative fixture is a way the report could look complete
# while the run measured nothing — a scenario missing, an enumeration of zero crash points, a
# double-crash count of zero, a seeded loop in which no seed drew a fault, a `SQLITE_FULL` half that
# injected nothing, and a mutant with no line naming what kills it. Five of them are the ways the
# slice's own review found the report could still claim more than it ran: a **gate** header over a
# sampled enumeration, a gate that skipped timeout-after-apply runs, a suite with no timeout run
# anywhere, a scenario with no stores to run them over (relay events, until S10b's review), and a
# mutant the registry counts while no run killed it.
DMR="$HARNESS/dm-report"
# Since the review of §22.38 a failing case of the exit-gate report (kinds gate and pr) names the
# violation it is for ($5, as `t2r_case` does), and that text must be one of the check's
# DM-REPORT-FAIL lines: until then a negative passed here as long as it failed at all, so one that had
# gone stale — failing for some other reason, or for its own no longer — could not be told from one
# that works. The privacy kinds keep the pass/fail rule for now.
dmr_case() { # $1 = expect pass|fail, $2 = report, $3 = kind, $4 = description, $5 = the violation (fail; gate and pr kinds)
  local err fails
  if err="$(bash "$DIR/dm-report-check.sh" "$DMR/$2" "$3" 2>&1 >/dev/null)"; then got=pass; else got=fail; fi
  fails="$(grep -E '^DM-REPORT-FAIL: ' <<<"$err" || true)"
  if [ "$got" != "$1" ]; then
    echo "SELF-TEST FAIL: dm-report-check $4 ($got)" >&2; rc=1
  elif [ "$1" = fail ] && case "$3" in gate|pr) true ;; *) [ -n "${5:-}" ] ;; esac &&
    { [ -z "${5:-}" ] || ! grep -qF -- "$5" <<<"$fails"; }; then
    echo "SELF-TEST FAIL: dm-report-check $4 (failed, but not with \"${5:-<no violation named>}\")" >&2; rc=1
  else
    echo "self-test ok: dm-report-check $4"
  fi
}
dmr_case pass pass-gate.txt gate "accepts a complete gate report"
dmr_case pass pass-pr.txt pr "accepts a complete PR-scale report"
dmr_case fail pass-pr.txt gate "rejects a PR-scale report as the gate's" "the report is not of the gate scale"
dmr_case fail pass-gate.txt pr "rejects a gate-scale report as a PR's" "the report is not of the pr scale"
dmr_case fail missing-scenario.txt gate "rejects a report without a scenario (SCN-D)" "no crash-class line for SCN-D"
dmr_case fail empty-enumeration.txt gate "rejects a scenario that enumerated 0 crash points" "SCN-G enumerated 0 crash points"
dmr_case fail no-doubles.txt gate "rejects SCN-F without double crashes (§15.3)" "SCN-F ran no double crashes"
dmr_case fail no-storage-full.txt gate "rejects SCN-J with no SQLITE_FULL injected" "SCN-J injected no SQLITE_FULL"
dmr_case fail no-fault-drawn.txt gate "rejects a faulted seeded loop in which no seed drew a fault" "no faulted seeded-world line, or no seed drew a fault"
dmr_case fail unkilled-mutant.txt gate "rejects a mutant with no line naming what kills it" "no detection line for mutant MC-10"
dmr_case fail undetected-mutant.txt gate "rejects a mutant the run recorded no kill for" "a registered mutant was not detected by any run"
dmr_case fail sampled-gate.txt gate "rejects a gate header over a sampled enumeration" "SCN-A sampled: 120 singles over 1550 events, and the gate crashes at every one"
dmr_case fail gate-sampled-timeouts.txt gate "rejects a gate that skipped timeout-after-apply runs" "SCN-G ran 2 timeout-after-apply runs over 4 stores"
dmr_case fail no-timeouts.txt pr "rejects a report with no timeout-after-apply run anywhere" "SCN-A ran no timeout-after-apply run"
dmr_case fail no-relay-events.txt gate "rejects a scenario whose timeout runs have no denominator" "SCN-B reported no stores, so its timeout runs have no denominator"
dmr_case fail no-such-report.txt gate "rejects a missing report" "no report at"
# Phase 10 S11 (design §13.1's `ch-report-check.sh` row): the channel gates' report check. The
# positive fixtures are a complete gate report and the PR-scale one; the negatives are the ways a
# report could look complete while its run measured nothing — a FAIL line (the single change of
# fail-line.txt), the privacy half missing, the mutant count missing, a mutant count above the
# registered one (the single change of wrong-mutant-count.txt), and a PR-scale report standing
# in for the gate's. (Amended §19.52 FIX 9: the FAIL-line and mutant-count negatives are strict
# single-change fixtures — the old fail-line.txt changed both at once.)
CHR="$HARNESS/ch-report"
chr_case() { # $1 = expect pass|fail, $2 = report, $3 = kind, $4 = description, $5 = the violation (fail)
  local err fails
  if err="$(bash "$DIR/ch-report-check.sh" "$CHR/$2" "$3" 2>&1 >/dev/null)"; then got=pass; else got=fail; fi
  fails="$(grep -E '^CH-REPORT-FAIL: ' <<<"$err" || true)"
  if [ "$got" != "$1" ]; then
    echo "SELF-TEST FAIL: ch-report-check $4 ($got)" >&2; rc=1
  elif [ "$1" = fail ] && { [ -z "${5:-}" ] || ! grep -qF -- "$5" <<<"$fails"; }; then
    echo "SELF-TEST FAIL: ch-report-check $4 (failed, but not with \"${5:-<no violation named>}\")" >&2; rc=1
  else
    echo "self-test ok: ch-report-check $4"
  fi
}
chr_case pass pass-gate.txt gate "accepts a complete gate report"
chr_case pass pass-pr.txt pr "accepts a complete PR-scale report"
chr_case fail pass-pr.txt gate "rejects a PR-scale report as the gate's" "the gate report does not hold all three pinned seeds"
chr_case fail fail-line.txt gate "rejects a report with a FAIL line" "a channel line reports FAIL"
chr_case fail wrong-mutant-count.txt gate "rejects a mutant count above the registered one" "the mutant line is not"
chr_case fail missing-privacy.txt gate "rejects a report without the privacy half" "no JC-1 line or not a PASS"
chr_case fail missing-mutants.txt gate "rejects a report without the mutant count" "the mutant line is not"
# Phase 9 S13 (design §9.5, §16.2): the `pq-model` comparison, proven without ProVerif. A fake
# replays recorded outputs; every negative fixture is a way a model run could look green while it
# decided nothing: a flipped result, `cannot be proved`, a query removed from a model, a query added
# to one, a model file nobody runs, a listed model that is gone, a ProVerif error, a timeout, a
# token that names two results, and an expectation that is neither true nor false.
PQM="$HARNESS/pq-model"
# The time limit per model: generous for every case (a fake that replays a file must never be cut off
# by a loaded machine's process start, which made the two "accepts" cases fail under load, and a
# negative must fail for its own reason, not for a timeout), except the timeout case itself, whose
# limit (PQM_TIMEOUT=1) stays below the 3 seconds its fake sleeps (`timeout/b.sleep`), so it overruns
# on any machine.
pqm_case() { # $1 = expect pass|fail, $2 = fixture directory, $3 = description
  if PROVERIF="$PQM/fake-proverif.sh" PQ_MODEL_TIMEOUT="${PQM_TIMEOUT:-300}" PQ_MODEL_DIR="$PQM/$2" \
    bash "$DIR/pq-model.sh" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$1" ]; then echo "self-test ok: pq-model $3"; else echo "SELF-TEST FAIL: pq-model $3 ($got)" >&2; rc=1; fi
}
pqm_case pass pass "accepts results that match their expectations"
pqm_case fail mismatch "rejects a flipped result"
pqm_case fail unproved "rejects a query ProVerif cannot prove"
pqm_case fail missing-result "rejects an expected query with no RESULT line"
pqm_case fail extra-result "rejects a RESULT line no expectation names"
pqm_case fail unlisted-model "rejects a model file expected.txt does not list"
pqm_case fail missing-model "rejects a listed model that is not there"
pqm_case fail proverif-error "rejects a ProVerif error"
PQM_TIMEOUT=1 pqm_case fail timeout "rejects a model that runs past the timeout"
pqm_case fail ambiguous-token "rejects a token that names two results"
pqm_case fail malformed-expected "rejects an expectation that is neither true nor false"
# The S13 review: mutants are generated from their originals by a patch, never copied.
pqm_case pass mutant-pass "accepts a mutant generated from its original by a patch"
pqm_case fail mutant-drift "rejects a mutant patch that no longer applies to its original"
pqm_case fail mutant-copied "rejects a mutant that is both a copied file and a patch"
# Phase 9 PQ1/PQ5 (design §15.5, §15.7 PM-32, §22.20): the PQ mutant gate, proven without compiling.
# A scratch git tree holds one state file; each fixture patch rewrites it, and a fake cargo answers
# from it. Every negative is a way the gate could pass while a mutant was never killed: a survivor, a
# kill the header names that did not happen, no header, a patch that no longer applies, a mutant that
# does not build, a failing run with no failing test, a mutant that broke the world every test reads
# (its kills are not its own) or names the world's test as a kill, a revert that fails (the tree is
# left mutated, so the case expects that too), and an unpatched run that fails, skips a named test,
# skips the world's test, ignores one, or has no patch to check at all. The positive also proves the
# tree is restored.
PQX="$HARNESS/pq-mutants"
pqx_case() { # $1 = expect pass|fail, $2 = description, $3 = unpatched mode, then patches as state:kills[,kills]
  local expect="$1" desc="$2" clean="$3" tmp spec state kills patch got
  shift 3
  tmp="$(mktemp -d)"
  git init -q "$tmp/repo"
  git -C "$tmp/repo" config core.autocrlf false
  printf 'clean\n' > "$tmp/repo/state"
  git -C "$tmp/repo" add state
  git -C "$tmp/repo" -c user.name=gate -c user.email=gate@self.test -c commit.gpgsign=false commit -q -m clean
  mkdir "$tmp/mutants"
  for spec in "$@"; do
    state="${spec%%:*}"
    kills="${spec#*:}"
    patch="$tmp/mutants/$state.patch"
    {
      [ -z "$kills" ] || tr ',' '\n' <<<"$kills" | sed 's/^/# kills: /'
      if [ "$state" = stale ]; then
        printf -- '--- a/state\n+++ b/state\n@@ -1 +1 @@\n-other\n+kill-a\n'
      else
        printf '%s\n' "$state" > "$tmp/repo/state"
        git -C "$tmp/repo" diff
        git -C "$tmp/repo" checkout -q -- state
      fi
    } > "$patch"
  done
  if GHOST_PQ_CARGO="$PQX/fake-cargo.sh" GHOST_PQ_FAKE_STATE="$tmp/repo/state" GHOST_PQ_FAKE_CLEAN="$clean" \
    GHOST_PQ_MUTANTS_DIR="$tmp/mutants" GHOST_PQ_MUTANTS_REPO="$tmp/repo" GHOST_PQ_WORLD=t::w \
    bash "$DIR/pq-mutants.sh" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$(tr -d '\r' < "$tmp/repo/state")" != clean ]; then got="$got, tree not restored"; fi
  if [ "$got" = "$expect" ]; then echo "self-test ok: pq-mutants $desc"; else echo "SELF-TEST FAIL: pq-mutants $desc ($got)" >&2; rc=1; fi
  rm -rf "$tmp"
}
pqx_case pass "accepts mutants each killed by the tests they name" pass "kill-a:t::a" "kill-ab:t::a,t::b"
pqx_case fail "rejects a mutant that survives" pass "kill-a:t::a" "survive:t::a"
pqx_case fail "rejects a named kill that did not happen" pass "kill-a:t::a,t::b"
pqx_case fail "rejects a mutant that names no test" pass "kill-a:"
pqx_case fail "rejects a patch that no longer applies" pass "stale:t::a"
pqx_case fail "rejects a mutant that does not build" pass "nobuild:t::a"
pqx_case fail "rejects a failing run without a failing test" pass "noname:t::a"
pqx_case fail "rejects an unpatched tree whose PQ tests fail" fail "kill-a:t::a"
pqx_case fail "rejects a named test the unpatched run did not run" missing "kill-ab:t::a,t::b"
pqx_case fail "rejects an unpatched run with an ignored test" ignored "kill-a:t::a"
pqx_case fail "rejects an empty mutant directory" pass
# The review of PQ1/PQ5 (design §22.20 item 9): the shared world, and a revert that fails.
pqx_case fail "rejects a mutant that breaks the shared world" pass "kill-a:t::a" "break-world:t::a"
pqx_case fail "rejects a mutant that names the world's test as a kill" pass "kill-a:t::a,t::w"
pqx_case fail "rejects an unpatched run that did not run the world's test" noworld "kill-a:t::a"
pqx_case "fail, tree not restored" "fails when a patch cannot be reverted" pass "tamper:t::a"
# Phase 9 S10b (design §22.19): the report now carries SCN-H, SCN-I, SCN-K and SCN-G-week and eleven
# mutants, and every negative above was regenerated from the new positives with its one change. Four
# more:
# a report of S10's shape (seven scenarios, seven mutants) — the check must not accept the old
# evidence as the new — SCN-I without the double crashes §15.3 names for it, a report without
# SCN-K, and one of S10b's mutants with no line naming its killer.
dmr_case fail s10-only-gate.txt gate "rejects an S10-shaped report without S10b's scenarios and mutants" "no crash-class line for SCN-H"
dmr_case fail no-scn-i-doubles.txt gate "rejects SCN-I without double crashes (§15.3)" "SCN-I ran no double crashes"
dmr_case fail missing-scn-k.txt gate "rejects a report without SCN-K" "no crash-class line for SCN-K"
dmr_case fail unkilled-s10b-mutant.txt gate "rejects MC-33 with no line naming what kills it" "no detection line for mutant MC-33"
# The review of S10b (design §22.19 item 14): a timeout counted at every relay event, three per
# store, where only the after-apply one injects anything — the inflated shape the S10b report had;
# one of S10b's kills held only to the fault-free rule, which the report could not show before the
# rule was printed on the line; and a PR report with one scenario that ran no timeout at all.
dmr_case fail relay-event-denominator.txt gate "rejects timeouts counted over relay events instead of stores" "SCN-A reported no stores, so its timeout runs have no denominator"
dmr_case fail weakened-kill-rule.txt gate "rejects MC-18 killed only fault-free" "mutant MC-18 was not killed under its rule"
dmr_case fail pr-scenario-no-timeout.txt pr "rejects a PR report in which SCN-K ran no timeout" "SCN-K ran no timeout-after-apply run"
# Phase 9 S10c (design §22.23): the report now carries SCN-C, both positives are real reports of the
# S10c code, and every negative above except `s10-only-gate.txt` was regenerated from them with its
# one change (that one is an S10-shaped report on purpose and is kept as S10b wrote it; it still
# fails for the reason it names). Two more: a gate and a PR report without SCN-C, which is also the
# shape of every report before S10c.
dmr_case fail missing-scn-c.txt gate "rejects a report without SCN-C" "no crash-class line for SCN-C"
dmr_case fail missing-scn-c-pr.txt pr "rejects a PR-scale report without SCN-C" "no crash-class line for SCN-C"
# Phase 9 SCN-E (design §22.25): the report now carries SCN-E's four `dm crash sample:` lines — its
# crash coverage is sampled, not every event — and thirteen mutants. `pass-pr.txt` is a real report
# of the SCN-E code; `pass-gate.txt` is **assembled** (§22.25 items 13 and 14: main's gate report of
# the S10c code with the SCN-E-alone gate-scale lines and this slice's mutant lines put in, because
# the whole gate was not run on this code) — the review found this comment calling both "real
# reports". Every negative above except `s10-only-gate.txt` was regenerated from the positives with
# its one change by a script that, run first on the previous positives, reproduced the previous
# negatives byte for byte. Eight more, each a way an SCN-E report could claim more than its run
# did: no SCN-E at all (every report before it), at either scale; a line that does not say it is
# sampled; a line in the every-event form; a gate report whose sample has the PR density; a line
# with no timeout run; MC-15 held only to the fault-free rule; and the eleven-mutant count.
dmr_case fail missing-scn-e.txt gate "rejects a report without SCN-E" "no crash-sample line for SCN-E bob"
dmr_case fail missing-scn-e-pr.txt pr "rejects a PR-scale report without SCN-E" "no crash-sample line for SCN-E bob"
dmr_case fail scn-e-not-said-sampled.txt gate "rejects an SCN-E line that does not say it is sampled" "SCN-E bob's line is not of the sample form, or does not say that its enumeration is sampled, not every event"
dmr_case fail scn-e-as-crash-classes.txt gate "rejects an SCN-E line that claims every event" "an SCN-E line claims the every-event enumeration it does not run"
dmr_case fail scn-e-pr-density-gate.txt gate "rejects a gate report whose SCN-E sample has the PR density" "SCN-E alice sampled 1 crash points per phase, and the gate scale samples 8"
dmr_case fail scn-e-no-timeout.txt pr "rejects an SCN-E line with no timeout run" "SCN-E/LOSE_KEYS bob ran 0 timeouts at 1 faulted stores"
dmr_case fail scn-e-weakened-kill-rule.txt gate "rejects MC-15 killed only fault-free" "mutant MC-15 was not killed under its rule"
dmr_case fail scn-e-old-mutant-count.txt gate "rejects the eleven-mutant report of the slices before SCN-E" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
# The review of SCN-E (design §22.25 item 14): an SCN-E line collapsed to one phase (the review's
# "8 singles over 1 phases", which the check accepted); a gate line whose store faults have the PR
# density; a line whose stores were timed out but never crashed after apply; MC-15 held to the
# whole-run crash points the review found all in the establishment; and a header that does not say
# its "every event" is not the SCN-E lines'.
dmr_case fail scn-e-one-phase.txt gate "rejects an SCN-E line sampled over fewer phases than its script has" "SCN-E bob sampled over 1 phases, and its script has 6"
dmr_case fail scn-e-gate-store-density.txt gate "rejects a gate SCN-E line whose store faults have the PR density" "SCN-E alice faulted 1 of the 12 stores of its phase 1, and the gate scale faults 3"
dmr_case fail scn-e-no-store-crash.txt gate "rejects an SCN-E line with no crash after apply at its stores" "SCN-E/LOSE_KEYS alice ran 0 crashes after apply at 6 faulted stores"
dmr_case fail scn-e-old-kill-window.txt gate "rejects MC-15 killed at crash points outside the window where it acts" "mutant MC-15 was not killed under its rule"
dmr_case fail scn-e-no-coverage-note.txt gate "rejects a header that does not say the SCN-E lines are sampled" "the header does not say that its scale is not the SCN-E lines', which are sampled"
# Phase 9 suite cases (design §22.27): the report now carries KC12, RS2 and RP7 as crash-class lines,
# the suite line pinned at seven cases, and fifteen mutants, MC-21 and MC-24 held to the rule of the
# transaction each first changes (six crash points spread over MC-21's, both events of MC-24's; the
# review's correction, §22.27 item 11). `pass-pr.txt` is a real report of the reviewed code;
# `pass-gate.txt` is assembled (§22.27 item 11(k)). Every negative above except `s10-only-gate.txt`
# was regenerated from the reviewed positives by replacing, in each, exactly the lines the positives
# changed (RS2's line and the MC-21 and MC-24 lines), each one's own change kept and checked to be
# its only difference from its positive. Eight more, each a way a report could claim more than was
# run: no KC12, no RS2 (at the PR scale), no RP7, the thirteen-mutant report of the slices before it,
# MC-21 held only to the fault-free rule, MC-24 held to crash points spread over the whole run, and
# (the review's) the four-case suite line of the slices before, and MC-21 held to the first version's
# window — from the mark to the end of the run, which put all six points after its only commit.
dmr_case fail missing-kc12.txt gate "rejects a report without KC12" "no crash-class line for KC12"
dmr_case fail missing-rs2-pr.txt pr "rejects a PR-scale report without RS2" "no crash-class line for RS2"
dmr_case fail missing-rp7.txt gate "rejects a report without RP7" "no crash-class line for RP7"
dmr_case fail suite-old-mutant-count.txt gate "rejects the thirteen-mutant report of the slices before §22.27" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail mc21-weakened-kill-rule.txt gate "rejects MC-21 killed only fault-free" "mutant MC-21 was not killed under its rule"
dmr_case fail mc24-whole-run-kill-rule.txt gate "rejects MC-24 killed at crash points over the whole run" "mutant MC-24 was not killed under its rule"
dmr_case fail suite-old-case-count.txt gate "rejects the four-case suite line of the slices before §22.27" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
dmr_case fail mc21-first-window-rule.txt gate "rejects MC-21 held to the first version's window (mark to end of run)" "mutant MC-21 was not killed under its rule"
# The second suite-case slice (design §22.37): RP5, RP4, RP11 and KC5b under the enumeration, the
# suite line pinned at eleven cases, sixteen mutants, MC-7′ held to the rule of both its halves (the
# CB replay and RP4 fault-free; RP5 at every event of its split window) and MC-20 to its four
# omissions. `pass-pr.txt` is a real PR-scale report of this slice (§22.37 item 10); `pass-gate.txt`
# is assembled, its four new crash-class lines the real counts of every-point enumerations. Every
# negative above that was a positive with an edit was re-derived from the new positives with its own
# edit and checked to fail with exactly the violations it failed with before; `no-timeouts.txt` and
# `relay-event-denominator.txt`, a positive under a transform (every timeout zeroed; stores counted
# as three relay events each), by that transform, checked to reproduce the old copies from the old
# positives exactly, so they fail the same way for the four new lines too; `s10-only-gate.txt`
# stays the S10-era report it is. Eight more, each a
# way a report could claim more than was run: no KC5b, no RP5 (at the PR scale), no RP11, the
# seven-case suite line of §22.27, the fifteen-mutant report of §22.27, MC-7′ held to its first
# half's fault-free rule alone, MC-20 killed for three of its four omissions, and no MC-20 line.
dmr_case fail missing-kc5b.txt gate "rejects a report without KC5b" "no crash-class line for KC5b"
dmr_case fail missing-rp5-pr.txt pr "rejects a PR-scale report without RP5" "no crash-class line for RP5"
dmr_case fail missing-rp11.txt gate "rejects a report without RP11" "no crash-class line for RP11"
dmr_case fail suite-seven-case-count.txt gate "rejects the seven-case suite line of §22.27" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
dmr_case fail suite-fifteen-mutant-count.txt gate "rejects the fifteen-mutant report of §22.27" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail mc7-first-half-rule.txt gate "rejects MC-7′ held to its first half's fault-free rule alone" "mutant MC-7' was not killed under its rule"
dmr_case fail mc20-three-omissions.txt gate "rejects MC-20 killed for three of its four omissions" "mutant MC-20 was not killed under its rule"
dmr_case fail mc20-no-kill-line.txt gate "rejects a report without MC-20's kill line" "no detection line for mutant MC-20"
# §22.38, group 1: EP-sweep-log under the enumeration, twelve suite cases, seventeen mutants, and
# ME-11 held to the window rule (its one event, SWEEP's first checkpoint after the mark). The
# positives are regenerated as §22.37's were (`pass-pr.txt` a real PR-scale report, `pass-gate.txt`
# assembled, the new crash-class line a real every-point count), and every negative above was
# re-derived from them with its own edit. Four more, each a positive with one violation: no
# EP-sweep-log line, the eleven-case suite line of §22.37, its sixteen-mutant line, and ME-11 held
# to the fault-free rule alone.
dmr_case fail missing-ep-sweep-log.txt gate "rejects a report without EP-sweep-log" "no crash-class line for EP-sweep-log"
dmr_case fail suite-eleven-case-count.txt gate "rejects the eleven-case suite line of §22.37" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
dmr_case fail suite-sixteen-mutant-count.txt gate "rejects the sixteen-mutant report of §22.37" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail me11-weakened-kill-rule.txt gate "rejects ME-11 killed only fault-free" "mutant ME-11 was not killed under its rule"
# §22.38, group 2: EP-clock-back under the enumeration, thirteen suite cases, eighteen mutants, and
# ME-17 held to the window rule. Positives and every negative regenerated as for group 1. Four more,
# each a positive with one violation: no EP-clock-back line, the twelve-case suite line of group 1,
# its seventeen-mutant line, and ME-17 held to the fault-free rule alone.
dmr_case fail missing-ep-clock-back.txt gate "rejects a report without EP-clock-back" "no crash-class line for EP-clock-back"
dmr_case fail suite-twelve-case-count.txt gate "rejects the twelve-case suite line of §22.38's group 1" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
dmr_case fail suite-seventeen-mutant-count.txt gate "rejects the seventeen-mutant report of §22.38's group 1" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail me17-weakened-kill-rule.txt gate "rejects ME-17 killed only fault-free" "mutant ME-17 was not killed under its rule"
# §22.38, group 3: MC-9 on RECV's freshness policy, killed by RP7 — no new case, so thirteen suite
# cases and nineteen mutants. Positives and every negative regenerated as for group 1. Two more, each
# a positive with one violation: the eighteen-mutant line of group 2, and MC-9 held to the
# fault-free rule alone.
dmr_case fail suite-eighteen-mutant-count.txt gate "rejects the eighteen-mutant report of §22.38's group 2" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail mc9-weakened-kill-rule.txt gate "rejects MC-9 killed only fault-free" "mutant MC-9 was not killed under its rule"
# §22.38, group 4: SCN-L-v3 (a v3 file migrated on the bus) under the enumeration, and MC-17 and ME-9
# killed there — thirteen suite cases (SCN-L-v3 is a scenario line) and twenty-one mutants.
# Positives and every negative regenerated as for group 1. Four more, each a positive with one
# violation: no SCN-L-v3 line, the nineteen-mutant line of group 3, MC-17 held to one half's rule,
# and ME-9 held to the fault-free rule alone.
dmr_case fail missing-scn-l-v3.txt gate "rejects a report without SCN-L-v3" "no crash-class line for SCN-L-v3"
dmr_case fail suite-nineteen-mutant-count.txt gate "rejects the nineteen-mutant report of §22.38's group 3" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail mc17-one-half.txt gate "rejects MC-17 killed for one of its two halves" "mutant MC-17 was not killed under its rule"
dmr_case fail me9-weakened-kill-rule.txt gate "rejects ME-9 killed only fault-free" "mutant ME-9 was not killed under its rule"
# §22.38, group 5: ME-24, a native hook per DM context, killed by the standing clause that every stored
# session state opens under the device's state key — no new case, so thirteen suite cases and
# twenty-two mutants. Positives and every negative regenerated as for group 1. Two more, each a
# positive with one violation: the twenty-one-mutant line of group 4, and ME-24 held to the
# fault-free rule alone.
dmr_case fail suite-twentyone-mutant-count.txt gate "rejects the twenty-one-mutant report of §22.38's group 4" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail me24-weakened-kill-rule.txt gate "rejects ME-24 killed only fault-free" "mutant ME-24 was not killed under its rule"
# §22.38, group 6: RO-prune under the enumeration, and MC-30 killed there, both halves — fourteen suite
# cases and twenty-three mutants. Positives and every negative regenerated as for group 1. Four more,
# each a positive with one violation: no RO-prune line, the thirteen-case suite line of group 5, its
# twenty-two-mutant line, and MC-30 held to one half's rule.
dmr_case fail missing-ro-prune.txt gate "rejects a report without RO-prune" "no crash-class line for RO-prune"
dmr_case fail suite-thirteen-case-count.txt gate "rejects the thirteen-case suite line of §22.38's group 5" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
dmr_case fail suite-twentytwo-mutant-count.txt gate "rejects the twenty-two-mutant report of §22.38's group 5" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail mc30-one-half.txt gate "rejects MC-30 killed for one of its two halves" "mutant MC-30 was not killed under its rule"
# §22.38, group 7: EP-store-after-expiry under the enumeration, and ME-20 killed there — fifteen suite
# cases and twenty-four mutants. Positives and every negative regenerated as for group 1. Four more,
# each a positive with one violation: no EP-store-after-expiry line, the fourteen-case suite line of
# group 6, its twenty-three-mutant line, and ME-20 held to the fault-free rule alone.
dmr_case fail missing-ep-store-after-expiry.txt gate "rejects a report without EP-store-after-expiry" "no crash-class line for EP-store-after-expiry"
dmr_case fail suite-fourteen-case-count.txt gate "rejects the fourteen-case suite line of §22.38's group 6" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
dmr_case fail suite-twentythree-mutant-count.txt gate "rejects the twenty-three-mutant report of §22.38's group 6" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail me20-weakened-kill-rule.txt gate "rejects ME-20 killed only fault-free" "mutant ME-20 was not killed under its rule"
# §22.38, group 8: EP-sender-ahead under the enumeration, and ME-19 killed there — sixteen suite cases
# and twenty-five mutants. Positives and every negative regenerated as for group 1. Four more, each a
# positive with one violation: no EP-sender-ahead line, the fifteen-case suite line of group 7, its
# twenty-four-mutant line, and ME-19 held to the fault-free rule alone.
dmr_case fail missing-ep-sender-ahead.txt gate "rejects a report without EP-sender-ahead" "no crash-class line for EP-sender-ahead"
dmr_case fail suite-fifteen-case-count.txt gate "rejects the fifteen-case suite line of §22.38's group 7" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
dmr_case fail suite-twentyfour-mutant-count.txt gate "rejects the twenty-four-mutant report of §22.38's group 7" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail me19-weakened-kill-rule.txt gate "rejects ME-19 killed only fault-free" "mutant ME-19 was not killed under its rule"
# §22.38, group 9: EP-stale-display under the enumeration, and ME-7 killed there — seventeen suite
# cases and twenty-six mutants. Positives and every negative regenerated as for group 1. Four more,
# each a positive with one violation: no EP-stale-display line, the sixteen-case suite line of group 8,
# its twenty-five-mutant line, and ME-7 held to the fault-free rule alone.
dmr_case fail missing-ep-stale-display.txt gate "rejects a report without EP-stale-display" "no crash-class line for EP-stale-display"
dmr_case fail suite-sixteen-case-count.txt gate "rejects the sixteen-case suite line of §22.38's group 8" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
dmr_case fail suite-twentyfive-mutant-count.txt gate "rejects the twenty-five-mutant report of §22.38's group 8" "the mutant line is not 'dm mutants: 26 run, 26 detected'"
dmr_case fail me7-weakened-kill-rule.txt gate "rejects ME-7 killed only fault-free" "mutant ME-7 was not killed under its rule"
# §22.38, group 10: RP8 under the enumeration, a suite case without a mutant of its own — eighteen
# suite cases, twenty-six mutants still. Positives and every negative regenerated as for group 1. Two
# more, each a positive with one violation: no RP8 line, and the seventeen-case suite line of group 9.
dmr_case fail missing-rp8.txt gate "rejects a report without RP8" "no crash-class line for RP8"
dmr_case fail suite-seventeen-case-count.txt gate "rejects the seventeen-case suite line of §22.38's group 9" "the suite-case line is not 'dm suite cases: 18 run, 0 failures'"
# The review of §22.38 (its item 23): ME-17's window is where its traced world parts from the clean
# one — bob's RECV, six points over events 311..329 — and no longer its first rewritten span, alice's
# read-only conversation read (4..8), which decided nothing; MC-9's kill is its B1 half (RP7 cannot
# tell R9's). `pass-pr.txt` is the report of the first run of the whole suite on the real build (AGP),
# `pass-gate.txt` stays assembled with the new mutant lines, and every negative above was re-derived
# with its own edit, checked to be the same edit and to fail with the same violations as before. Two
# more, each a positive with one line as the reviewed report had it: ME-17 held to its first
# rewritten span (5 of 5), and MC-9 recorded whole.
dmr_case fail me17-first-span-rule.txt gate "rejects ME-17 held to its first rewritten span, alice's read (5 of 5)" "mutant ME-17 was not killed under its rule"
dmr_case fail mc9-whole-rule.txt gate "rejects MC-9 recorded whole, where its kill is its B1 half" "mutant MC-9 was not killed under its rule"
# Phase 9 S11 (design §15.6, §15.7, §22.16): the privacy report. `privacy-pass-pr.txt` is a real
# PR-scale report of this slice (the owner's workstation); the gate and suite positives are its halves
# with the gate header, illustrative of the shape the check enforces. Every negative is a way the
# report could look complete while the run measured nothing, or claimed a scale or a build it was not.
dmr_case pass privacy-pass-pr.txt privacy-pr "accepts a complete PR-scale privacy report"
dmr_case pass privacy-pass-gate.txt privacy-gate "accepts a gate-scale world report"
dmr_case pass privacy-pass-suite.txt privacy-suite "accepts a twins, seizure and mutants report"
dmr_case fail privacy-pass-pr.txt privacy-gate "rejects a PR-scale privacy report as the gate's"
dmr_case fail privacy-pass-gate.txt privacy-pr "rejects a gate world report without the suite as a PR report"
dmr_case fail privacy-failed-join.txt privacy-pr "rejects a join that found a match (JD1)"
dmr_case fail privacy-empty-join.txt privacy-pr "rejects a join that passed over nothing (JD4 over 0)"
dmr_case fail privacy-missing-join.txt privacy-pr "rejects a report without a join line (JD9)"
dmr_case fail privacy-sdm3-floor.txt privacy-pr "rejects S-DM3 under the n >= 100 floor"
dmr_case fail privacy-sdm3-control.txt privacy-pr "rejects S-DM3 whose colluders' control mapped nothing"
dmr_case fail privacy-t35-plain.txt privacy-pr "rejects the NOT RUN T35 line of a plain host build"
dmr_case fail privacy-t34-empty.txt privacy-pr "rejects T34 over no expired-week pair blob"
dmr_case fail privacy-ni-missing.txt privacy-pr "rejects a report without NI-DM1"
dmr_case fail privacy-ni3-missing.txt privacy-pr "rejects a report without NI-DM3"
dmr_case fail privacy-undetected-mutant.txt privacy-pr "rejects a privacy mutant not killed by every check it names"
dmr_case fail privacy-idle-world.txt privacy-pr "rejects a world that sent nothing"
# Slice S11's review: each is a way the first version of the check still accepted a report that
# proved less than it said — a seizure control that opened 1 blob of 515, an S-DM3 PASS whose
# dictionary named namespaces, a PR-scale world under a gate header, a T35 PASS over a thrown seal,
# and a report without the one-reply seizure variant.
dmr_case fail privacy-t34-control.txt privacy-pr "rejects a T34 control that opened 1 of 515"
dmr_case fail privacy-sdm3-dictionary.txt privacy-pr "rejects S-DM3 whose dictionary named a namespace"
dmr_case fail privacy-world-scale.txt privacy-gate "rejects a PR-scale world line under a gate header"
dmr_case fail privacy-t35-threw.txt privacy-pr "rejects a T35 line over a seal call that threw"
dmr_case fail privacy-one-reply-missing.txt privacy-pr "rejects a report without the T34 one-reply variant"
# Phase 9 S11b (design §22.21): NI-DM2, JD7's WITHHOLD_ALL_BUNDLES variant and twelve mutants. Each
# negative is the PR positive with one change: a missing line, a twin set that never left pair mode
# (a message compared with itself), a variant world in which no establishment reached the bound, and
# S11's mutant count, which no longer names every mutant the registry holds.
dmr_case fail privacy-ni2-missing.txt privacy-pr "rejects a report without NI-DM2"
dmr_case fail privacy-ni2-one-state.txt privacy-pr "rejects an NI-DM2 PASS whose twins never left pair mode"
dmr_case fail privacy-withhold-missing.txt privacy-pr "rejects a report without the JD7 WITHHOLD_ALL_BUNDLES variant"
dmr_case fail privacy-withhold-unreached.txt privacy-pr "rejects a JD7 withhold variant in which no establishment ran its attempts out"
dmr_case fail privacy-old-mutant-count.txt privacy-pr "rejects S11's ten-mutant count"
dmr_case fail privacy-pm4-one-killer.txt privacy-suite "rejects PM-4 detected by JD4 alone"
# The S11b review: NI-DM2's declared open defect is exactly one and exactly the intro TIMER_SET's
# TTL (a second "declared" difference appended to a PASS, or a partial fix storing another TTL, is
# refused); the JD7 variant must show a session where an unbounded fourth attempt would fall; and
# PM-5 and JD5 must say what they do not cover.
dmr_case fail privacy-ni2-second-defect.txt privacy-pr "rejects an NI-DM2 PASS with a second declared difference appended"
dmr_case fail privacy-ni2-defect-partial.txt privacy-pr "rejects an NI-DM2 declared defect that stores another TTL than declared"
dmr_case fail privacy-withhold-no-room.txt privacy-pr "rejects a JD7 withhold variant with no session where a fourth attempt would fall"
dmr_case fail privacy-pm5-whole.txt privacy-pr "rejects a PM-5 line that does not say only its day-rounding half is built"
dmr_case fail privacy-jd5-no-split.txt privacy-pr "rejects a JD5 line that does not say which TIMER_SET path it covered"
# Phase 9 JD8 slice (design §22.26): JD8 over the entitlement world's twins, the control its kills
# are held against, the two timing leaks its timing clause must catch, and PM-1, PM-1b and PM-26
# killed by it. Every privacy fixture above was regenerated from this slice's real PR report of the
# merged code with its one change (the regeneration first reproduced all thirty of S11b's fixtures
# byte for byte from S11b's positive). Each negative below changes one clause of one line, so each
# trips one rule of the check and nothing else (§22.26 item 13(i)): a way a JD8 line could look like
# a comparison while it compared nothing, compared a world with itself, hid a difference or a moved
# call, or claimed a time the harness cannot test.
dmr_case fail privacy-jd8-missing.txt privacy-pr "rejects a report without JD8"
dmr_case fail privacy-jd8-fail.txt privacy-pr "rejects a JD8 that failed (a FAIL line as JD8 writes it)"
dmr_case fail privacy-jd8-appended.txt privacy-pr "rejects a JD8 PASS with a difference appended"
dmr_case fail privacy-jd8-nothing.txt privacy-pr "rejects a JD8 PASS that compared no call"
dmr_case fail privacy-jd8-bad-sum.txt privacy-pr "rejects a JD8 PASS whose per-client calls do not sum to its total"
dmr_case fail privacy-jd8-short-pairs.txt privacy-pr "rejects a JD8 PASS that paired fewer calls than it compared"
dmr_case fail privacy-jd8-register-moved.txt privacy-pr "rejects a JD8 PASS with a registration at another minute"
dmr_case fail privacy-jd8-redeem-other-session.txt privacy-pr "rejects a JD8 PASS with a redemption in another relay session"
dmr_case fail privacy-jd8-register-pairs.txt privacy-pr "rejects a JD8 PASS whose registration pairs are not its registrations"
dmr_case fail privacy-jd8-redeem-pairs.txt privacy-pr "rejects a JD8 PASS whose redemption pairs are not its redemptions"
dmr_case fail privacy-jd8-timing-claimed.txt privacy-pr "rejects a JD8 PASS that claims the redemption minute compared (the harness cannot test it)"
dmr_case fail privacy-jd8-untimed.txt privacy-pr "rejects the first version's JD8 line, which compared no time (0 of 186 pairs in the same minute)"
dmr_case fail privacy-jd8-three-contacts.txt privacy-pr "rejects a JD8 PASS whose active twin held 3 contacts"
dmr_case fail privacy-jd8-no-deliveries.txt privacy-pr "rejects a JD8 PASS whose active twin delivered no text"
dmr_case fail privacy-jd8-no-dm-calls.txt privacy-pr "rejects a JD8 PASS whose active twin made no call on a contact's namespace"
dmr_case fail privacy-jd8-no-local-skip.txt privacy-pr "rejects a JD8 PASS in which alice's planner skipped no LOCAL need"
dmr_case fail privacy-jd8-dave-ready.txt privacy-pr "rejects a JD8 PASS in which alice's establishment with dave completed"
dmr_case fail privacy-jd8-idle-contact.txt privacy-pr "rejects a JD8 PASS whose idle twin held a contact"
dmr_case fail privacy-jd8-idle-traffic.txt privacy-pr "rejects a JD8 PASS whose idle twin had DM traffic"
dmr_case fail privacy-jd8-dave.txt privacy-pr "rejects a JD8 PASS in which the client without tokens made calls"
dmr_case fail privacy-jd8-not-own.txt privacy-pr "rejects a JD8 PASS that does not say every call was on an own namespace"
dmr_case fail privacy-jd8-one-week.txt privacy-pr "rejects a JD8 PASS that covers one token week"
dmr_case fail privacy-jd8-no-renewal-period.txt privacy-pr "rejects a JD8 PASS without the renewal's registration period"
dmr_case fail privacy-jd8-control-missing.txt privacy-pr "rejects a report without the JD8 control"
dmr_case fail privacy-jd8-control-fail.txt privacy-pr "rejects a JD8 control that failed"
dmr_case fail privacy-jd8-control-other-run.txt privacy-pr "rejects a JD8 control that saw other calls than the report's run"
dmr_case fail privacy-jd8-leaks-missing.txt privacy-pr "rejects a report without the JD8 timing leaks"
dmr_case fail privacy-jd8-leaks-one.txt privacy-pr "rejects a JD8 timing clause that detected one leak of two"
dmr_case fail privacy-s11b-mutant-count.txt privacy-pr "rejects S11b's twelve-mutant count"
dmr_case fail privacy-mutant-count-only.txt privacy-pr "rejects a privacy mutant count other than the one pinned, every detection line kept"
dmr_case fail privacy-pm26-whole.txt privacy-pr "rejects a PM-26 line that does not say only its later-weeks half is built"
# Phase 9 statistics slice (design §22.30): S-DM1 (gating), S-DM2 and S-DM4 (reported against the
# baselines recorded from one PR-scale run of seed 5eed0001) and the controls that must move them.
# Every privacy fixture above was regenerated from this slice's real PR report with the keyed change
# it made to the previous positive (the regeneration first reproduced each of them byte for byte from
# the previous positive), except `privacy-world-scale.txt`, which now changes its world line only
# (the first regeneration also left it the PR baselines, so it failed three rules, §22.30 item 12).
# Each negative below is one edit of one line that trips one rule; where the line's own arithmetic
# ties numbers together, the edit keeps them tied (a raised AUC raises the strongest with it, a
# rejected difference is its AUCs' difference), so the rule tripped is the one named and not the
# consistency rules, which have negatives of their own.
dmr_case fail privacy-sdm1-missing.txt privacy-pr "rejects a report without S-DM1"
dmr_case fail privacy-sdm1-fail.txt privacy-pr "rejects an S-DM1 that failed (the open-fetch-window control's real FAIL line)"
dmr_case fail privacy-sdm1-floor.txt privacy-pr "rejects S-DM1 over fewer than 100 conversations"
dmr_case fail privacy-sdm1-floor-pairs.txt privacy-pr "rejects S-DM1 over fewer than 100 pairs"
dmr_case fail privacy-sdm1-structure.txt privacy-pr "rejects an S-DM1 PASS whose exact half found the full view's bytes on two clients' namespaces"
dmr_case fail privacy-sdm1-rejected.txt privacy-pr "rejects an S-DM1 PASS carrying a positive difference at p = 0.001"
dmr_case fail privacy-sdm1-permutations.txt privacy-pr "rejects an S-DM1 run with fewer permutations than the design's"
dmr_case fail privacy-sdm1-alpha.txt privacy-pr "rejects an S-DM1 run at a looser alpha than the design's"
dmr_case fail privacy-sdm1-unmeasured.txt privacy-pr "rejects an S-DM1 PASS with an attacker that measured nothing"
dmr_case fail privacy-sdm1-diff.txt privacy-pr "rejects an S-DM1 line whose printed difference is not its AUCs' difference"
dmr_case fail privacy-sdm2-missing.txt privacy-pr "rejects a report without S-DM2"
dmr_case fail privacy-sdm2-regression.txt privacy-pr "rejects an S-DM2 LD AUC above the recorded baseline + 0.02"
dmr_case fail privacy-sdm2-strongest.txt privacy-pr "rejects an S-DM2 line whose strongest is not the largest of its AUCs"
dmr_case fail privacy-sdm2-baseline-moved.txt privacy-pr "rejects an S-DM2 line that prints another baseline than the recorded one"
dmr_case fail privacy-sdm2-class-regression.txt privacy-pr "rejects an S-DM2 7 d class 0.03 above its recorded baseline"
dmr_case fail privacy-sdm2-floor.txt privacy-pr "rejects S-DM2 over fewer than 100 conversations"
dmr_case fail privacy-sdm2-floor-pairs.txt privacy-pr "rejects S-DM2 over fewer than 100 pairs"
dmr_case fail privacy-sdm2-gate-baseline.txt privacy-gate "rejects a gate-scale S-DM2 that claims the PR world's baseline"
dmr_case fail privacy-sdm4-missing.txt privacy-pr "rejects a report without S-DM4"
dmr_case fail privacy-sdm4-floor.txt privacy-pr "rejects S-DM4 over fewer than 100 deposits"
dmr_case fail privacy-sdm4-floor-pairs.txt privacy-pr "rejects S-DM4 over fewer than 100 pairs"
dmr_case fail privacy-sdm4-regression.txt privacy-pr "rejects an S-DM4 within-inbox value above the recorded baseline + 0.02 (§16.1)"
dmr_case fail privacy-sdm4-pairing-regression.txt privacy-pr "rejects an S-DM4 cross-inbox value above the recorded baseline + 0.02 (§16.1)"
dmr_case fail privacy-sdm4-baseline-moved.txt privacy-pr "rejects an S-DM4 line that prints another baseline than the recorded one"
dmr_case fail privacy-sdm4-gate-baseline.txt privacy-gate "rejects a gate-scale S-DM4 that claims the PR world's baseline"
dmr_case fail privacy-sdm-controls-missing.txt privacy-pr "rejects a report without the S-DM1 controls"
dmr_case fail privacy-sdm-controls-control.txt privacy-pr "rejects controls whose unmutated world failed S-DM1"
dmr_case fail privacy-sdm-controls-open.txt privacy-pr "rejects controls in which the open fetch window was not flagged by the comparison"
dmr_case fail privacy-sdm-controls-jd7.txt privacy-pr "rejects controls in which JD7 did not fail on the open fetch window"
dmr_case fail privacy-sdm-controls-open-sdm2.txt privacy-pr "rejects controls in which the open fetch window raised S-DM2 by no more than the 0.02 allowance"
dmr_case fail privacy-sdm-controls-delta.txt privacy-pr "rejects controls whose printed S-DM2 rise is not the difference of their AUCs"
dmr_case fail privacy-sdm-controls-tag.txt privacy-pr "rejects controls in which the conversation tag was not flagged by the exact half"
dmr_case fail privacy-sdm-controls-tag-zero.txt privacy-pr "rejects controls whose exact half found 0 shared byte windows under the tag"
dmr_case fail privacy-sdm-controls-pm2.txt privacy-pr "rejects controls in which PM-2, a leak inside LD's categories, was flagged by S-DM1"
# The privacy worlds on production's triggers (design §22.36): no case changed. Every privacy fixture
# above was regenerated from that slice's real PR report (its whole `:messaging` run), each negative
# with its keyed change re-derived on the new numbers (a regression is the re-recorded baseline + 0.03,
# never the old one moved) and the two real FAIL lines taken from the same run; the regeneration first
# reproduced every committed privacy fixture byte for byte from the committed positive. Each negative
# still fails with the messages it failed with before, numbers aside.
# The review of that slice (design §22.36 item 12): JD7's trigger clause, the engine's own record of the
# trigger that opened each later fetch attempt, which the windows JD7 infers from reads cannot see (a
# window no relay session lists is never read). Every privacy fixture above was regenerated again from
# the reviewed tree's real PR report, the regeneration first reproducing every committed one byte for
# byte; three negatives are new, each one edit of one line: a withheld world whose engine opened no
# later attempt (the rule never put to the test), one whose PASS counts later attempts a consumer tail
# opened, and a per-world JD7 line without the clause (a build that could not see such an attempt).
dmr_case fail privacy-withhold-no-later-attempt.txt privacy-pr "rejects a JD7 withhold variant in which the engine opened no later attempt"
dmr_case fail privacy-withhold-later-attempt-at-tail.txt privacy-pr "rejects a JD7 withhold variant whose later attempts were not all opened by a relay session start"
dmr_case fail privacy-jd7-no-trigger-clause.txt privacy-pr "rejects a JD7 line that does not say by which trigger each later attempt opened"
# Phase 9 S12 (design §15.9): the emulator report check. `pass/` is a green run on API 29 and 35;
# every negative case is a copy of it with one change, each a way an emulator run could look green
# while it proved less: an API level or a suite that never ran, a skipped or missing test, a
# comparator whose control was not detected or that compared fewer cases than the file holds, a
# failed or crashed instrumentation, the wrong emulator, and SCN-D's logcat scan absent.
DME="$HARNESS/dm-emulator"
dme_case() { # $1 = pass|fail, $2 = expected text ("" for a pass), $3 = description, $4 = change (a command on the copy), rest = API levels
  local expect="$1" want="$2" desc="$3" change="$4" copy out got
  shift 4
  copy="$(mktemp -d)"
  cp -r "$DME/pass/." "$copy/"
  "$change" "$copy"
  if out="$(GHOST_DM_EQUIVALENCE_CASES="$DME/cases.txt" bash "$DIR/dm-emulator-check.sh" "$copy" "$@" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" = "$expect" ] && { [ -z "$want" ] || grep -qF "$want" <<<"$out"; }; then
    echo "self-test ok: dm-emulator-check $desc"
  else
    echo "SELF-TEST FAIL: dm-emulator-check $desc ($got)" >&2
    printf '%s\n' "$out" | tail -3 >&2; rc=1
  fi
  rm -rf "$copy"
}
dme_same() { :; }
dme_no_api() { rm -r "$1/api29"; }
dme_no_suite() { rm "$1/api35/app-smoke.txt"; }
dme_skipped() { sed -i 's/^device tests: 6 run, 0 failed, 0 skipped$/device tests: 6 run, 0 failed, 1 skipped/' "$1/api35/messaging.txt"; }
dme_fewer() { sed -i 's/^device tests: 6 run,/device tests: 5 run,/' "$1/api35/messaging.txt"; }
dme_control() { sed -i 's/control detected/control NOT detected/' "$1/api35/crypto-bridge.txt"; }
dme_partial() { sed -i 's/3 cases, 3 identical/2 cases, 2 identical/' "$1/api35/crypto-bridge.txt"; }
dme_code() { sed -i 's/^INSTRUMENTATION_CODE: -1$/INSTRUMENTATION_CODE: 0/' "$1/api35/crypto-bridge.txt"; }
dme_crash() { printf 'INSTRUMENTATION_RESULT: shortMsg=Process crashed.\n' >> "$1/api35/messaging.txt"; }
dme_api() { sed -i 's/^sdk=35$/sdk=34/' "$1/api35/device.txt"; }
dme_abi() { sed -i 's/^abi=x86_64$/abi=arm64-v8a/' "$1/api35/device.txt"; }
dme_no_scan() { sed -i '/logcat holds no canary/d' "$1/api35/messaging.txt"; }
dme_case pass "" "accepts a green run on API 29 and 35" dme_same 29 35
dme_case fail "API 29: not run" "reports an API level that never ran as not run" dme_no_api 29 35
dme_case fail "app-smoke: not run" "reports a suite that never ran as not run" dme_no_suite 35
dme_case fail "1 skipped" "rejects a skipped device test" dme_skipped 35
dme_case fail "expected 6 run" "rejects a run with one device test fewer than the slice runs" dme_fewer 35
dme_case fail "control detected" "rejects an equivalence run whose control was not detected" dme_control 35
dme_case fail "3 cases, 3 identical" "rejects an equivalence run over fewer cases than the case file" dme_partial 35
dme_case fail "code '0'" "rejects an instrumentation that finished with RESULT_CANCELED" dme_code 35
dme_case fail "crashed" "rejects a crashed instrumentation" dme_crash 35
dme_case fail "reported API '34'" "rejects an emulator of another API level" dme_api 35
dme_case fail "not x86_64" "rejects an emulator of another ABI" dme_abi 35
dme_case fail "logcat holds no canary" "rejects a run without SCN-D's logcat scan" dme_no_scan 35
if bash "$DIR/dm-emulator-check.sh" "$DME/pass" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: dm-emulator-check accepts a run with no API level named" >&2; rc=1
else
  echo "self-test ok: dm-emulator-check refuses a call that names no API level"
fi
# The device scripts of slice S12 (§21.13 point 4: "each with a self-test"): the physical gate's
# orchestrator against a fake pair of phones, and the emulator run script against a fake emulator
# and through the check above. Both run here so `static-gates` proves them on every change.
bash "$DIR/../device/dm-gate-self-test.sh" || rc=1
bash "$DIR/../device/dm-emulator-self-test.sh" || rc=1
# Scope checks: these gates must also cover client-core/ (shipped in the APK, ADR-19).
for g in anti-placeholder no-logging; do
  expect_fail "$g" "$HARNESS/negative-client-core"
done
# Phase 8 (design §14.1, E-2): crates nested under issuer/crates/ are scanned, and an issuer main.rs
# is not exempt. Each fixture file must be reported by name (the rest of the fixture already fails).
for g in anti-placeholder no-logging; do
  out="$(GHOST_ROOT="$HARNESS/negative" bash "$DIR/$g.sh" 2>&1 || true)"
  for f in issuer/crates/blind-rsa/src/lib.rs issuer/crates/service/src/main.rs; do
    if grep -qF "$f:" <<<"$out"; then
      echo "self-test ok: $g reports $f"
    else
      echo "SELF-TEST FAIL: $g does not report $f" >&2; rc=1
    fi
  done
done
# Phase 8 (design §14.1, §19.17): the one no-logging exemption is exactly the operator tools'
# ops/src/report.rs, and only for println!/eprintln! there.
out="$(GHOST_ROOT="$HARNESS/negative" bash "$DIR/no-logging.sh" 2>&1 || true)"
for want in issuer/crates/ops/src/keygen.rs: issuer/crates/service/src/report.rs: issuer/crates/ops/src/report.rs:6:; do
  if grep -qF "$want" <<<"$out"; then
    echo "self-test ok: no-logging reports $want"
  else
    echo "SELF-TEST FAIL: no-logging does not report $want" >&2; rc=1
  fi
done
if grep -qF "issuer/crates/ops/src/report.rs:5:" <<<"$out"; then
  echo "SELF-TEST FAIL: no-logging reports the exempt eprintln! of ops/src/report.rs" >&2; rc=1
else
  echo "self-test ok: no-logging exempts println!/eprintln! in ops/src/report.rs only"
fi
# Phase 8 (design §6.5, §14.1): logging-framework paths and bare logging macros are reported in the
# issuer, relay and client-core sources, and logging crates in issuer manifests, one line each.
out="$(GHOST_ROOT="$HARNESS/negative" bash "$DIR/no-logging.sh" 2>&1 || true)"
for want in issuer/crates/service/src/logging.rs:3: issuer/crates/service/src/logging.rs:5: \
  issuer/crates/service/src/logging.rs:6: issuer/crates/service/src/logging.rs:7: \
  issuer/crates/service/src/logging.rs:8: issuer/crates/service/src/logging.rs:9: \
  issuer/crates/service/Cargo.toml:6: issuer/crates/service/Cargo.toml:9: relay/crates/bad/src/logging.rs:3: \
  issuer/crates/service/Cargo.toml:12: issuer/crates/service/Cargo.toml:15: \
  issuer/crates/service/src/renamed.rs:3: issuer/crates/service/src/renamed.rs:4: \
  issuer/crates/service/src/renamed.rs:5:; do
  if grep -qF "$want" <<<"$out"; then
    echo "self-test ok: no-logging reports $want"
  else
    echo "SELF-TEST FAIL: no-logging does not report $want" >&2; rc=1
  fi
done
out="$(GHOST_ROOT="$HARNESS/negative-client-core" bash "$DIR/no-logging.sh" 2>&1 || true)"
if grep -qF "client-core/bad/src/logging.rs:3:" <<<"$out"; then
  echo "self-test ok: no-logging reports client-core/bad/src/logging.rs:3:"
else
  echo "SELF-TEST FAIL: no-logging does not report client-core/bad/src/logging.rs:3:" >&2; rc=1
fi
# Phase 8 (design §6.5, §14.1, §19.17 point 4): issuer-output.sh reports every forbidden file or
# console write by file and line, and none of the allowed ones.
expect_fail issuer-output "$HARNESS/negative-issuer-output"
out="$(GHOST_ROOT="$HARNESS/negative-issuer-output" bash "$DIR/issuer-output.sh" 2>&1 || true)"
for want in service/src/service.rs:4: service/src/service.rs:5: service/src/service.rs:6: \
  service/src/service.rs:7: service/src/service.rs:8: service/src/service.rs:9: \
  service/src/service.rs:10: service/src/status.rs:4: service/src/store.rs:4: service/src/payout.rs:4: \
  ops/src/report.rs:4: ops/src/output.rs:4: ops/src/keygen.rs:3: api/src/lib.rs:3: \
  service/src/scanner.rs:3: service/src/scanner.rs:4: service/src/scanner.rs:5: \
  service/src/scanner.rs:8: service/src/scanner.rs:9:; do
  if grep -qF "issuer/crates/$want" <<<"$out"; then
    echo "self-test ok: issuer-output reports $want"
  else
    echo "SELF-TEST FAIL: issuer-output does not report $want" >&2; rc=1
  fi
done
# S12 review GATE-ISSUER-OUTPUT-BRACE: a read-only brace import is not a write.
for allowed in service/src/scanner.rs:10: service/src/scanner.rs:11:; do
  if grep -qF "issuer/crates/$allowed" <<<"$out"; then
    echo "SELF-TEST FAIL: issuer-output reports the read-only import $allowed" >&2; rc=1
  else
    echo "self-test ok: issuer-output allows the read-only import $allowed"
  fi
done
for allowed in service/src/status.rs:3: service/src/store.rs:3: service/src/payout.rs:3: \
  ops/src/report.rs:3: ops/src/output.rs:3:; do
  if grep -qF "issuer/crates/$allowed" <<<"$out"; then
    echo "SELF-TEST FAIL: issuer-output reports the allowed $allowed" >&2; rc=1
  else
    echo "self-test ok: issuer-output allows $allowed"
  fi
done
# Phase 8 (design §6.7, §14.1): monero-pin.sh on its fixture roots (test-harness/gates/monero-pin/
# README.md). Each case must end as expected and report the named reason, so a gate failing for
# another reason (or on everything) is caught.
MP_FIX="$HARNESS/monero-pin"
mp_case() { # $1 = case, $2 = pass|fail, $3 = text the output must contain
  local out got
  if out="$(GHOST_ROOT="$MP_FIX/$1/ghost" bash "$DIR/monero-pin.sh" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" != "$2" ]; then
    echo "SELF-TEST FAIL: monero-pin $1 ($got)" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  elif ! grep -qF -- "$3" <<<"$out"; then
    echo "SELF-TEST FAIL: monero-pin $1 without reporting: $3" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  else
    echo "self-test ok: monero-pin $1"
  fi
}
mp_case positive pass "[monero-pin] OK"
mp_case no-pin fail "monero-release.pin missing"
mp_case malformed fail "malformed SHA-256"
mp_case no-linux fail "no linux-x64 archive"
mp_case second-hash fail "docker-compose.stagenet.yml: second copy of a pinned SHA-256"
mp_case unpinned-fetch fail "Dockerfile: fetches Monero binaries without reading"
mp_case own-archive fail "fetch-monero.sh:3: a Monero archive name of its own"
mp_case missing-job fail "the regtest workflow is missing"
mp_case job-no-check fail "does not check the archive with sha256sum -c"
# Review fixes S5-MON-3, S5-SEC-2, S5-SEC-3, S5-SEC-4.
mp_case job-comment-check fail "monero-regtest.yml: does not check the archive with sha256sum -c"
mp_case job-check-after-extract fail "checks the archive with sha256sum -c only before its download or after its extraction"
mp_case job-paths fail "pull_request paths miss ghost/Cargo.lock"
mp_case dlsrc-templated fail "Dockerfile: fetches Monero binaries without reading"
mp_case dockerfile-no-check fail "Dockerfile: fetches Monero binaries without checking them with sha256sum -c"
mp_case monero-image fail "docker-compose.stagenet.yml:3: a Monero image not built from"
# Phase 8 (design §5.2, §14.1, RC G18): proto-check.sh checks every request message, not every
# file. The fixture (test-harness/gates/negative-proto/README.md) has eight unversioned requests in
# two files, each next to a versioned one: exactly those eight are reported, by name, and none of
# the versioned ones.
if command -v protoc >/dev/null; then
  expect_fail proto-check "$HARNESS/negative-proto"
  out="$(GHOST_ROOT="$HARNESS/negative-proto" bash "$DIR/proto-check.sh" 2>&1 || true)"
  proto_hits="$(printf '%s\n' "$out" | grep -c '^GATE-FAIL' || true)"
  if [ "$proto_hits" = "8" ]; then echo "self-test ok: proto-check reports the 8 unversioned request messages"; else echo "SELF-TEST FAIL: proto-check reported $proto_hits of 8 unversioned request messages" >&2; rc=1; fi
  for m in MissingRequest WrongNumberRequest NestedRequest NestedVersionRequest BraceOnNextLineRequest \
    RedeemTokenRequest GetBlobRequest ListNamespaceRequest; do
    if grep -qF "message $m lacks" <<<"$out"; then echo "self-test ok: proto-check reports $m"; else echo "SELF-TEST FAIL: proto-check does not report $m" >&2; rc=1; fi
  done
  for m in GoodRequest InlineGoodRequest GoodNextLineRequest StoreBlobRequest RegisterKeyRequest; do
    if grep -qF "message $m " <<<"$out"; then echo "SELF-TEST FAIL: proto-check reports the versioned $m" >&2; rc=1; else echo "self-test ok: proto-check accepts $m"; fi
  done
  # Phase 9 (design §4.2, §16.1): the key registration enums field for field and the request's
  # presence (test-harness/gates/negative-proto-register/README.md): exactly three violations.
  expect_fail proto-check "$HARNESS/negative-proto-register"
  out="$(GHOST_ROOT="$HARNESS/negative-proto-register" bash "$DIR/proto-check.sh" 2>&1 || true)"
  proto_hits="$(printf '%s\n' "$out" | grep -c '^GATE-FAIL' || true)"
  if [ "$proto_hits" = "3" ]; then echo "self-test ok: proto-check reports the 3 key registration schema violations"; else echo "SELF-TEST FAIL: proto-check reported $proto_hits of 3 key registration schema violations" >&2; rc=1; fi
  for want in "enum KeyKind must be exactly" "enum RegisterResult must be exactly" "message RegisterKeyRequest is missing"; do
    if grep -qF "$want" <<<"$out"; then echo "self-test ok: proto-check reports: $want"; else echo "SELF-TEST FAIL: proto-check does not report: $want" >&2; rc=1; fi
  done
elif [ -n "${CI:-}" ]; then
  echo "SELF-TEST FAIL: protoc missing in CI; proto-check not proven" >&2; rc=1
else
  echo "self-test skipped: proto-check (protoc not installed)"
fi
# Phase 8 (design §14.1): entitlement-schedule.sh on its fixture roots
# (test-harness/gates/entitlement-schedule/README.md). Each case must end as expected and report
# the named reason, so a gate failing for another reason (or on everything) is caught.
ES_FIX="$HARNESS/entitlement-schedule"
ES_PRED="$DIR/../../issuer/crates/entitlement/tests/fixtures/test_schedule.ghes"
ES_TEST_KEY=3466898f48dace3e2715583ee3d5ff128959839fdfe0fd24b49c079e86bb126b
ES_NOW=1790557200 # week 2960, Monday 01:00 UTC
es_case() { # $1 = description, $2 = pass|fail, $3 = fixture root, $4 = text the output must contain, rest = VAR=value
  local desc="$1" expect="$2" root="$3" want="$4" out got
  shift 4
  if out="$(env GHOST_ROOT="$root" "$@" bash "$DIR/entitlement-schedule.sh" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" != "$expect" ]; then
    echo "SELF-TEST FAIL: entitlement-schedule $desc ($got)" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  elif ! grep -qF -- "$want" <<<"$out"; then
    echo "SELF-TEST FAIL: entitlement-schedule $desc without reporting: $want" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  else
    echo "self-test ok: entitlement-schedule $desc"
  fi
}
es_case "passes while the schedule was never committed" pass "$ES_FIX/absent" "absent and never committed"
es_case "rejects a schedule removed after a commit" fail "$ES_FIX/absent" "committed before and is now missing" \
  GHOST_ES_PREDECESSOR="$ES_PRED"
es_case "rejects a second copy" fail "$ES_FIX/second-copy" "infra/relay/schedule.ghes: an Entitlement Schedule outside"
es_case "rejects infrastructure naming another path" fail "$ES_FIX/infra-other-path" \
  "infra/relay/Dockerfile:4: 'infra/relay/schedule.ghes'"
es_case "rejects production code naming a test fixture" fail "$ES_FIX/fixture-in-src" "production source names test material"
es_case "rejects a committed sealed key" fail "$ES_FIX/sealed-key-committed" "sealed key or key load file outside tests/fixtures"
# No directory name hides a copy or a key (only the issuer crates' tests/fixtures, test-harness/gates
# and real build outputs are skipped), and infra references resolve to the one schedule exactly.
es_case "rejects a copy under an infra tests/fixtures directory" fail "$ES_FIX/infra-fixtures-copy" \
  "infra/relay/tests/fixtures/protocol/entitlement/schedule.ghes: an Entitlement Schedule outside"
es_case "rejects infrastructure copying from an infra tests/fixtures directory" fail "$ES_FIX/infra-fixtures-copy" \
  "infra/relay/Dockerfile:4: 'infra/relay/tests/fixtures/protocol/entitlement/schedule.ghes'"
es_case "rejects a copy under an infra build directory" fail "$ES_FIX/infra-build-copy" \
  "infra/relay/build/protocol/entitlement/schedule.ghes: an Entitlement Schedule outside"
es_case "rejects a volume mounting an infra build directory" fail "$ES_FIX/infra-build-copy" \
  "infra/relay/docker-compose.yml:6: './build/protocol/entitlement/schedule.ghes'"
es_case "rejects a reference through a variable" fail "$ES_FIX/infra-variable-path" \
  "infra/relay/Dockerfile:5: '\${SRC}/copy.ghes'"
es_case "rejects an absolute path naming a gate fixture" fail "$ES_FIX/infra-stage-path" \
  "names the repository file test-harness/gates/copy/protocol/entitlement/schedule.ghes"
es_case "rejects a sealed key under an infra build directory" fail "$ES_FIX/sealed-key-hidden" \
  "infra/issuer/build/access-2957.ghks: sealed key or key load file"
es_case "rejects a sealed key under an infra tests/fixtures directory" fail "$ES_FIX/sealed-key-hidden" \
  "infra/issuer/tests/fixtures/access-2957.ghks: sealed key or key load file"
# Tor onion service secret keys (onion-keygen, S2b): by the file name Tor gives them, and under any
# other name by C Tor's secret key header (each file of the root trips one rule only).
es_case "rejects a committed onion service secret key by its name" fail "$ES_FIX/onion-key-committed" \
  "infra/relay/tor-keys/hs_ed25519_secret_key: Tor onion service secret key file (hs_ed25519_secret_key)"
es_case "rejects an onion service secret key under another name by its header" fail "$ES_FIX/onion-key-committed" \
  "infra/relay/slot-1.key: Tor onion service secret key (C Tor secret key header)"
es_case "accepts infrastructure naming the one schedule" pass "$ES_FIX/infra-one-path" "absent and never committed"
es_case "refuses its self-test hooks on the repository" fail "$DIR/../.." "self-test hook for fixture roots only" \
  GHOST_ES_TEST_KEY="$ES_TEST_KEY"
es_case "refuses its git hook on the repository" fail "$DIR/../.." "self-test hook for fixture roots only" \
  GHOST_ES_GIT=1
# T12 native-library check on fabricated archives: the right bytes pass; a missing ABI, changed
# bytes or an extra ABI directory fail.
make_zip() { # $1 = zip path, $2 = directory to archive
  if command -v zip >/dev/null; then (cd "$2" && zip -q -r "$1" lib)
  elif command -v jar >/dev/null; then (cd "$2" && jar cfM "$1" lib)
  else return 3; fi
}
apk_case() { # $1 = description, $2 = expect (pass|fail), $3 = setup function
  local desc="$1" expect="$2" w
  w="$(mktemp -d)"
  mkdir -p "$w/tree/lib/arm64-v8a" "$w/tree/lib/x86_64"
  printf 'arm' > "$w/tree/lib/arm64-v8a/libghost_client_net.so"
  printf 'x86' > "$w/tree/lib/x86_64/libghost_client_net.so"
  (cd "$w/tree/lib" && sha256sum arm64-v8a/libghost_client_net.so x86_64/libghost_client_net.so) > "$w/sums"
  "$3" "$w"
  if ! make_zip "$w/app.apk" "$w/tree"; then
    rm -rf "$w"
    if [ -n "${CI:-}" ]; then echo "SELF-TEST FAIL: no zip/jar in CI" >&2; rc=1; else echo "self-test skipped: apk-native-libs (no zip/jar)"; fi
    return
  fi
  if bash "$DIR/apk-native-libs.sh" "$w/app.apk" "$w/sums" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$expect" ]; then echo "self-test ok: apk-native-libs $desc"; else echo "SELF-TEST FAIL: apk-native-libs $desc ($got)" >&2; rc=1; fi
  rm -rf "$w"
}
apk_ok() { :; }
apk_missing_abi() { rm -r "$1/tree/lib/x86_64"; }
apk_changed() { printf 'tampered' > "$1/tree/lib/arm64-v8a/libghost_client_net.so"; }
apk_extra_abi() { mkdir -p "$1/tree/lib/armeabi-v7a" && printf 'x' > "$1/tree/lib/armeabi-v7a/libother.so"; }
apk_extra_lib() { printf 'x' > "$1/tree/lib/arm64-v8a/libtelemetry.so"; }
apk_allowed_lib() { printf 'x' > "$1/tree/lib/x86_64/libsqlcipher.so"; }
apk_case "accepts the recorded libraries" pass apk_ok
apk_case "accepts an allowlisted third-party library" pass apk_allowed_lib
apk_case "rejects a missing ABI" fail apk_missing_abi
apk_case "rejects changed bytes" fail apk_changed
apk_case "rejects an unexpected ABI directory" fail apk_extra_abi
apk_case "rejects an unlisted native library in an allowed ABI" fail apk_extra_lib

# Phase 9 S0′ (ADR-37, ADR-39; design §2.10.2, §22.8.9, §22.8.10): the dependency denylist names the
# Signal group, even where a version catalog declares it.
out="$(GHOST_ROOT="$HARNESS/negative" bash "$DIR/dependency-allowlist.sh" 2>&1 || true)"
if grep -qF "DENIED dependency group 'org.signal'" <<<"$out"; then
  echo "self-test ok: dependency-allowlist denies org.signal (ADR-37)"
else
  echo "SELF-TEST FAIL: dependency-allowlist does not deny org.signal" >&2; rc=1
fi
# G-L5 (no-public-binaries.sh) on its fixture roots (test-harness/gates/no-public-binaries/README.md):
# each case ends as expected and reports its reason; no event payload unless the case names one.
NPB="$HARNESS/no-public-binaries"
npb_case() { # $1 = case, $2 = pass|fail, $3 = expected text, $4 = event payload ("" for none)
  local out got
  if out="$(GHOST_VISIBILITY_EVENT="$4" GHOST_ROOT="$NPB/$1/ghost" bash "$DIR/no-public-binaries.sh" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" != "$2" ]; then
    echo "SELF-TEST FAIL: no-public-binaries $1 ($got)" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  elif ! grep -qF -- "$3" <<<"$out"; then
    echo "SELF-TEST FAIL: no-public-binaries $1 without reporting: $3" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  else
    echo "self-test ok: no-public-binaries $1${4:+ (with its event payload)}"
  fi
}
npb_case positive-private pass "[no-public-binaries] OK" ""
npb_case positive-public pass "[no-public-binaries] OK" ""
npb_case public-apk fail "artifact 'app-release-unsigned' uploads binaries (APK, AAR, .so, jniLibs or an image) while the repository is not declared private" ""
npb_case public-handoff fail "artifact 'ghost-client-net-jniLibs' uploads binaries (APK, AAR, .so, jniLibs or an image) while the repository is not declared private" ""
npb_case private-handoff-retention fail "hand-off artifact 'ghost-client-net-jniLibs' must set retention-days: 1" ""
npb_case private-apk fail "artifact 'app-release-unsigned' uploads binaries and is not an internal native hand-off" ""
npb_case private-handoff-unconsumed fail "hand-off artifact 'ghost-client-net-jniLibs': no job of this workflow downloads it" ""
npb_case no-retention fail "artifact 'gate-report' sets no retention-days (1 to 7)" ""
npb_case release-publish fail "publishes outside the repository (gh release upload)" ""
# The native hand-off through the Actions cache (Phase 9 design §22.33): allowed while private, under
# this run's key, restored by a job of the workflow; refused public, under a fixed key, or unrestored.
npb_case positive-private-cache pass "[no-public-binaries] OK" ""
npb_case public-cache-handoff fail "a cache saves binaries (APK, AAR, .so, jniLibs or an image) while the repository is not declared private" ""
npb_case private-cache-key fail "a cache saves binaries under key 'ghost-client-net-jniLibs-latest', which is not this run's hand-off" ""
npb_case private-cache-unrestored fail "no job of this workflow restores it" ""
npb_case event-mismatch pass "[no-public-binaries] OK" ""
npb_case event-mismatch fail "the event payload says the repository is public; scripts/gates/repository-visibility.txt declares it private" "$NPB/event-mismatch/event.json"
npb_case no-declaration fail "scripts/gates/repository-visibility.txt missing" ""
# The rule engine must fail closed like the other licence gates: G-L5 is the only gate that keeps a
# closed binary out of a published workflow, so a helper that cannot run may not report OK.
npb_stub="$(mktemp -d)"
printf '#!/usr/bin/env bash\necho "stub perl: the rule engine cannot run" >&2\nexit 2\n' > "$npb_stub/perl"
chmod +x "$npb_stub/perl"
if npb_out="$(PATH="$npb_stub:$PATH" GHOST_VISIBILITY_EVENT="" GHOST_ROOT="$NPB/private-apk/ghost" bash "$DIR/no-public-binaries.sh" 2>&1)"; then npb_got=pass; else npb_got=fail; fi
if [ "$npb_got" = fail ] && grep -qF "no-public-binaries.sh rule engine stopped" <<<"$npb_out"; then
  echo "self-test ok: no-public-binaries fails closed when its rule engine cannot run"
else
  echo "SELF-TEST FAIL: no-public-binaries did not fail closed on a broken rule engine ($npb_got)" >&2
  printf '%s\n' "$npb_out" | tail -5 >&2; rc=1
fi
rm -rf "$npb_stub"
# G-L1 (license-notices.sh rust), G-R5 (rust-license-headers.sh) and G-L4 (mpl-sources.sh) on the
# fixture root test-harness/gates/licenses (README.md there): package lists stand in for cargo.
LIC_FIX="$HARNESS/licenses"
lic_case() { # $1 = gate, $2 = description, $3 = pass|fail, $4 = expected text, rest = VAR=value, then -- and gate arguments
  local gate="$1" desc="$2" expect="$3" want="$4" out got
  shift 4
  local envs=()
  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
  [ "${1:-}" = -- ] && shift
  if out="$(env GHOST_ROOT="$LIC_FIX" "${envs[@]}" bash "$DIR/$gate.sh" "$@" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" != "$expect" ]; then
    echo "SELF-TEST FAIL: $gate $desc ($got)" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  elif ! grep -qF -- "$want" <<<"$out"; then
    echo "SELF-TEST FAIL: $gate $desc without reporting: $want" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  else
    echo "self-test ok: $gate $desc"
  fi
}
lic_list() { printf 'GHOST_LICENSE_PACKAGES=%s/lists/%s.tsv' "$LIC_FIX" "$1"; }
lic_case license-notices "accepts notices equal to the regenerated ones" pass "[license-notices (rust)] OK" "$(lic_list positive)" -- rust
lic_case license-notices "rejects committed notices that differ" fail "licenses/THIRD_PARTY_NOTICES-fixture.txt differs from the regenerated notices" "$(lic_list differs)" -- rust
lic_case license-notices "rejects a licence without a resolvable text" fail "isc-pkg 1.0.0: no text for licence ISC" "$(lic_list no-text)" -- rust
lic_case license-notices "rejects a dropped upstream NOTICE" fail "apache-dropped 1.0.0: dropped NOTICE: NOTICE of the upstream snapshot is missing" "$(lic_list dropped-notice)" -- rust
lic_case license-notices "rejects an Apache-2.0 package without an upstream NOTICE snapshot entry" fail "apache-nosnapshot 1.0.0: used under Apache-2.0 without an upstream NOTICE snapshot entry" "$(lic_list no-snapshot)" -- rust
lic_case license-notices "rejects an undecided licence file of vendored sources" fail "undecided-pkg 1.0.0: vendor/lib/LICENSE: a licence file of vendored sources" "$(lic_list undecided-vendored)" -- rust
lic_case license-notices "rejects a copyleft-only package" fail "gpl-pkg 1.0.0: no alternative of 'GPL-3.0-only' is an allowed licence" "$(lic_list copyleft)" -- rust
# The SPDX template clause (Phase 10 review of S2a, F1): a package that ships no MIT text would get
# the template's "<year> <copyright holders>" in place of a copyright line; unreviewed, it fails, and
# a reviewed line no package needs fails too.
lic_case license-notices "rejects an unreviewed package that would carry an SPDX template text" fail "template-pkg 1.0.0: ships no MIT text, and the SPDX one is a template without a copyright line" "$(lic_list template)" -- rust
lic_case license-notices "rejects a template review line no package needs" fail "template-texts-reviewed.txt: mit-pkg 1.0.0 is not needed" "$(lic_list positive)" GHOST_LICENSE_TEMPLATE_REVIEWED="$LIC_FIX/lists/template-reviewed-stale.txt" -- rust
if grep -q "used under: Apache-2.0" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-fixture.txt" && ! grep -q "LICENSE-APACHE of dual-pkg" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-fixture.txt" \
  && grep -q "NOTICE of https://github.com/fixture/apache-pkg" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-fixture.txt" \
  && grep -q "third_party/zlib/LICENSE of vendored-pkg" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-fixture.txt"; then
  echo "self-test ok: license-notices carries the upstream NOTICE and the vendored licence, and leaves out the unused alternative"
else
  echo "SELF-TEST FAIL: the fixture notices miss the upstream NOTICE or the vendored licence, or carry the unused alternative" >&2; rc=1
fi
# The SPDX snapshot is the provenance the notices cite: an edited text, one SOURCE.txt does not
# record, or one it records and the tree does not, fails even though a regeneration would match.
spdx_case() { # $1 = description, $2 = expected text, $3 = change (a command on the spdx directory)
  local w out
  w="$(mktemp -d)"
  cp -r "$LIC_FIX/." "$w/"
  "$3" "$w/licenses/spdx"
  if out="$(env GHOST_ROOT="$w" "$(lic_list positive)" bash "$DIR/license-notices.sh" rust 2>&1)"; then
    echo "SELF-TEST FAIL: license-notices $1 passed" >&2; rc=1
  elif ! grep -qF -- "$2" <<<"$out"; then
    echo "SELF-TEST FAIL: license-notices $1 without reporting: $2" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  else
    echo "self-test ok: license-notices $1"
  fi
  rm -rf "$w"
}
spdx_edit_text() { printf 'x\n' >> "$1/MIT.txt"; }
spdx_add_text() { cp "$1/MIT.txt" "$1/ISC.txt"; }
spdx_drop_text() { rm -f "$1/MPL-2.0.txt"; }
spdx_case "rejects an SPDX text altered by one line" "licenses/spdx/MIT.txt does not match the SHA-256 that SOURCE.txt records" spdx_edit_text
spdx_case "rejects an SPDX text SOURCE.txt does not record" "licenses/spdx/ISC.txt: SOURCE.txt records no SHA-256 for it" spdx_add_text
spdx_case "rejects an SPDX text SOURCE.txt records and the tree has not" "licenses/spdx/MPL-2.0.txt is missing; SOURCE.txt records it" spdx_drop_text
hdr_env="$(lic_list headers)"
out="$(env GHOST_ROOT="$LIC_FIX" "$hdr_env" GHOST_LICENSE_EXCEPTIONS="$LIC_FIX/lists/headers-exceptions.txt" bash "$DIR/rust-license-headers.sh" 2>&1 || true)"
hdr_hits="$(printf '%s\n' "$out" | grep -c '^GATE-FAIL' || true)"
if [ "$hdr_hits" = "5" ]; then echo "self-test ok: rust-license-headers reports the 5 fixture violations"; else echo "SELF-TEST FAIL: rust-license-headers reported $hdr_hits of 5 fixture violations" >&2; rc=1; fi
for want in "agpl-header 1.0.0: src/lib.rs: SPDX-License-Identifier: AGPL-3.0-only" \
  "signal-copyright 1.0.0: src/lib.rs: a Signal Messenger copyright" \
  "gpl-notice 1.0.0: src/lib.rs: a GNU licence notice" \
  "gpl-text 1.0.0: COPYING: the text of a GNU licence" \
  "bad-expression 1.0.0: no alternative of 'GPL-3.0-only' is an allowed licence"; do
  if grep -qF -- "$want" <<<"$out"; then echo "self-test ok: rust-license-headers reports $want"; else echo "SELF-TEST FAIL: rust-license-headers does not report $want" >&2; rc=1; fi
done
lic_case rust-license-headers "scans GHOST's own crates and rejects an exception that matches nothing" fail "rust-license-exceptions.txt: clean 1.0.0 src/lib.rs is not needed" \
  "$(lic_list headers-own)" GHOST_LICENSE_EXCEPTIONS="$LIC_FIX/lists/headers-exceptions-unused.txt"
# G-M7 (Phase 11 design faza11-media.md §16.1; slice S1): a crate of GHOST's own whose manifest declares
# no licence (a missing licence header: `license.workspace = true` dropped), or another licence, fails.
lic_case rust-license-headers "rejects an own crate that declares no licence (G-M7)" fail \
  "clean 1.0.0: GHOST's own crate declares no licence, not LicenseRef-GHOST-Proprietary" \
  "$(lic_list headers-own-unlicensed)" GHOST_LICENSE_EXCEPTIONS=/dev/null
lic_case rust-license-headers "rejects an own crate that declares another licence (G-M7)" fail \
  "clean 1.0.0: GHOST's own crate declares 'MIT', not LicenseRef-GHOST-Proprietary" \
  "$(lic_list headers-own-mit)" GHOST_LICENSE_EXCEPTIONS=/dev/null
lic_case mpl-sources "accepts the MPL-2.0 manifest" pass "[mpl-sources] OK" "$(lic_list mpl)"
lic_case mpl-sources "rejects an MPL-2.0 package missing from the manifest" fail "mpl-pkg 1.0.0 is used under MPL-2.0 and missing from" "$(lic_list mpl)" GHOST_MPL_SOURCES="$LIC_FIX/licenses/mpl-sources-empty.txt"
lic_case mpl-sources "rejects a checksum Cargo.lock does not record" fail "mpl-pkg 1.0.0: mpl-sources.txt records 0000" "$(lic_list mpl)" GHOST_MPL_SOURCES="$LIC_FIX/licenses/mpl-sources-wrong-sum.txt"
lic_case mpl-sources "rejects a manifest line of a package no graph ships" fail "mpl-sources.txt: mpl-pkg 1.0.0 is not an MPL-2.0 package of a shipped graph" "$(lic_list mit-only)"
lic_case mpl-sources "rejects a [patch] of an MPL-2.0 package without a published diff" fail "[patch] on the MPL-2.0 package mpl-patched 1.0.0 without a published diff" "$(lic_list mpl-patched)" GHOST_MPL_SOURCES="$LIC_FIX/licenses/mpl-sources-patched.txt"
bundle="$(mktemp -d)"
lic_case mpl-sources "builds the source bundle from checked .crate archives" pass "[mpl-sources] OK" "$(lic_list mpl)" CARGO_HOME="$LIC_FIX" -- --bundle "$bundle"
if [ -f "$bundle/mpl-pkg-1.0.0.crate" ]; then echo "self-test ok: mpl-sources --bundle holds mpl-pkg-1.0.0.crate"; else echo "SELF-TEST FAIL: mpl-sources --bundle did not copy the .crate archive" >&2; rc=1; fi
rm -rf "$bundle"
# scripts/license-upstream-snapshot.sh, the maintainer tool that writes ghost/licenses/upstream: a
# listing it cannot read must stop the run, never be recorded as `none` (an entry recorded `none` is
# what lets G-L1 accept a package used under Apache-2.0 with no NOTICE reproduced). The fixture puts
# stubs for gh and cargo on PATH (test-harness/gates/upstream-snapshot/README.md).
US="$HARNESS/upstream-snapshot"
us_case() { # $1 = description, $2 = pass|fail, $3 = expected text, $4 = gh mode, $5 = text of the written index
  local w out got
  w="$(mktemp -d)"
  mkdir -p "$w/scripts/gates" "$w/licenses/upstream" "$w/bin"
  cp "$DIR/../license-upstream-snapshot.sh" "$w/scripts/"
  cp "$DIR/licenses.pl" "$w/scripts/gates/"
  cp "$US/deny.toml" "$w/deny.toml"
  cp "$US/bin/gh" "$US/bin/cargo" "$w/bin/"
  chmod +x "$w/bin/gh" "$w/bin/cargo"
  printf '# No Gradle component in this fixture.\n' > "$w/licenses/upstream/maven-sources.txt"
  if out="$(env PATH="$w/bin:$PATH" GHOST_FIXTURE_GH="$4" GHOST_LICENSE_PACKAGES="$US/lists/candidates.tsv" \
    bash "$w/scripts/license-upstream-snapshot.sh" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" != "$2" ]; then
    echo "SELF-TEST FAIL: license-upstream-snapshot $1 ($got)" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  elif ! grep -qF -- "$3" <<<"$out"; then
    echo "SELF-TEST FAIL: license-upstream-snapshot $1 without reporting: $3" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
  elif [ -n "${5:-}" ] && ! grep -qF -- "$5" "$w/licenses/upstream/index.txt"; then
    echo "SELF-TEST FAIL: license-upstream-snapshot $1 did not write: $5" >&2; rc=1
  elif [ "$2" = fail ] && grep -q '^cargo ' "$w/licenses/upstream/index.txt" 2>/dev/null; then
    echo "SELF-TEST FAIL: license-upstream-snapshot $1 wrote an index entry anyway" >&2; rc=1
  else
    echo "self-test ok: license-upstream-snapshot $1"
  fi
  rm -rf "$w"
}
us_case "records none when the package ships no upstream NOTICE" pass "upstream snapshot: 1 entries" empty \
  "cargo apache-vcs 1.0.0 https://github.com/fixture/apache-vcs 4444444444444444444444444444444444444444 none"
us_case "stops when the package-directory listing fails" fail "apache-vcs 1.0.0: cannot list fixture/apache-vcs/apache-vcs at" dir-error
us_case "stops when the repository-root listing fails" fail "apache-vcs 1.0.0: cannot list fixture/apache-vcs at" root-error
# G-L1 android mode and G-L2 (gradle-license-allowlist.txt) on a fabricated Gradle cache: a POM, a
# classes jar with a NOTICE and the component as published, an AAR whose root carries a licence text
# the classes jar does not (all built here; no binary fixture is committed).
jar_of() { # $1 = jar path, $2 = directory holding META-INF
  mkdir -p "$(dirname "$1")"
  if command -v zip >/dev/null; then (cd "$2" && zip -q -r "$1" META-INF)
  elif command -v jar >/dev/null; then (cd "$2" && jar cfM "$1" META-INF)
  else return 3; fi
}
gradle_case() { # $1 = description, $2 = pass|fail, $3 = expected text, $4 = allowlist lines, $5 = POM licences, $6 = no-archive to publish no AAR
  local w cache jarfile
  w="$(mktemp -d)"
  cache="$w/gradle/caches/modules-2/files-2.1/org.example/lib/1.0.0/0a1b"
  mkdir -p "$cache" "$w/classes/META-INF" "$w/aar/META-INF"
  printf '<project><licenses>%s</licenses></project>\n' "$5" > "$cache/lib-1.0.0.pom"
  printf 'org.example lib\nCopyright 2026 The lib fixture authors\n' > "$w/classes/META-INF/NOTICE.txt"
  printf 'The lib fixture licence, as the AAR carries it at its own root.\n' > "$w/aar/META-INF/LICENSE.txt"
  jarfile="$w/gradle/caches/9.7.1/transforms/0a1b/transformed/lib-1.0.0-runtime.jar"
  if ! jar_of "$jarfile" "$w/classes" || ! jar_of "$w/lib-1.0.0.aar" "$w/aar"; then
    rm -rf "$w"
    if [ -n "${CI:-}" ]; then echo "SELF-TEST FAIL: no zip/jar in CI" >&2; rc=1; else echo "self-test skipped: license-notices android (no zip/jar)"; fi
    return
  fi
  [ "${6:-}" = no-archive ] || mv "$w/lib-1.0.0.aar" "$cache/lib-1.0.0.aar"
  printf 'org.example:lib:1.0.0\t%s\n' "$jarfile" > "$w/components.txt"
  printf '%s\n' "$4" > "$w/allowlist.txt"
  lic_case license-notices "$1" "$2" "$3" GHOST_GRADLE_ALLOWLIST="$w/allowlist.txt" -- android "$w/components.txt"
  rm -rf "$w"
}
APACHE_POM='<license><name>The Apache Software License, Version 2.0</name><url>https://www.apache.org/licenses/LICENSE-2.0.txt</url></license>'
gradle_case "(android) accepts notices equal to the regenerated ones" pass "[license-notices (android)] OK" "org.example:lib Apache-2.0" "$APACHE_POM"
gradle_case "(android) rejects a component missing from the Gradle licence allowlist" fail "org.example:lib:1.0.0: unknown licence: org.example:lib is not in gradle-license-allowlist.txt" "org.example:other Apache-2.0" "$APACHE_POM"
gradle_case "(android) rejects a copyleft licence" fail "org.example:lib:1.0.0: 'GPL-2.0-only' is not an allowed licence" "org.example:lib GPL-2.0-only" \
  '<license><name>GNU General Public License, version 2</name><url>https://www.gnu.org/licenses/old-licenses/gpl-2.0.html</url></license>'
gradle_case "(android) rejects a POM declaring another licence" fail "org.example:lib:1.0.0: its POM declares MIT, gradle-license-allowlist.txt says 'Apache-2.0'" "org.example:lib Apache-2.0" \
  '<license><name>MIT License</name><url>https://opensource.org/licenses/MIT</url></license>'
gradle_case "(android) rejects an allowlist line whose component is gone" fail "gradle-license-allowlist.txt: org.example:gone is not a release runtime component any more" \
  "$(printf 'org.example:lib Apache-2.0\norg.example:gone MIT')" "$APACHE_POM"
gradle_case "(android) rejects a component whose published archive is not in the Gradle cache" fail \
  "org.example:lib:1.0.0: no aar or jar of the component in the Gradle cache" "org.example:lib Apache-2.0" "$APACHE_POM" no-archive
if grep -qF "META-INF/LICENSE.txt of org.example:lib:1.0.0" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-android.txt"; then
  echo "self-test ok: license-notices (android) carries the licence text the AAR ships outside its classes jar"
else
  echo "SELF-TEST FAIL: the fixture Gradle notices miss the licence text of the published AAR" >&2; rc=1
fi
# G-L3 (apk-notices.sh) on fabricated APKs: the committed notices pass; changed or missing ones fail.
notices_case() { # $1 = description, $2 = pass|fail, $3 = setup (assets directory)
  local w got
  w="$(mktemp -d)"
  mkdir -p "$w/tree/assets"
  cat "$DIR/../../licenses/apk-notices-preamble.txt" "$DIR/../../licenses/THIRD_PARTY_NOTICES-android.txt" "$DIR/../../licenses/THIRD_PARTY_NOTICES-client-net.txt" > "$w/tree/assets/THIRD_PARTY_NOTICES.txt"
  "$3" "$w/tree/assets"
  if command -v zip >/dev/null; then (cd "$w/tree" && zip -q -r "$w/app.apk" assets)
  elif command -v jar >/dev/null; then (cd "$w/tree" && jar cfM "$w/app.apk" assets)
  else
    rm -rf "$w"
    if [ -n "${CI:-}" ]; then echo "SELF-TEST FAIL: no zip/jar in CI" >&2; rc=1; else echo "self-test skipped: apk-notices (no zip/jar)"; fi
    return
  fi
  if bash "$DIR/apk-notices.sh" "$w/app.apk" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$2" ]; then echo "self-test ok: apk-notices $1"; else echo "SELF-TEST FAIL: apk-notices $1 ($got)" >&2; rc=1; fi
  rm -rf "$w"
}
notices_same() { :; }
notices_changed() { printf 'one more line\n' >> "$1/THIRD_PARTY_NOTICES.txt"; }
notices_missing() { mv "$1/THIRD_PARTY_NOTICES.txt" "$1/OTHER.txt"; }
notices_case "accepts the committed notices" pass notices_same
notices_case "rejects changed notices" fail notices_changed
notices_case "rejects an APK without the notices asset" fail notices_missing

# Rust gates need cargo; in CI its absence is a failure, not a skip.
expect_fail_msg() { # $1 = description, $2 = expected stderr text, rest = command
  local desc="$1" want="$2" out
  shift 2
  if out="$("$@" 2>&1)"; then
    echo "SELF-TEST FAIL: $desc passed" >&2; rc=1
  elif ! grep -qF "$want" <<<"$out"; then
    echo "SELF-TEST FAIL: $desc failed without reporting: $want" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  else
    echo "self-test ok: $desc"
  fi
}
# G-R6 (Phase 9 design §2.6, §2.3): the DM JNI surface is a closed list, checked in both
# directions and against the Kotlin declarations. The fixtures are source excerpts, because the
# gate reads the closed-list constant, the macro arms and the `external fun` lines as text.
DM_JNI="$HARNESS/dm-jni"
expect_fail_msg "dm-jni-surface rejects an export outside the closed list" \
  "which is not on the closed list" \
  env GHOST_DM_JNI_SOURCE="$DM_JNI/undeclared-export.rs" GHOST_DM_JNI_KOTLIN="$DM_JNI/DmNativeExtra.kt" \
  bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects an Exported entry with no entry point" \
  "'sessionOutbound' is marked Exported on the closed list but the crate emits no entry point" \
  env GHOST_DM_JNI_SOURCE="$DM_JNI/missing-export.rs" GHOST_DM_JNI_KOTLIN="$DM_JNI/DmNativeMissing.kt" \
  bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects a later slice's function exported early" \
  "'sealIntro' is emitted but not marked Exported" \
  env GHOST_DM_JNI_SOURCE="$DM_JNI/unmarked-export.rs" GHOST_DM_JNI_KOTLIN="$DM_JNI/DmNativeMissing.kt" \
  bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects a Kotlin declaration the crate does not export" \
  "DmNative declares 'external fun debugDumpState'" \
  env GHOST_DM_JNI_SOURCE="$DM_JNI/missing-export.rs" GHOST_DM_JNI_KOTLIN="$DM_JNI/DmNativeExtra.kt" \
  bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects a missing Kotlin declaration" \
  "DmNative does not declare 'external fun ctxClose'" \
  env GHOST_DM_JNI_KOTLIN="$DM_JNI/DmNativeMissing.kt" bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects an entry point declared outside the closed list's file" \
  "the crate exports 'debugDumpState'" \
  env GHOST_DM_JNI_SCAN="$DM_JNI/stray" bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects a public native declaration" \
  "it must be internal" \
  env GHOST_DM_JNI_KOTLIN="$DM_JNI/DmNativePublic.kt" bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects an internal declaration Kotlin would mangle" \
  "would mangle the JNI name" \
  env GHOST_DM_JNI_KOTLIN="$DM_JNI/DmNativeMangled.kt" bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects a library that was named but is not there" \
  "library not found" bash "$DIR/dm-jni-surface.sh" "$HARNESS/dm-jni/no-such-library.so"
# The symbol half (review round 2, R2-05), whose only fixture used to be the missing library. The
# readers in `dm-jni/nm/` stand in for built libraries — they print the closed list with one symbol
# too many, one too few, or fail outright — so the diff and the reader-failure path are drilled
# without committing binaries. The file itself only has to look like ELF.
elf="$(mktemp)"
printf '\177ELF G-R6 fixture: the symbols come from GHOST_DM_JNI_NM\n' > "$elf"
expect_fail_msg "dm-jni-surface rejects a library exporting a symbol outside the closed list" \
  "exports 'debugDumpState'" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/stray-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
expect_fail_msg "dm-jni-surface rejects a library that does not export an Exported entry" \
  "does not export 'sessionPrune'" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/missing-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
expect_fail_msg "dm-jni-surface rejects a symbol reader that cannot read the library" \
  "could not read" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/unreadable-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
# Slice S12 (§15.9 item 7, §22.8.10 point 6, §21.13 point 7): the test-vectors entry point is one
# symbol of a test library and none of a shipped one, and only `:crypto-bridge` src/{main,gate}
# references DmNative.
expect_fail_msg "dm-jni-surface rejects the test-vectors entry point in a shipped library" \
  "a shipped library never carries it" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/entry-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
expect_fail_msg "dm-jni-surface rejects a test library without the test-vectors entry point" \
  "does not export the test-vectors entry point" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/exact-nm" bash "$DIR/dm-jni-surface.sh" --test "$elf"
expect_fail_msg "dm-jni-surface rejects the binding hooks in a shipped library (§22.37)" \
  "exports the test-vectors entry point 'DmEquivalence.bindingHooks': a shipped library never carries it" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/hooks-only-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
expect_fail_msg "dm-jni-surface rejects a test library without the binding hooks (§22.37)" \
  "does not export the test-vectors entry point 'DmEquivalence.bindingHooks'" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/entry-run-only-nm" bash "$DIR/dm-jni-surface.sh" --test "$elf"
expect_fail_msg "dm-jni-surface rejects the state-wrap hook in a shipped library (§22.38)" \
  "exports the test-vectors entry point 'DmEquivalence.stateWrapHook': a shipped library never carries it" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/state-hook-only-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
expect_fail_msg "dm-jni-surface rejects a test library without the state-wrap hook (§22.38)" \
  "does not export the test-vectors entry point 'DmEquivalence.stateWrapHook'" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/entry-no-state-hook-nm" bash "$DIR/dm-jni-surface.sh" --test "$elf"
expect_fail_msg "dm-jni-surface rejects the sidecar-log hook in a shipped library (§22.38)" \
  "exports the test-vectors entry point 'DmEquivalence.sidecarLogHook': a shipped library never carries it" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/sidecar-hook-only-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
expect_fail_msg "dm-jni-surface rejects a test library without the sidecar-log hook (§22.38)" \
  "does not export the test-vectors entry point 'DmEquivalence.sidecarLogHook'" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/entry-no-sidecar-hook-nm" bash "$DIR/dm-jni-surface.sh" --test "$elf"
if env GHOST_DM_JNI_NM="$DM_JNI/nm/entry-nm" bash "$DIR/dm-jni-surface.sh" --test "$elf" >/dev/null 2>&1; then
  echo "self-test ok: dm-jni-surface accepts a test library with exactly the test-vectors entry points"
else
  echo "SELF-TEST FAIL: dm-jni-surface rejects a test library with exactly the test-vectors entry points" >&2; rc=1
fi
# Phase 9 review GATES-3: every half named one class, `DmNative`. A JNI entry point of another
# class or package — in the workspace's sources, in a built library — and a native method in any
# other production Android class are refused now; the network surface's three classes are not.
expect_fail_msg "dm-jni-surface rejects a JNI entry point of another class in the workspace" \
  "the workspace exports the JNI entry point 'Java_org_ghost_crypto_bridge_DmDebug_exportSessionState'" \
  env GHOST_DM_JNI_SCAN="$DM_JNI/foreign" bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects a library exporting a JNI symbol of another class" \
  "exports the JNI symbol 'Java_org_ghost_crypto_bridge_DmDebug_exportSessionState'" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/foreign-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
expect_fail_msg "dm-jni-surface rejects a library exporting a JNI symbol of another package" \
  "exports the JNI symbol 'Java_org_ghost_messaging_engine_Shortcut_decrypt'" \
  env GHOST_DM_JNI_NM="$DM_JNI/nm/foreign-package-nm" bash "$DIR/dm-jni-surface.sh" "$elf"
jni_native_out="$(env GHOST_DM_JNI_ANDROID="$DM_JNI/android-native" bash "$DIR/dm-jni-surface.sh" 2>&1 || true)"
if [ "$(grep -c '^GATE-FAIL' <<<"$jni_native_out" || true)" = "2" ] \
   && grep -qF "DmDebug.kt:9: declares a native method outside DmNative" <<<"$jni_native_out" \
   && grep -qF "Leak.java:6: declares a native method outside DmNative" <<<"$jni_native_out"; then
  echo "self-test ok: dm-jni-surface reports native methods outside DmNative and the network classes (Kotlin and Java)"
else
  echo "SELF-TEST FAIL: dm-jni-surface does not report exactly the two native declarations of android-native/" >&2; rc=1
fi
jni_ref_out="$(env GHOST_DM_JNI_ANDROID="$DM_JNI/android-ref" bash "$DIR/dm-jni-surface.sh" 2>&1 || true)"
if [ "$(grep -c '^GATE-FAIL' <<<"$jni_ref_out" || true)" = "2" ] && grep -qF "Shortcut.kt:8: references DmNative outside" <<<"$jni_ref_out"; then
  echo "self-test ok: dm-jni-surface reports DmNative referenced outside :crypto-bridge (code, not prose)"
else
  echo "SELF-TEST FAIL: dm-jni-surface does not report exactly the two code references to DmNative" >&2; rc=1
fi
if env GHOST_DM_JNI_NM="$DM_JNI/nm/exact-nm" bash "$DIR/dm-jni-surface.sh" "$elf" >/dev/null 2>&1
then
  echo "self-test ok: dm-jni-surface accepts a library whose symbols are the closed list"
else
  echo "SELF-TEST FAIL: dm-jni-surface rejects a library whose symbols are the closed list" >&2
  rc=1
fi
rm -f "$elf"
if bash "$DIR/dm-jni-surface.sh" >/dev/null 2>&1; then
  echo "self-test ok: dm-jni-surface accepts the real closed list"
else
  echo "SELF-TEST FAIL: dm-jni-surface rejects the real closed list" >&2; rc=1
fi

# G-DM6 (Phase 9 design §13.6 R-M4, §10.7; mutant ME-18): no CREATE VIRTUAL TABLE and no `fts`
# token in production SQL. The five fixtures are single-purpose — one statement on one line, the
# same statement split across lines (the house style, which a line-oriented grep cannot match),
# one token, one `.sql` file, one vacuous tree — so each half of the gate is proven without the
# others, and each says how many violations it holds so a gate that started reporting everything
# is caught too.
dmfts_case() { # $1 = fixture suffix, $2 = expected violation count, $3 = expected text, $4 = description
  local out hits
  out="$(GHOST_ROOT="$HARNESS/negative-dm-fts-$1" bash "$DIR/dm-no-fts.sh" 2>&1 || true)"
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$hits" = "$2" ] && grep -qF "$3" <<<"$out"; then
    echo "self-test ok: dm-no-fts $4"
  else
    echo "SELF-TEST FAIL: dm-no-fts $4 (reported $hits of $2 violations)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
expect_fail dm-no-fts "$HARNESS/negative-dm-fts-virtual"
dmfts_case virtual 1 "VirtualTableSchema.kt:18" "reports the virtual table and nothing else"
expect_fail dm-no-fts "$HARNESS/negative-dm-fts-virtual-split"
dmfts_case virtual-split 1 "SplitVirtualTableSchema.kt (R-M4" \
  "reports a CREATE VIRTUAL TABLE whose words sit on different lines"
expect_fail dm-no-fts "$HARNESS/negative-dm-fts-token"
dmfts_case token 3 "SearchIndexSchema.kt:19" "reports all three fts tokens and no decoy"
expect_fail dm-no-fts "$HARNESS/negative-dm-fts-sql-file"
dmfts_case sql-file 1 "relay/schema/search.sql:8" "reads a plain .sql file outside android/"
expect_fail dm-no-fts "$HARNESS/negative-dm-fts-no-sql"
dmfts_case no-sql 1 "contains a CREATE TABLE (the gate would pass vacuously)" \
  "refuses a tree whose production sources hold no SQL"
dmfts_empty="$(mktemp -d)"
expect_fail_msg "dm-no-fts refuses a tree with no production sources at all" \
  "no production SQL sources found" env GHOST_ROOT="$dmfts_empty" bash "$DIR/dm-no-fts.sh"
rmdir "$dmfts_empty"
if bash "$DIR/dm-no-fts.sh" >/dev/null 2>&1; then
  echo "self-test ok: dm-no-fts accepts the real schema"
else
  echo "SELF-TEST FAIL: dm-no-fts rejects the real schema" >&2; rc=1
fi

# G-DM2 (Phase 9 design §16.1, §21.7, §21.9; T28, T31): the restricted sync calls are made only
# from the steps that may make them, an owner pass is started only by what may start one, and a
# relay-visible step is driven only by what may drive one. Seven single-purpose fixtures (an eighth,
# `funding`, is Phase 10 slice S1a's, below) — a RECV
# that registers (the reflex T28 forbids), a store-layer `Namespaces.remove` (§21.12 point 3 makes
# it SWEEP's), a RECV that hides its three call sites from a line-by-line reader (a receiver on the
# line above, a local alias, a scope function, a safe call, a port injected under a name of the
# author's choosing), a SWEEP that does more than remove a namespace, a
# RECV that reaches the enqueue through the facade instead (PM-11, PM-30), a RECV that reaches it
# through a **step object** instead (the S8 review's fourth rule), and a tree whose DM sources make
# no restricted call at all — plus an empty tree, so each half is proven without the others. Slice
# S6 arms the mechanism; its corpus grows with S7 and S8 (see §22.11, §22.13).
dmenq_case() { # $1 = fixture suffix, $2 = expected violation count, $3 = expected text, $4 = description
  local out hits
  out="$(GHOST_ROOT="$HARNESS/negative-dm-enqueue-$1" bash "$DIR/dm-enqueue-callers.sh" 2>&1 || true)"
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$hits" = "$2" ] && grep -qF "$3" <<<"$out"; then
    echo "self-test ok: dm-enqueue-callers $4"
  else
    echo "SELF-TEST FAIL: dm-enqueue-callers $4 (reported $hits of $2 violations)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-recv"
dmenq_case recv 1 "ReceiveStep.kt:9" "refuses a RECV step that registers a namespace"
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-remove"
dmenq_case remove 1 "ContactDao.kt:10" "refuses Namespaces.remove from the store layer"
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-evasion"
dmenq_case evasion 8 "ReceiveStep.kt:47" \
  "sees a call through a line break, an alias, a scope function, a safe call and a typed port"
# Phase 10 review of S1a: a callable reference to a restricted call and a parenthesized receiver.
dmenq_case evasion 8 "ReceiveStep.kt:59" "sees a callable reference to a restricted call (sync.funding::set)"
dmenq_case evasion 8 "ReceiveStep.kt:61" "sees a parenthesized receiver ((sync.funding).set(…))"
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-sweeper"
dmenq_case sweeper 1 "Sweeper.kt:11" "lets SWEEP remove a namespace and nothing else"
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-trigger"
dmenq_case trigger 1 "an owner pass starts from the actor timer" \
  "refuses a RECV step that starts an owner pass through the facade"
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-step"
dmenq_case step 2 "a send, a resend, a control or an establishment step is driven by" \
  "refuses a RECV step that reaches a relay through a step object"
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-vacuous"
dmenq_case vacuous 1 "makes a restricted call (the gate would pass vacuously" \
  "refuses a tree whose DM sources make no restricted call"
# Phase 10, slice S1a: `Funding.set` joins the restricted calls (design §7.5 item 1, item 7; T40).
# One fixture, three call sites in a RECV step — the port by its name, a local alias, a port injected
# as a `Funding` under a name of the author's choosing — beside an allowed OwnerSteps that funds and a
# RECV `Inbox.reofferDeferred` that is no violation (it makes no relay call). Slice S4 gave `Funding.set`
# a file list of its own, and it is empty: the allowed OwnerSteps that funds is the fourth violation (3 → 4).
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-funding"
dmenq_case funding 4 "ReceiveStep.kt:13" \
  "refuses a RECV step that funds a namespace by name, through an alias and through a typed port (and lets reofferDeferred pass)"
dmenq_case funding 4 "OwnerSteps.kt:14:        sync.funding.set(tx, ns, true) (G-DM2: no DM step funds a namespace" \
  "refuses an allowed step that funds a namespace (Funding.set's own list, slice S4)"
# Phase 10, slice S4: the funding rule reads every shape the restricted rule reads, in a file that may enqueue —
# an alias, a typed port, a scope function, a callable reference, a parenthesized receiver, a line break with a safe
# call — and leaves the install, a map's `set` and another port's `setRelays` beside them alone.
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-funding-shapes"
dmenq_case funding-shapes 6 "OwnerSteps.kt:23:            set(tx, ns, true)" \
  "sees a funding call in an allowed step through an alias, a typed port, a scope, a reference, parentheses and a line break"
dmenq_case funding-shapes 6 "OwnerSteps.kt:27:        sync.funding?.set(tx, ns, true)" \
  "sees a funding call written across a line break with a safe call"
# Phase 10, slice S3: the channel stores (org.ghost.messaging.channel.store) make no port call (design 10.4); the
# gate reads them like the rest of :messaging, so a store that funds a namespace is refused.
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-channel"
dmenq_case channel 1 "channel/store/MirrorStore.kt:11" "refuses a channel store that funds a namespace"
# Phase 10, slice S4: the restricted and the removal calls of the channel engine's files are G-M5's (ch-enqueue-callers,
# below, which lists them per step); this gate's facade and step rules still read those files. One fixture: a channel
# step's enqueue, not reported here, and a DM send driven from the same step, reported.
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-channel-engine"
dmenq_case channel-engine 1 "channel/engine/ChannelPostStep.kt:11:        sendStep.flushPending()" \
  "leaves a channel step's enqueue to G-M5 and refuses a channel step that drives a DM send"
# Phase 10, the review of S4 (design §19.38): where a file sits. An allowed name outside the DM engine's directory, an
# `:app` file under a channel engine package path (G-DM2 left any such path to G-M5, which read `:messaging` alone),
# and files of the `debug` and `gate` source sets: four violations, beside an allowed OwnerSteps that enqueues.
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-placement"
dmenq_case placement 4 "messaging/other/OwnerSteps.kt:6:        sync.outbox.enqueue(tx, blob)" \
  "refuses an allowed step's name outside the DM engine's directory"
dmenq_case placement 4 "app/messaging/channel/engine/ChannelReflexStep.kt:9:" \
  "refuses an :app file under a channel engine package path (the boundary is :messaging's channel engine)"
dmenq_case placement 4 "android/app/src/debug/kotlin/org/ghost/app/Reflex.kt:6:" "reads the debug source set"
dmenq_case placement 4 "android/app/src/gate/kotlin/org/ghost/app/gate/Reflex.kt:6:" "reads the gate source set"
# Phase 11, slice S3: the media store (org.ghost.media.store of android/media) makes no port call (design faza11-media.md 16.1,
# G-M6); the gate reads the new module like :messaging, so a store that enqueues an operation is refused, and MediaFeeder
# (org.ghost.media.send) will have to be put on the allowlist on purpose.
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-media"
dmenq_case media 1 "media/store/MediaMirror.kt:11" "refuses a media store that enqueues an operation"
# A tree whose media module moved away (review of slice S3): the other two modules meet the floor of sources and the fixture holds the
# one allowed restricted call, so G-DM2 must fail for the missing module alone (the first version passed this tree).
expect_fail dm-enqueue-callers "$HARNESS/negative-dm-enqueue-no-media"
dmenq_case no-media 1 "android/media/src/main: missing" "refuses a tree whose media module moved away"
dmenq_empty="$(mktemp -d)"
expect_fail_msg "dm-enqueue-callers refuses a tree with no DM production sources at all" \
  "no DM production sources found" env GHOST_ROOT="$dmenq_empty" bash "$DIR/dm-enqueue-callers.sh"
rmdir "$dmenq_empty"
if bash "$DIR/dm-enqueue-callers.sh" >/dev/null 2>&1; then
  echo "self-test ok: dm-enqueue-callers accepts the real DM engine"
else
  echo "SELF-TEST FAIL: dm-enqueue-callers rejects the real DM engine" >&2; rc=1
fi

# G-M5 (Phase 10 design faza10-forum.md §13.1, §14 S4; T40): the channel engine's relay-visible calls, step by step.
# CH-RECV and CH-JOIN make none; every other channel step makes only the calls of its own row (CH-SETTLE enqueues its
# Welcomes and never funds, the join sweep removes or stops listening and never enqueues); and a channel step that
# enqueues, admits, settles or sweeps is driven by the channel engine and by nothing else. Five single-purpose
# fixtures (a CH-RECV that enqueues and registers, two steps that make a call outside their row, a CH-JOIN and a DM
# RECV that drive channel steps, G-DM2's evasions in CH-RECV, a tree whose channel files make no restricted call),
# an empty tree, and the real tree.
chenq_case() { # $1 = fixture suffix, $2 = expected violation count, $3 = expected text, $4 = description
  local out hits
  out="$(GHOST_ROOT="$HARNESS/negative-ch-enqueue-$1" bash "$DIR/ch-enqueue-callers.sh" 2>&1 || true)"
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$hits" = "$2" ] && grep -qF -- "$3" <<<"$out"; then
    echo "self-test ok: ch-enqueue-callers $4"
  else
    echo "SELF-TEST FAIL: ch-enqueue-callers $4 (reported $hits of $2 violations)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-recv"
chenq_case recv 2 "ChannelReceiveStep.kt:9:        sync.outbox.enqueue(tx, blob) (G-M5: ChannelReceiveStep.kt may make no relay-visible call" \
  "refuses a CH-RECV that enqueues (and lets CH-CREATE register)"
chenq_case recv 2 "ChannelReceiveStep.kt:10:        sync.namespaces.register(tx, ns)" "refuses a CH-RECV that registers"
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-wrongcall"
chenq_case wrongcall 2 "ChannelSettleStep.kt:10:        sync.funding.set(tx, ns, true) (G-M5: set is not one of ChannelSettleStep.kt's calls (enqueue remove setListening))" \
  "refuses a CH-SETTLE that funds, though it may enqueue its Welcomes"
chenq_case wrongcall 2 "ChannelSweepStep.kt:11:        ob.enqueue(tx, blob) (G-M5: enqueue is not one of ChannelSweepStep.kt's calls (remove setListening))" \
  "refuses a join sweep that enqueues through a typed port, though it may remove"
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-step"
# The review of S4 (§19.38) added the third rule, which also reads the two constructors that name step classes (3 → 5).
chenq_case step 5 "ChannelJoinStep.kt:9:        postStep.compose(tx) (G-M5: a channel step that enqueues" "refuses a CH-JOIN that drives a post"
chenq_case step 5 "ChannelJoinStep.kt:10:        passStep.admit(channel)" "refuses a CH-JOIN that drives an admission"
chenq_case step 5 "messaging/engine/ReceiveStep.kt:9:        settle.settleDue()" "refuses a DM RECV that drives a channel settle"
chenq_case step 5 "messaging/engine/ReceiveStep.kt:7:internal class ReceiveStep(private val settle: ChannelSettleStep) { (G-M5: ReceiveStep.kt names a step" \
  "refuses a DM RECV that holds a channel step"
# The review of S4 (§19.38): the third rule — who may hold a step — over the entry points the second rule does not list
# (a post, a settle, an accept, the engine's post), a companion constant left alone, and `:app` importing the engine.
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-holders"
chenq_case holders 6 "ChannelReceiveStep.kt:10:    private val posts: ChannelPostStep," "refuses a CH-RECV that holds the post step"
chenq_case holders 6 "ChannelReceiveStep.kt:11:    private val engine: ChannelEngine," "refuses a CH-RECV that holds the engine"
chenq_case holders 6 "ChannelReceiveStep.kt:20:        settleStep.settle(c)" "refuses a CH-RECV that writes a settle step's name"
chenq_case holders 6 "android/app/src/main/kotlin/org/ghost/app/Reflex.kt:3:import org.ghost.messaging.channel.engine.ChannelEngine" \
  "refuses an :app file that imports the channel engine"
# The recognizer's widening (§19.38): a block comment, backticks, a trailing dot, an unbound reference of the port type,
# a qualified parameter type, a type alias of the port type, a destructuring declaration — seven violations in CH-RECV.
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-shapes"
CHSH="android/messaging/src/main/kotlin/org/ghost/messaging/channel/engine/ChannelReceiveStep.kt"
chenq_case shapes 7 "$CHSH:14:" "sees a call behind a block comment"
chenq_case shapes 7 "$CHSH:15:        sync.outbox.enqueue(tx, blob)" "sees backticked names"
chenq_case shapes 7 "$CHSH:16:        sync.outbox.enqueue(tx, blob)" "sees a receiver whose line ends with the dot"
chenq_case shapes 7 "$CHSH:18:        (org.ghost.sync.api.Outbox::enqueue)" "sees an unbound callable reference of the port type"
chenq_case shapes 7 "$CHSH:21:" "sees a port passed as a qualified parameter"
chenq_case shapes 7 "$CHSH:23:" "sees a port passed as a type alias of the port type"
chenq_case shapes 7 "$CHSH:27:        a.enqueue(tx, blob)" "sees a port bound by a destructuring declaration"
# Where a channel file sits (§19.38): the debug and gate source sets, and an allowed step's name outside the channel
# engine's directory (in :app) — three violations beside an allowed CH-CREATE.
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-placement"
chenq_case placement 3 "android/messaging/src/debug/kotlin/org/ghost/messaging/channel/engine/ChannelReflexStep.kt:6:" \
  "reads the debug source set"
chenq_case placement 3 "android/messaging/src/gate/kotlin/org/ghost/messaging/channel/engine/ChannelReflexStep.kt:6:" \
  "reads the gate source set"
chenq_case placement 3 "app/messaging/channel/engine/ChannelPostStep.kt:9:        sync.outbox.enqueue(tx, blob) (G-M5: ChannelPostStep.kt may make no relay-visible call" \
  "gives an allowed step's name no entry outside the channel engine's directory"
# A port renamed in the ports holder is a port by its type (§19.38): CH-SETTLE funding through `sync.fund`.
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-renamed-port"
chenq_case renamed-port 1 "ChannelSettleStep.kt:10:        sync.fund.set(tx, ns, true) (G-M5: set is not one of ChannelSettleStep.kt's calls" \
  "sees a funding call through a port property renamed in ChannelSyncPorts"
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-evasion"
CHEV="android/messaging/src/main/kotlin/org/ghost/messaging/channel/engine/ChannelReceiveStep.kt"
evasion_count ch-enqueue-callers negative-ch-enqueue-evasion 7
evasion_named ch-enqueue-callers "$CHEV:10:        sync.outbox.enqueue(tx, blob)" "sees a receiver on the line above its call"
evasion_named ch-enqueue-callers "$CHEV:13:        o.enqueue(tx, blob)" "sees a call through a local alias"
evasion_named ch-enqueue-callers "$CHEV:14:        with(sync.namespaces) { register(tx, ns) }" "sees a bare call in a scope function"
evasion_named ch-enqueue-callers "$CHEV:15:        sync.capabilities?.put(tx, ns)" "sees a safe call"
evasion_named ch-enqueue-callers "$CHEV:16:        ledger.set(tx, ns, true)" "sees a port injected as its type"
evasion_named ch-enqueue-callers "$CHEV:17:        val fund = sync.funding::set" "sees a callable reference"
evasion_named ch-enqueue-callers "$CHEV:18:        (sync.registrations).keep(tx, ns)" "sees a parenthesized receiver"
expect_fail ch-enqueue-callers "$HARNESS/negative-ch-enqueue-vacuous"
chenq_case vacuous 1 "makes a restricted call (the gate would pass vacuously)" \
  "refuses a tree whose channel sources make no restricted call"
chenq_empty="$(mktemp -d)"
expect_fail_msg "ch-enqueue-callers refuses a tree with no channel production sources at all" \
  "no channel production sources found" env GHOST_ROOT="$chenq_empty" bash "$DIR/ch-enqueue-callers.sh"
rmdir "$chenq_empty"
if bash "$DIR/ch-enqueue-callers.sh" >/dev/null 2>&1; then
  echo "self-test ok: ch-enqueue-callers accepts the real channel engine"
else
  echo "SELF-TEST FAIL: ch-enqueue-callers rejects the real channel engine" >&2; rc=1
fi

# The S0′ gate slice (Phase 9 design §16.1, §22.33). Each fixture holds one kind of violation and
# says how many, so a gate that reported everything, or nothing but the first hit, is caught too.
#
# G-DM1 (T28, ADR-20): the DM modules name no network package, socket or HTTP class and no coroutine.
# `imports` holds five package imports (two of them also a class name) in `:messaging`, an HTTP client
# in `:crypto-bridge`, decoys that must not match, and a test source that must not be read; `bare` a
# wildcard import and the bare class on a later line; `gate-set` the `gate` build type's source set;
# `vacuous` a tree without `:crypto-bridge`.
dmnet_case() { # $1 = fixture suffix, $2 = expected violation count, $3 = expected text, $4 = description
  local out hits
  out="$(GHOST_ROOT="$HARNESS/negative-dm-network-$1" bash "$DIR/messaging-no-network.sh" 2>&1 || true)"
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$hits" = "$2" ] && grep -qF "$3" <<<"$out"; then
    echo "self-test ok: messaging-no-network $4"
  else
    echo "SELF-TEST FAIL: messaging-no-network $4 (reported $hits of $2 violations)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
expect_fail messaging-no-network "$HARNESS/negative-dm-network-imports"
dmnet_case imports 9 "NetworkedStep.kt:6:import org.ghost.network" \
  "reports every network package and class import and no decoy or test source"
expect_fail messaging-no-network "$HARNESS/negative-dm-network-bare"
dmnet_case bare 2 "Wildcard.kt:8:" "reports a wildcard import and the bare class that uses it"
expect_fail messaging-no-network "$HARNESS/negative-dm-network-gate-set"
dmnet_case gate-set 1 "src/gate/kotlin/org/ghost/crypto/bridge/gate/GateProbe.kt:5:" "reads the gate build type's source set"
expect_fail messaging-no-network "$HARNESS/negative-dm-network-vacuous"
dmnet_case vacuous 1 "android/crypto-bridge/src/main: missing" "refuses a tree without a DM module"
if bash "$DIR/messaging-no-network.sh" >/dev/null 2>&1; then
  echo "self-test ok: messaging-no-network accepts the real DM modules"
else
  echo "SELF-TEST FAIL: messaging-no-network rejects the real DM modules" >&2; rc=1
fi

# G-DM4 (§13.6 REPLACE guards): DM SQL never replaces a row. `messaging` holds the four forms in a DM
# store — one built with a template, one split over two literals — beside comments, a KDoc, a string
# holding `//`, a quote character, the `replace()` function, `INSERT OR IGNORE` and `DO NOTHING`, none
# of which may count; `schema` a constraint conflict clause and a template-built REPLACE inside
# migration 5, an upsert on a DM table in a later migration, and a pre-DM REPLACE and a sync upsert
# that are not DM SQL; `vacuous` a tree whose DM store holds no SQL and whose schema lost its markers.
dmrep_case() { # $1 = fixture suffix, $2 = expected violation count, $3 = expected text, $4 = description
  local out hits
  out="$(GHOST_ROOT="$HARNESS/negative-dm-replace-$1" bash "$DIR/dm-no-replace.sh" 2>&1 || true)"
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$hits" = "$2" ] && grep -qF "$3" <<<"$out"; then
    echo "self-test ok: dm-no-replace $4"
  else
    echo "SELF-TEST FAIL: dm-no-replace $4 (reported $hits of $2 violations)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-messaging"
dmrep_case messaging 5 "ReplacingStore.kt:23: ON CONFLICT ... DO UPDATE" \
  "reports every REPLACE form in a DM store, split and templated ones included, and no comment or decoy"
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-schema"
dmrep_case schema 3 "Schema.kt:27: OR REPLACE, REPLACE INTO" \
  "reads migration 5 and later DM migrations, and not the pre-DM or sync SQL"
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-vacuous"
dmrep_case vacuous 2 "no SQL string found (the gate would pass vacuously)" \
  "refuses a DM store without SQL and a schema without its migration 5 markers"
# Phase 10, slice S1a: the two tables migration 6 adds to `:sync` (`sync_namespace_fund`,
# `relay_register_capability`) are REPLACE-guarded like the DM tables, so the rule reads their writers
# too. `v6tables` holds an upsert on the one and an INSERT OR REPLACE on the other in a `:sync` store,
# beside the v2 `relay_capability` upsert, the writers' own UPDATE-then-INSERT form and a longer table
# name, none of which may count.
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-v6tables"
dmrep_case v6tables 2 "CapabilityStore.kt:17: ON CONFLICT ... DO UPDATE" \
  "reads the writers of the two migration-6 sync tables, and not relay_capability's upsert or a longer table name"
# Phase 10, slice S3: the channel tables of migration 7 (`ch_*`, `mls_kv`, `mls_global_kv`) are REPLACE-guarded
# like the DM tables (all but `ch_seen` and `ch_kp_seen`, design faza10-forum.md §9, §19.35), so the rule reads
# their writers wherever they are and requires the schema region to hold a `ch_` table. `v7tables` holds an
# upsert on `mls_global_kv`, an INSERT OR REPLACE on `ch_post` and a REPLACE INTO on `mls_kv` in a `:sync` store
# and an INSERT OR REPLACE on `ch_channel` in a later migration of Schema.kt, beside the writers' own
# UPDATE-then-INSERT form, tables that only end like a channel table (`launch_log`, `research_kv`), a word that
# only starts with `ch` (`chart_cache`) and a pre-channel REPLACE, none of which may count; `no-channel` a
# schema whose migration 5 region holds no `ch_` table. The other fixtures' schemas gained a `ch_channel` line.
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-v7tables"
dmrep_case v7tables 4 "ChannelMirrorStore.kt:16: ON CONFLICT ... DO UPDATE" \
  "reads the writers of the channel tables outside :messaging and in a later migration, and not launch_log, research_kv, chart_cache or the pre-channel REPLACE"
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-no-channel"
dmrep_case no-channel 1 "no CREATE TABLE ch_ between the migration 5 markers" \
  "refuses a schema whose migration 5 region holds no channel table"
# Phase 11, slice S3: the five media tables of migration 8 (`media_*`) are REPLACE-guarded like the DM tables (design
# faza11-media.md 13.6), and the media store (`android/media`) is read whole like :messaging. `v8tables` holds, in the
# media store, an upsert on `media_blob`, an INSERT OR REPLACE on `media_fragment`, one on a table that is no media table
# (the module is read, not the name), `ContentValues` and `insertWithOnConflict(..., 5)`; in a `:sync` store an upsert on
# `media_outbound_op`, an INSERT OR REPLACE on `MEDIA_OBJECT` and a REPLACE INTO on `Media_Upload` (the name in any case);
# in a later migration of Schema.kt an INSERT OR REPLACE on `media_object`: 9 violations, beside the writers' own
# UPDATE-then-INSERT form, INSERT OR IGNORE, DO NOTHING, replace(), `social_media_cache`, `mediate_log` and the pre-DM
# REPLACE, none of which may count. `no-media` is a schema whose migration 5 region holds no `media_` table and a media
# store with no SQL string (2).
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-v8tables"
dmrep_case v8tables 9 "ReplacingMediaStore.kt:10: ON CONFLICT ... DO UPDATE" \
  "reports the writers of the media tables: the media store read whole, a store outside it by the table name, a later migration"
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-no-media"
dmrep_case no-media 2 "no CREATE TABLE media_ between the migration 5 markers" \
  "refuses a schema whose migration 5 region holds no media table"
dmrep_case no-media 2 "android/media/src/main: no SQL string found" \
  "refuses a media store that holds no SQL string"
if bash "$DIR/dm-no-replace.sh" >/dev/null 2>&1; then
  echo "self-test ok: dm-no-replace accepts the real DM SQL"
else
  echo "SELF-TEST FAIL: dm-no-replace rejects the real DM SQL" >&2; rc=1
fi

# sync-no-catch-all over the DM modules (§16.1 last rows): catch-alls in `:messaging`, in
# `:crypto-bridge` and in its `gate` source set, an allowlisted clause found more often than allowed,
# and a fixture allowlist with a stale entry, an entry outside the DM modules and a malformed one
# (8); a tree whose DM modules moved away (2). negative-sync and negative-sync-no-entitlement above
# carry clean DM modules, so their counts are unchanged.
syncdm_case() { # $1 = fixture, $2 = expected violation count, $3 = expected text, $4 = description
  local out hits
  out="$(GHOST_ROOT="$HARNESS/$1" bash "$DIR/sync-no-catch-all.sh" 2>&1 || true)"
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$hits" = "$2" ] && grep -qF "$3" <<<"$out"; then
    echo "self-test ok: sync-no-catch-all $4"
  else
    echo "SELF-TEST FAIL: sync-no-catch-all $4 (reported $hits of $2 violations)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
expect_fail sync-no-catch-all "$HARNESS/negative-sync-dm"
syncdm_case negative-sync-dm 8 "DmNative.kt:13: catch (e: UnsatisfiedLinkError) (catch-all in a DM module: 2 found, the allowlist permits 1" \
  "reports DM catch-alls, an allowlist exceeded, and a stale, foreign and malformed allowlist entry"
expect_fail sync-no-catch-all "$HARNESS/negative-sync-dm-vacuous"
syncdm_case negative-sync-dm-vacuous 2 "android/crypto-bridge/src/main: missing" "refuses a tree whose DM modules moved away"
if bash "$DIR/sync-no-catch-all.sh" >/dev/null 2>&1; then
  echo "self-test ok: sync-no-catch-all accepts the real sync, entitlement and DM modules"
else
  echo "SELF-TEST FAIL: sync-no-catch-all rejects the real sources" >&2; rc=1
fi

# The evasion review of the S0′ gates (Phase 9 design §22.33 item 16). Each negative fixture holds, one
# per file, the violations the line-by-line gates passed, each on the line its README names; each
# near-miss fixture holds what the whole-file reading must still accept. One case per evasion, so a
# gate that stops seeing one is named, and the exact total, so a gate that reports too much is too.
# (`evasion_count`, `evasion_named` and `near_misses` are defined at the top: G-M5's cases above use them.)
# G-DM1: the coroutine modifier in every shape, and package names across lines, comments and quotes.
EV_KT="android/messaging/src/main/kotlin/org/ghost/messaging/evasion"
evasion_count messaging-no-network negative-dm-network-evasions 8
evasion_named messaging-no-network "$EV_KT/SuspendFun.kt:4:" "reports a suspend fun"
evasion_named messaging-no-network "$EV_KT/SuspendFunctionType.kt:5:" "reports a suspending function type with a receiver"
evasion_named messaging-no-network "$EV_KT/SuspendSplit.kt:5:" "reports suspend split from fun across a line"
evasion_named messaging-no-network "$EV_KT/SplitQualifiedName.kt:5:" "reports a package name written across lines"
evasion_named messaging-no-network "$EV_KT/SplitImport.kt:3:" "reports an import written across lines"
evasion_named messaging-no-network "$EV_KT/QuotedName.kt:5:" "reports a backtick-quoted package name"
evasion_named messaging-no-network "$EV_KT/CommentInName.kt:5:" "reports a package name split by a comment"
evasion_named messaging-no-network "$EV_KT/StdlibCoroutines.kt:3:" "reports the standard library's coroutine package"
near_misses messaging-no-network positive-dm-network-near-misses
# sync-no-catch-all: a catch clause in every layout, and aliases of a catch-all type.
evasion_count sync-no-catch-all negative-sync-dm-evasions 9
evasion_named sync-no-catch-all "android/sync/src/main/kotlin/org/ghost/sync/evasion/SplitCatch.kt:6:catch ( e: Throwable )" "reports a catch split across lines in the sync engine"
evasion_named sync-no-catch-all "$EV_KT/CommentInCatch.kt:5: catch (e: Throwable)" "reports a comment inside the catch"
evasion_named sync-no-catch-all "$EV_KT/AnnotatedCatch.kt:5: catch (@Suppress(" "reports an annotated catch parameter"
evasion_named sync-no-catch-all "$EV_KT/TrailingComma.kt:5: catch (e: Exception,)" "reports a trailing comma in the catch"
evasion_named sync-no-catch-all "$EV_KT/QuotedCatch.kt:5: catch ( e : Exception)" "reports a backtick-quoted catch parameter"
evasion_named sync-no-catch-all "$EV_KT/SplitType.kt:5: catch (e: java .lang.Throwable)" "reports a catch type written across lines"
evasion_named sync-no-catch-all "$EV_KT/TypeAlias.kt:4: typealias Oops = Throwable" "reports a type alias of Throwable"
evasion_named sync-no-catch-all "$EV_KT/ImportAlias.kt:3: import java.lang.Exception as Oops" "reports an import alias of Exception"
evasion_named sync-no-catch-all "android/messaging/src/main/java/org/ghost/messaging/evasion/SplitJava.java:5: catch (Throwable t)" "reports a Java catch split across lines"
near_misses sync-no-catch-all positive-sync-dm-near-misses
# G-DM4: the conflict-algorithm APIs, and a conflict clause held apart from its statement.
evasion_count dm-no-replace negative-dm-replace-evasions 9
evasion_named dm-no-replace "$EV_KT/InsertWithOnConflictFive.kt:6: insertWithOnConflict in a DM module" "reports insertWithOnConflict(…, 5)"
evasion_named dm-no-replace "$EV_KT/ConflictReplaceConstant.kt:5: CONFLICT_REPLACE in a DM module" "reports the CONFLICT_REPLACE constant"
evasion_named dm-no-replace "$EV_KT/ReplaceOrThrow.kt:6: replaceOrThrow in a DM module" "reports replaceOrThrow"
evasion_named dm-no-replace "$EV_KT/ContentValuesRow.kt:5: ContentValues in a DM module" "reports ContentValues"
evasion_named dm-no-replace "$EV_KT/VerbInAValue.kt:5: REPLACE held apart from its statement" "reports REPLACE in a literal of its own"
evasion_named dm-no-replace "$EV_KT/OrFollowedByValue.kt:5: OR followed by a value" "reports INSERT OR followed by a value"
evasion_named dm-no-replace "$EV_KT/ActionInAValue.kt:5: DO UPDATE held apart from its ON CONFLICT" "reports DO UPDATE in a literal of its own"
evasion_named dm-no-replace "$EV_KT/ConflictFollowedByValue.kt:6: ON CONFLICT followed by a value" "reports ON CONFLICT followed by a value"
evasion_named dm-no-replace "$EV_KT/TemplateVerb.kt:5: OR followed by a value" "reports the algorithm as a template"
near_misses dm-no-replace positive-dm-replace-near-misses
# G-DM4, slice S3: each violation of the channel-table fixture by line (the writers outside :messaging).
evasion_count dm-no-replace negative-dm-replace-v7tables 4
evasion_named dm-no-replace "sync/store/ChannelMirrorStore.kt:16: ON CONFLICT ... DO UPDATE in DM SQL" "reports an upsert on mls_global_kv"
evasion_named dm-no-replace "sync/store/ChannelMirrorStore.kt:19: OR REPLACE, REPLACE INTO in DM SQL" "reports an INSERT OR REPLACE on ch_post"
evasion_named dm-no-replace "sync/store/ChannelMirrorStore.kt:22: REPLACE INTO in DM SQL" "reports a REPLACE INTO on mls_kv"
evasion_named dm-no-replace "storage/Schema.kt:25: OR REPLACE, REPLACE INTO in DM SQL" "reports an INSERT OR REPLACE on ch_channel in a later migration"
# G-DM4, Phase 11 slice S3: each violation of the media-table fixture by line (the media store, a store outside it, a later migration).
evasion_count dm-no-replace negative-dm-replace-v8tables 9
evasion_named dm-no-replace "media/store/ReplacingMediaStore.kt:10: ON CONFLICT ... DO UPDATE in DM SQL" "reports an upsert on media_blob in the media store"
evasion_named dm-no-replace "media/store/ReplacingMediaStore.kt:12: OR REPLACE, REPLACE INTO in DM SQL" "reports an INSERT OR REPLACE on media_fragment"
evasion_named dm-no-replace "media/store/ReplacingMediaStore.kt:14: OR REPLACE, REPLACE INTO in DM SQL" "reads every literal of the media store, whatever table it names"
evasion_named dm-no-replace "media/store/ReplacingMediaStore.kt:16: ContentValues in a DM module" "reports ContentValues in the media store"
evasion_named dm-no-replace "media/store/ReplacingMediaStore.kt:18: insertWithOnConflict in a DM module" "reports insertWithOnConflict in the media store"
evasion_named dm-no-replace "sync/store/MediaMirrorStore.kt:9: ON CONFLICT ... DO UPDATE in DM SQL" "reports an upsert on media_outbound_op outside the media module"
evasion_named dm-no-replace "sync/store/MediaMirrorStore.kt:11: OR REPLACE, REPLACE INTO in DM SQL" "reports an INSERT OR REPLACE on MEDIA_OBJECT"
evasion_named dm-no-replace "sync/store/MediaMirrorStore.kt:13: REPLACE INTO in DM SQL" "reports a REPLACE INTO on Media_Upload"
evasion_named dm-no-replace "storage/Schema.kt:26: OR REPLACE, REPLACE INTO in DM SQL" "reports an INSERT OR REPLACE on media_object in a later migration"
# G-DM4, review of slice S3: a table name is matched without regard to case (SQLite resolves it so) and every
# module's `gate`, `debug` and `release` source sets are read, not only the two DM modules'. One fixture of six
# violations the first version passed: three in a `:sync` store in capitals or mixed case, and one in each of
# `src/release`, `src/gate` and `src/debug` of a module that is not a DM module.
expect_fail dm-no-replace "$HARNESS/negative-dm-replace-casesets"
evasion_count dm-no-replace negative-dm-replace-casesets 6
evasion_named dm-no-replace "sync/store/ShoutingStore.kt:12: OR REPLACE, REPLACE INTO in DM SQL" "reports an INSERT OR REPLACE on CH_POST"
evasion_named dm-no-replace "sync/store/ShoutingStore.kt:15: REPLACE INTO in DM SQL" "reports a REPLACE INTO on Mls_Kv"
evasion_named dm-no-replace "sync/store/ShoutingStore.kt:20: ON CONFLICT ... DO UPDATE in DM SQL" "reports an upsert on MLS_GLOBAL_KV"
evasion_named dm-no-replace "android/sync/src/release/kotlin/org/ghost/sync/store/ReleaseStore.kt:11: REPLACE INTO in DM SQL" "reads src/release of a module that is not a DM module"
evasion_named dm-no-replace "android/sync/src/gate/kotlin/org/ghost/sync/store/GateStore.kt:9: ON CONFLICT ... DO UPDATE in DM SQL" "reads src/gate of a module that is not a DM module"
evasion_named dm-no-replace "android/storage/src/debug/kotlin/org/ghost/storage/DebugSeed.kt:9: OR REPLACE, REPLACE INTO in DM SQL" "reads src/debug of a module that is not a DM module"
# The scopes of the source gates (design faza10-forum.md 13.1, the row of the hygiene gates; slice S3):
# anti-placeholder, no-logging, sync-no-catch-all, kotlin-clearnet, G-DM1, G-DM4 and G-DM6 read the package of
# the channel stores, and the first two the channel crate too. One fixture, one violation of each in
# org.ghost.messaging.channel.store (and a TODO and a println! in client-core/mls/src for the two gates that
# read Rust): a gate whose scope named the DM packages one by one would pass this tree. The other half of each
# gate (the clean side) is the run against the real tree.
CHP=negative-channel-packages
CHS="android/messaging/src/main/kotlin/org/ghost/messaging/channel/store/LeakyChannelStore.kt"
evasion_count anti-placeholder $CHP 2
evasion_named anti-placeholder "$CHS:11:" "reads the package of the channel stores"
evasion_named anti-placeholder "client-core/mls/src/lib.rs:5:" "reads the channel crate"
evasion_count no-logging $CHP 2
evasion_named no-logging "$CHS:14:" "reads the package of the channel stores"
evasion_named no-logging "client-core/mls/src/lib.rs:6:" "reads the channel crate"
evasion_count sync-no-catch-all $CHP 1
evasion_named sync-no-catch-all "$CHS:19: catch (e: Exception)" "reads the package of the channel stores against the allowlist"
evasion_count kotlin-clearnet $CHP 1
evasion_named kotlin-clearnet "$CHS:3:import java.net.Socket" "reads the package of the channel stores"
evasion_count messaging-no-network $CHP 2
evasion_named messaging-no-network "$CHS:3:import java.net.Socket (G-DM1: a DM module names a network package" "reads the package of the channel stores (the package)"
evasion_named messaging-no-network "$CHS:3:import java.net.Socket (G-DM1: a DM module names a socket, address or HTTP class" "reads the package of the channel stores (the class)"
evasion_count dm-no-replace $CHP 1
evasion_named dm-no-replace "$CHS:24: OR REPLACE, REPLACE INTO in DM SQL" "reads the package of the channel stores"
evasion_count dm-no-fts $CHP 2
evasion_named dm-no-fts "$CHS:25:" "reads the package of the channel stores (the virtual table and the token)"
# The same scopes over the package of the channel engine (org.ghost.messaging.channel.engine; slice S4, which adds
# it): one violation of each in one file. The channel crate of this fixture is clean (S3's fixture above holds its
# violations), so anti-placeholder and no-logging report one each here, not two.
CHE=negative-channel-engine
CHF="android/messaging/src/main/kotlin/org/ghost/messaging/channel/engine/LeakyChannelStep.kt"
evasion_count anti-placeholder $CHE 1
evasion_named anti-placeholder "$CHF:11:" "reads the package of the channel engine"
evasion_count no-logging $CHE 1
evasion_named no-logging "$CHF:14:" "reads the package of the channel engine"
evasion_count sync-no-catch-all $CHE 1
evasion_named sync-no-catch-all "$CHF:19: catch (e: Exception)" "reads the package of the channel engine against the allowlist"
evasion_count kotlin-clearnet $CHE 1
evasion_named kotlin-clearnet "$CHF:3:import java.net.Socket" "reads the package of the channel engine"
evasion_count messaging-no-network $CHE 2
evasion_named messaging-no-network "$CHF:3:import java.net.Socket (G-DM1: a DM module names a network package" "reads the package of the channel engine (the package)"
evasion_named messaging-no-network "$CHF:3:import java.net.Socket (G-DM1: a DM module names a socket, address or HTTP class" "reads the package of the channel engine (the class)"
evasion_count dm-no-replace $CHE 1
evasion_named dm-no-replace "$CHF:24: OR REPLACE, REPLACE INTO in DM SQL" "reads the package of the channel engine"
evasion_count dm-no-fts $CHE 2
evasion_named dm-no-fts "$CHF:25:" "reads the package of the channel engine (the virtual table and the token)"
# The same for the media store (Phase 11 design faza11-media.md 13.1, 13.6 and the last row of 16.1; slice S3): anti-placeholder,
# no-logging, sync-no-catch-all, kotlin-clearnet, G-DM1, G-DM4 and G-DM6 read `org.ghost.media.store` of the new module
# `android/media`. One fixture, one violation of each: a gate whose scope named the DM modules one by one would pass this
# tree. G-DM2 (dm-enqueue-callers) and G-DM3 (dm-derivation-inputs) have fixtures of their own, further down, because
# each needs a file of its own to be non-vacuous.
MDP=negative-media-packages
MDS="android/media/src/main/kotlin/org/ghost/media/store/LeakyMediaStore.kt"
evasion_count anti-placeholder $MDP 1
evasion_named anti-placeholder "$MDS:11:" "reads the package of the media store"
evasion_count no-logging $MDP 1
evasion_named no-logging "$MDS:14:" "reads the package of the media store"
evasion_count sync-no-catch-all $MDP 1
evasion_named sync-no-catch-all "$MDS:19: catch (e: Exception)" "reads the package of the media store against the allowlist"
evasion_count kotlin-clearnet $MDP 1
evasion_named kotlin-clearnet "$MDS:3:import java.net.Socket" "reads the package of the media store"
evasion_count messaging-no-network $MDP 2
evasion_named messaging-no-network "$MDS:3:import java.net.Socket (G-DM1: a DM module names a network package" "reads the package of the media store (the package)"
evasion_named messaging-no-network "$MDS:3:import java.net.Socket (G-DM1: a DM module names a socket, address or HTTP class" "reads the package of the media store (the class)"
evasion_count dm-no-replace $MDP 1
evasion_named dm-no-replace "$MDS:24: OR REPLACE, REPLACE INTO in DM SQL" "reads the package of the media store"
evasion_count dm-no-fts $MDP 2
evasion_named dm-no-fts "$MDS:25:" "reads the package of the media store (the virtual table and the token)"
# A tree whose media module moved away is refused by the three gates that require it to exist (it would otherwise be read as
# a tree with one module fewer): one violation each, for that reason alone.
for mvg in messaging-no-network sync-no-catch-all dm-no-replace; do
  expect_fail $mvg "$HARNESS/negative-media-vacuous"
  evasion_count $mvg negative-media-vacuous 1
  evasion_named $mvg "android/media/src/main: missing" "refuses a tree whose media module moved away"
done
# G-R4's source half (no-logging): a standard stream without a print macro.
evasion_count no-logging negative-rust-std-streams 1
evasion_named no-logging "client-core/dm/src/lib.rs:7:    let _ = writeln!(std::io::stderr()" "reports writeln! to the process's error stream"
# The source finder's exemptions are exact (Phase 10 review of S2a, F4): a module directory named
# target and a module file named main.rs are read; the crate's own src/main.rs stays exempt.
evasion_count no-logging negative-rust-path-exemptions 2
evasion_named no-logging "client-core/fx/src/target/mod.rs:3:    eprintln!" "reads a module directory named target"
evasion_named no-logging "client-core/fx/src/x/main.rs:3:" "reads a module file named main.rs"
near_misses no-logging positive-rust-std-streams
# G-DM3's Kotlin half (§22.33 item 17): the split-call evasion, one violation per rule, the allowlist's
# own checks, and a positive with a listed site and a seed branch both written across lines.
near_misses dm-derivation-inputs dm-derivation/positive
evasion_count dm-derivation-inputs dm-derivation/negative-split-call 1
evasion_named dm-derivation-inputs "Leak.kt:11: SecretKeySpec( identityPublicKey, \"HmacSHA256\") is not on G-DM3's allowlist" \
  "reports an HMAC keyed by a public key, its call split across lines"
evasion_count dm-derivation-inputs dm-derivation/negative-rules 13
evasion_named dm-derivation-inputs "HkdfSite.kt:7: Hkdf.derive(ikm = cardPublicKey" "reports an unlisted KDF site"
evasion_named dm-derivation-inputs "RootFromRaw.kt:8: RootEntropy.fromRaw(publicKey) is not on" "reports a seed built from raw bytes"
evasion_named dm-derivation-inputs "BranchFromString.kt:7: deriveBranch called with something other than one DerivationLabels constant" "reports a seed branch under a String label"
evasion_named dm-derivation-inputs "LabelOutsideBranch.kt:7: a DerivationLabels constant outside RootEntropy.deriveBranch" "reports a seed label outside deriveBranch"
evasion_named dm-derivation-inputs "ExtensionBranch.kt:4: deriveBranch declared outside RootEntropy" "reports a second deriveBranch declaration"
evasion_named dm-derivation-inputs "NewLabel.kt:5: \"ghost/v1/dm/new-thing\": a DM label that is not on" "reports an unlisted DM label"
evasion_named dm-derivation-inputs "MovedLabel.kt:5: \"ghost/v1/dm/moved-here\": a DM label outside the DM modules" "reports a DM label outside the DM modules"
evasion_named dm-derivation-inputs "Twice.kt:10: SecretKeySpec(namespace, \"HmacSHA256\") found 2 times, the allowlist permits 1" "reports the first copy of a call allowed once"
evasion_named dm-derivation-inputs "Twice.kt:14: SecretKeySpec(namespace, \"HmacSHA256\") found 2 times" "reports the second copy too"
evasion_named dm-derivation-inputs "Renamed.kt:11: SecretKeySpec(key, \"HmacSHA256\"), but the file no longer holds the declaration" "reports a listed call whose key changed source"
evasion_named dm-derivation-inputs "stale site android/crypto-bridge/src/main/kotlin/org/ghost/crypto/bridge/Gone.kt" "reports a stale allowlist entry"
evasion_named dm-derivation-inputs "dm-derivation-inputs.allow:5: android/sync/src/main/kotlin/org/ghost/sync/MovedLabel.kt is outside the DM modules" "refuses an allowlist entry outside the DM modules"
evasion_named dm-derivation-inputs "dm-derivation-inputs.allow:6: malformed entry" "refuses a malformed allowlist entry"
# Phase 10, slice S3: the package of the channel stores is read like the rest of :messaging.
evasion_count dm-derivation-inputs dm-derivation/negative-channel-package 1
evasion_named dm-derivation-inputs "channel/store/ChannelLeak.kt:13: SecretKeySpec(channelId, \"HmacSHA256\") is not on G-DM3's allowlist" \
  "reports a MAC keyed by a channel identifier in the channel store package"
# Phase 10, slice S4: and the package of the channel engine, whose one listed site is the dedup tags' MAC (ChannelTags.kt).
evasion_count dm-derivation-inputs dm-derivation/negative-channel-engine 1
evasion_named dm-derivation-inputs "channel/engine/ChannelLeak.kt:13: SecretKeySpec(channelId, \"HmacSHA256\") is not on G-DM3's allowlist" \
  "reports a MAC keyed by a channel identifier in the channel engine package"
# Phase 11, slice S3: the media store is read like the DM modules (every media derivation lives in ghost-client-media).
evasion_count dm-derivation-inputs dm-derivation/negative-media-package 2
evasion_named dm-derivation-inputs "media/store/MediaLeak.kt:14: SecretKeySpec(objectId, \"HmacSHA256\") is not on G-DM3's allowlist" \
  "reports a MAC keyed by an object identifier in the media store package"
evasion_named dm-derivation-inputs "media/store/MediaLeak.kt:19: \"ghost/v1/media/fragment\": a DM label that is not on G-DM3's allowlist for this file" \
  "reports a media label in the media store package"
# The media module moved away (review of slice S3): messaging, crypto-bridge and identity meet the floor, so G-DM3 must fail for the
# missing module alone (the first version passed this tree).
evasion_count dm-derivation-inputs dm-derivation/negative-no-media 1
evasion_named dm-derivation-inputs "android/media/src/main: missing" "refuses a tree whose media module moved away"
if bash "$DIR/dm-derivation-inputs.sh" >/dev/null 2>&1; then
  echo "self-test ok: dm-derivation-inputs accepts the real DM modules against their allowlist"
else
  echo "SELF-TEST FAIL: dm-derivation-inputs rejects the real DM modules" >&2; rc=1
fi
# G-M3's script half (Phase 10 design faza10-forum.md §5.2 rule (1), §13.1; slice S2a): a positive with
# a declaration split over lines, one in a comment and one in a string, the two exports and the hint
# label in Kotlin; then one fixture per rule (test-harness/gates/ch-derivation/README.md).
near_misses ch-derivation-inputs ch-derivation/positive
evasion_count ch-derivation-inputs ch-derivation/raw-key 1
evasion_named ch-derivation-inputs "src/derive.rs:3: derive_bad takes \`&[u8]\` as its key input" "reports an untyped key input declared across lines"
evasion_count ch-derivation-inputs ch-derivation/public-elsewhere 1
evasion_named ch-derivation-inputs "src/derive.rs:4: derive_something_else takes the public OpenInviteSalt" "reports the open invite's public salt keying another derivation"
evasion_count ch-derivation-inputs ch-derivation/outside 2
evasion_named ch-derivation-inputs "src/seal.rs:2: derive_hidden is declared outside src/derive.rs" "reports a derivation declared outside the typed module"
evasion_named ch-derivation-inputs "src/seal.rs:3: HKDF outside src/derive.rs" "reports an HKDF outside the typed module, its path split over lines"
evasion_count ch-derivation-inputs ch-derivation/exporter 2
evasion_named ch-derivation-inputs "src/group.rs:3: export_secret with a label other than" "reports an export under another label"
evasion_named ch-derivation-inputs "src/kv.rs:2: export_secret outside src/group.rs" "reports an export outside group.rs"
evasion_count ch-derivation-inputs ch-derivation/kotlin 2
evasion_named ch-derivation-inputs "Channel.kt:3: a channel derivation label in Kotlin (\"ghost/v1/ch-seal\")" "reports a channel label in Kotlin and not the hint label"
# Rules 2 and 5 as the review of S2a (F6) extended them: an untyped helper, a second parameter as
# the key, a function a macro generates, HKDF by other names, and T36's own from_bytes scenario.
evasion_count ch-derivation-inputs ch-derivation/helper-untyped 1
evasion_named ch-derivation-inputs "src/derive.rs:12: HKDF (\`hkdf32\`) outside a derive_* function" "reports an HKDF helper keyed by untyped bytes"
evasion_count ch-derivation-inputs ch-derivation/second-param 1
evasion_named ch-derivation-inputs "src/derive.rs:12: derive_twice keys HKDF with \`ikm\`, not its first parameter \`k\`" "reports a derivation keyed by its second parameter"
evasion_count ch-derivation-inputs ch-derivation/macro 1
evasion_named ch-derivation-inputs "src/derive.rs:14: HKDF (\`hkdf32\`) outside a derive_* function" "reports a derivation a macro generates"
evasion_count ch-derivation-inputs ch-derivation/other-names 2
evasion_named ch-derivation-inputs "src/seal.rs:3: HKDF outside src/derive.rs" "reports SimpleHkdf outside the typed module"
evasion_named ch-derivation-inputs "src/group.rs:3: HKDF outside src/derive.rs" "reports the provider's hkdf_expand outside the typed module"
evasion_count ch-derivation-inputs ch-derivation/from-bytes 1
evasion_named ch-derivation-inputs "src/seal.rs: EpochExport::from_bytes at 1 site(s), typed-key-sites.txt pins 0" "reports a typed key built from a channel id (T36)"
if bash "$DIR/ch-derivation-inputs.sh" >/dev/null 2>&1; then
  echo "self-test ok: ch-derivation-inputs accepts the real channel crate"
else
  echo "SELF-TEST FAIL: ch-derivation-inputs rejects the real channel crate" >&2; rc=1
fi

# G-R3 (ADR-36): the portable-libcrux detector over build outputs. A host build's JSON stream
# (portable with a decoy package, SIMD on all three packages, one package missing) and a cargo-ndk
# profile directory (portable with a decoy, SIMD in both directive syntaxes, a stale second run, no
# libcrux at all). It reads files only, so it runs here; the CI jobs run it on their real builds.
LCX="$HARNESS/libcrux-portable"
lcx_case() { # $1 = expect pass|fail, $2 = expected violation count, $3 = expected text, $4 = description, rest = args
  local want="$1" count="$2" text="$3" desc="$4" out got hits
  shift 4
  if out="$(bash "$DIR/libcrux-portable.sh" "$@" 2>&1)"; then got=pass; else got=fail; fi
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$got" = "$want" ] && [ "$hits" = "$count" ] && grep -qF "$text" <<<"$out"; then
    echo "self-test ok: libcrux-portable $desc"
  else
    echo "SELF-TEST FAIL: libcrux-portable $desc ($got, $hits of $count violations)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
lcx_case pass 0 "[libcrux-portable] OK" "accepts a portable host build and ignores a longer package name" --json "$LCX/portable.json"
lcx_case fail 3 "libcrux-intrinsics enabled SIMD code" "rejects SIMD cfgs in a host build" --json "$LCX/simd.json"
lcx_case fail 1 "no build-script-executed message of libcrux-intrinsics" "refuses a host build without one of the packages" --json "$LCX/missing.json"
lcx_case pass 0 "[libcrux-portable] OK" "accepts a portable cargo-ndk profile directory" --target-dir "$LCX/dir-portable"
lcx_case fail 2 "libcrux-sha3-0123456789abcdef/output:1:cargo::rustc-cfg" "rejects SIMD cfgs in both directive syntaxes" --target-dir "$LCX/dir-simd"
lcx_case fail 1 "a stale run the libcrux clean did not remove" "refuses two build script runs of one package" --target-dir "$LCX/dir-stale"
lcx_case fail 3 "no build script output of libcrux-ml-kem" "refuses a directory with no libcrux build" --target-dir "$LCX/dir-empty"
lcx_case fail 2 "dir-simd" "checks every build it is given" --json "$LCX/portable.json" --target-dir "$LCX/dir-simd"
lcx_case pass 0 "[libcrux-portable] OK" "accepts workspace path package ids (upstream's layout, §22.35)" --json "$LCX/portable-path.json"
lcx_case fail 1 "libcrux-ml-kem enabled SIMD code" "rejects SIMD cfgs under a path package id" --json "$LCX/simd-path.json"
# G-M9 (Phase 10 design §13.1, S0-8, V10-7; slice S2a): libcrux-aes joins the rule wherever it was
# built, and `--with-aes` requires it (the builds that compile the OpenMLS provider say so).
lcx_case pass 0 "[libcrux-portable] OK" "accepts a portable build with libcrux-aes and ignores libcrux-aesgcm (G-M9)" --with-aes --json "$LCX/aes-portable.json"
lcx_case fail 1 "no build-script-executed message of libcrux-aes" "refuses a host build without libcrux-aes under --with-aes (G-M9)" --with-aes --json "$LCX/portable.json"
lcx_case fail 1 "libcrux-aes enabled SIMD code" "rejects SIMD cfgs in libcrux-aes, --with-aes or not (G-M9)" --json "$LCX/aes-simd.json"
lcx_case fail 1 "libcrux-aes-0123456789abcdef/output:2:cargo:rustc-cfg" "rejects SIMD cfgs in libcrux-aes's build script output (G-M9)" --target-dir "$LCX/dir-aes-simd"
lcx_case fail 1 "no build script output of libcrux-aes" "refuses a profile directory without libcrux-aes under --with-aes (G-M9)" --with-aes --target-dir "$LCX/dir-portable"

# G-R7 (c) (§2.9, V-9): the shipped library carries Olm's KDF labels and none of the HPKE strings
# the linker drops. Byte files stand in for stripped libraries (test-harness/gates/dm-golden/).
DMG="$HARNESS/dm-golden"
dmg_lib_case() { # $1 = expect pass|fail, $2 = expected violation count, $3 = expected text, $4 = description, $5 = file
  local out got hits
  if out="$(bash "$DIR/dm-golden-lock.sh" --library "$DMG/$5" 2>&1)"; then got=pass; else got=fail; fi
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$got" = "$1" ] && [ "$hits" = "$2" ] && grep -qF "$3" <<<"$out"; then
    echo "self-test ok: dm-golden-lock $4"
  else
    echo "SELF-TEST FAIL: dm-golden-lock $4 ($got, $hits of $2 violations)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
dmg_lib_case pass 0 "[dm-golden-lock] OK" "accepts a library with Olm and without HPKE" hpke-dropped.bin
dmg_lib_case fail 2 "contains 'HPKEXXYYZZ'" "rejects a library the linker left RustCrypto's hpke and vodozemac's HPKE in" hpke-linked.bin
# Phase 10 slice S2b (faza10-forum.md §19.32): OpenMLS's HPKE (hpke-rs) is linked on purpose and its
# RFC 9180 labels no longer count as RustCrypto's hpke.
dmg_lib_case pass 0 "[dm-golden-lock] OK" "accepts OpenMLS's hpke-rs labels (HPKE-v1, psk_id_hash) beside Olm" hpke-rs-linked.bin
dmg_lib_case fail 2 "does not contain 'OLM_KEYS'" "refuses a library with no Olm code" no-olm.bin
# `--library` is the whole of its mode and reads no git base: the `android-native` job's checkout is
# shallow, and the first CI run fell through to the pin rule after "OK" (design §22.33 item 18). A
# base that cannot be read must not matter; with a full clone the fall-through passed unnoticed.
if dmg_out="$(env GHOST_GOLDEN_BASE=no-such-revision bash "$DIR/dm-golden-lock.sh" --library "$DMG/hpke-dropped.bin" 2>&1)" \
   && [ "$(grep -c '^GATE-FAIL' <<<"$dmg_out" || true)" = 0 ]; then
  echo "self-test ok: dm-golden-lock --library stops at the library check and reads no base"
else
  echo "SELF-TEST FAIL: dm-golden-lock --library went on to the pin rule" >&2
  printf '%s\n' "$dmg_out" | tail -3 >&2; rc=1
fi

# G-M6 (Phase 10 design faza10-forum.md §10.2, §13.1; slice S2b): the channel JNI surface is a
# closed list — G-R6's halves for `MlsNative`, its one test entry (`MlsVectors.run`) only in a
# test library, and one list of allowed classes shared with G-R6. S2b reserved function 16 for
# slice S9; S9 exported it (revealSeal/revealOpen), so the negative library fixture now exports
# a function beyond the list's maximum instead (review of S9, the self-test's fixture fix).
MLS_JNI="$HARNESS/mls-jni"
if env GHOST_MLS_JNI_SOURCE="$MLS_JNI/good.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeSmall.kt" \
     GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh" >/dev/null 2>&1; then
  echo "self-test ok: mls-jni-surface accepts a closed list whose entry points and declarations agree"
else
  echo "SELF-TEST FAIL: mls-jni-surface rejects the good fixture" >&2; rc=1
fi
expect_fail_msg "mls-jni-surface rejects an export outside the closed list" \
  "the workspace exports 'MlsNative.debugDump', which is not on the closed list" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/undeclared-export.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeSmall.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects function 16 written before slice S9" \
  "'MlsNative.revealSeal' is reserved on the closed list (a later slice's: Declared) but the workspace already writes its entry point" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/early-reveal.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeSmall.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects an Exported entry with no entry point" \
  "'MlsNative.ctxClose' is marked Exported on the closed list but the workspace writes no entry point for it" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/missing-export.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeSmall.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects a Kotlin declaration the crate does not export" \
  "MlsNative declares 'external fun debugDump', which the crate does not export" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/good.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeExtra.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects a Kotlin declaration of the reserved function 16" \
  "MlsNative declares 'external fun revealSeal', which is reserved for a later slice" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/good.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeReveal.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects a public native declaration" \
  "it must be internal" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/good.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativePublic.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects an internal declaration Kotlin would mangle" \
  "would mangle the JNI name" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/good.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeMangled.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects a missing Kotlin declaration" \
  "MlsNative does not declare 'external fun ctxClose'" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/good.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeMissing.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects an MlsNative entry point written outside the closed list's file" \
  "the workspace exports 'MlsNative.debugDump'" \
  env GHOST_MLS_JNI_SCAN="$MLS_JNI/stray" GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects a JNI entry point of a class no surface gate knows" \
  "the workspace exports the JNI entry point 'Java_org_ghost_crypto_bridge_MlsDebug_dump'" \
  env GHOST_MLS_JNI_SCAN="$MLS_JNI/foreign" GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
# Review of S2b. The source halves read code, not one spelling (common.sh jni_source_symbols): every
# MlsNative name of mls-jni/evasions/ is reported — `pub unsafe extern "system"`, no `pub`, `extern
# "C"`, a line break after `fn`, an `export_name` a macro argument writes, module directories named
# `target` and `build` under `src/` — with the foreign class a macro exports, and neither the name in
# a comment nor the build output outside `src/`. G-R6 reads the same files the same way.
mls_ev_out="$(env GHOST_MLS_JNI_SCAN="$MLS_JNI/evasions" GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh" 2>&1 || true)"
mls_ev_missing=""
for name in debugUnsafe debugPrivate debugC debugSplit debugMacro debugTarget debugBuild; do
  grep -qF "the workspace exports 'MlsNative.$name', which is not on the closed list" <<<"$mls_ev_out" || mls_ev_missing+="$name "
done
if [ -z "$mls_ev_missing" ] && [ "$(grep -c '^GATE-FAIL' <<<"$mls_ev_out" || true)" = "8" ] \
   && grep -qF "the workspace exports the JNI entry point 'Java_org_ghost_crypto_bridge_DmDebug_dump'" <<<"$mls_ev_out" \
   && ! grep -qE 'debugComment|debugOutput' <<<"$mls_ev_out"; then
  echo "self-test ok: mls-jni-surface reads every spelling of an entry point rustc exports, and no comment or build output"
else
  echo "SELF-TEST FAIL: mls-jni-surface does not report exactly the eight entry points of mls-jni/evasions/ (missing: ${mls_ev_missing:-none})" >&2
  printf '%s\n' "$mls_ev_out" | grep '^GATE-FAIL' >&2; rc=1
fi
dm_ev_out="$(env GHOST_DM_JNI_SCAN="$MLS_JNI/evasions" bash "$DIR/dm-jni-surface.sh" 2>&1 || true)"
if grep -qF "the crate exports 'debugDm', which is not on the closed list" <<<"$dm_ev_out" \
   && grep -qF "the workspace exports the JNI entry point 'Java_org_ghost_crypto_bridge_DmDebug_dump'" <<<"$dm_ev_out" \
   && ! grep -qE 'debugComment|debugOutput' <<<"$dm_ev_out"; then
  echo "self-test ok: dm-jni-surface reads the same spellings (a DmNative entry point in src/target/, a foreign class a macro exports)"
else
  echo "SELF-TEST FAIL: dm-jni-surface misses an entry point of mls-jni/evasions/" >&2
  printf '%s\n' "$dm_ev_out" | grep '^GATE-FAIL' >&2; rc=1
fi
# Phase 11 S0: `spikes/` directly under the scan root is evidence tooling (its crash probe exports a
# `Java_…` symbol on purpose); the same export anywhere else — `client-core/spikes/` included — is
# still a JNI entry point of the workspace. Both source halves, one fixture each.
SPIKES="$HARNESS/jni-spikes"
if env GHOST_DM_JNI_SCAN="$SPIKES/exempt" bash "$DIR/dm-jni-surface.sh" >/dev/null 2>&1; then
  echo "self-test ok: dm-jni-surface does not read the spikes/ evidence tooling"
else
  echo "SELF-TEST FAIL: dm-jni-surface rejects an export under spikes/" >&2; rc=1
fi
if env GHOST_MLS_JNI_SCAN="$SPIKES/exempt" GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" \
     bash "$DIR/mls-jni-surface.sh" >/dev/null 2>&1; then
  echo "self-test ok: mls-jni-surface does not read the spikes/ evidence tooling"
else
  echo "SELF-TEST FAIL: mls-jni-surface rejects an export under spikes/" >&2; rc=1
fi
expect_fail_msg "dm-jni-surface still reports the same export outside the one exempt path" \
  "the workspace exports the JNI entry point 'Java_org_ghost_spike_media_NativeCrash_crashIn'" \
  env GHOST_DM_JNI_SCAN="$SPIKES/nested" bash "$DIR/dm-jni-surface.sh"
expect_fail_msg "mls-jni-surface still reports the same export outside the one exempt path" \
  "the workspace exports the JNI entry point 'Java_org_ghost_spike_media_NativeCrash_crashIn'" \
  env GHOST_MLS_JNI_SCAN="$SPIKES/nested" GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
# A closed list with no reserved entry (slice S9 exports function 16): an empty selection ended the
# gate with no message under pipefail.
if env GHOST_MLS_JNI_SOURCE="$MLS_JNI/all-exported.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeSmall.kt" \
     GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh" >/dev/null 2>&1; then
  echo "self-test ok: mls-jni-surface accepts a closed list with no reserved entry"
else
  echo "SELF-TEST FAIL: mls-jni-surface rejects a closed list with no reserved entry" >&2; rc=1
fi
# JNI binds by name: the declarations' parameter types are the entry points' (review of S2b).
expect_fail_msg "mls-jni-surface rejects a declaration whose parameter types are not its entry point's" \
  "MlsNative.ctxClose: Kotlin declares (I), its entry point takes (J)" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/good.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeRetyped.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "mls-jni-surface rejects a public declaration on its @JvmName's line" \
  "MlsNative declares 'external fun ctxOpen' outside the module: it must be internal" \
  env GHOST_MLS_JNI_SOURCE="$MLS_JNI/good.rs" GHOST_MLS_JNI_KOTLIN="$MLS_JNI/MlsNativeOneLine.kt" \
  GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh"
expect_fail_msg "dm-jni-surface rejects a public declaration on its @JvmName's line" \
  "DmNative declares 'external fun ctxOpen' outside the module: it must be internal" \
  env GHOST_DM_JNI_KOTLIN="$HARNESS/dm-jni/DmNativeOneLine.kt" bash "$DIR/dm-jni-surface.sh"
mls_native_out="$(env GHOST_MLS_JNI_ANDROID="$MLS_JNI/android-native" bash "$DIR/mls-jni-surface.sh" 2>&1 || true)"
if [ "$(grep -c '^GATE-FAIL' <<<"$mls_native_out" || true)" = "2" ] \
   && grep -qF "MlsDebug.kt:8: declares a native method outside MlsNative" <<<"$mls_native_out" \
   && grep -qF "ChannelLeak.java:6: declares a native method outside MlsNative" <<<"$mls_native_out"; then
  echo "self-test ok: mls-jni-surface reports native methods outside the allowed files (Kotlin and Java, comments skipped)"
else
  echo "SELF-TEST FAIL: mls-jni-surface does not report exactly the two native declarations of mls-jni/android-native/" >&2
  printf '%s\n' "$mls_native_out" | tail -4 >&2; rc=1
fi
mls_ref_out="$(env GHOST_MLS_JNI_ANDROID="$MLS_JNI/android-ref" bash "$DIR/mls-jni-surface.sh" 2>&1 || true)"
if [ "$(grep -c '^GATE-FAIL' <<<"$mls_ref_out" || true)" = "2" ] \
   && grep -qF "ChannelShortcut.kt:9: references MlsNative outside :crypto-bridge src/main" <<<"$mls_ref_out" \
   && grep -qF "GateChannel.kt:5: references MlsNative outside :crypto-bridge src/main" <<<"$mls_ref_out"; then
  echo "self-test ok: mls-jni-surface reports MlsNative referenced outside :crypto-bridge src/main (code, not prose)"
else
  echo "SELF-TEST FAIL: mls-jni-surface does not report exactly the two code references to MlsNative" >&2
  printf '%s\n' "$mls_ref_out" | tail -4 >&2; rc=1
fi
expect_fail_msg "mls-jni-surface rejects a library that was named but is not there" \
  "library not found" env GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh" "$MLS_JNI/no-such-library.so"
mls_elf="$(mktemp)"
printf '\177ELF G-M6 fixture: the symbols come from GHOST_MLS_JNI_NM\n' > "$mls_elf"
mls_lib_case() { # $1 = expect pass|fail, $2 = expected text ("" for pass), $3 = description, $4 = reader, rest = gate arguments
  local want="$1" text="$2" desc="$3" reader="$4" out got
  shift 4
  if out="$(env GHOST_MLS_JNI_NM="$MLS_JNI/nm/$reader" GHOST_MLS_JNI_ANDROID="$MLS_JNI/no-such-tree" bash "$DIR/mls-jni-surface.sh" "$@" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" = "$want" ] && { [ -z "$text" ] || grep -qF "$text" <<<"$out"; }; then
    echo "self-test ok: mls-jni-surface $desc"
  else
    echo "SELF-TEST FAIL: mls-jni-surface $desc ($got)" >&2; printf '%s\n' "$out" | tail -4 >&2; rc=1
  fi
}
mls_lib_case pass "" "accepts a shipped library whose symbols are exactly the closed list's Exported entries" exact-nm "$mls_elf"
mls_lib_case pass "" "accepts a test library with exactly its one test entry point" entry-nm --test "$mls_elf"
mls_lib_case fail "exports 'MlsNative.debugDump', which is not on the closed list" "rejects a library exporting a symbol outside the closed list" stray-nm "$mls_elf"
mls_lib_case fail "does not export 'MlsNative.trialCount'" "rejects a library that does not export an Exported entry" missing-nm "$mls_elf"
mls_lib_case fail "exports 'MlsNative.revealVerify', which is not on the closed list" "rejects a library exporting a function beyond the closed list's maximum (function 16 is S9's, exported; a would-be next function is still unlisted)" reveal-nm "$mls_elf"
mls_lib_case fail "exports the test entry point 'MlsVectors.run': a shipped library never carries it" "rejects the test entry point in a shipped library" entry-nm "$mls_elf"
mls_lib_case fail "does not export the test entry point 'MlsVectors.run'" "rejects a test library without its test entry point" exact-nm --test "$mls_elf"
mls_lib_case fail "exports 'MlsVectors.dumpState', which is not its one test entry point" "rejects a test library with a second test entry" entry-extra-nm --test "$mls_elf"
mls_lib_case fail "exports the JNI symbol 'Java_org_ghost_crypto_bridge_MlsDebug_dump'" "rejects a library exporting a JNI symbol of another class" foreign-nm "$mls_elf"
mls_lib_case fail "could not read" "rejects a symbol reader that cannot read the library" unreadable-nm "$mls_elf"
# The two surface gates agree (one class list, common.sh GHOST_JNI_CLASSES): a shipped library with
# both closed surfaces passes both, and a foreign class fails both.
mls_lib_case pass "" "accepts a library carrying both closed surfaces" both-nm "$mls_elf"
if env GHOST_DM_JNI_NM="$MLS_JNI/nm/both-nm" bash "$DIR/dm-jni-surface.sh" "$mls_elf" >/dev/null 2>&1; then
  echo "self-test ok: dm-jni-surface accepts a library carrying both closed surfaces (the gates agree)"
else
  echo "SELF-TEST FAIL: dm-jni-surface rejects a library carrying both closed surfaces" >&2; rc=1
fi
expect_fail_msg "dm-jni-surface rejects the channel gate's foreign class too" \
  "exports the JNI symbol 'Java_org_ghost_crypto_bridge_MlsDebug_dump'" \
  env GHOST_DM_JNI_NM="$MLS_JNI/nm/foreign-nm" bash "$DIR/dm-jni-surface.sh" "$mls_elf"
rm -f "$mls_elf"

# dm-fuzz and the libcrux suites (Phase 9 design §16.2 `dm-fuzz` and `vendor-tests`, §22.35): the
# decisions the nightly jobs apply to a libFuzzer run and to a crate's own `cargo test` suite, over
# logs with one failure each (test-harness/gates/dm-fuzz/, test-harness/gates/vendor-tests/).
FUZZV="$HARNESS/dm-fuzz"
verdict_case() { # $1 = script, $2 = flag, $3 = expect pass|fail, $4 = expected verdict, $5 = description, $6 = log, $7 = exit code
  local out got
  if out="$(bash "$DIR/../ci/$1" "$2" "$6" "$7" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" = "$3" ] && [ "$out" = "$4" ]; then
    echo "self-test ok: $1 $5"
  else
    echo "SELF-TEST FAIL: $1 $5 ($got: $out)" >&2; rc=1
  fi
}
verdict_case dm-fuzz.sh --verdict pass "PASS 503141" "accepts a clean run" "$FUZZV/pass.txt" 0
verdict_case dm-fuzz.sh --verdict fail "FAIL exit 1" "rejects a clean log from a run that exited non-zero" "$FUZZV/pass.txt" 1
verdict_case dm-fuzz.sh --verdict fail "FAIL crash" "rejects a panic (deadly signal)" "$FUZZV/crash.txt" 1
verdict_case dm-fuzz.sh --verdict fail "FAIL crash" "rejects an AddressSanitizer report" "$FUZZV/asan.txt" 1
verdict_case dm-fuzz.sh --verdict fail "FAIL timeout" "rejects a timeout" "$FUZZV/timeout.txt" 70
verdict_case dm-fuzz.sh --verdict fail "FAIL out-of-memory" "rejects an out-of-memory" "$FUZZV/oom.txt" 71
verdict_case dm-fuzz.sh --verdict fail "FAIL zero executions" "rejects a run that executed nothing" "$FUZZV/zero.txt" 0
verdict_case dm-fuzz.sh --verdict fail "FAIL no statistics (the run did not finish: exit 137)" "rejects a run killed before its statistics" "$FUZZV/truncated.txt" 137
VTV="$HARNESS/vendor-tests"
verdict_case vendor-tests.sh --suite-verdict pass "PASS 3" "accepts a suite and sums its binaries and doc-tests" "$VTV/suite-pass.txt" 0
verdict_case vendor-tests.sh --suite-verdict fail "FAIL exit 101" "rejects a passing log from a run that exited non-zero" "$VTV/suite-pass.txt" 101
verdict_case vendor-tests.sh --suite-verdict fail "FAIL a test failed" "rejects a failed test" "$VTV/suite-failed.txt" 101
verdict_case vendor-tests.sh --suite-verdict fail "FAIL zero tests ran" "rejects a suite that runs no test" "$VTV/suite-zero.txt" 0
verdict_case vendor-tests.sh --suite-verdict fail "FAIL the suite did not build" "rejects a suite that does not build" "$VTV/suite-build-error.txt" 101
# The GHSA watch of G-M1 (Phase 10 design §13.1, §13.2, S0-2; slice S2a), offline: GitHub advisories
# and a RustSec checkout from test-harness/gates/mls-advisories/ over a fixture lock. Fixed advisories
# and a draft pass, a former-name entry passes only while the reviewed list accounts for it, and an
# open range fails, under the current name and under the former one.
ADV="$HARNESS/mls-advisories"
adv_case() { # $1 = expect pass|fail, $2 = expected text, $3 = description, $4 = GHSA dir, $5 = reviewed list
  local out got
  if out="$(GHOST_ADV_LOCK="$ADV/lock.toml" GHOST_ADV_RUSTSEC_DIR="$ADV/clean/rustsec" GHOST_ADV_GHSA_DIR="$4" \
      GHOST_ADV_REVIEWED="$5" bash "$DIR/../ci/mls-advisories.sh" "$(mktemp -d)" 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" = "$1" ] && grep -qF -- "$2" <<<"$out"; then
    echo "self-test ok: mls-advisories $3"
  else
    echo "SELF-TEST FAIL: mls-advisories $3 ($got)" >&2; printf '%s\n' "$out" | tail -4 >&2; rc=1
  fi
}
if command -v perl >/dev/null && perl -MJSON::PP -e 1 2>/dev/null; then
  adv_case pass "reviewed: RUSTSEC-2026-0209 libcrux-aes 0.0.9 (RustSec crates/libcrux-aesgcm)" \
    "accepts fixed advisories, a draft, and a reviewed entry under a former name" "$ADV/clean/ghsa" "$ADV/clean/reviewed.txt"
  adv_case fail "ADVISORY: RUSTSEC-2026-0209 libcrux-aes 0.0.9 (RustSec crates/libcrux-aesgcm)" \
    "reads RustSec under a former name and refuses an entry nobody reviewed" "$ADV/clean/ghsa" "$ADV/empty-reviewed.txt"
  adv_case fail "ADVISORY: GHSA-fixt-ure0-0004 openmls 0.9.0" \
    "refuses a GitHub advisory whose range contains the pin" "$ADV/open-ghsa/ghsa" "$ADV/clean/reviewed.txt"
  adv_case fail "ADVISORY: GHSA-fixt-ure0-0005 libcrux-aes 0.0.9" \
    "maps a GitHub advisory under a former name to the pinned crate" "$ADV/former-ghsa/ghsa" "$ADV/clean/reviewed.txt"
else
  echo "SELF-TEST FAIL: perl with JSON::PP missing; the GHSA watch is not proven" >&2; rc=1
fi

# G-DM5 (Phase 9 design §16.1, §21.13 points 5 and 7; slice S12): each source tree and each mapping
# fixture reports exactly its own violations, the positive mapping passes, and the real tree passes.
DMH="$HARNESS/dm-hooks"
dmhooks_case() { # $1 = description, $2 = expected count, $3 = expected text, rest = env and args
  local desc="$1" want="$2" text="$3" out hits
  shift 3
  out="$(env "$@" 2>&1 || true)"
  hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
  if [ "$hits" = "$want" ] && grep -qF "$text" <<<"$out"; then
    echo "self-test ok: apk-no-debug-hooks $desc"
  else
    echo "SELF-TEST FAIL: apk-no-debug-hooks $desc (reported $hits of $want)" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  fi
}
dmhooks_case "refuses a release source set that reaches the key-change hook" 2 "names a debug-only class" \
  GHOST_ROOT="$DMH/release-ref" GHOST_DM_HOOKS_MIN_SOURCES=1 bash "$DIR/apk-no-debug-hooks.sh"
dmhooks_case "refuses a harness package in a release source set" 1 "declares a harness or gate package" \
  GHOST_ROOT="$DMH/harness-package" GHOST_DM_HOOKS_MIN_SOURCES=1 bash "$DIR/apk-no-debug-hooks.sh"
dmhooks_case "refuses the equivalence entry point in a release source set" 1 "declares the equivalence-test entry point" \
  GHOST_ROOT="$DMH/equivalence" GHOST_DM_HOOKS_MIN_SOURCES=1 bash "$DIR/apk-no-debug-hooks.sh"
dmhooks_case "refuses a tree without the gate build type" 1 "the gate build type is missing" \
  GHOST_ROOT="$DMH/no-gate" GHOST_DM_HOOKS_MIN_SOURCES=1 bash "$DIR/apk-no-debug-hooks.sh"
dmhooks_case "refuses a build script that adds a directory to a release source set" 2 "adds a directory to a release source set" \
  GHOST_ROOT="$DMH/srcdir" GHOST_DM_HOOKS_MIN_SOURCES=1 bash "$DIR/apk-no-debug-hooks.sh"
dmhooks_case "reads annotated declarations and code after a block comment, and exempts a build-type twin" 3 "names a debug-only class" \
  GHOST_ROOT="$DMH/declarations" GHOST_DM_HOOKS_MIN_SOURCES=1 bash "$DIR/apk-no-debug-hooks.sh"
dmhooks_case "refuses the device runner (src/deviceRunner) in mapping.txt" 1 "ships the debug-only class org.ghost.device.DeviceRunner" \
  bash "$DIR/apk-no-debug-hooks.sh" "$DMH/mapping/device-runner.txt"
dmhooks_case "refuses a renamed org.ghost. class in mapping.txt" 1 "maps to itself" \
  bash "$DIR/apk-no-debug-hooks.sh" "$DMH/mapping/renamed.txt"
dmhooks_case "refuses the key-change hook and a gate lambda in mapping.txt" 2 "ships the debug-only class" \
  bash "$DIR/apk-no-debug-hooks.sh" "$DMH/mapping/debug-class.txt"
dmhooks_case "refuses a harness class in mapping.txt" 1 "from a harness or gate package" \
  bash "$DIR/apk-no-debug-hooks.sh" "$DMH/mapping/harness.txt"
dmhooks_case "refuses the equivalence entry point in mapping.txt" 1 "ships the equivalence-test entry point" \
  bash "$DIR/apk-no-debug-hooks.sh" "$DMH/mapping/entry.txt"
dmhooks_case "refuses the channel vector replay's test entry point (MlsVectors) in mapping.txt (Phase 10 S2b)" 1 "ships the vector-replay test entry point org.ghost.crypto.bridge.MlsVectors" \
  bash "$DIR/apk-no-debug-hooks.sh" "$DMH/mapping/mls-vectors.txt"
dmhooks_case "refuses a mapping without an org.ghost. class" 1 "lists no org.ghost. class" \
  bash "$DIR/apk-no-debug-hooks.sh" "$DMH/mapping/no-ghost.txt"
if bash "$DIR/apk-no-debug-hooks.sh" "$DMH/mapping/positive.txt" >/dev/null 2>&1; then
  echo "self-test ok: apk-no-debug-hooks accepts the real tree and a -keepnames mapping"
else
  echo "SELF-TEST FAIL: apk-no-debug-hooks rejects the real tree or a -keepnames mapping" >&2; rc=1
fi

if command -v cargo >/dev/null; then
  tmp="$(mktemp)"
  grep -vx "tokio" "$DIR/../../client-core/rust-dependency-allowlist.txt" > "$tmp"
  expect_fail_msg "rust-client-allowlist rejects an unlisted package" "Rust package 'tokio'" \
    env GHOST_RUST_ALLOWLIST="$tmp" bash "$DIR/rust-client-allowlist.sh"
  rm -f "$tmp"
  expect_fail_msg "rust-feature-policy rejects a missing required feature" \
    "arti-client feature 'pt-client' must be enabled" \
    env GHOST_POLICY_REQUIRE_EXTRA=pt-client bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy rejects an enabled forbidden feature" \
    "arti-client feature 'tokio' is enabled without an ADR" \
    env GHOST_POLICY_FORBID_EXTRA=tokio bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy rejects a forbidden feature on a secondary crate" \
    "tor-proto feature 'hs-client' is enabled in the client" \
    env GHOST_POLICY_FORBID_ON=tor-proto:hs-client bash "$DIR/rust-feature-policy.sh"
  # G-R2's DM clauses (Phase 9 design §16.1; review round 2, R2-03). The vodozemac pairs live in
  # the same `forbid_on` loop as the Arti ones and no vodozemac feature is enabled in the shipped
  # graph — which is the point of the gate — so the loop is drilled here on a DM crate whose
  # feature really is on, and the two clauses that can fail on their own get a fixture each.
  expect_fail_msg "rust-feature-policy rejects a forbidden feature on a DM crate" \
    "ghost-client-dm feature 'jni-bridge' is enabled in the client" \
    env GHOST_POLICY_FORBID_ON=ghost-client-dm:jni-bridge bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy rejects a ghost-client-dm feature outside G-R2's list" \
    "G-R2 allows: default" \
    env GHOST_POLICY_DM_FORBID_EXTRA=jni-bridge bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy rejects a shipped graph without the Olm library" \
    "is not in the shipped client graph" \
    env GHOST_POLICY_DM_GRAPH="vodozemac-no-such-crate" bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy fails when a secondary cargo query fails" \
    "GATE-FAIL: cargo tree" \
    env GHOST_POLICY_BAD_SPEC=tor-hsclient bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy rejects a non-Arti rsa 0.9.10 dependent" \
    "'ssh-key-fork-arti' depends on rsa 0.9.10 directly" \
    env GHOST_POLICY_RSA_ALLOWED="tor-llcrypto tor-key-forge" bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy rejects an rsa 0.10.0-rc.18 dependent other than the signer" \
    "'blind-rsa-signatures' depends on rsa 0.10.0-rc.18 directly" \
    env GHOST_POLICY_RSA10_ALLOWED="none" bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy rejects an issuer-only package in the client graph" \
    "package 'num-bigint-dig' is linked into ghost-client-net (aarch64-linux-android)" \
    env GHOST_POLICY_ISSUER_ONLY_EXTRA=num-bigint-dig bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "rust-feature-policy rejects an issuer-only package in the relay graph" \
    "package 'redb' is linked into ghost-relay-node" \
    env GHOST_POLICY_ISSUER_ONLY_EXTRA=redb bash "$DIR/rust-feature-policy.sh"
  # Crypto pins: a mutated copy of Cargo.lock (a second rsa 0.9 version), a mutated pins file (a
  # version drift in one graph, a required crate missing from a graph).
  tmp="$(mktemp)"
  awk 'prev == "name = \"rsa\"" && $0 == "version = \"0.9.10\"" {$0 = "version = \"0.9.9\""} {print; prev = $0}' \
    "$DIR/../../Cargo.lock" > "$tmp"
  expect_fail_msg "rust-crypto-pins rejects a mutated Cargo.lock" "Cargo.lock holds rsa [0.10.0-rc.18 0.9.9]" \
    env GHOST_CRYPTO_PINS_LOCK="$tmp" bash "$DIR/rust-crypto-pins.sh"
  sed 's/^\(graph ghost-client-net .* ring\) 0\.17\.14 required$/\1 0.17.13 required/' \
    "$DIR/rust-crypto-pins.txt" > "$tmp"
  expect_fail_msg "rust-crypto-pins rejects a version drift in one graph" \
    "ghost-client-net (aarch64-linux-android,x86_64-linux-android): ring resolves to [0.17.14], pinned 0.17.13" \
    env GHOST_CRYPTO_PINS="$tmp" bash "$DIR/rust-crypto-pins.sh"
  { cat "$DIR/rust-crypto-pins.txt"; echo "graph ghost-relay-node all blind-rsa-signatures 0.17.2 required"; } > "$tmp"
  expect_fail_msg "rust-crypto-pins rejects a required crate missing from a graph" \
    "ghost-relay-node (all): blind-rsa-signatures is missing" \
    env GHOST_CRYPTO_PINS="$tmp" bash "$DIR/rust-crypto-pins.sh"
  # Version sets (Phase 9 design §22.8.10 point 5, slice S4b): a `graph` line may name several
  # versions of one crate, and the gate must still refuse a set that is missing a member the graph
  # actually resolves to (here the vodozemac dalek major dropped from ghost-client-dm's pin).
  sed 's/^\(graph ghost-client-dm all ed25519-dalek\) 2\.2\.0,3\.0\.0 required$/\1 2.2.0 required/' \
    "$DIR/rust-crypto-pins.txt" > "$tmp"
  expect_fail_msg "rust-crypto-pins rejects an incomplete version set" \
    "ghost-client-dm (all): ed25519-dalek resolves to [2.2.0 3.0.0], pinned 2.2.0" \
    env GHOST_CRYPTO_PINS="$tmp" bash "$DIR/rust-crypto-pins.sh"
  rm -f "$tmp"
  # G-R7 (§2.8, §15.2 items 2 and 4, §22.33): the pin rule. Base and current locks are mutated copies
  # of the real one: a vodozemac bump whose previous goldens are gone, two vodozemac versions at once,
  # a pin without its golden directory and an unreadable base fail; the first pin is exempt; and a
  # libcrux change runs the drills (goldens, UpgradeTest, the encoder check, PQ5), which must pass.
  tmp="$(mktemp)"
  awk 'prev == "name = \"vodozemac\"" && $0 == "version = \"0.11.0\"" {$0 = "version = \"0.10.0\""} {print; prev = $0}' \
    "$DIR/../../Cargo.lock" > "$tmp"
  expect_fail_msg "dm-golden-lock rejects a vodozemac bump that dropped the previous goldens" \
    "vodozemac 0.10.0 -> 0.11.0: the previous pin's goldens" \
    env GHOST_GOLDEN_NO_TESTS=1 GHOST_GOLDEN_BASE_LOCK="$tmp" bash "$DIR/dm-golden-lock.sh"
  awk '{print} $0 == "name = \"vodozemac\"" && !done {getline v; print "version = \"0.10.0\""; print ""; print "[[package]]"; print "name = \"vodozemac\""; print v; done = 1}' \
    "$DIR/../../Cargo.lock" > "$tmp"
  expect_fail_msg "dm-golden-lock rejects two vodozemac versions in one lock" \
    "the lock holds several vodozemac versions" \
    env GHOST_GOLDEN_NO_TESTS=1 GHOST_GOLDEN_LOCK="$tmp" bash "$DIR/dm-golden-lock.sh" --base none
  dmg_empty="$(mktemp -d)"
  expect_fail_msg "dm-golden-lock rejects a pin without its golden directory" \
    "vodozemac-0.11.0/olm-session.txt is missing" \
    env GHOST_GOLDEN_NO_TESTS=1 GHOST_GOLDEN_DIR="$dmg_empty" bash "$DIR/dm-golden-lock.sh" --base none
  rmdir "$dmg_empty"
  # Both refusals are the same fail-closed rule (G-R7 never guesses a base): on a full clone the base
  # is named and unreadable; on CI's shallow checkout the gate stops one step earlier, at the
  # shallow check, whatever the base is (run 36434212692 failed this case on that difference).
  if [ "$(git -C "$DIR" rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    dmg_unreadable_msg="the repository is shallow"
  else
    dmg_unreadable_msg="cannot read Cargo.lock at the base 'no-such-revision'"
  fi
  expect_fail_msg "dm-golden-lock fails closed on an unreadable base" \
    "$dmg_unreadable_msg" \
    env GHOST_GOLDEN_NO_TESTS=1 bash "$DIR/dm-golden-lock.sh" --base no-such-revision
  if out="$(GHOST_GOLDEN_NO_TESTS=1 bash "$DIR/dm-golden-lock.sh" --base none 2>&1)" && grep -qF "first pin, exempt" <<<"$out"; then
    echo "self-test ok: dm-golden-lock exempts the first pin"
  else
    echo "SELF-TEST FAIL: dm-golden-lock does not exempt the first pin" >&2; printf '%s\n' "$out" | tail -3 >&2; rc=1
  fi
  awk 'prev == "name = \"libcrux-kem\"" && $0 == "version = \"0.0.9\"" {$0 = "version = \"0.0.8\""} {print; prev = $0}' \
    "$DIR/../../Cargo.lock" > "$tmp"
  if out="$(GHOST_GOLDEN_BASE_LOCK="$tmp" bash "$DIR/dm-golden-lock.sh" 2>&1)" && grep -qF "bump drills: 4 golden tests" <<<"$out"; then
    echo "self-test ok: dm-golden-lock runs and passes the drills at a libcrux change"
  else
    echo "SELF-TEST FAIL: dm-golden-lock did not run and pass the drills at a libcrux change" >&2; printf '%s\n' "$out" | tail -3 >&2; rc=1
  fi
  rm -f "$tmp"
  # G-R4, graph half (Phase 9 design §16.1, §22.33): each clause fails on its own. A crate the graph
  # really holds added to the forbidden list (both graphs report it), `jni` removed from log's allowed
  # dependents, a required package the graph does not hold, a failing query, and a function name the
  # graph's sources really call added to the logger-installing list (the source scan reads them).
  expect_fail_msg "dm-rust-no-logging rejects a forbidden crate in the DM graph" \
    "ghost-client-dm without jni-bridge links 'zeroize'" \
    env GHOST_DMLOG_FORBID_EXTRA=zeroize bash "$DIR/dm-rust-no-logging.sh"
  expect_fail_msg "dm-rust-no-logging rejects log reached through anything but jni" \
    "'jni' depends on log directly in ghost-client-dm's graph" \
    env GHOST_DMLOG_LOG_VIA=none bash "$DIR/dm-rust-no-logging.sh"
  expect_fail_msg "dm-rust-no-logging refuses a graph without the Olm library" \
    "vodozemac-no-such-crate is not in ghost-client-dm's graph" \
    env GHOST_DMLOG_REQUIRED=vodozemac-no-such-crate bash "$DIR/dm-rust-no-logging.sh"
  expect_fail_msg "dm-rust-no-logging fails when its cargo query fails" \
    "GATE-FAIL: cargo tree" \
    env GHOST_DMLOG_BAD_SPEC=ghost-client-dm bash "$DIR/dm-rust-no-logging.sh"
  expect_fail_msg "dm-rust-no-logging reads the graph's sources for a logger" \
    "src/pq.rs:203:pub fn encapsulate(" \
    env GHOST_DMLOG_INSTALLER=encapsulate bash "$DIR/dm-rust-no-logging.sh"
  if bash "$DIR/dm-rust-no-logging.sh" >/dev/null 2>&1; then
    echo "self-test ok: dm-rust-no-logging accepts the real DM graph"
  else
    echo "SELF-TEST FAIL: dm-rust-no-logging rejects the real DM graph" >&2; rc=1
  fi
  # G-R8 (§22.8.10 point 4): the baseline equals the scan. A site removed from a copy of the baseline
  # is unjustified, a site added to it is stale, a site stripped of its reason or left as UNJUSTIFIED
  # fails, and so does a line of no known kind.
  tmp="$(mktemp)"
  g8="$DIR/dm-vendored-clock-log.baseline"
  grep -v '^site serde_core@1.0.229 src/crate_root.rs:77 std::net network' "$g8" > "$tmp"
  expect_fail_msg "dm-vendored-clock-log rejects a site missing from the baseline" \
    "unjustified: site serde_core@1.0.229 src/crate_root.rs:77 std::net network [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/dm-vendored-clock-log.sh"
  { cat "$g8"; echo "site vodozemac@0.11.0 src/lib.rs:1 SystemTime clock-log [lib]  # fixture: a site the scan does not find"; } > "$tmp"
  expect_fail_msg "dm-vendored-clock-log rejects a stale baseline entry" \
    "stale: site vodozemac@0.11.0 src/lib.rs:1 SystemTime clock-log [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/dm-vendored-clock-log.sh"
  sed 's#^\(site rand@0.10.2 src/distr/uniform_other.rs:15 time:: clock-log \[lib\]\)  \# .*$#\1#' "$g8" > "$tmp"
  expect_fail_msg "dm-vendored-clock-log rejects a site without its reason" \
    "no justification for: site rand@0.10.2 src/distr/uniform_other.rs:15 time:: clock-log [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/dm-vendored-clock-log.sh"
  sed 's#^\(site rand@0.10.2 src/distr/uniform_other.rs:15 time:: clock-log \[lib\]\)  \# .*$#\1  \# UNJUSTIFIED#' "$g8" > "$tmp"
  expect_fail_msg "dm-vendored-clock-log rejects an entry left UNJUSTIFIED" \
    "no justification for: site rand@0.10.2" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/dm-vendored-clock-log.sh"
  { cat "$g8"; echo "sites rand@0.10.2 everywhere"; } > "$tmp"
  expect_fail_msg "dm-vendored-clock-log rejects a line of no known kind" \
    "not a site, directive, note or crate line: sites rand@0.10.2 everywhere" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/dm-vendored-clock-log.sh"
  rm -f "$tmp"
  if bash "$DIR/dm-vendored-clock-log.sh" >/dev/null 2>&1; then
    echo "self-test ok: dm-vendored-clock-log accepts the real graph against its baseline"
  else
    echo "SELF-TEST FAIL: dm-vendored-clock-log rejects the real graph" >&2; rc=1
  fi
  # The CI rust job exports CARGO_TERM_COLOR=always, under which cargo colours `cargo tree`'s `(*)`
  # markers into a pipe; the gate asks for plain output itself. Before it did, the runner's scan lost a
  # feature to the escape codes and reported a baseline note stale (run 36233077404, §22.33 item 18).
  if env CARGO_TERM_COLOR=always bash "$DIR/dm-vendored-clock-log.sh" >/dev/null 2>&1; then
    echo "self-test ok: dm-vendored-clock-log accepts the real graph under CARGO_TERM_COLOR=always"
  else
    echo "SELF-TEST FAIL: dm-vendored-clock-log fails under CARGO_TERM_COLOR=always" >&2; rc=1
  fi
  # G-R8's token list (§22.33 item 16): the standard streams and the Unix sockets. Each scanner fixture
  # is copied into a throwaway crate of its own (no manifest is committed under test-harness) and
  # scanned for aarch64-linux-android: streams.rs and unix-socket.rs give exactly their one site,
  # clean.rs none. The scanner is the one the gate above built.
  scanner="${CARGO_TARGET_DIR:-$DIR/../../target}/release/vendored-scan"
  [ -x "$scanner" ] || [ ! -x "$scanner.exe" ] || scanner="$scanner.exe"
  scan_tmp="$(mktemp -d)"
  vs_case() { # $1 = fixture name, $2 = the expected site line ("" for none)
    local fx="$1" want="$2" crate="fixture-$1" out sites
    mkdir -p "$scan_tmp/$fx/src"
    cp "$HARNESS/vendored-scan/$fx.rs" "$scan_tmp/$fx/src/lib.rs"
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n\n[workspace]\n' "$crate" > "$scan_tmp/$fx/Cargo.toml"
    printf '%s v0.1.0\n' "$crate" > "$scan_tmp/$fx/tree.txt"
    printf '%s v0.1.0|\n' "$crate" > "$scan_tmp/$fx/features.txt"
    if ! out="$("$scanner" "$scan_tmp/$fx/Cargo.toml" aarch64-linux-android "$scan_tmp/$fx/tree.txt" \
        "$scan_tmp/$fx/features.txt" "$scan_tmp/$fx/tree.txt" 2>&1)"; then
      echo "SELF-TEST FAIL: the G-R8 scanner stopped on $fx.rs: $(tail -n 1 <<<"$out")" >&2; rc=1; return
    fi
    sites="$(grep '^site ' <<<"$out" | sed -E 's/ \| .*$//' || true)"
    if [ "$sites" = "$want" ]; then
      echo "self-test ok: the G-R8 scanner lists ${want:-no site} for $fx.rs"
    else
      echo "SELF-TEST FAIL: the G-R8 scanner lists [$sites] for $fx.rs, not [$want]" >&2; rc=1
    fi
  }
  if [ -x "$scanner" ]; then
    vs_case streams "site fixture-streams@0.1.0 src/lib.rs:6 stderr clock-log [lib]"
    vs_case unix-socket "site fixture-unix-socket@0.1.0 src/lib.rs:5 UnixStream network [lib]"
    # A clock read through the imported constant (review of S2a, F5): std::time found only the import.
    vs_case clock-epoch "site fixture-clock-epoch@0.1.0 src/lib.rs:3 UNIX_EPOCH clock-log [lib]
site fixture-clock-epoch@0.1.0 src/lib.rs:3 std::time clock-log [lib]
site fixture-clock-epoch@0.1.0 src/lib.rs:6 UNIX_EPOCH clock-log [lib]
site fixture-clock-epoch@0.1.0 src/lib.rs:6 elapsed clock-log [lib]"
    vs_case clean ""
  else
    echo "SELF-TEST FAIL: the G-R8 scanner was not built at $scanner" >&2; rc=1
  fi
  rm -rf "$scan_tmp"
  # Phase 10's channel gates (design faza10-forum.md §13.1; slice S2a): every clause fires, and the
  # real graphs pass. G-M1: a copy of the allowlist without openmls, and another package's graph
  # standing in for the channel crate's (the issuer's brings new versions of names the client has).
  # G-M2 and G-R2's seeded-stream clauses: a feature the graph really has added to the forbidden list,
  # a required package it lacks, the KAT exemption given to another package, the stand-in with a
  # source and with a build script, a source root with forbidden calls across lines (and a KAT crate
  # that holds them and is skipped), a package of the channel graph named host-only, and a build
  # configuration naming the backend cfg (test-harness/gates/mls-policy/). G-M4: `log` through a
  # dependent not on the list, a crate of the graph named forbidden, a missing required package, a
  # function the crate defines named as a logger installer, and a failing query. G-M8: the G-R8 rules
  # on the channel baseline. (The GHSA watch runs offline above, without cargo.)
  # The clauses that do not stop a gate share one run of it: each hook adds exactly its own
  # violations, and the run must report every expected text and exactly the expected count, so a
  # clause that never fires, or one that fires twice, fails the case as surely as in a run of its own,
  # at a fifth of the job's time (a feature-policy run reads some twenty cargo graphs).
  multi_case() { # $1 = description, $2 = expected violation count, $3 = expected texts (one per line), rest = command
    local desc="$1" want="$2" texts="$3" out got hits t missing=""
    shift 3
    if out="$("$@" 2>&1)"; then got=pass; else got=fail; fi
    hits="$(grep -c '^GATE-FAIL' <<<"$out" || true)"
    while IFS= read -r t; do
      [ -n "$t" ] || continue
      grep -qF -- "$t" <<<"$out" || missing+="[$t] "
    done <<<"$texts"
    if [ "$got" = fail ] && [ "$hits" = "$want" ] && [ -z "$missing" ]; then
      echo "self-test ok: $desc"
    else
      echo "SELF-TEST FAIL: $desc ($got, $hits of $want violations; missing: ${missing:-none})" >&2
      printf '%s\n' "$out" | grep '^GATE-FAIL' | tail -12 >&2; rc=1
    fi
  }
  tmp="$(mktemp)"
  grep -vx "openmls" "$DIR/../../client-core/rust-dependency-allowlist.txt" > "$tmp"
  expect_fail_msg "rust-client-allowlist rejects an unlisted package of the channel graph (G-M1)" "Rust package 'openmls'" \
    env GHOST_RUST_ALLOWLIST="$tmp" bash "$DIR/rust-client-allowlist.sh"
  rm -f "$tmp"
  expect_fail_msg "rust-client-allowlist rejects a new version of a name the client graph has (G-M1)" \
    "(G-M1: no second copy of a crate in the library unreviewed)" \
    env GHOST_ALLOWLIST_MLS_PACKAGE=ghost-issuer bash "$DIR/rust-client-allowlist.sh"
  # G-M1's duplicate baseline (review of S2a, F2): a duplicate the baseline does not list fails, and
  # so does a line the graphs no longer reach.
  tmp="$(mktemp)"
  grep -v '^getrandom ' "$DIR/../../client-core/rust-duplicate-versions.txt" > "$tmp"
  expect_fail_msg "rust-client-allowlist rejects a duplicate the baseline does not list (G-M1)" \
    "getrandom is at 2 versions" env GHOST_RUST_DUPLICATES="$tmp" bash "$DIR/rust-client-allowlist.sh"
  { cat "$DIR/../../client-core/rust-duplicate-versions.txt"; echo "bitflags 2"; } > "$tmp"
  expect_fail_msg "rust-client-allowlist rejects a stale baseline line (G-M1)" \
    "bitflags 2 is stale" env GHOST_RUST_DUPLICATES="$tmp" bash "$DIR/rust-client-allowlist.sh"
  rm -f "$tmp"
  # The linked state of slice S2b, simulated: a scratch workspace whose root links ghost-client-net
  # and ghost-client-mls (the lock copied, resolved offline). It passes today's baseline; with a
  # second bitflags beside it — S2a's rule saw nothing there, since the client graph then contains
  # every version the MLS graph brings — it fails.
  linked_case() { # $1 = pass|fail, $2 = extra dependency line ("" for none), $3 = expected text, $4 = description
    local fx gw out got
    fx="$(mktemp -d)"
    gw="$(cd "$DIR/../.." && { pwd -W 2>/dev/null || pwd; })"
    mkdir -p "$fx/src" && : > "$fx/src/lib.rs"
    printf '[package]\nname = "ghost-linked-fixture"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[dependencies]\nghost-client-net = { path = "%s/client-core/net" }\nghost-client-mls = { path = "%s/client-core/mls" }\nghost-client-media = { path = "%s/client-core/media" }\n%s\n\n[workspace]\n' "$gw" "$gw" "$gw" "$2" > "$fx/Cargo.toml"
    cp "$DIR/../../Cargo.lock" "$fx/Cargo.lock"
    { cat "$DIR/../../client-core/rust-dependency-allowlist.txt"; echo ghost-linked-fixture; } > "$fx/allowlist.txt"
    if ! (cd "$fx" && cargo update -w --offline -q >/dev/null 2>&1); then
      echo "SELF-TEST FAIL: rust-client-allowlist $4: the linked fixture does not resolve offline" >&2; rc=1; rm -rf "$fx"; return
    fi
    if out="$(env GHOST_ALLOWLIST_WORKSPACE="$fx" GHOST_ALLOWLIST_NET_PACKAGE=ghost-linked-fixture \
        GHOST_RUST_ALLOWLIST="$fx/allowlist.txt" bash "$DIR/rust-client-allowlist.sh" 2>&1)"; then got=pass; else got=fail; fi
    if [ "$got" = "$1" ] && grep -qF -- "$3" <<<"$out"; then
      echo "self-test ok: rust-client-allowlist $4"
    else
      echo "SELF-TEST FAIL: rust-client-allowlist $4 ($got)" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
    fi
    rm -rf "$fx"
  }
  linked_case pass "" "[rust-client-allowlist] OK" "accepts the linked state of S2b against the baseline (G-M1)"
  linked_case fail 'bitflags = "=1.3.2"' "bitflags is at 2 versions (1.3.2 2.13.2)" "rejects a second copy of a crate in the linked state (G-M1)"
  MLSP="$HARNESS/mls-policy"
  # Since slice S2b links the crate into ghost-client-net, the forbidden-feature and host-only
  # clauses read both graphs, so their hooks fire twice (the review of S2b found this case still
  # expecting 17 and failing); and S2b's two shipped-graph clauses get their hooks here.
  multi_case "rust-feature-policy reports each channel clause (G-M2, G-R2): a forbidden feature the graphs have (the channel crate's and, linked since S2b, the shipped one), a graph without OpenMLS, test-utils outside the KAT crate, a stand-in with a source, forbidden names split over lines (the KAT crate skipped, a module directory named target read), a host-only package in both graphs, a build configuration naming the backend cfg, a patched fork, a lock with sources other than crates.io, a shipped graph without the channel crate and a feature of the crate's own the shipped graph may not carry" 21 \
"hpke-rs feature 'hazmat' is enabled in ghost-client-mls's graph (G-M2
hpke-rs feature 'hazmat' is enabled in ghost-client-net's graph (G-M2
package 'openmls-no-such-crate' is not in ghost-client-mls's graph
ghost-client-mls-kat enables openmls/test-utils (dev); G-M2 allows it only as a dev-dependency of ghost-client-mls
the stub's src/lib.rs is not empty
mls/src/group.rs:3: openmls_memory_storage
mls/src/group.rs:9: build_with_new_signer
mls/src/group.rs:11: store_pending_proposal
mls/src/target/mod.rs:3: export_group_info
package 'rayon' is in ghost-client-mls's graph: host and test builds only (G-R2
package 'rayon' is in ghost-client-net's graph: host and test builds only (G-R2
shipped-config.toml names getrandom_backend
Cargo.toml:7: [patch.crates-io] names openmls (G-M2
a [patch.\"https://github.com/example/tls_codec\"] table
Cargo.toml:13: [replace] names hpke-rs:0.6.0
Cargo.lock: openmls 0.9.0 has no source and is not a workspace member
Cargo.lock: tls_codec 0.5.0 comes from git+https://github.com/example/tls_codec
Cargo.lock: hpke-rs 0.6.0 has no checksum
package 'ghost-client-mls-no-such-crate' is not in the shipped client graph
ghost-client-mls feature 'jni-bridge' is enabled in the shipped client graph; G-M2 allows: default" \
    env GHOST_POLICY_MLS_FORBID_EXTRA=hpke-rs:hazmat GHOST_POLICY_MLS_GRAPH=openmls-no-such-crate \
      GHOST_POLICY_KAT=ghost-client-mls GHOST_POLICY_STUB_DIR="$MLSP/stub-nonempty" \
      GHOST_POLICY_MLS_SOURCES="$MLSP/sources" GHOST_POLICY_HOST_ONLY_EXTRA=rayon \
      GHOST_POLICY_SHIPPED_CONFIGS="$MLSP/shipped-config.toml" \
      GHOST_POLICY_ROOT_MANIFEST="$MLSP/fork/Cargo.toml" GHOST_POLICY_LOCK="$MLSP/fork/Cargo.lock" \
      GHOST_POLICY_SHIPPED_MLS=ghost-client-mls-no-such-crate GHOST_POLICY_MLS_SHIPPED_ALLOWED=default \
      bash "$DIR/rust-feature-policy.sh"
  multi_case "rust-feature-policy rejects a stand-in with a build script (G-M2)" 1 \
    "the openmls_sqlite_storage stub holds [Cargo.toml README.md build.rs src/lib.rs ]" \
    env GHOST_POLICY_STUB_DIR="$MLSP/stub-extra" bash "$DIR/rust-feature-policy.sh"
  # Fail-closed readers (review of S2a, F3): with a perl that fails on PATH, G-M2's metadata reader,
  # its patch and lock-source reader (F7) and its source scan each fail the gate, and the two that
  # count report reading nothing, instead of reading no violation. G-M3's script fails the same way.
  perl_stub="$(mktemp -d)"
  printf '#!/bin/sh\necho "perl stub: failing on purpose" >&2\nexit 2\n' > "$perl_stub/perl"
  chmod +x "$perl_stub/perl"
  multi_case "rust-feature-policy fails closed when perl fails (G-M2)" 5 \
"the workspace metadata reader (perl) failed
the workspace metadata reader read no package
the patch and lock-source reader (perl) failed
the GHOST source scan (perl) failed
the GHOST source scan read no Rust file" \
    env PATH="$perl_stub:$PATH" bash "$DIR/rust-feature-policy.sh"
  expect_fail_msg "ch-derivation-inputs fails closed when perl fails (G-M3)" "the channel source reader (perl) failed" \
    env PATH="$perl_stub:$PATH" bash "$DIR/ch-derivation-inputs.sh"
  rm -rf "$perl_stub"
  multi_case "mls-rust-no-logging reports each clause (G-M4): log through a dependent not on the list, a forbidden crate, a graph without OpenMLS, a logger installer in the graph's sources" 6 \
"'openmls_memory_storage' depends on log directly in ghost-client-mls's graph
ghost-client-mls links 'rayon'
openmls-no-such-crate is not in ghost-client-mls's graph
src/derive.rs:200:pub fn derive_epoch_recognition(" \
    env GHOST_DMLOG_LOG_VIA="openmls hpke-rs" GHOST_DMLOG_FORBID_EXTRA=rayon \
      GHOST_DMLOG_REQUIRED=openmls-no-such-crate GHOST_DMLOG_INSTALLER=derive_epoch_recognition \
      bash "$DIR/mls-rust-no-logging.sh"
  expect_fail_msg "mls-rust-no-logging fails when its cargo query fails (G-M4)" \
    "GATE-FAIL: cargo tree -p ghost-client-mls@0.0.0-no-such-version" \
    env GHOST_DMLOG_BAD_SPEC=ghost-client-mls bash "$DIR/mls-rust-no-logging.sh"
  if bash "$DIR/mls-rust-no-logging.sh" >/dev/null 2>&1; then
    echo "self-test ok: mls-rust-no-logging accepts the real channel graph"
  else
    echo "SELF-TEST FAIL: mls-rust-no-logging rejects the real channel graph" >&2; rc=1
  fi
  tmp="$(mktemp)"
  gm8="$DIR/mls-vendored-clock-log.baseline"
  grep -v '^site ghost-client-mls@0.1.0 src/group.rs:14 std::time clock-log' "$gm8" > "$tmp"
  expect_fail_msg "mls-vendored-clock-log rejects a site missing from the baseline (G-M8)" \
    "unjustified: site ghost-client-mls@0.1.0 src/group.rs:14 std::time clock-log [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/mls-vendored-clock-log.sh"
  { cat "$gm8"; echo "site openmls@0.9.0 src/lib.rs:1 SystemTime clock-log [lib]  # fixture: a site the scan does not find"; } > "$tmp"
  expect_fail_msg "mls-vendored-clock-log rejects a stale baseline entry (G-M8)" \
    "stale: site openmls@0.9.0 src/lib.rs:1 SystemTime clock-log [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/mls-vendored-clock-log.sh"
  sed 's#^\(site openmls@0.9.0 src/ciphersuite/aead.rs:47 log:: clock-log \[lib\]\)  \# .*$#\1#' "$gm8" > "$tmp"
  expect_fail_msg "mls-vendored-clock-log rejects a site without its reason (G-M8)" \
    "no justification for: site openmls@0.9.0 src/ciphersuite/aead.rs:47 log:: clock-log [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/mls-vendored-clock-log.sh"
  # Slice S2b (faza10-forum.md §19.32): the scan reads the graph as the shipped library links it,
  # `jni-bridge` on, so the `jni` subtree is in it; a jni site left out of the baseline fails.
  grep -v '^site jni@0.21.1 src/wrapper/jnienv.rs:9 log::' "$gm8" > "$tmp"
  expect_fail_msg "mls-vendored-clock-log scans the jni-bridge graph the shipped library links (G-M8, S2b)" \
    "unjustified: site jni@0.21.1 src/wrapper/jnienv.rs:9 log:: clock-log [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/mls-vendored-clock-log.sh"
  rm -f "$tmp"
  if bash "$DIR/mls-vendored-clock-log.sh" >/dev/null 2>&1; then
    echo "self-test ok: mls-vendored-clock-log accepts the real channel graph against its baseline"
  else
    echo "SELF-TEST FAIL: mls-vendored-clock-log rejects the real channel graph" >&2; rc=1
  fi
  # G-M7 (Phase 11 design faza11-media.md §13.1, §16.1 G-M7; slice S1): the media crate's graph rules,
  # each failing for its own reason. G-R1: the workspace line and the direct-dependency clause (an
  # external crate the allowlist holds for another reason, simulated by narrowing the allowed five);
  # G-R2: a feature reaching the crate's own graph, the graph without the crate, and the shipped-graph
  # requirement S2's link turns on; G-R4's graph half; G-R8 against its baseline.
  tmp="$(mktemp)"
  grep -vx "ghost-client-media" "$DIR/../../client-core/rust-dependency-allowlist.txt" > "$tmp"
  expect_fail_msg "rust-client-allowlist rejects the media crate without its workspace line (G-M7)" \
    "Rust package 'ghost-client-media'" env GHOST_RUST_ALLOWLIST="$tmp" bash "$DIR/rust-client-allowlist.sh"
  rm -f "$tmp"
  expect_fail_msg "rust-client-allowlist rejects an external crate as the media crate's dependency (G-M7)" \
    "ghost-client-media depends on 'zeroize' directly: design §13.1 allows chacha20poly1305 hkdf hmac sha2" \
    env GHOST_ALLOWLIST_MEDIA_DEPS="chacha20poly1305 hkdf hmac sha2" bash "$DIR/rust-client-allowlist.sh"
  multi_case "rust-feature-policy reports each media clause (G-M7): a feature in the crate's own graph, a graph without the crate's stack, the shipped graph S2 must link it into" 3 \
"ghost-client-media feature 'nonce-registry' is enabled in its own graph; G-M7 allows: default
package 'media-no-such-crate' is not in ghost-client-media's graph
package 'ghost-client-media' is not in the shipped client graph although ghost-client-dm declares it" \
    env GHOST_POLICY_MEDIA_QUERY_FEATURES=nonce-registry GHOST_POLICY_MEDIA_GRAPH="ghost-client-media media-no-such-crate" \
      GHOST_POLICY_MEDIA_SHIPPED_REQUIRED=1 bash "$DIR/rust-feature-policy.sh"
  multi_case "media-rust-no-logging reports each clause (G-M7): a forbidden crate (rules 1 and 2), a graph without the media stack (both queries)" 4 \
"ghost-client-media links 'zeroize'
media-no-such-crate is not in ghost-client-media's graph" \
    env GHOST_DMLOG_FORBID_EXTRA=zeroize GHOST_DMLOG_REQUIRED="ghost-client-media media-no-such-crate" \
      bash "$DIR/media-rust-no-logging.sh"
  expect_fail_msg "media-rust-no-logging reads the media crate's own sources for a logger (G-M7)" \
    "ghost-client-media 0.1.0: src/sniff.rs" env GHOST_DMLOG_INSTALLER=sniff bash "$DIR/media-rust-no-logging.sh"
  if bash "$DIR/media-rust-no-logging.sh" >/dev/null 2>&1; then
    echo "self-test ok: media-rust-no-logging accepts the real media graph"
  else
    echo "SELF-TEST FAIL: media-rust-no-logging rejects the real media graph" >&2; rc=1
  fi
  tmp="$(mktemp)"
  gm7="$DIR/media-vendored-clock-log.baseline"
  grep -v '^site libc@0.2.189 src/new/mod.rs:218 time::' "$gm7" > "$tmp"
  expect_fail_msg "media-vendored-clock-log rejects a site missing from the baseline (G-M7)" \
    "unjustified: site libc@0.2.189 src/new/mod.rs:218 time:: clock-log [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/media-vendored-clock-log.sh"
  { cat "$gm7"; echo "site ghost-client-media@0.1.0 src/sealer.rs:1 SystemTime clock-log [lib]  # fixture: a clock site the scan does not find"; } > "$tmp"
  expect_fail_msg "media-vendored-clock-log rejects a stale baseline entry (G-M7)" \
    "stale: site ghost-client-media@0.1.0 src/sealer.rs:1 SystemTime clock-log [lib]" \
    env GHOST_G_R8_BASELINE="$tmp" bash "$DIR/media-vendored-clock-log.sh"
  rm -f "$tmp"
  if bash "$DIR/media-vendored-clock-log.sh" >/dev/null 2>&1; then
    echo "self-test ok: media-vendored-clock-log accepts the real media graph against its baseline"
  else
    echo "SELF-TEST FAIL: media-vendored-clock-log rejects the real media graph" >&2; rc=1
  fi
  # The review of S1 (finding 7): three G-M7 mechanisms no case reached, and the S2 switch of the
  # clock-log scan. (1) The shipped-graph feature clause, run on a package the shipped graph holds
  # with a non-default feature (the media crate is not linked before S2). (2) S2's link detected
  # from the workspace metadata — a normal and an optional dependency of ghost-client-dm require the
  # crate in the shipped graph, a dev-dependency does not — instead of forced by
  # GHOST_POLICY_MEDIA_SHIPPED_REQUIRED. (3) The licence gates refuse a graphs.txt that drops the
  # media crate, which the header scan used to pass. (4) The clock-log scan reads the features where
  # the library links the crate, decided from the graph.
  multi_case "rust-feature-policy runs the media shipped-graph feature clause (G-M7)" 1 \
"ghost-client-mls feature 'jni-bridge' is enabled in the shipped client graph; G-M7 allows: default" \
    env GHOST_POLICY_MEDIA_SHIPPED=ghost-client-mls bash "$DIR/rust-feature-policy.sh"
  for mp_link in normal optional; do
    multi_case "rust-feature-policy detects S2's link from the metadata: ghost-client-dm's $mp_link dependency on the crate (G-M7)" 1 \
"package 'ghost-client-media' is not in the shipped client graph although ghost-client-dm declares it" \
      env GHOST_POLICY_MEDIA_METADATA="$HARNESS/media-policy/linked-$mp_link.json" bash "$DIR/rust-feature-policy.sh"
  done
  if GHOST_POLICY_MEDIA_METADATA="$HARNESS/media-policy/linked-dev.json" bash "$DIR/rust-feature-policy.sh" >/dev/null 2>&1; then
    echo "self-test ok: rust-feature-policy requires nothing of a dev-dependency on the media crate (G-M7)"
  else
    echo "SELF-TEST FAIL: rust-feature-policy treats a dev-dependency on the media crate as S2's link" >&2; rc=1
  fi
  tmp="$(mktemp)"
  sed 's/^graph client-net ghost-client-net,ghost-client-media /graph client-net ghost-client-net /' \
    "$DIR/../../licenses/graphs.txt" > "$tmp"
  if cmp -s "$tmp" "$DIR/../../licenses/graphs.txt"; then
    echo "SELF-TEST FAIL: the graphs.txt fixture did not drop the media crate" >&2; rc=1
  else
    expect_fail_msg "rust-license-headers rejects a graphs.txt without the media crate (G-R5, G-M7)" \
      "GHOST's own crate ghost-client-media is in no shipped graph" \
      env GHOST_LICENSE_GRAPHS="$tmp" bash "$DIR/rust-license-headers.sh"
    expect_fail_msg "license-notices rust rejects a graphs.txt without the media crate (G-L1, G-M7)" \
      "GHOST's own crate ghost-client-media is in no shipped graph" \
      env GHOST_LICENSE_GRAPHS="$tmp" bash "$DIR/license-notices.sh" rust
  fi
  rm -f "$tmp"
  if mp_out="$(GHOST_G_R8_MEDIA_LINKER=ghost-client-media bash "$DIR/media-vendored-clock-log.sh" 2>&1)" \
    && grep -qF "ghost-client-media links ghost-client-media: each package's features as ghost-client-media's graph has them" <<<"$mp_out" \
    && mp_out="$(bash "$DIR/media-vendored-clock-log.sh" 2>&1)" \
    && grep -qF "ghost-client-net does not link ghost-client-media yet" <<<"$mp_out"; then
    echo "self-test ok: media-vendored-clock-log reads the features where the linking graph has them (G-M7, S2)"
  else
    echo "SELF-TEST FAIL: media-vendored-clock-log does not switch its features by the linking graph" >&2; rc=1
  fi
  # ADR-37 (design §2.10.2, §22.8.10 point 1): cargo-deny takes package specs, not globs, so every
  # named ban of the libsignal family must fire on its own. A scratch package depends on a local crate
  # of each banned name; its lock file must fail with a [banned] diagnostic naming that crate and the
  # summary "bans FAILED", and a crate of an unbanned name must pass with "bans ok". The output is
  # parsed, so it is asked for plainly (--color never): the CI rust job exports CARGO_TERM_COLOR=always
  # (dtolnay/rust-toolchain), cargo-deny honours it even into a pipe, and the colour escapes split the
  # summary into "bans <ESC>[31mFAILED<ESC>[0m" (run 35461620207 failed every case that way, on the
  # same cargo-deny 0.20.2 that passes plainly on a Windows shell). The match keys on the diagnostic
  # code [banned], cargo-deny's documented identifier, and on the crate as it prints it
  # ('name = version'); the sentence after them may change between versions.
  # Needs the cargo-deny binary (the CI rust job installs it and sets GHOST_SELFTEST_DENY).
  if cargo deny --version >/dev/null 2>&1; then
    deny_names="$(grep -oP '\{ crate = "\K[^"]+(?=", reason = "ADR-37)' "$DIR/../../deny.toml")"
    if [ "$(printf '%s\n' "$deny_names" | grep -c .)" != "14" ]; then
      echo "SELF-TEST FAIL: deny.toml names $(printf '%s\n' "$deny_names" | grep -c .) of the 14 ADR-37 bans" >&2; rc=1
    fi
    deny_fix="$(mktemp -d)"
    mkdir -p "$deny_fix/src" "$deny_fix/dep/src"
    : > "$deny_fix/src/lib.rs"
    : > "$deny_fix/dep/src/lib.rs"
    cp "$DIR/../../deny.toml" "$deny_fix/deny.toml"
    deny_case() { # $1 = crate name, $2 = pass|fail
      local out got
      printf '[package]\nname = "ghost-deny-bans-fixture"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[dependencies]\n%s = { path = "dep" }\n\n[workspace]\n' "$1" > "$deny_fix/Cargo.toml"
      printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\npublish = false\n' "$1" > "$deny_fix/dep/Cargo.toml"
      rm -f "$deny_fix/Cargo.lock"
      if ! (cd "$deny_fix" && cargo generate-lockfile --offline >/dev/null 2>&1); then
        echo "SELF-TEST FAIL: cargo-deny bans: no scratch lock file for $1" >&2; rc=1; return
      fi
      if out="$(cargo deny --offline --color never --manifest-path "$deny_fix/Cargo.toml" check bans 2>&1)"; then got=pass; else got=fail; fi
      if [ "$2" = fail ] && [ "$got" = fail ] && grep -qE "^error\[banned\]:.*'$1 = 0\.1\.0'" <<<"$out" && grep -qF "bans FAILED" <<<"$out"; then
        echo "self-test ok: cargo-deny bans FAILED on $1"
      elif [ "$2" = pass ] && [ "$got" = pass ] && grep -qF "bans ok" <<<"$out"; then
        echo "self-test ok: cargo-deny bans ok on the unbanned $1"
      else
        echo "SELF-TEST FAIL: cargo-deny bans on $1 ($got, expected $2)" >&2; printf '%s\n' "$out" | tail -5 >&2; rc=1
      fi
    }
    for name in $deny_names; do deny_case "$name" fail; done
    deny_case ghost-deny-unbanned-fixture pass
    rm -rf "$deny_fix"
  elif [ -n "${GHOST_SELFTEST_DENY:-}" ]; then
    echo "SELF-TEST FAIL: cargo-deny missing; the ADR-37 bans are not proven" >&2; rc=1
  else
    echo "self-test skipped: cargo-deny bans (cargo-deny not installed)"
  fi
  # entitlement-schedule.sh cases that run ghost-issuer-ops (they build it): opt-in like the clippy
  # fixture below; the CI rust job sets GHOST_SELFTEST_OPS.
  if [ -n "${GHOST_SELFTEST_OPS:-}" ]; then
    es_env=(GHOST_ES_TEST_KEY="$ES_TEST_KEY" GHOST_ES_NOW="$ES_NOW")
    es_case "accepts a valid successor (rule 5)" pass "$ES_FIX/positive" "ES_APPEND_ONLY previous_seq=1" \
      "${es_env[@]}" GHOST_ES_PREDECESSOR="$ES_PRED"
    es_case "checks the relay directory of the current and the next week" pass "$ES_FIX/positive" "DIRECTORY_OK weeks=2" \
      "${es_env[@]}" GHOST_ES_PREDECESSOR="$ES_PRED"
    es_case "never accepts a test schedule under the pinned key" fail "$ES_FIX/positive" \
      "ES_REFUSED file=schedule reason=no-pinned-key" GHOST_ES_NOW="$ES_NOW"
    es_case "rejects a tampered schedule" fail "$ES_FIX/tampered" "ES_REFUSED file=schedule reason=signature" "${es_env[@]}"
    es_case "rejects a changed slot set" fail "$ES_FIX/slot-set-changed" "reason=slot-set-changed" \
      "${es_env[@]}" GHOST_ES_PREDECESSOR="$ES_PRED"
    es_case "rejects a duplicated key" fail "$ES_FIX/duplicated-key" "reason=duplicate-key" "${es_env[@]}"
    es_case "rejects a slot onion missing from the relay directory" fail "$ES_FIX/directory-missing-onion" \
      "reason=onion-not-in-directory week=2960 slot=2" "${es_env[@]}"
    es_case "rejects a week whose relays have one operator" fail "$ES_FIX/directory-single-operator" \
      "reason=single-operator" "${es_env[@]}"
    es_case "rejects a schedule without a relay directory" fail "$ES_FIX/directory-absent" "relay-directory.txt missing" \
      "${es_env[@]}"
    # Rule 5 over the whole first-parent history, in a throwaway repository: every committed
    # version is checked against all versions before it, not only the head against its predecessor.
    ES_B="$ES_FIX/slot-set-changed/protocol/entitlement/schedule.ghes"
    ES_C="$ES_FIX/resigned-slot-set-changed/protocol/entitlement/schedule.ghes"
    es_case "accepts a re-signed schedule against its immediate predecessor alone" pass \
      "$ES_FIX/resigned-slot-set-changed" "ES_APPEND_ONLY previous_seq=2" "${es_env[@]}" GHOST_ES_PREDECESSOR="$ES_B"
    es_git_case() { # $1 = description, $2 = pass|fail, $3 = expected text, rest = schedule versions to commit, oldest first ("-" removes it)
      local desc="$1" expect="$2" want="$3" repo v n=0
      shift 3
      repo="$(mktemp -d)"
      git -C "$repo" init -q
      mkdir -p "$repo/protocol/entitlement"
      cp "$ES_FIX/positive/protocol/entitlement/relay-directory.txt" "$repo/protocol/entitlement/"
      for v in "$@"; do
        n=$((n + 1))
        if [ "$v" = - ]; then rm "$repo/protocol/entitlement/schedule.ghes"; else cp "$v" "$repo/protocol/entitlement/schedule.ghes"; fi
        git -C "$repo" add -A
        git -C "$repo" -c user.name=gate -c user.email=gate@self.test -c commit.gpgsign=false commit -q -m "version $n"
      done
      es_case "$desc" "$expect" "$repo" "$want" "${es_env[@]}" GHOST_ES_GIT=1
      rm -rf "$repo"
    }
    es_git_case "rejects a violating middle version of the git history (A, B, C)" fail \
      "ES_REFUSED file=previous reason=slot-set-changed seq=2 previous_seq=1" "$ES_PRED" "$ES_B" "$ES_C"
    es_git_case "accepts a valid git history" pass "ES_APPEND_ONLY previous_seq=1 history=1" \
      "$ES_PRED" "$ES_FIX/positive/protocol/entitlement/schedule.ghes"
    es_git_case "rejects a schedule removed after a commit (git history)" fail "committed before and is now missing" \
      "$ES_PRED" -
  fi
  # The clippy fixture compiles the client library: opt-in (the CI rust job sets it, cache warm).
  if [ -n "${GHOST_SELFTEST_CLIPPY:-}" ]; then
    expect_fail_msg "clippy-clearnet-fixture reports a ban that does not fire" \
      "clippy.toml ban 'std::net::TcpListener::bind' did not fire" \
      env GHOST_CLIPPY_EXTRA_BAN=std::net::TcpListener::bind bash "$DIR/clippy-clearnet-fixture.sh"
  fi
elif [ -n "${CI:-}" ]; then
  echo "SELF-TEST FAIL: cargo missing in CI; Rust gates not proven" >&2; rc=1
else
  echo "self-test skipped: Rust gates (cargo not installed)"
fi
# Every command the self-test itself called and did not have (see command_not_found_handle at the top) is a failure.
if [ -s "$NOT_FOUND_LOG" ]; then
  echo "SELF-TEST FAIL: $(wc -l < "$NOT_FOUND_LOG" | tr -d ' ') call(s) of a command the self-test does not have: $(sort -u "$NOT_FOUND_LOG" | tr '\n' ' ')" >&2
  rc=1
fi
rm -f "$NOT_FOUND_LOG"
exit $rc
