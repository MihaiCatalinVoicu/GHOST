#!/usr/bin/env bash
# Proves each gate actually fails on a known-bad tree (ADR-10: "demonstrated to fail on
# counter-examples"). The fixtures live in test-harness/gates/negative* and mirror the layout of
# ghost/ so the gates scan them unchanged via GHOST_ROOT.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="$(cd "$DIR/../../test-harness/gates" && pwd)"
rc=0
expect_fail() {
  local gate="$1" root="$2"
  if GHOST_ROOT="$root" bash "$DIR/$gate.sh" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: $gate passed on fixture $(basename "$root")" >&2; rc=1
  else
    echo "self-test ok: $gate rejects fixture $(basename "$root")"
  fi
}
for g in anti-placeholder no-logging manifest-lint dependency-allowlist; do
  expect_fail "$g" "$HARNESS/negative"
done
# Phase 7 crash fidelity: every catch-all form in the fixture is reported, one line each. Phase 8
# (design §11.1): the fixture's entitlement module adds 3 lines, each reported by its file name, and
# a tree without android/entitlement/src/main fails for that reason alone.
expect_fail sync-no-catch-all "$HARNESS/negative-sync"
sync_out="$(GHOST_ROOT="$HARNESS/negative-sync" bash "$DIR/sync-no-catch-all.sh" 2>&1 || true)"
sync_hits="$(printf '%s\n' "$sync_out" | grep -c '^GATE-FAIL' || true)"
if [ "$sync_hits" = "12" ]; then echo "self-test ok: sync-no-catch-all reports all 12 fixture lines"; else echo "SELF-TEST FAIL: sync-no-catch-all reported $sync_hits of 12 fixture lines" >&2; rc=1; fi
for want in CatchAllParticipant.kt:6: CatchAllParticipant.kt:10: CatchAllParticipant.kt:13:; do
  if printf '%s\n' "$sync_out" | grep -qF "android/entitlement/src/main/kotlin/org/ghost/entitlement/bad/$want"; then
    echo "self-test ok: sync-no-catch-all reports entitlement $want"
  else
    echo "SELF-TEST FAIL: sync-no-catch-all does not report entitlement $want" >&2; rc=1
  fi
done
expect_fail sync-no-catch-all "$HARNESS/negative-sync-no-entitlement"
out="$(GHOST_ROOT="$HARNESS/negative-sync-no-entitlement" bash "$DIR/sync-no-catch-all.sh" 2>&1 || true)"
if [ "$(printf '%s\n' "$out" | grep -c '^GATE-FAIL' || true)" = "1" ] && printf '%s\n' "$out" | grep -qF "android/entitlement/src/main: missing"; then
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
MERGED_FIXTURES="$HARNESS/negative-merged-manifest"
merged_hits="$(bash "$DIR/merged-manifest-lint.sh" "$MERGED_FIXTURES/AndroidManifest.xml" 2>&1 | grep -c '^GATE-FAIL' || true)"
if [ "$merged_hits" = "15" ]; then echo "self-test ok: merged-manifest-lint reports all 15 violations of the negative fixture"; else echo "SELF-TEST FAIL: merged-manifest-lint reported $merged_hits of 15 violations" >&2; rc=1; fi
if bash "$DIR/merged-manifest-lint.sh" "$MERGED_FIXTURES/positive/AndroidManifest.xml" >/dev/null 2>&1; then
  echo "self-test ok: merged-manifest-lint accepts the Phase 7 merged release manifest"
else
  echo "SELF-TEST FAIL: merged-manifest-lint rejects the Phase 7 merged release manifest" >&2; rc=1
fi
# Phase 8 T2 (design §13.4, §13.6, §19.31): the report check accepts only a complete PASS report of
# the right scale (A1, the FR-6′.7 amount uniformity, included), and all 26 privacy mutants detected.
T2R="$HARNESS/t2-report"
t2r_case() { # $1 = expect pass|fail, $2 = report, $3 = kind, $4 = description
  if bash "$DIR/t2-report-check.sh" "$T2R/$2" "$3" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$1" ]; then echo "self-test ok: t2-report-check $4"; else echo "SELF-TEST FAIL: t2-report-check $4 ($got)" >&2; rc=1; fi
}
t2r_case pass pass-gate.txt gate "accepts a complete gate report"
t2r_case pass pass-pr.txt pr "accepts a complete PR-variant report"
t2r_case fail missing-check.txt gate "rejects a report without a check (NI-1d)"
t2r_case fail failed-check.txt gate "rejects a report with a failed check"
t2r_case fail wrong-scale.txt gate "rejects a PR-scale report as the gate's"
t2r_case fail vacuous.txt gate "rejects a check that passed on an empty sample (S3d, n=0)"
t2r_case fail missing-e30.txt gate "rejects a report without the E30 redeem-hold line"
t2r_case fail vacuous-e30.txt gate "rejects an E30 line that measured no held session"
t2r_case fail vacuous-reads.txt gate "rejects an NI-2 line whose twin moved no drop read by an hour"
t2r_case fail exempt-twin.txt gate "rejects an NI-2 line that compared an inviter only before a horizon (no exemption, §19.29)"
t2r_case fail no-such-report.txt gate "rejects a missing report"
t2r_case fail missing-a1.txt gate "rejects a report without the A1 amount-uniformity line (FR-6′.7, §19.31)"
t2r_case fail vacuous-a1.txt gate "rejects an A1 line that checked no wallet transfer"
t2r_case pass mutants-ok.txt mutants "accepts 26 detected mutants"
t2r_case pass mutants-interleaved.txt mutants "accepts a detected mutant whose ok line another test's output ran into"
t2r_case fail mutants-short.txt mutants "rejects 25 detected mutants"
# Scope checks: these gates must also cover client-core/ (shipped in the APK, ADR-19).
for g in anti-placeholder no-logging; do
  expect_fail "$g" "$HARNESS/negative-client-core"
done
# Phase 8 (design §14.1, E-2): crates nested under issuer/crates/ are scanned, and an issuer main.rs
# is not exempt. Each fixture file must be reported by name (the rest of the fixture already fails).
for g in anti-placeholder no-logging; do
  out="$(GHOST_ROOT="$HARNESS/negative" bash "$DIR/$g.sh" 2>&1 || true)"
  for f in issuer/crates/blind-rsa/src/lib.rs issuer/crates/service/src/main.rs; do
    if printf '%s\n' "$out" | grep -qF "$f:"; then
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
  if printf '%s\n' "$out" | grep -qF "$want"; then
    echo "self-test ok: no-logging reports $want"
  else
    echo "SELF-TEST FAIL: no-logging does not report $want" >&2; rc=1
  fi
done
if printf '%s\n' "$out" | grep -qF "issuer/crates/ops/src/report.rs:5:"; then
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
  if printf '%s\n' "$out" | grep -qF "$want"; then
    echo "self-test ok: no-logging reports $want"
  else
    echo "SELF-TEST FAIL: no-logging does not report $want" >&2; rc=1
  fi
done
out="$(GHOST_ROOT="$HARNESS/negative-client-core" bash "$DIR/no-logging.sh" 2>&1 || true)"
if printf '%s\n' "$out" | grep -qF "client-core/bad/src/logging.rs:3:"; then
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
  if printf '%s\n' "$out" | grep -qF "issuer/crates/$want"; then
    echo "self-test ok: issuer-output reports $want"
  else
    echo "SELF-TEST FAIL: issuer-output does not report $want" >&2; rc=1
  fi
done
# S12 review GATE-ISSUER-OUTPUT-BRACE: a read-only brace import is not a write.
for allowed in service/src/scanner.rs:10: service/src/scanner.rs:11:; do
  if printf '%s\n' "$out" | grep -qF "issuer/crates/$allowed"; then
    echo "SELF-TEST FAIL: issuer-output reports the read-only import $allowed" >&2; rc=1
  else
    echo "self-test ok: issuer-output allows the read-only import $allowed"
  fi
done
for allowed in service/src/status.rs:3: service/src/store.rs:3: service/src/payout.rs:3: \
  ops/src/report.rs:3: ops/src/output.rs:3:; do
  if printf '%s\n' "$out" | grep -qF "issuer/crates/$allowed"; then
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
  elif ! printf '%s\n' "$out" | grep -qF -- "$3"; then
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
    if printf '%s\n' "$out" | grep -qF "message $m lacks"; then echo "self-test ok: proto-check reports $m"; else echo "SELF-TEST FAIL: proto-check does not report $m" >&2; rc=1; fi
  done
  for m in GoodRequest InlineGoodRequest GoodNextLineRequest StoreBlobRequest; do
    if printf '%s\n' "$out" | grep -qF "message $m "; then echo "SELF-TEST FAIL: proto-check reports the versioned $m" >&2; rc=1; else echo "self-test ok: proto-check accepts $m"; fi
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
  elif ! printf '%s\n' "$out" | grep -qF -- "$want"; then
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
if printf '%s\n' "$out" | grep -qF "DENIED dependency group 'org.signal'"; then
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
  elif ! printf '%s\n' "$out" | grep -qF -- "$3"; then
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
npb_case event-mismatch pass "[no-public-binaries] OK" ""
npb_case event-mismatch fail "the event payload says the repository is public; scripts/gates/repository-visibility.txt declares it private" "$NPB/event-mismatch/event.json"
npb_case no-declaration fail "scripts/gates/repository-visibility.txt missing" ""
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
  elif ! printf '%s\n' "$out" | grep -qF -- "$want"; then
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
if grep -q "used under: Apache-2.0" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-fixture.txt" && ! grep -q "LICENSE-APACHE of dual-pkg" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-fixture.txt" \
  && grep -q "NOTICE of https://github.com/fixture/apache-pkg" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-fixture.txt" \
  && grep -q "third_party/zlib/LICENSE of vendored-pkg" "$LIC_FIX/licenses/THIRD_PARTY_NOTICES-fixture.txt"; then
  echo "self-test ok: license-notices carries the upstream NOTICE and the vendored licence, and leaves out the unused alternative"
else
  echo "SELF-TEST FAIL: the fixture notices miss the upstream NOTICE or the vendored licence, or carry the unused alternative" >&2; rc=1
fi
hdr_env="$(lic_list headers)"
out="$(env GHOST_ROOT="$LIC_FIX" "$hdr_env" GHOST_LICENSE_EXCEPTIONS="$LIC_FIX/lists/headers-exceptions.txt" bash "$DIR/rust-license-headers.sh" 2>&1 || true)"
hdr_hits="$(printf '%s\n' "$out" | grep -c '^GATE-FAIL' || true)"
if [ "$hdr_hits" = "5" ]; then echo "self-test ok: rust-license-headers reports the 5 fixture violations"; else echo "SELF-TEST FAIL: rust-license-headers reported $hdr_hits of 5 fixture violations" >&2; rc=1; fi
for want in "agpl-header 1.0.0: src/lib.rs: SPDX-License-Identifier: AGPL-3.0-only" \
  "signal-copyright 1.0.0: src/lib.rs: a Signal Messenger copyright" \
  "gpl-notice 1.0.0: src/lib.rs: a GNU licence notice" \
  "gpl-text 1.0.0: COPYING: the text of a GNU licence" \
  "bad-expression 1.0.0: no alternative of 'GPL-3.0-only' is an allowed licence"; do
  if printf '%s\n' "$out" | grep -qF -- "$want"; then echo "self-test ok: rust-license-headers reports $want"; else echo "SELF-TEST FAIL: rust-license-headers does not report $want" >&2; rc=1; fi
done
lic_case rust-license-headers "scans GHOST's own crates and rejects an exception that matches nothing" fail "rust-license-exceptions.txt: clean 1.0.0 src/lib.rs is not needed" \
  "$(lic_list headers-own)" GHOST_LICENSE_EXCEPTIONS="$LIC_FIX/lists/headers-exceptions-unused.txt"
lic_case mpl-sources "accepts the MPL-2.0 manifest" pass "[mpl-sources] OK" "$(lic_list mpl)"
lic_case mpl-sources "rejects an MPL-2.0 package missing from the manifest" fail "mpl-pkg 1.0.0 is used under MPL-2.0 and missing from" "$(lic_list mpl)" GHOST_MPL_SOURCES="$LIC_FIX/licenses/mpl-sources-empty.txt"
lic_case mpl-sources "rejects a checksum Cargo.lock does not record" fail "mpl-pkg 1.0.0: mpl-sources.txt records 0000" "$(lic_list mpl)" GHOST_MPL_SOURCES="$LIC_FIX/licenses/mpl-sources-wrong-sum.txt"
lic_case mpl-sources "rejects a manifest line of a package no graph ships" fail "mpl-sources.txt: mpl-pkg 1.0.0 is not an MPL-2.0 package of a shipped graph" "$(lic_list mit-only)"
lic_case mpl-sources "rejects a [patch] of an MPL-2.0 package without a published diff" fail "[patch] on the MPL-2.0 package mpl-patched 1.0.0 without a published diff" "$(lic_list mpl-patched)" GHOST_MPL_SOURCES="$LIC_FIX/licenses/mpl-sources-patched.txt"
bundle="$(mktemp -d)"
lic_case mpl-sources "builds the source bundle from checked .crate archives" pass "[mpl-sources] OK" "$(lic_list mpl)" CARGO_HOME="$LIC_FIX" -- --bundle "$bundle"
if [ -f "$bundle/mpl-pkg-1.0.0.crate" ]; then echo "self-test ok: mpl-sources --bundle holds mpl-pkg-1.0.0.crate"; else echo "SELF-TEST FAIL: mpl-sources --bundle did not copy the .crate archive" >&2; rc=1; fi
rm -rf "$bundle"
# G-L1 android mode and G-L2 (gradle-license-allowlist.txt) on a fabricated Gradle cache: a POM and a
# classes jar with a NOTICE, built here (no binary fixture is committed).
jar_of() { # $1 = jar path, $2 = directory holding META-INF
  mkdir -p "$(dirname "$1")"
  if command -v zip >/dev/null; then (cd "$2" && zip -q -r "$1" META-INF)
  elif command -v jar >/dev/null; then (cd "$2" && jar cfM "$1" META-INF)
  else return 3; fi
}
gradle_case() { # $1 = description, $2 = pass|fail, $3 = expected text, $4 = allowlist lines, $5 = POM licences
  local w jarfile
  w="$(mktemp -d)"
  mkdir -p "$w/gradle/caches/modules-2/files-2.1/org.example/lib/1.0.0/0a1b" "$w/classes/META-INF"
  printf '<project><licenses>%s</licenses></project>\n' "$5" > "$w/gradle/caches/modules-2/files-2.1/org.example/lib/1.0.0/0a1b/lib-1.0.0.pom"
  printf 'org.example lib\nCopyright 2026 The lib fixture authors\n' > "$w/classes/META-INF/NOTICE.txt"
  jarfile="$w/gradle/caches/9.7.1/transforms/0a1b/transformed/lib-1.0.0-runtime.jar"
  if ! jar_of "$jarfile" "$w/classes"; then
    rm -rf "$w"
    if [ -n "${CI:-}" ]; then echo "SELF-TEST FAIL: no zip/jar in CI" >&2; rc=1; else echo "self-test skipped: license-notices android (no zip/jar)"; fi
    return
  fi
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
  elif ! printf '%s' "$out" | grep -qF "$want"; then
    echo "SELF-TEST FAIL: $desc failed without reporting: $want" >&2
    printf '%s\n' "$out" | tail -5 >&2; rc=1
  else
    echo "self-test ok: $desc"
  fi
}
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
  rm -f "$tmp"
  # ADR-37 (design §2.10.2, §22.8.10 point 1): cargo-deny takes package specs, not globs, so every
  # named ban of the libsignal family must fire on its own. A scratch package depends on a local crate
  # of each banned name; its lock file must fail with "bans FAILED", and a crate of an unbanned name
  # must pass. Needs the cargo-deny binary (the CI rust job installs it and sets GHOST_SELFTEST_DENY).
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
      if out="$(cargo deny --offline --manifest-path "$deny_fix/Cargo.toml" check bans 2>&1)"; then got=pass; else got=fail; fi
      if [ "$2" = fail ] && [ "$got" = fail ] && printf '%s\n' "$out" | grep -qF "crate '$1 = 0.1.0' is explicitly banned" && printf '%s\n' "$out" | grep -qF "bans FAILED"; then
        echo "self-test ok: cargo-deny bans FAILED on $1"
      elif [ "$2" = pass ] && [ "$got" = pass ] && printf '%s\n' "$out" | grep -qF "bans ok"; then
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
exit $rc
