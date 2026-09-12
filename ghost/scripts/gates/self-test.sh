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
# Phase 7 crash fidelity: every catch-all form in the fixture is reported, one line each.
expect_fail sync-no-catch-all "$HARNESS/negative-sync"
sync_hits="$(GHOST_ROOT="$HARNESS/negative-sync" bash "$DIR/sync-no-catch-all.sh" 2>&1 | grep -c '^GATE-FAIL' || true)"
if [ "$sync_hits" = "9" ]; then echo "self-test ok: sync-no-catch-all reports all 9 fixture lines"; else echo "SELF-TEST FAIL: sync-no-catch-all reported $sync_hits of 9 fixture lines" >&2; rc=1; fi
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
  service/src/service.rs:10: service/src/status.rs:4: service/src/store.rs:4: ops/src/report.rs:4: ops/src/output.rs:4: \
  ops/src/keygen.rs:3: api/src/lib.rs:3:; do
  if printf '%s\n' "$out" | grep -qF "issuer/crates/$want"; then
    echo "self-test ok: issuer-output reports $want"
  else
    echo "SELF-TEST FAIL: issuer-output does not report $want" >&2; rc=1
  fi
done
for allowed in service/src/status.rs:3: service/src/store.rs:3: ops/src/report.rs:3: ops/src/output.rs:3:; do
  if printf '%s\n' "$out" | grep -qF "issuer/crates/$allowed"; then
    echo "SELF-TEST FAIL: issuer-output reports the allowed $allowed" >&2; rc=1
  else
    echo "self-test ok: issuer-output allows $allowed"
  fi
done
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
