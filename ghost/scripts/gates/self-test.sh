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
