#!/usr/bin/env bash
# Gate G-R7 (Phase 9 design §16.1 G-R7, §2.8 bump policy, §15.2 items 2 and 4, §22.9 item 15; ADR-35,
# ADR-36; S0′ gate slice, §22.33): **a vodozemac or libcrux bump cannot land without its drills.**
# What the tests of `ghost-client-dm` already hold per pin — the golden pickles and transcripts, the
# pinned `chainPosition` and `sessionPrune` outputs (`tests/golden.rs`), the dehydrated-pickle encoder
# check, PQ5, and the wildcard-free matches over the library's error enums (a variant added at a bump
# fails the build) — this script turns into a rule about the *change*:
#
#   always       the lock holds exactly one vodozemac version (a bump replaces, it never adds), its
#                golden directory `client-core/dm/tests/golden/vodozemac-<version>/` exists, and the
#                named tests exist (`cargo test -- --list`): the four golden tests, `UpgradeTest`
#                (`upgrade_every_previous_pin_loads_with_the_current_pin`) among them, the encoder
#                check, the PQ world and at least four `pq5_` tests;
#   at a vodozemac change against the base
#                the previous version's golden directory is still committed (the first pin is exempt:
#                a base without vodozemac has none), so `UpgradeTest` loads the previous pin's
#                pickles — pruned ones included — with the new pin and continues both ways;
#   at a vodozemac or libcrux change
#                the named tests run and each passes, none ignored: the goldens and `UpgradeTest`,
#                the encoder check, PQ5 and its world.
#
# The base is `--base <rev>` (CI passes the pull request's base or the push's previous head), else
# `$GHOST_GOLDEN_BASE`, else `HEAD~1`; it needs the git history (CI: fetch-depth 0) and fails closed
# without it. `--base none` declares that there is no base (the first pin).
#
# `--library <so>...` is G-R7 (c), the V-9 check that the linker still drops `hpke` (§2.9, §22.8.10
# point 13): in each shipped `libghost_client_net.so` (android-native, stripped release builds), none
# of the strings V-9 found only in RustCrypto's `hpke` and in vodozemac's HPKE and QR-login code
# (`HPKEXXYYZZ`, `MATRIX_QR_CODE_LOGIN`) and both of Olm's KDF labels (`OLM_KEYS`, `OLM_RATCHET`),
# without which the library would not hold the DM code this check is about. **Narrowed by Phase 10
# slice S2b** (faza10-forum.md §19.32): the library now links OpenMLS's HPKE, `hpke-rs` and
# `hpke-rs-libcrux` (ADR-40, the channel stack's audit scope, §3.7), whose RFC 9180 labels are the
# other two strings V-9 listed (`HPKE-v1` in `hpke-rs/src/kdf.rs` and `hpke-rs-libcrux`, `psk_id_hash`
# in `hpke-rs/src/lib.rs`); they say nothing about RustCrypto's `hpke` any more, so the check keeps the
# two strings only that crate (`HPKEXXYYZZ`, its suite-id template in `hpke/src/util.rs`) and
# vodozemac's QR login carry. Measured on S2b's libraries: both absent, both Olm labels present.
#
# Runs in the CI `rust` job and in rust-gates.sh (pins, goldens, tests) and in `android-native`
# (`--library`). Self-test hooks: GHOST_GOLDEN_LOCK=<file> reads the current lock from a file;
# GHOST_GOLDEN_BASE_LOCK=<file> reads the base's lock from a file instead of git; GHOST_GOLDEN_DIR=<dir>
# replaces `client-core/dm/tests/golden`; GHOST_GOLDEN_NO_TESTS=1 skips the cargo test list and runs.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
# The test output of the drills is parsed below: plain whatever the job exports (the CI rust job
# exports CARGO_TERM_COLOR=always; see dm-vendored-clock-log.sh for what colour did to a parse).
export CARGO_TERM_COLOR=never
cd "$GHOST_ROOT"

usage() { echo "usage: dm-golden-lock.sh [--base <rev>|none] | --library <libghost_client_net.so>..." >&2; exit 2; }
base="${GHOST_GOLDEN_BASE:-HEAD~1}"
libraries=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --base) [ -n "${2:-}" ] || usage; base="$2"; shift 2 ;;
    --library) shift; [ "$#" -gt 0 ] || usage; while [ "$#" -gt 0 ] && [ "${1#--}" = "$1" ]; do libraries+=("$1"); shift; done ;;
    *) usage ;;
  esac
done

if [ "${#libraries[@]}" -gt 0 ]; then
  for so in "${libraries[@]}"; do
    [ -f "$so" ] || { fail "$so: no such library"; continue; }
    for s in HPKEXXYYZZ MATRIX_QR_CODE_LOGIN; do
      if grep -a -F -q -- "$s" "$so"; then fail "$so: contains '$s' (G-R7 (c): RustCrypto's hpke is no longer dropped by the linker; V-9 must be re-run and the audit scope re-decided, §2.9)"; fi
    done
    for s in OLM_KEYS OLM_RATCHET; do
      grep -a -F -q -- "$s" "$so" || fail "$so: does not contain '$s' (the library holds no Olm code: the hpke check would pass vacuously)"
    done
  done
  finish dm-golden-lock
  # `finish` exits only on a failure: the library check is the whole of this mode, and the pin rule
  # below needs the git history the `android-native` job's shallow checkout does not have (its first
  # run, 36233077404, fell through to it and failed "the repository is shallow" after "OK").
  exit 0
fi

# Versions of one package name in a Cargo.lock text: `name version` lines.
lock_versions() { # $1 = lock text, $2 = name regex
  awk -v re="^($2)\$" '
    /^\[\[package\]\]/ { name = ""; next }
    /^name = / { gsub(/"/, "", $3); name = $3; next }
    /^version = / && name ~ re { gsub(/"/, "", $3); print name " " $3 }' <<< "$1" | sort -u
}
current_lock="$(cat "${GHOST_GOLDEN_LOCK:-Cargo.lock}")"
if [ -n "${GHOST_GOLDEN_BASE_LOCK:-}" ]; then
  base_lock="$(cat "$GHOST_GOLDEN_BASE_LOCK")"
elif [ "$base" = none ]; then
  base_lock=""
else
  command -v git >/dev/null || { echo "git not found" >&2; exit 2; }
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    fail "the repository is shallow: G-R7 needs the base's Cargo.lock (CI: fetch-depth 0), or --base none for the first pin"
    finish dm-golden-lock
  fi
  if ! base_lock="$(git show "$base:./Cargo.lock" 2>/dev/null)"; then
    fail "cannot read Cargo.lock at the base '$base' (G-R7 fails closed; pass --base <rev> or --base none)"
    finish dm-golden-lock
  fi
fi

vz_now="$(lock_versions "$current_lock" vodozemac | awk '{print $2}')"
vz_base="$(lock_versions "$base_lock" vodozemac | awk '{print $2}')"
crux_now="$(lock_versions "$current_lock" 'libcrux-[a-z0-9-]+')"
crux_base="$(lock_versions "$base_lock" 'libcrux-[a-z0-9-]+')"
GOLDEN="${GHOST_GOLDEN_DIR:-client-core/dm/tests/golden}"

case "$(grep -c . <<< "$vz_now")" in
  1) ;;
  0) fail "the lock holds no vodozemac (the DM crate's pin is gone; the gate would pass vacuously)"; finish dm-golden-lock ;;
  *) fail "the lock holds several vodozemac versions ($(tr '\n' ' ' <<< "$vz_now")): a bump replaces the pin, it never adds one"; finish dm-golden-lock ;;
esac
vz_now="$(head -1 <<< "$vz_now")"
[ -f "$GOLDEN/vodozemac-$vz_now/olm-session.txt" ] || \
  fail "$GOLDEN/vodozemac-$vz_now/olm-session.txt is missing: every pin commits its goldens (GHOST_DM_GOLDEN_WRITE=1 cargo test -p ghost-client-dm --test golden)"

vz_changed=0; crux_changed=0
if [ -n "$vz_base" ] && [ "$vz_base" != "$vz_now" ]; then
  vz_changed=1
  for v in $vz_base; do
    [ -f "$GOLDEN/vodozemac-$v/olm-session.txt" ] || \
      fail "vodozemac $v -> $vz_now: the previous pin's goldens $GOLDEN/vodozemac-$v/ are gone; keep them until UpgradeTest has loaded them with the new pin (design 2.8, 15.2 item 2)"
  done
fi
[ -n "$vz_base" ] || echo "[dm-golden-lock] no vodozemac at the base: first pin, exempt from the previous-pin drill"
[ "$crux_now" = "$crux_base" ] || [ -z "$crux_base" ] || crux_changed=1
echo "[dm-golden-lock] vodozemac ${vz_base:-none} -> $vz_now; libcrux $([ "$crux_changed" = 1 ] && echo changed || echo unchanged) (base: $base)"

if [ "${GHOST_GOLDEN_NO_TESTS:-}" != 1 ]; then
  command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
  work="$(mktemp -d)"
  trap 'rc=$?; rm -rf "$work"; exit $rc' EXIT
  GOLDEN_TESTS=(golden_pickles_load_and_both_sides_continue golden_chain_positions_are_pinned
    golden_prune_outputs_are_pinned_and_the_pruned_state_continues upgrade_every_previous_pin_loads_with_the_current_pin)
  LIB_TESTS=(olm::account::tests::ghost_reencodes_vodozemacs_own_dehydrated_device
    pq_bump::pq_world_every_honest_flight_opens_and_every_root_arrives)
  cargo test --locked -q -p ghost-client-dm --test golden -- --list > "$work/golden.list" 2>"$work/err" || { cat "$work/err" >&2; fail "cargo test --list (golden) failed"; finish dm-golden-lock; }
  cargo test --locked -q -p ghost-client-dm --lib -- --list > "$work/lib.list" 2>"$work/err" || { cat "$work/err" >&2; fail "cargo test --list (lib) failed"; finish dm-golden-lock; }
  for t in "${GOLDEN_TESTS[@]}"; do grep -qxF "$t: test" "$work/golden.list" || fail "tests/golden.rs has no test $t"; done
  for t in "${LIB_TESTS[@]}"; do grep -qxF "$t: test" "$work/lib.list" || fail "ghost-client-dm has no test $t"; done
  pq5="$(grep -cE '^pq_bump::pq5_[a-z0-9_]+: test$' "$work/lib.list" || true)"
  [ "$pq5" -ge 4 ] || fail "ghost-client-dm lists $pq5 PQ5 tests (pq_bump::pq5_*), fewer than the 4 of RG-5"
  if [ "$vz_changed" = 1 ] || [ "$crux_changed" = 1 ]; then
    # libtest prints `test <name> ... ok`; every named test must be among the passes.
    cargo test --locked -p ghost-client-dm --test golden 2>&1 | tr -d '\r' > "$work/golden.run" || true
    cargo test --locked -p ghost-client-dm --lib -- pq5_ pq_world_ ghost_reencodes_vodozemacs_own_dehydrated_device 2>&1 | tr -d '\r' > "$work/lib.run" || true
    for f in golden lib; do
      grep -qE '^test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;' "$work/$f.run" || \
        fail "the $f drill did not pass with 0 ignored: $(grep -E '^test result:' "$work/$f.run" | head -1)"
    done
    for t in "${GOLDEN_TESTS[@]}"; do grep -qxF "test $t ... ok" "$work/golden.run" || fail "at the bump, $t did not run and pass"; done
    for t in "${LIB_TESTS[@]}"; do grep -qxF "test $t ... ok" "$work/lib.run" || fail "at the bump, $t did not run and pass"; done
    ran="$(grep -cE '^test pq_bump::pq5_[a-z0-9_]+ \.\.\. ok$' "$work/lib.run" || true)"
    [ "$ran" -ge 4 ] || fail "at the bump, $ran PQ5 tests ran and passed, fewer than 4"
    echo "[dm-golden-lock] bump drills: $(grep -c ' \.\.\. ok$' "$work/golden.run") golden tests and $(grep -c ' \.\.\. ok$' "$work/lib.run") encoder, PQ world and PQ5 tests passed"
  fi
fi
finish dm-golden-lock
