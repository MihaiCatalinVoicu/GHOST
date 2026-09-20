#!/usr/bin/env bash
# Gate (ADR-01, ADR-16, ADR-19; review 2026-09-11): Arti and tonic feature policy for the client
# library, checked on the shipped (non-dev) graph for every target.
#  required: onion-service-client + vanguards (arti-client), vanguards (tor-circmgr);
#  forbidden until an ADR enables them:
#   - relay (tor-proto, tor-chanmgr, tor-llcrypto: the Arti 0.46 crates whose `relay` feature adds
#     relay code), onion-service-service (arti-client) and the packages tor-hsservice / arti-relay /
#     tor-relay-crypto: relay and onion-service code paths are the ones that sign or decrypt with
#     RSA private keys (RSA key-pair code itself is compiled in tor-llcrypto regardless).
#     tor-cell/relay is NOT checked: tor-proto 0.46 enables it unconditionally, and it only adds
#     one certificate-encoding helper (CertsCell::push_cert; reviewed 2026-09-11);
#   - keymgr / ctor-keystore / ephemeral-keystore on arti-client and keymgr on tor-hsclient
#     (experimental; the native keystore Arti opens through tor-chanmgr must stay empty, which
#     the client tests check);
#   - pt-client (Phase 12), hs-pow-full, experimental-api, experimental, full (arti-client);
#   - any tonic feature beyond `codegen` (Channel/Endpoint = clearnet dialer with system DNS);
#   - ghost-client-net's own `clippy-fixture` feature (negative fixture, never shipped);
#  and, for the whole workspace on every target, rsa per version (ADR-22, Phase 8 design §14.1):
#  rsa 0.9.10 only through Arti's crates, rsa 0.10.0-rc.18 only through blind-rsa-signatures (the
#  issuer's signer); re-review RUSTSEC-2023-0071 in deny.toml before either scope changes. The
#  issuer-only crates (blind-rsa-signatures, crypto-bigint 0.7.5, md-5, ghost-issuer and the operator
#  tools ghost-issuer-ops) must not be linked into the client library (both Android targets) or the
#  relay node (normal and build edges).
#  and, for the DM stack (Phase 9 design §16.1 G-R2, ADR-35), vodozemac without `libolm-compat`,
#  `low-level-api`, `experimental-session-config` or `insecure-pk-encryption`, and `ghost-client-dm`
#  with no feature of its own but `jni-bridge` (its `default` is the empty list). Both crates must
#  be present in the shipped graph, or the clause would hold vacuously.
# Every cargo query result is stored in a variable first, so a failing `cargo tree` (e.g. an
# ambiguous spec after an Arti bump) aborts the gate instead of being read as "no features".
# Self-test hooks (scripts/gates/self-test.sh): GHOST_POLICY_REQUIRE_EXTRA / _FORBID_EXTRA add an
# arti-client feature to the required / forbidden list; GHOST_POLICY_FORBID_ON="crate:feature"
# forbids one more feature on one more crate; GHOST_POLICY_RSA_ALLOWED / GHOST_POLICY_RSA10_ALLOWED
# override the allowed direct dependents of rsa 0.9.10 / 0.10.0-rc.18; GHOST_POLICY_ISSUER_ONLY_EXTRA
# adds a package to the issuer-only list; GHOST_POLICY_BAD_SPEC="crate" makes that crate's query fail;
# GHOST_POLICY_DM_GRAPH replaces the packages the DM stack must contribute to the shipped graph and
# GHOST_POLICY_DM_FORBID_EXTRA drops one name from `ghost-client-dm`'s allowed feature list.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
cd "$GHOST_ROOT"
err="$(mktemp)"
trap 'rm -f "$err"' EXIT

tree() { # args passed to cargo tree; on error: print cargo's stderr and exit non-zero
  if ! cargo tree --locked "$@" 2>"$err"; then
    cat "$err" >&2
    echo "GATE-FAIL: cargo tree $* failed" >&2
    echo "[rust-feature-policy] FAILED (cargo tree error)" >&2
    return 1
  fi
}
features() { # $1 = crate; features enabled on it in the shipped client graph
  local spec="$1" out
  [ "${GHOST_POLICY_BAD_SPEC:-}" = "$1" ] && spec="$1@0.0.0-no-such-version"
  out="$(tree -p ghost-client-net -e features,no-dev -i "$spec" --target all)" || return 1
  # No match only means "no features" (grep exit 1), not a query error: that was handled above.
  { printf '%s\n' "$out" | grep -oE "$1 feature \"[a-z0-9_-]+\"" || true; } \
    | sed -E 's/.*"(.*)"/\1/' | sort -u
}
has() { printf '%s\n' "$1" | grep -qx "$2"; }

arti="$(features arti-client)"
[ -n "$arti" ] || { fail "no arti-client features resolved"; finish rust-feature-policy; }
for f in onion-service-client vanguards ${GHOST_POLICY_REQUIRE_EXTRA:-}; do
  has "$arti" "$f" || fail "arti-client feature '$f' must be enabled"
done
circ="$(features tor-circmgr)"
has "$circ" vanguards || fail "tor-circmgr feature 'vanguards' must be enabled"
for f in onion-service-service keymgr ctor-keystore ephemeral-keystore pt-client hs-pow-full \
  experimental-api experimental full ${GHOST_POLICY_FORBID_EXTRA:-}; do
  if has "$arti" "$f"; then fail "arti-client feature '$f' is enabled without an ADR"; fi
done

forbid_on=("tor-proto:relay" "tor-chanmgr:relay" "tor-llcrypto:relay" "tor-hsclient:keymgr")
# G-R2 (Phase 9 design §16.1, ADR-35): the DM stack's Olm library ships without `libolm-compat`,
# `low-level-api`, `experimental-session-config` and `insecure-pk-encryption`. `low-level-api` is a
# **dev** feature of the key-schedule oracle, which this query cannot see (`no-dev`); a normal
# dependency that turned any of these on would otherwise pass every gate.
forbid_on+=("vodozemac:libolm-compat" "vodozemac:low-level-api")
forbid_on+=("vodozemac:experimental-session-config" "vodozemac:insecure-pk-encryption")
[ -n "${GHOST_POLICY_FORBID_ON:-}" ] && forbid_on+=("$GHOST_POLICY_FORBID_ON")
for pair in "${forbid_on[@]}"; do
  crate="${pair%%:*}"
  feat="${pair#*:}"
  got="$(features "$crate")"
  if has "$got" "$feat"; then fail "$crate feature '$feat' is enabled in the client"; fi
done

tonic_f="$(features tonic)"
while IFS= read -r f; do
  case "$f" in
    ''|codegen) ;;
    *) fail "tonic feature '$f' is enabled in the client (only 'codegen' is allowed)" ;;
  esac
done <<< "$tonic_f"

own="$(features ghost-client-net)"
if has "$own" clippy-fixture; then fail "ghost-client-net feature 'clippy-fixture' is enabled"; fi

pkgs_raw="$(tree -p ghost-client-net -e normal --target all --prefix none -f '{p}')"
pkgs="$(printf '%s\n' "$pkgs_raw" | awk '{print $1}' | sort -u)"
for p in tor-hsservice arti-relay tor-relay-crypto; do
  if has "$pkgs" "$p"; then fail "package '$p' is linked into the client"; fi
done

# G-R2, second half: the DM crate ships with **no feature of its own** beyond `jni-bridge` (its
# `default` is the empty list, §16.1). `provenance` turns the PQ-B assertions of T35 into runtime
# checks and belongs to tests; anything else is a feature nobody approved for the shipped library.
# The vodozemac clause above is only meaningful while the library really is in this graph, so the
# two packages that carry it are checked for presence: a DM stack dropped from
# `libghost_client_net.so` must fail loudly, not silently pass a feature policy about it.
for p in ${GHOST_POLICY_DM_GRAPH:-ghost-client-dm vodozemac}; do
  if ! has "$pkgs" "$p"; then
    fail "package '$p' is not in the shipped client graph: G-R2's vodozemac clause would be vacuous"
  fi
done
dm_allowed="default jni-bridge"
[ -n "${GHOST_POLICY_DM_FORBID_EXTRA:-}" ] \
  && dm_allowed="$(printf '%s\n' $dm_allowed | grep -vx "$GHOST_POLICY_DM_FORBID_EXTRA" || true)"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if ! printf '%s\n' $dm_allowed | grep -qx "$f"; then
    fail "ghost-client-dm feature '$f' is enabled in the client; G-R2 allows: $(echo $dm_allowed)"
  fi
done <<< "$(features ghost-client-dm)"

# rsa, per version: direct dependents across the whole workspace, all targets (dev edges excluded,
# so the differential test's dev-dependency on the reference signer does not count).
check_rsa() { # $1 = version, $2 = allowed direct dependents
  local raw users u
  raw="$(tree --workspace -i "rsa@$1" -e normal,build --depth 1 --target all --prefix none -f '{p}')" || { FAILURES=$((FAILURES + 1)); return; }
  users="$(printf '%s\n' "$raw" | awk 'NR>1 && NF {print $1}' | sort -u)"
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    if ! printf '%s\n' $2 | grep -qx "$u"; then
      fail "'$u' depends on rsa $1 directly: re-review RUSTSEC-2023-0071 in deny.toml first"
    fi
  done <<< "$users"
}
check_rsa 0.9.10 "${GHOST_POLICY_RSA_ALLOWED:-tor-llcrypto tor-key-forge ssh-key-fork-arti}"
check_rsa 0.10.0-rc.18 "${GHOST_POLICY_RSA10_ALLOWED:-blind-rsa-signatures}"

# Issuer-only packages ("name" or "name@version") stay out of the client and relay graphs.
issuer_only="blind-rsa-signatures crypto-bigint@0.7.5 md-5 ghost-issuer ghost-issuer-ops ${GHOST_POLICY_ISSUER_ONLY_EXTRA:-}"
check_absent() { # $1 = graph label, $2 = packages ("name vX.Y.Z" lines)
  local spec name version
  for spec in $issuer_only; do
    name="${spec%@*}"
    version=""
    [ "$spec" != "$name" ] && version="${spec#*@}"
    if printf '%s\n' "$2" | awk -v n="$name" -v v="v$version" '$1 == n && (v == "v" || $2 == v) {found = 1} END {exit !found}'; then
      fail "package '$spec' is linked into $1: issuer graphs only (ADR-22)"
    fi
  done
}
for t in aarch64-linux-android x86_64-linux-android; do # keep in sync with scripts/build-native.sh
  client_raw="$(tree -p ghost-client-net -e normal,build --target "$t" --prefix none -f '{p}')" || { FAILURES=$((FAILURES + 1)); continue; }
  check_absent "ghost-client-net ($t)" "$client_raw"
done
relay_raw="$(tree -p ghost-relay-node -e normal,build --target all --prefix none -f '{p}')" && check_absent "ghost-relay-node" "$relay_raw" || true
[ -n "${relay_raw:-}" ] || fail "no ghost-relay-node packages resolved"
finish rust-feature-policy
