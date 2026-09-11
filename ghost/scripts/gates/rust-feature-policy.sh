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
#  and, for the whole workspace on every target: rsa may only be reached through Arti's crates
#  (re-review RUSTSEC-2023-0071 in deny.toml before any GHOST crate depends on rsa).
# Every cargo query result is stored in a variable first, so a failing `cargo tree` (e.g. an
# ambiguous spec after an Arti bump) aborts the gate instead of being read as "no features".
# Self-test hooks (scripts/gates/self-test.sh): GHOST_POLICY_REQUIRE_EXTRA / _FORBID_EXTRA add an
# arti-client feature to the required / forbidden list; GHOST_POLICY_FORBID_ON="crate:feature"
# forbids one more feature on one more crate; GHOST_POLICY_RSA_ALLOWED overrides the allowed rsa
# dependents; GHOST_POLICY_BAD_SPEC="crate" makes that crate's query fail.
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

# rsa: direct dependents across the whole workspace, all targets, must be Arti crates only.
rsa_raw="$(tree --workspace -i rsa -e normal,build --depth 1 --target all --prefix none -f '{p}')"
rsa_users="$(printf '%s\n' "$rsa_raw" | awk 'NR>1 && NF {print $1}' | sort -u)"
allowed_rsa="${GHOST_POLICY_RSA_ALLOWED:-tor-llcrypto tor-key-forge ssh-key-fork-arti}"
while IFS= read -r u; do
  [ -n "$u" ] || continue
  if ! printf '%s\n' $allowed_rsa | grep -qx "$u"; then
    fail "'$u' depends on rsa directly: re-review RUSTSEC-2023-0071 in deny.toml first"
  fi
done <<< "$rsa_users"
finish rust-feature-policy
