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
#  and, for the channel stack (Phase 10 design faza10-forum.md §3.2, §13.1 G-M2, ADR-40), none of
#  §3.2's forbidden OpenMLS, openmls_traits, provider and hpke-rs features in ghost-client-mls's
#  graph and ghost-client-net's (which links it since slice S2b), no feature of ghost-client-mls's own
#  in its own graph and only `jni-bridge` in the shipped one (`test-vectors` is ghost-dm-host's),
#  `test-utils` only as a dev-dependency of ghost-client-mls-kat, no workspace package naming the
#  memory storage, the basic credential, the RustCrypto provider, openmls_test or the SQLite storage,
#  the SQLite stand-in exactly as reviewed (by hash) and unreachable, and no GHOST source naming the
#  memory storage or the basic credential or calling the four forbidden group entry points.
#  `hpke-rs/hazmat` is not forbidden: openmls_libcrux_crypto 0.4.0 enables it unconditionally (its
#  manifest; the provider reads private keys with `HpkePrivateKey::as_slice`, which only `hazmat`
#  compiles). It also makes hpke-rs's `Debug` print private-key bytes and context secrets: GHOST code
#  never formats a provider or OpenMLS value (no logging, G-M4; MlsError carries codes only; S2a §19.30).
#  And G-R2 for the seeded stream (§12.1, S0-7): ghost-host-rng in no shipped graph, no shipped build
#  configuration naming `getrandom_backend`, and one getrandom major in each host graph.
# Every cargo query result is stored in a variable first, so a failing `cargo tree` (e.g. an
# ambiguous spec after an Arti bump) aborts the gate instead of being read as "no features".
# Self-test hooks (scripts/gates/self-test.sh): GHOST_POLICY_REQUIRE_EXTRA / _FORBID_EXTRA add an
# arti-client feature to the required / forbidden list; GHOST_POLICY_FORBID_ON="crate:feature"
# forbids one more feature on one more crate; GHOST_POLICY_RSA_ALLOWED / GHOST_POLICY_RSA10_ALLOWED
# override the allowed direct dependents of rsa 0.9.10 / 0.10.0-rc.18; GHOST_POLICY_ISSUER_ONLY_EXTRA
# adds a package to the issuer-only list; GHOST_POLICY_BAD_SPEC="crate" makes that crate's query fail;
# GHOST_POLICY_DM_GRAPH replaces the packages the DM stack must contribute to the shipped graph and
# GHOST_POLICY_DM_FORBID_EXTRA drops one name from `ghost-client-dm`'s allowed feature list;
# GHOST_POLICY_MLS_FORBID_EXTRA adds "crate:feature" pairs to G-M2's forbidden list,
# GHOST_POLICY_MLS_GRAPH replaces the packages ghost-client-mls's graph must hold, GHOST_POLICY_KAT
# names the one package allowed openmls/test-utils (as a dev-dependency), GHOST_POLICY_STUB_DIR
# points the stand-in check at another directory, GHOST_POLICY_MLS_SOURCES at another source root,
# GHOST_POLICY_HOST_ONLY_EXTRA adds a package that must stay out of the shipped graphs,
# GHOST_POLICY_SHIPPED_CONFIGS replaces the build configurations that must not name the backend cfg,
# and GHOST_POLICY_ROOT_MANIFEST / GHOST_POLICY_LOCK replace the manifest and lock whose [patch],
# [replace] and sources are checked (review of S2a, F7).
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
# A here-string, not `printf ... | grep -qx ...`: under `set -o pipefail`, grep's early exit on a
# match can SIGPIPE printf while it is still writing a large haystack (e.g. `pkgs`, the whole
# shipped dependency graph), and the pipeline's exit status then reflects the SIGPIPE, not the
# match (self-test.sh and clippy-clearnet-fixture.sh hit the same class; see their comments).
has() { grep -qx "$2" <<< "$1"; }

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
  if ! grep -qx "$f" <<< "$(printf '%s\n' $dm_allowed)"; then
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
    if ! grep -qx "$u" <<< "$(printf '%s\n' $2)"; then
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
# ---- G-M2 (Phase 10 design faza10-forum.md §3.2, §13.1; ADR-40; slice S2a) ----------------------
# The OpenMLS stack ships with none of its forbidden features. `ghost-client-mls` is checked now;
# `ghost-client-net` too as soon as it links the stack (slice S2b). The forbidden lists are §3.2's,
# plus the provider-side switches that would make HPKE deterministic or add suites
# (`hpke-rs-libcrux/deterministic-prng`, the draft KEMs, the RustCrypto curves); and
# `ghost-client-mls` has no feature of its own in its own graph, and only `jni-bridge` in the shipped
# one (slice S2b).
mls_forbidden="openmls:crypto-debug openmls:content-debug openmls:test-utils openmls:targeted-messages-draft
openmls:virtual-clients-draft openmls:sqlite-provider openmls:js openmls:js-test openmls:backtrace
openmls:0-8-1-storage-format openmls:migration-import openmls:extensions-draft openmls:fork-resolution
openmls:draft-ietf-mls-pq-ciphersuites openmls:all-ciphersuites openmls:generate-kats
openmls:unchecked-conversions openmls:libcrux-provider openmls:extensions-draft-test-dependencies
openmls:virtual-clients-draft-test-dependencies
openmls_traits:crypto-debug openmls_traits:test-utils openmls_traits:draft-ietf-mls-pq-ciphersuites
openmls_traits:extensions-draft openmls_traits:targeted-messages-draft openmls_traits:virtual-clients-draft
openmls_libcrux_crypto:draft-ietf-mls-pq-ciphersuites openmls_libcrux_crypto:extensions-draft
openmls_libcrux_crypto:targeted-messages-draft openmls_libcrux_crypto:virtual-clients-draft
hpke-rs:hpke-test hpke-rs:hpke-test-prng hpke-rs:experimental hpke-rs:rustcrypto
hpke-rs:draft-connolly-cfrg-hpke-mlkem hpke-rs:libcrux-rustcrypto-p-curves
hpke-rs-libcrux:deterministic-prng hpke-rs-libcrux:draft-connolly-cfrg-hpke-mlkem hpke-rs-libcrux:rustcrypto-p-curves
${GHOST_POLICY_MLS_FORBID_EXTRA:-}"
graph_features() { # $1 = root package, $2 = crate: its features in the root's normal graph
  local out
  out="$(tree -p "$1" -e features,no-dev -i "$2" --target all)" || return 1
  { printf '%s\n' "$out" | grep -oE "$2 feature \"[a-z0-9_-]+\"" || true; } | sed -E 's/.*"(.*)"/\1/' | sort -u
}
if ! mls_pkgs="$(tree -p ghost-client-mls -e normal --target all --prefix none -f '{p}')"; then
  FAILURES=$((FAILURES + 1))
  mls_pkgs=""
fi
mls_pkgs="$(awk '{print $1}' <<< "$mls_pkgs" | sort -u)"
for p in ${GHOST_POLICY_MLS_GRAPH:-ghost-client-mls openmls openmls_libcrux_crypto hpke-rs-libcrux}; do
  has "$mls_pkgs" "$p" || fail "package '$p' is not in ghost-client-mls's graph: G-M2's feature clauses would be vacuous"
done
roots="ghost-client-mls"
if has "$pkgs" openmls; then roots="$roots ghost-client-net"; fi
for root in $roots; do
  root_pkgs="$mls_pkgs"
  [ "$root" = ghost-client-net ] && root_pkgs="$pkgs"
  for pair in $mls_forbidden; do
    crate="${pair%%:*}"
    feat="${pair#*:}"
    has "$root_pkgs" "$crate" || continue
    got="$(graph_features "$root" "$crate")" || { FAILURES=$((FAILURES + 1)); continue; }
    if has "$got" "$feat"; then fail "$crate feature '$feat' is enabled in $root's graph (G-M2, design §3.2)"; fi
  done
done
while IFS= read -r f; do
  [ -n "$f" ] || continue
  [ "$f" = default ] || fail "ghost-client-mls feature '$f' is enabled in its own graph; G-M2 allows none there"
done <<< "$(graph_features ghost-client-mls ghost-client-mls)"
# Slice S2b links the crate into the shipped library with its JNI export: in ghost-client-net's
# graph the crate must be present (or the clauses above would be vacuous for the shipped library)
# and carry `jni-bridge` and nothing else of its own — `test-vectors`, the JDK replay's entry point,
# belongs to ghost-dm-host alone (G-M6 refuses a shipped library that exports it).
has "$pkgs" ghost-client-mls || fail "package 'ghost-client-mls' is not in the shipped client graph: slice S2b links it (G-M2, G-M6)"
mls_allowed="default jni-bridge"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if ! grep -qx "$f" <<< "$(printf '%s\n' $mls_allowed)"; then
    fail "ghost-client-mls feature '$f' is enabled in the shipped client graph; G-M2 allows: $(echo $mls_allowed)"
  fi
done <<< "$(features ghost-client-mls)"

# `test-utils` only in ghost-client-mls-kat, and there only as a dev-dependency; no workspace
# package depends directly on the memory storage, the basic credential, OpenMLS's RustCrypto
# provider or its test macros (G-M2; the libcrux provider's own dependency on the memory storage is
# upstream's, and the linker drops it, V10-3).
# The perl reader is fail-closed (review of S2a, F3): its output is taken whole, a perl that fails
# fails the gate, and it must report the packages it read (a reader that read none is vacuous).
if meta="$(cargo metadata --locked --no-deps --format-version 1 2>"$err")"; then
  if ! meta_out="$(KAT="${GHOST_POLICY_KAT:-ghost-client-mls-kat}" perl -MJSON::PP -e '
    local $/; my $m = JSON::PP->new->decode(<STDIN>);
    my %banned = map { $_ => 1 } qw(openmls_memory_storage openmls_basic_credential openmls_rust_crypto openmls_test openmls_sqlite_storage);
    for my $p (@{ $m->{packages} }) {
      for my $d (@{ $p->{dependencies} }) {
        print "$p->{name} depends on $d->{name} directly (G-M2: GHOST code never names it)\n" if $banned{$d->{name}};
        next unless $d->{name} eq "openmls";
        my %f = map { $_ => 1 } @{ $d->{features} || [] };
        next unless $f{"test-utils"};
        my $kind = $d->{kind} // "normal";
        print "$p->{name} enables openmls/test-utils ($kind); G-M2 allows it only as a dev-dependency of $ENV{KAT}\n"
          if $p->{name} ne $ENV{KAT} || $kind ne "dev";
      }
    }
    print "PACKAGES-READ " . scalar(@{ $m->{packages} }) . "\n";' <<< "$meta")"; then
    fail "the workspace metadata reader (perl) failed: G-M2's test-utils and banned-name clauses are unproven"
    meta_out=""
  fi
  read_n="$(sed -n 's/^PACKAGES-READ //p' <<< "$meta_out")"
  [ "${read_n:-0}" -gt 0 ] || fail "the workspace metadata reader read no package (G-M2's test-utils and banned-name clauses would pass vacuously)"
  while IFS= read -r line; do
    [ -n "$line" ] && fail "$line"
  done < <(grep -v '^PACKAGES-READ ' <<< "$meta_out" || true)
else
  cat "$err" >&2
  fail "cargo metadata failed"
fi

# No fork of a pinned crate through the manifest (review of S2a, F7): the workspace's `[patch]` tables
# may name only the reviewed stand-in (`openmls_sqlite_storage` under `[patch.crates-io]`), and it has
# no `[replace]`; and every package of Cargo.lock that is not a workspace member comes from the
# crates.io registry with a checksum — so a copied `third_party/openmls` patched in with one added
# function, or a git source, fails here, where every other PR gate passed it. Fail-closed, like the
# readers above. Hooks: GHOST_POLICY_ROOT_MANIFEST, GHOST_POLICY_LOCK.
ROOT_MANIFEST="${GHOST_POLICY_ROOT_MANIFEST:-$GHOST_ROOT/Cargo.toml}"
LOCK="${GHOST_POLICY_LOCK:-$GHOST_ROOT/Cargo.lock}"
if [ -z "${meta:-}" ]; then
  fail "no workspace metadata: the patch and lock-source clause is unproven"
elif ! patch_out="$(MANIFEST="$ROOT_MANIFEST" LOCK="$LOCK" perl -MJSON::PP -e '
    local $/;
    my $m = JSON::PP->new->decode(<STDIN>);
    my %member = map { ("$_->{name} $_->{version}" => 1) } @{ $m->{packages} };
    open(my $fh, "<", $ENV{MANIFEST}) or die "cannot read $ENV{MANIFEST}\n";
    my $toml = <$fh>;
    close $fh;
    my ($table, $n) = ("", 0);
    for my $line (split /\n/, $toml) {
      $n++;
      (my $l = $line) =~ s/^\s+|\s+$//g;
      next if $l eq "" || $l =~ /^#/;
      if ($l =~ /^\[\s*([^\]]+?)\s*\]$/) {
        $table = $1;
        if ($table =~ /^replace(\.|$)/) { print "Cargo.toml:$n: a [replace] table (G-M2: no replaced crate)\n" }
        elsif ($table =~ /^patch\.(?:crates-io|"crates-io")\.("?)([\w-]+)\1$/) {
          print "Cargo.toml:$n: [patch.crates-io] names $2 (G-M2: only the reviewed openmls_sqlite_storage stand-in)\n" unless $2 eq "openmls_sqlite_storage";
        }
        elsif ($table =~ /^patch\.(.+)$/ && $1 !~ /^(?:crates-io|"crates-io")$/) { print "Cargo.toml:$n: a [$table] table (G-M2: patches of crates.io only, and only the stand-in)\n" }
        next;
      }
      next unless $table =~ /^patch\.(?:crates-io|"crates-io")$/ || $table =~ /^replace$/;
      if ($l =~ /^("?)([^"=\s]+)\1\s*=/) {
        my $name = $2;
        if ($table eq "replace") { print "Cargo.toml:$n: [replace] names $name (G-M2: no replaced crate)\n" }
        elsif ($name ne "openmls_sqlite_storage") { print "Cargo.toml:$n: [patch.crates-io] names $name (G-M2: only the reviewed openmls_sqlite_storage stand-in)\n" }
      }
    }
    open($fh, "<", $ENV{LOCK}) or die "cannot read $ENV{LOCK}\n";
    my $lock = <$fh>;
    close $fh;
    my $packages = 0;
    for my $block (split /\n(?=\[\[)/, $lock) {
      next unless $block =~ /^\[\[package\]\]/;
      $packages++;
      my ($name) = $block =~ /^name = "([^"]+)"/m;
      my ($version) = $block =~ /^version = "([^"]+)"/m;
      my ($source) = $block =~ /^source = "([^"]+)"/m;
      my $checksum = $block =~ /^checksum = "[0-9a-f]{64}"/m;
      my $what = "$name $version";
      if (!defined $source) {
        print "Cargo.lock: $what has no source and is not a workspace member (G-M2: a path package outside the workspace, such as a [patch]ed fork)\n" unless $member{$what};
      } elsif ($source ne "registry+https://github.com/rust-lang/crates.io-index") {
        print "Cargo.lock: $what comes from $source (G-M2: every dependency from the crates.io registry)\n";
      } elsif (!$checksum) {
        print "Cargo.lock: $what has no checksum (G-M2: every registry package with its checksum)\n";
      }
    }
    print "LOCK-PACKAGES $packages\n";' <<< "$meta")"; then
  fail "the patch and lock-source reader (perl) failed: the clause is unproven"
else
  read_n="$(sed -n 's/^LOCK-PACKAGES //p' <<< "$patch_out")"
  [ "${read_n:-0}" -gt 0 ] || fail "Cargo.lock held no package (the lock-source clause would pass vacuously)"
  while IFS= read -r line; do
    [ -n "$line" ] && fail "$line"
  done < <(grep -v '^LOCK-PACKAGES ' <<< "$patch_out" || true)
fi

# The openmls_sqlite_storage stand-in (§3.2, S0-1, Q40 (a)): exactly its manifest, an empty lib.rs
# and its README, by hash, and no graph of the workspace reaches it (never compiled).
STUB="${GHOST_POLICY_STUB_DIR:-$GHOST_ROOT/third_party/openmls-sqlite-storage-stub}"
stub_files="$(cd "$STUB" 2>/dev/null && find . -type f | sed 's|^\./||' | sort | tr '\n' ' ')"
[ "$stub_files" = "Cargo.toml README.md src/lib.rs " ] \
  || fail "the openmls_sqlite_storage stub holds [$stub_files], not exactly Cargo.toml, README.md and src/lib.rs (G-M2)"
stub_sum() { sha256sum "$STUB/$1" 2>/dev/null | cut -c1-64; }
[ "$(stub_sum Cargo.toml)" = ba07f24d81f4be38c96ea35ec39c9cdddaa3d656f17eea2c29a17333797af2db ] \
  || fail "the stub's Cargo.toml changed (SHA-256 $(stub_sum Cargo.toml)); review it and update the pin (G-M2)"
[ "$(stub_sum src/lib.rs)" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] \
  || fail "the stub's src/lib.rs is not empty (G-M2: no source beyond an empty lib.rs)"
if stub_tree="$(cargo tree --locked -q --workspace -e all --target all -i openmls_sqlite_storage 2>"$err")"; then
  [ -z "$stub_tree" ] || fail "a graph of the workspace reaches openmls_sqlite_storage (G-M2): $(head -3 <<< "$stub_tree" | tr '\n' ' ')"
elif ! grep -qE 'did not match any packages|nothing to print' "$err"; then
  cat "$err" >&2
  fail "cargo tree -i openmls_sqlite_storage failed"
fi

# No GHOST code names the memory storage or the basic credential, or calls
# `CommitBuilder::build_with_new_signer`, `MlsGroup::store_pending_proposal`, `export_group_info` or
# `into_group_info*` (§19.14, §19.16, S0-9). Read as code (comments and strings blanked; a call split
# over lines is still the call: source-text.pl) over every Rust source under client-core but the
# test-only KAT crate (which replays standalone proposals) and the spikes (evidence tooling outside
# the workspace). Those three and a build directory are skipped **by their exact path under the
# root** (client-core/mls-kat, …, client-core/target), never by a directory name found anywhere: a
# `src/target/` module is read (review of S2a, F4). The reader is fail-closed and counts its files
# (F3).
if ! src_out="$(ROOTS="${GHOST_POLICY_MLS_SOURCES:-$GHOST_ROOT/client-core}" GATES="$GATES_DIR" perl -e '
  require "$ENV{GATES}/source-text.pl";
  use File::Find;
  my @files;
  my %skip = map { ("$ENV{ROOTS}/$_" => 1) } qw(target mls-kat mls-spike dm-spike);
  find({ no_chdir => 1, wanted => sub {
    if (-d $_ && $skip{$_}) { $File::Find::prune = 1; return; }
    push @files, $_ if -f $_ && /\.rs$/;
  } }, $ENV{ROOTS});
  my $bad = qr/\b(openmls_memory_storage|openmls_basic_credential|build_with_new_signer|store_pending_proposal|export_group_info\w*|into_group_info\w*)\b/;
  for my $f (sort @files) {
    my (undef, $code) = views(read_text($f), "rust");
    while ($code =~ /$bad/g) {
      my $name = $1;
      my $line = line_of(\$code, $-[0]);
      (my $rel = $f) =~ s{^\Q$ENV{ROOTS}\E/?}{};
      print "$rel:$line: $name (G-M2: never in GHOST code, design §3.2, §19.14, §19.16, S0-9)\n";
    }
  }
  print "FILES-READ " . scalar(@files) . "\n";')"; then
  fail "the GHOST source scan (perl) failed: G-M2's forbidden-entry-point clause is unproven"
  src_out=""
fi
read_n="$(sed -n 's/^FILES-READ //p' <<< "$src_out")"
[ "${read_n:-0}" -gt 0 ] || fail "the GHOST source scan read no Rust file (G-M2's forbidden-entry-point clause would pass vacuously)"
while IFS= read -r line; do
  [ -n "$line" ] && fail "$line"
done < <(grep -v '^FILES-READ ' <<< "$src_out" || true)

# ---- G-R2 for the seeded stream (Phase 10 design §12.1, §19.10; S0-7; slice S2a) ----------------
# ghost-host-rng (the getrandom custom backend of host and test builds) never reaches a shipped
# graph — the client library's, the channel crate's or the DM crate's, on any target —; no shipped
# build configuration names the cfg that activates it; and the host graphs link one getrandom
# major, so its one custom symbol covers every draw (S0-7 (c), with `-e normal,no-proc-macro`: the
# test-only KAT crate links getrandom 0.2 through openmls/test-utils and the openmls_test
# proc-macro, and is not a determinism subject).
for root in ghost-client-net ghost-client-mls ghost-client-dm; do
  raw="$(tree -p "$root" -e normal,build --target all --prefix none -f '{p}')" || { FAILURES=$((FAILURES + 1)); continue; }
  names="$(awk '{print $1}' <<< "$raw" | sort -u)"
  for p in ghost-host-rng ${GHOST_POLICY_HOST_ONLY_EXTRA:-}; do
    if has "$names" "$p"; then fail "package '$p' is in $root's graph: host and test builds only (G-R2, design §12.1)"; fi
  done
done
for cfgfile in ${GHOST_POLICY_SHIPPED_CONFIGS:-$GHOST_ROOT/.cargo/config.toml $GHOST_ROOT/scripts/build-native.sh}; do
  [ -f "$cfgfile" ] || continue
  if grep -q 'getrandom_backend' "$cfgfile"; then fail "$cfgfile names getrandom_backend: a shipped build configuration must not (G-R2)"; fi
done
while IFS= read -r gf; do
  [ -n "$gf" ] || continue
  if grep -q 'getrandom_backend' "$gf"; then fail "$gf names getrandom_backend (G-R2: never in an Android build)"; fi
done < <(gradle_files)
for root in ghost-dm-host ghost-client-mls ghost-host-rng; do
  raw="$(tree -p "$root" -e normal,no-proc-macro --target all --prefix none -f '{p}')" || { FAILURES=$((FAILURES + 1)); continue; }
  majors="$(awk '$1 == "getrandom" {sub(/^v/, "", $2); split($2, v, "."); print v[1] "." v[2]}' <<< "$raw" | sort -u)"
  if [ -z "$majors" ]; then fail "no getrandom in $root's linked graph (the check would pass vacuously)"; continue; fi
  [ "$(grep -c . <<< "$majors")" = 1 ] || fail "$root links getrandom $(tr '\n' ' ' <<< "$majors")(G-R2, S0-7 (c): one major)"
done
finish rust-feature-policy
