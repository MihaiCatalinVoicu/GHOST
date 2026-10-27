#!/usr/bin/env bash
# Regenerates the UpdateWorld fixture world (Phase 14 design §11.2's JVM world): a throwaway
# stagenet chain (network 2, software keys committed under test-harness/update/keys, the G-D1
# carve-out), one signed fixture APK (apksigner, build-tools 37.0.0), a manifest of one release,
# closed-fixture-log proofs, the bundle the model mirrors serve — and every hostile variant the
# refusal worlds need (§11.2's mirror modes), each built with ghost-release-ops or by documented
# byte-level surgery on the committed formats (GHRB section swap, APK signing-block splice).
#
# Outputs:
#   test-harness/update/keys/                       the throwaway keyset + APK keystore
#   android/update/src/test/resources/update-world/ the world documents (see README)
#
# The committed ghost_client_net host library embeds the REAL stagenet chain; the world pre-seeds
# its clients from THIS fixture chain through UpdateNative.start (§7.4 step 0 with a fixture
# embedded chain), so no native rebuild is needed. Never run apksigner outside this directory's
# key paths (G-D1's carve-out).
set -euo pipefail

OPS=/d/Forum/ghost/target/release/ghost-release-ops.exe
GHOST=/d/Forum/ghost
W=/d/Forum/ghost/test-harness/update
KEYS="$W/keys"
OUT="$W/work"
RES=/d/Forum/ghost/android/update/src/test/resources/update-world
BT="/c/Users/mihai/AppData/Local/Android/Sdk/build-tools/37.0.0"
KEYSTORE_PASS=ghost-fixture

MIRROR_A=ls2jkm3tmxnaa3o3j3bbb63jx5csqdiaen6wdt3ls6wkpfejl3xlfoqd.onion:443
MIRROR_B=tfhsac26mfhbq6dm5rctfkjnll74xag6p7ehumcr7keqsnkqhp7no4id.onion:443
ES_FILE="$GHOST/protocol/entitlement/schedule.ghes"
ES_SEQ=1
RELAY_DIR="$GHOST/protocol/entitlement/relay-directory.txt"
JAVA_HOME='C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot'
export JAVA_HOME

rm -rf "$OUT" "$RES"
mkdir -p "$OUT" "$RES" "$KEYS"
rm -f "$KEYS"/*.hex "$KEYS"/*.pub "$KEYS"/fixture.ks

# ops keygen hardcodes /dev/urandom (Linux-only); the keyset format is 32-byte Ed25519 seeds +
# public keys, generated here with RFC 8032 reference arithmetic (self-checked against a
# library-verified test vector; ops' root-build/manifest-build/inspect verify key correspondence
# downstream). root-2/release-2/attest-2 serve the hostile and rotation fixtures.
python3 "$(dirname "$0")/gen-keys.py" "$KEYS" root-1 root-2 root-3 root-rc release-1 release-2 attest-1 attest-2 apk-1 log-1 witness-1 witness-2 witness-3 attacker-log attacker-witness

TODAY=$(python3 -c 'import time; print(int(time.time()/86400))')
ISSUED=$((TODAY - 1))
NOT_AFTER=$((TODAY + 30))

# --- the fixture APKs: minimal STORED zips (equal lengths for the swap pair), signed v1+v2 ---
python3 - "$OUT" <<'PY'
import sys, zipfile, os
out = sys.argv[1]
def build(path, dex_bytes):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        z.writestr("AndroidManifest.xml", bytes([3, 0, 8, 0]) + b"fixture-world-apk")
        z.writestr("classes.dex", dex_bytes)
    return os.path.getsize(path)
# The single fixture APK's unsigned zip (the multi-chunk one for DROP_MID_RANGE and SLOW).
build(f"{out}/unsigned.zip", bytes(((i * 7 + 3) & 0xff) for i in range(2048)))
big = bytes(((i * 31 + 11) & 0xff) for i in range(5 * 1024 * 1024))
build(f"{out}/unsigned-big.zip", big)
PY

"$JAVA_HOME/bin/keytool.exe" -genkeypair -keystore "$KEYS/fixture.ks" -storepass "$KEYSTORE_PASS" \
  -keypass "$KEYSTORE_PASS" -alias fixture -keyalg RSA -keysize 2048 -validity 20000 \
  -dname "CN=Ghost UpdateWorld Fixture, OU=test, O=ghost-fixture" 2>/dev/null
CERT_SHA=$("$JAVA_HOME/bin/keytool.exe" -exportcert -keystore "$KEYS/fixture.ks" -storepass "$KEYSTORE_PASS" \
  -alias fixture 2>/dev/null | sha256sum | cut -d' ' -f1)
echo "fixture APK cert sha256: $CERT_SHA"

sign() { # sign <in> <out>
  cmd //c "$(cygpath -w "$BT/apksigner.bat")" sign --ks "$(cygpath -w "$KEYS/fixture.ks")" \
    --ks-pass "pass:$KEYSTORE_PASS" --key-pass "pass:$KEYSTORE_PASS" \
    --min-sdk-version 29 --max-sdk-version 34 \
    --out "$(cygpath -w "$2")" "$(cygpath -w "$1")"
}
sign "$OUT/unsigned.zip" "$OUT/app-v2.apk"
sign "$OUT/unsigned-big.zip" "$OUT/app-v2-big.apk"

# The swap APK: the signed fixture with 32 bytes flipped inside its core data region (offset
# 1024, far before the signing block). Same layout, same length, a different core - exactly
# APK_SWAP's vector - and deterministic where re-signing is not (a fresh signature's trailing
# bytes shift the inferred zero-padding boundary and trip the padding rule before the hash).
python3 - "$OUT/app-v2.apk" "$OUT/app-v2-swap.apk" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, "rb").read())
for i in range(32):
    d[1024 + i] ^= 0x5A
open(dst, "wb").write(bytes(d))
PY

# APK_EXTRA: same length, bytes spliced inside the v2 signing block (the crafted-APK suite's
# territory; here one deterministic splice between the block's size fields and its magics).
python3 - "$OUT/app-v2.apk" "$OUT/app-v2-extra.apk" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
magic = b"APK Sig Block 42"
at = data.rfind(magic)
assert at > 8, "signing block magic not found"
import struct
block_size = struct.unpack_from("<Q", data, at - 8)[0]
pairs_start = at - 8 - block_size + 8
# Flip bytes safely inside the pairs region (away from the size words and the magic).
pos = pairs_start + 64
assert pos + 32 < at - 8, "pairs region too small"
for i in range(32):
    data[pos + i] ^= 0x5A
open(dst, "wb").write(bytes(data))
PY

# --- the root, the rotation root (v2, new release key), and the foreign root (MIXED_ROOT) ----
root_cfg() { # root_cfg <version> <root-key> <release-key> <out-toml>
  cat > "$4" <<EOF
network = 2
version = $1
apk_signers = ["$CERT_SHA"]
witnesses = ["witness-1"]
quorum = 1
[root]
keys = ["$2"]
threshold = 1
[release]
keys = ["$3"]
threshold = 1
[attest]
keys = ["attest-1"]
threshold = 1
[[logs]]
key = "log-1"
origin = "stg-log-1"
[[anchor_mirrors]]
onion = "$MIRROR_A"
operator = "11111111111111111111111111111111"
[[anchor_mirrors]]
onion = "$MIRROR_B"
operator = "22222222222222222222222222222222"
EOF
}
root_cfg 1 root-1 release-1 "$OUT/cfg-root.toml"
"$OPS" root-build --config "$OUT/cfg-root.toml" --keys "$KEYS" --out "$OUT/root-1.ghrt"
mkdir -p "$OUT/roots1" && cp "$OUT/root-1.ghrt" "$OUT/roots1/"
"$OPS" chain-build --network 2 --roots "$OUT/roots1" --out "$OUT/chain.ghrc"

# RK4's rotation root: same root key, the release key replaced (the stolen-release-key world).
root_cfg 2 root-1 release-2 "$OUT/cfg-root2.toml"
"$OPS" root-build --config "$OUT/cfg-root2.toml" --keys "$KEYS" --out "$OUT/root-2.ghrt"
mkdir -p "$OUT/roots2" && cp "$OUT/root-1.ghrt" "$OUT/root-2.ghrt" "$OUT/roots2/"
"$OPS" chain-build --network 2 --roots "$OUT/roots2" --out "$OUT/chain2.ghrc"
"$OPS" proof-build --file "$OUT/root-2.ghrt" --log-index 0 --log-key log-1 --submit-key root-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/root-2.ghrp"

# NI-U4: the four-root chain (same anchors in every root) and a same-set swapped-order anchor
# variant (L10-D22: where roots change their anchor mirrors, the mirror choice differs by design).
root_cfg 3 root-1 release-1 "$OUT/cfg-root3.toml"
"$OPS" root-build --config "$OUT/cfg-root3.toml" --keys "$KEYS" --out "$OUT/root-3.ghrt"
root_cfg 4 root-1 release-1 "$OUT/cfg-root4.toml"
"$OPS" root-build --config "$OUT/cfg-root4.toml" --keys "$KEYS" --out "$OUT/root-4.ghrt"
mkdir -p "$OUT/roots4" && cp "$OUT/root-1.ghrt" "$OUT/root-2.ghrt" "$OUT/root-3.ghrt" "$OUT/root-4.ghrt" "$OUT/roots4/"
"$OPS" chain-build --network 2 --roots "$OUT/roots4" --out "$OUT/chain4.ghrc"
for v in 2 3 4; do
  "$OPS" proof-build --file "$OUT/root-$v.ghrt" --log-index 0 --log-key log-1 --submit-key root-1 \
    --witness witness-1 --keys "$KEYS" --out "$OUT/root-$v.ghrp"
done

# The recovery-epoch world: the attacker keeps publishing roots on the stolen key (v5, v6 -
# valid by the chain rule, that is the attack), the recovery APK's NEW lineage (root-rc v1 -
# its own numbering, not because order decides anything, §3.5), and the root-swap world's
# attacker-log root (correctly signed under the old chain rule, logged under the ATTACKER's
# log and witnesses - MC-D23's named refusal is ROOT_UNLOGGED).
root_cfg 5 root-1 release-1 "$OUT/cfg-root5.toml"
"$OPS" root-build --config "$OUT/cfg-root5.toml" --keys "$KEYS" --out "$OUT/root-5.ghrt"
root_cfg 6 root-1 release-1 "$OUT/cfg-root6.toml"
"$OPS" root-build --config "$OUT/cfg-root6.toml" --keys "$KEYS" --out "$OUT/root-6.ghrt"
for n in 5 6; do
  rm -rf "$OUT/rootsn" && mkdir -p "$OUT/rootsn" && cp "$OUT"/root-{1,2,3,4,5}.ghrt "$OUT/rootsn/" && cp "$OUT/root-$n.ghrt" "$OUT/rootsn/"
  "$OPS" chain-build --network 2 --roots "$OUT/rootsn" --out "$OUT/chain$n.ghrc"
  "$OPS" proof-build --file "$OUT/root-$n.ghrt" --log-index 0 --log-key log-1 --submit-key root-1 \
    --witness witness-1 --keys "$KEYS" --out "$OUT/root-$n.ghrp"
done
# The recovery lineage: a new keyset at its own version 1, same anchors.
root_cfg 1 root-rc release-2 "$OUT/cfg-rootrc.toml"
"$OPS" root-build --config "$OUT/cfg-rootrc.toml" --keys "$KEYS" --out "$OUT/root-rc.ghrt"
rm -rf "$OUT/rootsrc" && mkdir -p "$OUT/rootsrc" && cp "$OUT/root-rc.ghrt" "$OUT/rootsrc/"
"$OPS" chain-build --network 2 --roots "$OUT/rootsrc" --out "$OUT/chain-rc.ghrc"
# The root-swap root: signed by the stolen old root key, but listing the attacker's log and
# witnesses - its block verifies under the old chain rule; its proof fails the old policy's log key.
root_cfg 2 root-1 release-1 "$OUT/cfg-root-swap.toml"
sed -i 's/^key = "log-1"$/key = "attacker-log"/; s/^origin = "stg-log-1"$/origin = "attacker-log"/; s/^witnesses = \["witness-1"\]$/witnesses = ["attacker-witness"]/' "$OUT/cfg-root-swap.toml"
"$OPS" root-build --config "$OUT/cfg-root-swap.toml" --keys "$KEYS" --out "$OUT/root-swap.ghrt"
rm -rf "$OUT/rootswap" && mkdir -p "$OUT/rootswap" && cp "$OUT/root-1.ghrt" "$OUT/root-swap.ghrt" "$OUT/rootswap/"
"$OPS" chain-build --network 2 --roots "$OUT/rootswap" --out "$OUT/chain-swap.ghrc"
"$OPS" proof-build --file "$OUT/root-swap.ghrt" --log-index 0 --log-key attacker-log --submit-key root-1 \
  --witness attacker-witness --keys "$KEYS" --out "$OUT/root-swap.ghrp"
# The foreign root (a different keyset at version 1) for MIXED_ROOT.
root_cfg 1 root-2 release-2 "$OUT/cfg-rootb.toml"
"$OPS" root-build --config "$OUT/cfg-rootb.toml" --keys "$KEYS" --out "$OUT/root-b.ghrt"

# The wrong-network world: a mainnet (network 1) bundle. The native network check fires on
# the bundle's own byte before any manifest parse, so one root and one manifest suffice.
# §4.3's mainnet rules: 3 root keys at threshold 2, 3 witnesses at quorum 2.
cat > "$OUT/cfg-root-main.toml" <<EOF
network = 1
version = 1
apk_signers = ["$CERT_SHA"]
witnesses = ["witness-1", "witness-2", "witness-3"]
quorum = 2
[root]
keys = ["root-1", "root-2", "root-3"]
threshold = 2
[release]
keys = ["release-1"]
threshold = 1
[attest]
keys = ["attest-1"]
threshold = 1
[[logs]]
key = "log-1"
origin = "main-log-fixture"
[[anchor_mirrors]]
onion = "$MIRROR_A"
operator = "11111111111111111111111111111111"
[[anchor_mirrors]]
onion = "$MIRROR_B"
operator = "22222222222222222222222222222222"
EOF
"$OPS" root-build --config "$OUT/cfg-root-main.toml" --keys "$KEYS" --out "$OUT/root-main.ghrt"
mkdir -p "$OUT/roots-main" && cp "$OUT/root-main.ghrt" "$OUT/roots-main/"
"$OPS" chain-build --network 1 --roots "$OUT/roots-main" --out "$OUT/chain-main.ghrc"

# --- the unsigned cores -------------------------------------------------
CORE_LINE=$("$OPS" apk-core --apk "$OUT/app-v2.apk" --extract "$OUT/core.apk")
echo "$CORE_LINE"
"$OPS" apk-core --apk "$OUT/app-v2-big.apk" --extract "$OUT/core-big.apk" >/dev/null

APK_SHA=$(sha256sum "$OUT/app-v2.apk" | cut -d' ' -f1)
APK_LEN=$(stat -c%s "$OUT/app-v2.apk")
APK_BIG_SHA=$(sha256sum "$OUT/app-v2-big.apk" | cut -d' ' -f1)
SALT=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
COMMIT=$(printf 'ghost-update-world-fixture-%.0s' 1 | sha256sum | cut -c1-40)
APK_WIN=$(cygpath -m "$OUT/app-v2.apk")
CORE_WIN=$(cygpath -m "$OUT/core.apk")
BIG_WIN=$(cygpath -m "$OUT/app-v2-big.apk")
CORE_BIG_WIN=$(cygpath -m "$OUT/core-big.apk")

# A canonical attacker onion (v3 checksum) for the stolen manifest's extra mirrors.
ATTACKER_ONION=$(python3 - <<'PY'
import hashlib, secrets, base64
pk = secrets.token_bytes(32)
c = hashlib.sha3_256(b".onion checksum" + pk + b"\x03").digest()[:2]
print(base64.b32encode(pk + c + b"\x03").decode().lower() + ".onion:443")
PY
)

# --- manifests ----------------------------------------------------------
# write_manifest <name> <root-ghrt> <seq> <issued> <not_after> <floor> <attest> <version-name> <apk-win> <core-win> [extra toml lines...]
write_manifest() {
  local name=$1 root=$2 seq=$3 issued=$4 notafter=$5 floor=$6 attest=$7 vname=$8 apk=$9 core=${10}; shift 10
  {
    echo "seq = $seq"
    echo "issued_day = $issued"
    echo "not_after_day = $notafter"
    echo "floor_version_code = $floor"
    echo "[[release]]"
    echo "version_code = 2"
    echo "version_name = \"$vname\""
    echo "min_sdk = 29"
    echo "anchor_root = 1"
    echo "wire_changing = false"
    echo "apk = \"$apk\""
    echo "unsigned = \"$core\""
    echo "rollout_permille = ${ROLLOUT_PERMILLE:-1000}"
    echo "rollout_salt = \"$SALT\""
    echo "commit = \"$COMMIT\""
    echo "es_seq = $ES_SEQ"
    echo "es_file = \"$(cygpath -m "$ES_FILE")\""
    echo "[[release.artifacts]]"
    echo "kind = 16"
    echo "file = \"$core\""
    grep '^relay ' "$RELAY_DIR" | while read -r _ onion _op; do
      echo "[[relay]]"
      echo "onion = \"$onion\""
      echo "operator = \"$(grep "^relay $onion" "$RELAY_DIR" | awk '{print $3}')\""
    done
    for extra in "$@"; do echo "$extra"; done
  } > "$OUT/cfg-$name.toml"
  "$OPS" manifest-build --source "$OUT/cfg-$name.toml" --root "$root" --keys "$KEYS" \
    --attest-keys "$attest" --out "$OUT/$name.ghrm"
}
proof_and_bundle() { # proof_and_bundle <manifest-name> [submit-key] [time]
  local name=$1 submit=${2:-release-1} time=${3:-}
  local tflag=()
  [ -n "$time" ] && tflag=(--time "$time")
  "$OPS" proof-build --file "$OUT/$name.ghrm" --log-index 0 --log-key log-1 --submit-key "$submit" \
    --witness witness-1 "${tflag[@]}" --keys "$KEYS" --out "$OUT/$name.ghrp"
}

write_manifest manifest-1 "$OUT/root-1.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-1

# The wrong-network bundle: mainnet chain and manifest (the native network check fires on the
# bundle's own network byte before any manifest parse).
write_manifest manifest-main "$OUT/root-main.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN"
"$OPS" proof-build --file "$OUT/manifest-main.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --witness witness-1 --witness witness-2 --keys "$KEYS" --out "$OUT/manifest-main.ghrp"
"$OPS" bundle --chain "$OUT/chain-main.ghrc" --manifest "$OUT/manifest-main.ghrm" \
  --manifest-proof "$OUT/manifest-main.ghrp" --out "$OUT/bundle-mainnet.ghrb"

# EQUIVOCATE: two manifests at one pair (root 1, seq 1), different bytes.
write_manifest manifest-eq-a "$OUT/root-1.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.0-equiv-a" "$APK_WIN" "$CORE_WIN"
write_manifest manifest-eq-b "$OUT/root-1.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.1-equiv" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-eq-a
proof_and_bundle manifest-eq-b

# FAST_FORWARD: the pair pushed to its u64 maximum.
write_manifest manifest-ff "$OUT/root-1.ghrt" 9223372036854775807 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-ff

# EXPIRED_REPLAY: a higher pair, expired (issued in its own era, cosigned then), carrying an
# attacker relay — MC-D30's oracle: accepted as a fact, but its directory must not apply.
ATTACKER_RELAY=$(python3 - <<'PY'
import hashlib, secrets, base64
pk = secrets.token_bytes(32)
c = hashlib.sha3_256(b".onion checksum" + pk + b"\x03").digest()[:2]
onion = base64.b32encode(pk + c + b"\x03").decode().lower() + ".onion:443"
print(f'[[relay]]\nonion = "{onion}"\noperator = "{hashlib.sha256(pk).hexdigest()[:32]}"')
PY
)
write_manifest manifest-replay "$OUT/root-1.ghrt" 2 $((TODAY - 30)) $((TODAY - 10)) 0 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN" "$ATTACKER_RELAY"
proof_and_bundle manifest-replay release-1 $(( (TODAY - 30) * 86400 + 43200 ))

# FLOOR_MAX: the floor at the manifest's bound (floor == the release itself, the maximum ops'
# release-time rule admits), and the release at rollout_permille 0: a client below the floor is
# offered it ignoring the bucket (§7.4 step 8's escape), a client at or above the floor is not.
# The literal FLOOR_INVALID branch (floor above every attested release) is unreachable through
# ops' stricter release-time check — that vector needs GHRM re-signing surgery, a crafted-suite slice.
ROLLOUT_PERMILLE=0
write_manifest manifest-floor "$OUT/root-1.ghrt" 1 "$ISSUED" "$NOT_AFTER" 2 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN"
ROLLOUT_PERMILLE=1000
proof_and_bundle manifest-floor

# RELABEL: the committed relays with their operator ids flipped (the directory guard's world).
# write_manifest's inline relay list dedups by onion, so the flip lives in a swapped directory.
FLIPPED_DIR="$OUT/relayed-directory.txt"
RELAY_DIR_REAL="$RELAY_DIR"
awk '{op=$3; gsub(/0/,"f",op); gsub(/1/,"e",op); print $1, $2, op}' "$RELAY_DIR" > "$FLIPPED_DIR"
RELAY_DIR="$FLIPPED_DIR"
write_manifest manifest-relabel "$OUT/root-1.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-relabel
RELAY_DIR="$RELAY_DIR_REAL"

# MIXED_ROOT: a manifest of the foreign root, served in the fixture root's chain.
write_manifest manifest-wrongroot "$OUT/root-b.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-wrongroot release-2

# The multi-chunk release (DROP_MID_RANGE, SLOW).
write_manifest manifest-big "$OUT/root-1.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.0-world" "$BIG_WIN" "$CORE_BIG_WIN"
proof_and_bundle manifest-big

# The rotation world: RK4's manifest (root 2) and the stolen-release-key manifest (root 1,
# floor at its bound, only attacker mirrors as extras).
write_manifest manifest-2 "$OUT/root-2.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.1.0-rk4" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-2 release-2

write_manifest manifest-3 "$OUT/root-3.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.1.0-rk4" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-3
write_manifest manifest-4 "$OUT/root-4.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.1.0-rk4" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-4
# The swapped-order anchors: same onion set, reversed (L10-D22's legitimate divergence).
{
  echo "network = 2"
  echo "version = 4"
  echo "apk_signers = [\"$CERT_SHA\"]"
  echo "witnesses = [\"witness-1\"]"
  echo "quorum = 1"
  echo "[root]"
  echo "keys = [\"root-1\"]"
  echo "threshold = 1"
  echo "[release]"
  echo "keys = [\"release-1\"]"
  echo "threshold = 1"
  echo "[attest]"
  echo "keys = [\"attest-1\"]"
  echo "threshold = 1"
  echo "[[logs]]"
  echo "key = \"log-1\""
  echo "origin = \"stg-log-1\""
  echo "[[anchor_mirrors]]"
  echo "onion = \"$MIRROR_B\""
  echo "operator = \"22222222222222222222222222222222\""
  echo "[[anchor_mirrors]]"
  echo "onion = \"$MIRROR_A\""
  echo "operator = \"11111111111111111111111111111111\""
} > "$OUT/cfg-root4x.toml"
"$OPS" root-build --config "$OUT/cfg-root4x.toml" --keys "$KEYS" --out "$OUT/root-4x.ghrt"
mkdir -p "$OUT/roots4x" && cp "$OUT/root-1.ghrt" "$OUT/root-2.ghrt" "$OUT/root-3.ghrt" "$OUT/root-4x.ghrt" "$OUT/roots4x/"
"$OPS" chain-build --network 2 --roots "$OUT/roots4x" --out "$OUT/chain4x.ghrc"
"$OPS" proof-build --file "$OUT/root-4x.ghrt" --log-index 0 --log-key log-1 --submit-key root-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/root-4x.ghrp"
write_manifest manifest-4x "$OUT/root-4x.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.1.0-rk4" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-4x


# --- the crafted-suite gaps (S6c-crafted): MC-D27, FLOOR_INVALID, MC-D9 -----------------
# MC-D27: a real v3.1-lineage APK. A second throwaway key (G-D1's carve-out), apksigner
# rotate for the lineage, then signed by the NEW key with --lineage and v2 disabled: the
# v3.1 block carries the new certificate (SDK 33+), the v3.0 block the original one, so the
# signer digests differ and the misread flips. The trusted root lists ONLY the new digest.
rm -f "$KEYS/fixture2.ks" && "$JAVA_HOME/bin/keytool.exe" -genkeypair -keystore "$KEYS/fixture2.ks" -storepass "$KEYSTORE_PASS" \
  -keypass "$KEYSTORE_PASS" -alias fixture2 -keyalg RSA -keysize 2048 -validity 20000 \
  -dname "CN=Ghost UpdateWorld Fixture 2, OU=test, O=ghost-fixture" 2>/dev/null
CERT2_SHA=$("$JAVA_HOME/bin/keytool.exe" -exportcert -keystore "$KEYS/fixture2.ks" -storepass "$KEYSTORE_PASS" \
  -alias fixture2 2>/dev/null | sha256sum | cut -d' ' -f1)
cmd //c "$(cygpath -w "$BT/apksigner.bat")" rotate --out "$(cygpath -w "$KEYS/lineage-v31")" \
  --old-signer --ks "$(cygpath -w "$KEYS/fixture.ks")" --ks-pass "pass:$KEYSTORE_PASS" --key-pass "pass:$KEYSTORE_PASS" \
  --new-signer --ks "$(cygpath -w "$KEYS/fixture2.ks")" --ks-pass "pass:$KEYSTORE_PASS" --key-pass "pass:$KEYSTORE_PASS"
cmd //c "$(cygpath -w "$BT/apksigner.bat")" sign \
  --ks "$(cygpath -w "$KEYS/fixture.ks")" --ks-pass "pass:$KEYSTORE_PASS" --key-pass "pass:$KEYSTORE_PASS" \
  --next-signer --ks "$(cygpath -w "$KEYS/fixture2.ks")" --ks-pass "pass:$KEYSTORE_PASS" --key-pass "pass:$KEYSTORE_PASS" \
  --lineage "$(cygpath -w "$KEYS/lineage-v31")" --v1-signing-enabled false --v2-signing-enabled false \
  --min-sdk-version 29 --max-sdk-version 34 \
  --out "$(cygpath -w "$OUT/app-v31.apk")" "$(cygpath -w "$OUT/unsigned.zip")"
"$OPS" apk-core --apk "$OUT/app-v31.apk" --extract "$OUT/core-31.apk" >/dev/null
# The kill runs at SDK 29: shipped reads the v3.0 block (window [24,32], the ORIGINAL cert);
# the mutant's sdk 255 falls into the v3.1 window [33, INT_MAX] (the rotated cert).
root_cfg 1 root-1 release-1 "$OUT/cfg-root31.toml"
"$OPS" root-build --config "$OUT/cfg-root31.toml" --keys "$KEYS" --out "$OUT/root-31.ghrt"
rm -rf "$OUT/roots31" && mkdir -p "$OUT/roots31" && cp "$OUT/root-31.ghrt" "$OUT/roots31/"
"$OPS" chain-build --network 2 --roots "$OUT/roots31" --out "$OUT/chain-31.ghrc"
V31_WIN=$(cygpath -m "$OUT/app-v31.apk")
CORE31_WIN=$(cygpath -m "$OUT/core-31.apk")

# FLOOR_INVALID: the literal native case (floor above every attested release), unreachable
# through ops' stricter release-time rule: manifest-1's floor raised to 3, the release block
# re-signed with release-1 (the S6e removedkey pattern).
python3 "$(dirname "$0")/floorbad.py" "$OUT"
"$OPS" proof-build --file "$OUT/manifest-floorbad.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/manifest-floorbad.ghrp"
"$OPS" bundle --chain "$OUT/chain.ghrc" \
  --manifest "$OUT/manifest-floorbad.ghrm" --manifest-proof "$OUT/manifest-floorbad.ghrp" --out "$OUT/bundle-floorbad.ghrb"

# The revocation world: a manifest naming the new root at a higher pair, signed ONLY by the
# release key RK2 dropped - shipped refuses it at BAD_SIGNATURE whatever its sequence (DS-5,
# §3.5). The body is manifest-2's with the seq bumped; the block is re-signed with release-1.
python3 - "$(dirname "$0")" "$OUT" <<'PY'
import hashlib, os, sys
here = os.path.abspath(sys.argv[1])
sys.path.insert(0, here)
import ghostsign
out = sys.argv[2]
d = open(f"{out}/manifest-2.ghrm", "rb").read()
assert d[:4] == b"GHRM" and d[4] == 1 and d[-97] == 1
body = bytearray(d[:-97])
body[6:14] = (2).to_bytes(8, "big")  # a pair above the stored (2,1): not a rollback
body = bytes(body)
seed = bytes.fromhex(open(f"{here}/keys/release-1.hex").read())
msg = b"ghost/v1/release-manifest " + bytes([2]) + hashlib.sha256(body).digest()
sig = ghostsign.sign(seed, msg)
pk = ghostsign.publickey(seed)
open(f"{out}/manifest-removedkey.ghrm", "wb").write(body + bytes([1]) + ghostsign.key_id(pk) + sig)
PY
"$OPS" proof-build --file "$OUT/manifest-removedkey.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/manifest-removedkey.ghrp"
"$OPS" bundle --chain "$OUT/chain2.ghrc" --root-proof "$OUT/root-2.ghrp" \
  --manifest "$OUT/manifest-removedkey.ghrm" --manifest-proof "$OUT/manifest-removedkey.ghrp" --out "$OUT/bundle-removedkey.ghrb"

# The new root's manifest with an extra mirror (c): normality resumes - the offer, the
# directory, and the manifest's mirror list re-enter the run.
write_manifest manifest-2x "$OUT/root-2.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.1.0-rk4" "$APK_WIN" "$CORE_WIN" \
  "[[mirror]]" "onion = \"$ATTACKER_ONION\"" "operator = \"$(echo "$ATTACKER_ONION" | sha256sum | cut -c1-32)\""
proof_and_bundle manifest-2x release-2

write_manifest manifest-31 "$OUT/root-31.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "3.1.0-lineage" "$V31_WIN" "$CORE31_WIN"
proof_and_bundle manifest-31
"$OPS" bundle --chain "$OUT/chain-31.ghrc" \
  --manifest "$OUT/manifest-31.ghrm" --manifest-proof "$OUT/manifest-31.ghrp" --out "$OUT/bundle-31.ghrb"
"$OPS" bundle --chain "$OUT/chain2.ghrc" --root-proof "$OUT/root-2.ghrp" \
  --manifest "$OUT/manifest-2x.ghrm" --manifest-proof "$OUT/manifest-2x.ghrp" --out "$OUT/bundle-2x.ghrb"
write_manifest manifest-5 "$OUT/root-5.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.1.0-rk4" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-5
write_manifest manifest-6 "$OUT/root-6.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.1.0-rk4" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-6
write_manifest manifest-rc "$OUT/root-rc.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.1.0-rk4" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-rc release-2
"$OPS" bundle --chain "$OUT/chain4x.ghrc" --root-proof "$OUT/root-2.ghrp" --root-proof "$OUT/root-3.ghrp" \
  --root-proof "$OUT/root-4x.ghrp" \
  --manifest "$OUT/manifest-4x.ghrm" --manifest-proof "$OUT/manifest-4x.ghrp" --out "$OUT/bundle-4x.ghrb"
write_manifest manifest-stolen "$OUT/root-1.ghrt" 1 "$ISSUED" "$NOT_AFTER" 2 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN" \
  "[[mirror]]" "onion = \"$ATTACKER_ONION\"" "operator = \"$(echo "$ATTACKER_ONION" | sha256sum | cut -c1-32)\""
proof_and_bundle manifest-stolen

# --- bundles ------------------------------------------------------------
bundle1() { # bundle1 <manifest-name> <out> [chain]
  "$OPS" bundle --chain "${3:-$OUT/chain.ghrc}" --manifest "$OUT/$1.ghrm" \
    --manifest-proof "$OUT/$1.ghrp" --out "$2"
}
bundle1 manifest-1 "$OUT/bundle.ghrb"
bundle1 manifest-eq-a "$OUT/bundle-eq-a.ghrb"
bundle1 manifest-eq-b "$OUT/bundle-eq-b.ghrb"
bundle1 manifest-ff "$OUT/bundle-ff.ghrb"
bundle1 manifest-replay "$OUT/bundle-replay.ghrb"
bundle1 manifest-floor "$OUT/bundle-floor.ghrb"
bundle1 manifest-relabel "$OUT/bundle-relabel.ghrb"
bundle1 manifest-wrongroot "$OUT/bundle-wrongroot.ghrb"
bundle1 manifest-big "$OUT/bundle-big.ghrb"
# The rotation bundle: the two-root chain needs its root proof (one per entry after the first).
"$OPS" bundle --chain "$OUT/chain2.ghrc" --root-proof "$OUT/root-2.ghrp" \
  --manifest "$OUT/manifest-2.ghrm" --manifest-proof "$OUT/manifest-2.ghrp" --out "$OUT/bundle-2.ghrb"
"$OPS" bundle --chain "$OUT/chain4.ghrc" --root-proof "$OUT/root-2.ghrp" --root-proof "$OUT/root-3.ghrp" --root-proof "$OUT/root-4.ghrp" --manifest "$OUT/manifest-4.ghrm" --manifest-proof "$OUT/manifest-4.ghrp" --out "$OUT/bundle-4.ghrb"
"$OPS" bundle --chain "$OUT/chain5.ghrc" --root-proof "$OUT/root-2.ghrp" --root-proof "$OUT/root-3.ghrp" \
  --root-proof "$OUT/root-4.ghrp" --root-proof "$OUT/root-5.ghrp" \
  --manifest "$OUT/manifest-5.ghrm" --manifest-proof "$OUT/manifest-5.ghrp" --out "$OUT/bundle-5.ghrb"
"$OPS" bundle --chain "$OUT/chain6.ghrc" --root-proof "$OUT/root-2.ghrp" --root-proof "$OUT/root-3.ghrp" \
  --root-proof "$OUT/root-4.ghrp" --root-proof "$OUT/root-5.ghrp" --root-proof "$OUT/root-6.ghrp" \
  --manifest "$OUT/manifest-6.ghrm" --manifest-proof "$OUT/manifest-6.ghrp" --out "$OUT/bundle-6.ghrb"
"$OPS" bundle --chain "$OUT/chain-rc.ghrc" \
  --manifest "$OUT/manifest-rc.ghrm" --manifest-proof "$OUT/manifest-rc.ghrp" --out "$OUT/bundle-rc.ghrb"
"$OPS" bundle --chain "$OUT/chain-swap.ghrc" --root-proof "$OUT/root-swap.ghrp" \
  --manifest "$OUT/manifest-1.ghrm" --manifest-proof "$OUT/manifest-1.ghrp" --out "$OUT/bundle-swap.ghrb"
"$OPS" bundle --chain "$OUT/chain4.ghrc" --root-proof "$OUT/root-2.ghrp" --root-proof "$OUT/root-3.ghrp" --root-proof "$OUT/root-4.ghrp" \
  --manifest "$OUT/manifest-3.ghrm" --manifest-proof "$OUT/manifest-3.ghrp" --out "$OUT/bundle-3att.ghrb"
bundle1 manifest-stolen "$OUT/bundle-stolen.ghrb"

# --- the mutant-kill fixtures (§11.3, slice S6c) -----------------------------------------
# MC-D1/MC-D2: the bad transition root — a v2 root signed by a key of neither old keyset
# (root-2), logged correctly (the leaf by root-1). Shipped refuses the chain walk; both
# threshold mutants adopt.
root_cfg 2 root-2 release-2 "$OUT/cfg-root-bad2.toml"
"$OPS" root-build --config "$OUT/cfg-root-bad2.toml" --keys "$KEYS" --out "$OUT/root-bad2.ghrt"
mkdir -p "$OUT/roots2bad" && cp "$OUT/root-1.ghrt" "$OUT/root-bad2.ghrt" "$OUT/roots2bad/"
"$OPS" chain-build --network 2 --roots "$OUT/roots2bad" --out "$OUT/chain2bad.ghrc"
"$OPS" proof-build --file "$OUT/root-bad2.ghrt" --log-index 0 --log-key log-1 --submit-key root-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/root-bad2.ghrp"
write_manifest manifest-2bad "$OUT/root-bad2.ghrt" 1 "$ISSUED" "$NOT_AFTER" 0 attest-1 "2.0.0-bad2" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-2bad release-2
"$OPS" bundle --chain "$OUT/chain2bad.ghrc" --root-proof "$OUT/root-bad2.ghrp" \
  --manifest "$OUT/manifest-2bad.ghrm" --manifest-proof "$OUT/manifest-2bad.ghrp" --out "$OUT/bundle-2bad.ghrb"

# MC-D3: the same release with one flipped byte in the release signature block, and an honest
# proof over the flipped bytes. Shipped: BAD_SIGNATURE; the mutant accepts.
python3 - "$OUT/manifest-1.ghrm" "$OUT/manifest-flipsig.ghrm" <<'PY'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
assert d[-97] == 1, "expected a one-entry release block at the end"
d[-10] ^= 0x01  # inside the 64-byte signature, not the count or the key id
open(sys.argv[2], "wb").write(bytes(d))
PY
"$OPS" proof-build --file "$OUT/manifest-flipsig.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/manifest-flipsig.ghrp"
"$OPS" bundle --chain "$OUT/chain.ghrc" --manifest "$OUT/manifest-flipsig.ghrm" \
  --manifest-proof "$OUT/manifest-flipsig.ghrp" --out "$OUT/bundle-flipsig.ghrb"

# MC-D9/MC-D10/MC-D20: proof-level surgeries, rebundled over the honest manifest. The two
# that ops' bundle cross-check would refuse (the index past the tree, the foreign message) are
# rebundled by section surgery; the flipped tree-head signature passes ops' checks (it does not
# verify the log's signature, only the message and the inclusion).
python3 - "$OUT" <<'PY'
import struct, sys, hashlib
out = sys.argv[1]
d = open(f"{out}/manifest-1.ghrp", "rb").read()
assert d[:4] == b"GHRP" and d[4] == 1
pos = 5
message = d[pos:pos+32]; pos += 32
log = d[pos]; pos += 1
leaf_sig = d[pos:pos+64]; pos += 64
leaf_key = d[pos:pos+32]; pos += 32
tree_size = d[pos:pos+8]; pos += 8
leaf_index = d[pos:pos+8]; pos += 8
(npath,) = struct.unpack_from(">B", d, pos); pos += 1
path = d[pos:pos+32*npath]; pos += 32*npath
root_hash = d[pos:pos+32]; pos += 32
log_sig = d[pos:pos+64]; pos += 64
rest = d[pos:]  # the cosignatures
def build(message=message, leaf_index=leaf_index, root_hash=root_hash, log_sig=log_sig):
    return (b"GHRP" + b"\x01" + message + bytes([log]) + leaf_sig + leaf_key +
            tree_size + leaf_index + bytes([npath]) + path +
            root_hash + log_sig + rest)
variants = {}
# MC-D9: the leaf index past the tree size — the inclusion path cannot verify.
variants[f"{out}/manifest-badindex.ghrp"] = build(leaf_index=(1).to_bytes(8, "big"))
# MC-D10: one flipped byte in the log's tree-head signature.
bad = bytearray(log_sig); bad[20] ^= 0x40
variants[f"{out}/manifest-badhead.ghrp"] = build(log_sig=bytes(bad))
# MC-D20: an honest proof whose message names another manifest.
other = hashlib.sha256(open(f"{out}/manifest-eq-a.ghrm", "rb").read()).digest()
variants[f"{out}/manifest-othermsg.ghrp"] = build(message=other)
for path_out, doc in variants.items():
    open(path_out, "wb").write(doc)

def split_bundle(p):
    b = open(p, "rb").read()
    assert b[:4] == b"GHRB"
    q = 6
    (n,) = struct.unpack_from(">I", b, q); q += 4 + n
    (nroot,) = struct.unpack_from(">H", b, q); q += 2
    for _ in range(nroot):
        (n,) = struct.unpack_from(">I", b, q); q += 4 + n
    mlen = struct.unpack_from(">I", b, q)[0]
    return b[:q + 4 + mlen]  # through the manifest section, before the proof's u32
head = split_bundle(f"{out}/bundle.ghrb")
for name in ("badindex", "badhead", "othermsg"):
    proof = open(f"{out}/manifest-{name}.ghrp", "rb").read()
    open(f"{out}/bundle-{name}.ghrb", "wb").write(
        head + struct.pack(">I", len(proof)) + proof)
PY

# MC-D11/MC-D12: quorum proofs — none, and one by a witness the root does not list.
"$OPS" proof-build --file "$OUT/manifest-1.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --keys "$KEYS" --out "$OUT/manifest-nocosig.ghrp"
"$OPS" bundle --chain "$OUT/chain.ghrc" --manifest "$OUT/manifest-1.ghrm" \
  --manifest-proof "$OUT/manifest-nocosig.ghrp" --out "$OUT/bundle-nocosig.ghrb"
"$OPS" proof-build --file "$OUT/manifest-1.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --witness attest-2 --keys "$KEYS" --out "$OUT/manifest-unknownwit.ghrp"
"$OPS" bundle --chain "$OUT/chain.ghrc" --manifest "$OUT/manifest-1.ghrm" \
  --manifest-proof "$OUT/manifest-unknownwit.ghrp" --out "$OUT/bundle-unknownwit.ghrb"

# MC-D23: the rotation bundle with another file's proof in the root-proof section.
python3 - "$OUT" <<'PY'
import struct, sys
out = sys.argv[1]
def split_bundle(path):
    d = open(path, "rb").read()
    assert d[:4] == b"GHRB"
    pos = 6
    (n,) = struct.unpack_from(">I", d, pos); pos += 4 + n
    head = d[:pos]          # through the chain, before nroot
    (nroot,) = struct.unpack_from(">H", d, pos); pos += 2
    rp = []
    for _ in range(nroot):
        (n,) = struct.unpack_from(">I", d, pos); pos += 4
        rp.append(d[pos:pos+n]); pos += n
    rest = d[pos:]
    return head, nroot, rp, rest
head, nroot, rp, rest = split_bundle(f"{out}/bundle-2.ghrb")
assert nroot == 1
# The foreign proof: bundle-2's own manifest proof — a valid GHRP whose message names the
# manifest, not the root.
(mlen,) = struct.unpack_from(">I", rest, 0)
ppos = 4 + mlen
(plen,) = struct.unpack_from(">I", rest, ppos)
foreign = rest[ppos + 4: ppos + 4 + plen]
open(f"{out}/bundle-badrootproof.ghrb", "wb").write(
    head + struct.pack(">H", 1) + struct.pack(">I", len(foreign)) + foreign + rest)
PY

# MC-D18: a manifest of the OLD root (patched from manifest-2: root_version 1, root hash of
# root-1, seq 2) re-signed with release-2 — the key root 2 trusts — and an honest proof.
# Shipped: ROOT_MISMATCH (the manifest does not name the trusted root); the mutant accepts it.
python3 - "$(dirname "$0")" "$OUT" <<'PY'
import hashlib, os, sys
here = os.path.abspath(sys.argv[1])
sys.path.insert(0, here)
import ghostsign
out = sys.argv[2]
d = open(f"{out}/manifest-2.ghrm", "rb").read()
assert d[:4] == b"GHRM" and d[4] == 1 and d[-97] == 1
body = bytearray(d[:-97])
body[14:18] = (1).to_bytes(4, "big")  # root_version: name the old root
root1 = open(f"{out}/root-1.ghrt", "rb").read()
body[18:50] = hashlib.sha256(root1).digest()  # its hash
body[6:14] = (2).to_bytes(8, "big")  # seq: above the stored pair
body = bytes(body)
seed = bytes.fromhex(open(f"{here}/keys/release-2.hex").read())
msg = b"ghost/v1/release-manifest\x00" + bytes([2]) + hashlib.sha256(body).digest()
sig = ghostsign.sign(seed, msg)
pk = ghostsign.publickey(seed)
block = bytes([1]) + ghostsign.key_id(pk) + sig
open(f"{out}/manifest-xroot.ghrm", "wb").write(body + block)
PY
"$OPS" proof-build --file "$OUT/manifest-xroot.ghrm" --log-index 0 --log-key log-1 --submit-key release-2 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/manifest-xroot.ghrp"
"$OPS" bundle --chain "$OUT/chain2.ghrc" --root-proof "$OUT/root-2.ghrp" \
  --manifest "$OUT/manifest-xroot.ghrm" --manifest-proof "$OUT/manifest-xroot.ghrp" --out "$OUT/bundle-xroot.ghrb"

# PM-D7/PM-D13: one manifest with two releases sharing a rollout salt (version 2 = the fixture
# APK, version 3 = the swap APK): the bucket is per release because the APK's SHA-256 salts it.
# The permille of version 2 is computed so the with-APK-hash bucket passes and the
# without-APK-hash bucket (PM-D13's mutant) does not: the oracle test reads the predictions.
"$OPS" apk-core --apk "$OUT/app-v2-swap.apk" --extract "$OUT/core-swap.apk" >/dev/null
BUCKET_META=$(python3 - "$OUT" "$SALT" <<'PY'
import hashlib, hmac, secrets, sys
out, salt_hex = sys.argv[1], sys.argv[2]
salt = bytes.fromhex(salt_hex)
apk2 = hashlib.sha256(open(f"{out}/app-v2.apk", "rb").read()).digest()
apk3 = hashlib.sha256(open(f"{out}/app-v2-swap.apk", "rb").read()).digest()
for _ in range(100):
    key = secrets.token_bytes(32)
    def bucket(with_apk, apk=b""):
        m = hmac.new(key, b"ghost/v1/rollout", hashlib.sha256)
        if with_apk:
            m.update(apk)
        m.update(salt)
        return int.from_bytes(m.digest()[:8], "big") * 1000 // (1 << 64)
    b2, b3, shared = bucket(True, apk2), bucket(True, apk3), bucket(False)
    if b2 != b3 and b2 < 999 and shared >= b2 + 1:
        break
else:
    raise SystemExit("no rollout key separates the buckets")
open(f"{out}/bucket-key.hex", "w").write(key.hex())
print(f"{b2} {b3} {shared} {key.hex()}")
PY
)
read -r B2 B3 SHARED BUCKET_KEY <<<"$BUCKET_META"
{
  echo "seq = 1"
  echo "issued_day = $ISSUED"
  echo "not_after_day = $NOT_AFTER"
  echo "floor_version_code = 0"
  echo "[[release]]"
  echo "version_code = 2"
  echo "version_name = \"2.0.0-world\""
  echo "min_sdk = 29"
  echo "anchor_root = 1"
  echo "wire_changing = false"
  echo "apk = \"$APK_WIN\""
  echo "unsigned = \"$CORE_WIN\""
  echo "rollout_permille = $((B2 + 1))"
  echo "rollout_salt = \"$SALT\""
  echo "commit = \"$COMMIT\""
  echo "es_seq = $ES_SEQ"
  echo "es_file = \"$(cygpath -m "$ES_FILE")\""
  echo "[[release.artifacts]]"
  echo "kind = 16"
  echo "file = \"$CORE_WIN\""
  echo "[[release]]"
  echo "version_code = 3"
  echo "version_name = \"3.0.0-swap\""
  echo "min_sdk = 29"
  echo "anchor_root = 1"
  echo "wire_changing = false"
  echo "apk = \"$(cygpath -m "$OUT/app-v2-swap.apk")\""
  echo "unsigned = \"$(cygpath -m "$OUT/core-swap.apk")\""
  echo "rollout_permille = 0"
  echo "rollout_salt = \"$SALT\""
  echo "commit = \"$COMMIT\""
  echo "es_seq = $ES_SEQ"
  echo "es_file = \"$(cygpath -m "$ES_FILE")\""
  echo "[[release.artifacts]]"
  echo "kind = 16"
  echo "file = \"$(cygpath -m "$OUT/core-swap.apk")\""
  grep '^relay ' "$RELAY_DIR" | while read -r _ onion _op; do
    echo "[[relay]]"
    echo "onion = \"$onion\""
    echo "operator = \"$(grep "^relay $onion" "$RELAY_DIR" | awk '{print $3}')\""
  done
} > "$OUT/cfg-bucket.toml"
"$OPS" manifest-build --source "$OUT/cfg-bucket.toml" --root "$OUT/root-1.ghrt" --keys "$KEYS" \
  --attest-keys attest-1 --out "$OUT/manifest-bucket.ghrm"
"$OPS" proof-build --file "$OUT/manifest-bucket.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/manifest-bucket.ghrp"
"$OPS" bundle --chain "$OUT/chain.ghrc" --manifest "$OUT/manifest-bucket.ghrm" \
  --manifest-proof "$OUT/manifest-bucket.ghrp" --out "$OUT/bundle-bucket.ghrb"

# GHRB surgery: WRONG_PROOF (the proof section of another manifest's bundle) and WITHHOLD_PROOF
# (no proof section at all). Layout (§4.8): GHRB|u8|u8|u32 chain|...|u32 manifest|manifest|u32 proof|proof.
python3 - "$OUT" <<'PY'
import struct, sys
out = sys.argv[1]
def sections(path):
    d = open(path, "rb").read()
    assert d[:4] == b"GHRB"
    pos = 6
    (n,) = struct.unpack_from(">I", d, pos); pos += 4 + n
    (nroot,) = struct.unpack_from(">H", d, pos); pos += 2
    for _ in range(nroot):
        (n,) = struct.unpack_from(">I", d, pos); pos += 4 + n
    (mstart,) = struct.unpack_from(">I", d, pos); mlen_pos = pos; pos += 4 + mstart
    (plen,) = struct.unpack_from(">I", d, pos); proof_pos = pos; pos += 4
    assert pos + plen == len(d), "trailing bytes: not a tight GHRB"
    head = d[:mlen_pos + 4]  # keep the manifest's u32 length prefix
    manifest = d[mlen_pos + 4:proof_pos]
    proof = d[proof_pos:]
    return head, manifest, proof
head, manifest, _ = sections(f"{out}/bundle.ghrb")
_, _, foreign_proof = sections(f"{out}/bundle-eq-a.ghrb")
def build(path, proof_section):
    with open(path, "wb") as f:
        f.write(head)
        f.write(manifest)
        f.write(proof_section)
build(f"{out}/bundle-wrongproof.ghrb", foreign_proof)
build(f"{out}/bundle-nowproof.ghrb", struct.pack(">I", 0))
PY

# The STALE mirror's world: the same release under an expired manifest (issued 40 days ago,
# expired 10 days ago), cosigned in its own era so the only refusal ground is expiry.
write_manifest manifest-stale "$OUT/root-1.ghrt" 1 $((TODAY - 40)) $((TODAY - 10)) 0 attest-1 "2.0.0-world" "$APK_WIN" "$CORE_WIN"
proof_and_bundle manifest-stale release-1 $(( (TODAY - 40) * 86400 + 43200 ))
bundle1 manifest-stale "$OUT/stale-bundle.ghrb"

MANIFEST_SHA=$(sha256sum "$OUT/manifest-1.ghrm" | cut -d' ' -f1)
BUNDLE_SHA=$(sha256sum "$OUT/bundle.ghrb" | cut -d' ' -f1)
cat > "$RES/meta.properties" <<EOF
# The world's fixed clock lives inside the fixture validity window (determinism: a committed
# fixture must not expire under CI weeks later). Regenerated by gen-fixtures.sh.
issued_day=$ISSUED
not_after_day=$NOT_AFTER
apk_sha256=$APK_SHA
apk_big_sha256=$APK_BIG_SHA
manifest_sha256=$MANIFEST_SHA
bundle_sha256=$BUNDLE_SHA
anchor.onion.0=$MIRROR_A
anchor.onion.1=$MIRROR_B
anchor.operator.0=11111111111111111111111111111111
anchor.operator.1=22222222222222222222222222222222
bucket.salt=$SALT
apk.swap_sha256=$(sha256sum "$OUT/app-v2-swap.apk" | cut -d' ' -f1)
rollout.test_key=$BUCKET_KEY
rollout.bucket2=${B2:-0}
rollout.bucket3=${B3:-0}
rollout.bucket.shared=${SHARED:-0}
rollout.permille2=${B2:+$(($B2 + 1))}
EOF

"$OPS" inspect --bundle "$OUT/bundle.ghrb" --today "$TODAY"

# MC-D9: a real multi-leaf fixture log (4 leaves, so the inclusion path branches). The honest
# proof over manifest-1 passes everything; the bad-path proof swaps one path sibling - the
# tree-head signature stays valid, so the ONLY failing check is the inclusion fold. Hand-built
# with ghostsign (the same RFC 8032 machinery), bundled by section surgery (ops' bundle would
# refuse the broken inclusion).
python3 - "$(dirname "$0")" "$OUT" <<'PY'
import hashlib, os, struct, sys
here = os.path.abspath(sys.argv[1])
sys.path.insert(0, here)
import ghostsign
out = sys.argv[2]
f = lambda b: hashlib.sha256(b).digest()
manifest = open(f"{out}/manifest-1.ghrm", "rb").read()
message = f(manifest)
checksum = f(message)  # SHA-256(SHA-256(file)): the leaf checksum the log stores
release = bytes.fromhex(open(f"{here}/keys/release-1.hex").read())
log = bytes.fromhex(open(f"{here}/keys/log-1.hex").read())
wit = bytes.fromhex(open(f"{here}/keys/witness-1.hex").read())
leaf_stmt = b"sigsum.org/v1/tree-leaf\x00" + checksum
leaf_sig = ghostsign.sign(release, leaf_stmt)
leaf128 = checksum + leaf_sig + ghostsign.key_id(ghostsign.publickey(release))
h0 = f(b"\x00" + leaf128)
leaves = [h0] + [f(b"fixture-leaf-%d" % i) for i in (1, 2, 3)]
def node(a, b):
    return f(b"\x01" + a + b)
h01 = node(leaves[0], leaves[1])
h23 = node(leaves[2], leaves[3])
root = node(h01, h23)
log_key_id = ghostsign.key_id(ghostsign.publickey(log))
checkpoint = b"sigsum.org/v1/tree/" + log_key_id.hex().encode() + b"\n4\n" + root.hex().encode() + b"\n"
log_sig = ghostsign.sign(log, checkpoint)
cosign_stmt = b"cosignature/v1\ntime 0\n" + checkpoint
cosig = ghostsign.key_id(ghostsign.publickey(wit)) + (0).to_bytes(8, "big") + ghostsign.sign(wit, cosign_stmt)
def ghrp(path):
    return (b"GHRP" + b"\x01" + message + b"\x00" + leaf_sig +
        ghostsign.key_id(ghostsign.publickey(release)) + (4).to_bytes(8, "big") +
        (0).to_bytes(8, "big") + bytes([len(path)]) + b"".join(path) +
        root + log_sig + b"\x01" + cosig)
open(f"{out}/manifest-ml.ghrp", "wb").write(ghrp([leaves[1], h23]))
open(f"{out}/manifest-badpath.ghrp", "wb").write(ghrp([leaves[2], h23]))
# Section surgery: the honest ops bundle with the hand-built proof section swapped in.
def split_bundle(path):
    d = open(path, "rb").read()
    pos = 6
    (n,) = struct.unpack_from(">I", d, pos); pos += 4 + n
    (nroot,) = struct.unpack_from(">H", d, pos); pos += 2
    for _ in range(nroot):
        (n,) = struct.unpack_from(">I", d, pos); pos += 4 + n
    (m,) = struct.unpack_from(">I", d, pos)
    return d[:pos + 4 + m]
head = split_bundle(f"{out}/bundle.ghrb")
for name in ("ml", "badpath"):
    proof = open(f"{out}/manifest-{name}.ghrp", "rb").read()
    open(f"{out}/bundle-{name}.ghrb", "wb").write(head + struct.pack(">I", len(proof)) + proof)
PY

cp "$OUT"/chain.ghrc "$OUT"/chain2.ghrc "$OUT"/chain-main.ghrc "$OUT"/root-2.ghrp \
   "$OUT"/manifest-1.ghrm "$OUT"/manifest-1.ghrp "$OUT"/bundle.ghrb \
   "$OUT"/manifest-eq-a.ghrm "$OUT"/manifest-eq-b.ghrm "$OUT"/bundle-eq-a.ghrb "$OUT"/bundle-eq-b.ghrb \
   "$OUT"/bundle-wrongproof.ghrb "$OUT"/bundle-nowproof.ghrb \
   "$OUT"/manifest-wrongroot.ghrm "$OUT"/bundle-wrongroot.ghrb \
   "$OUT"/manifest-ff.ghrm "$OUT"/bundle-ff.ghrb \
   "$OUT"/manifest-replay.ghrm "$OUT"/manifest-replay.ghrp "$OUT"/bundle-replay.ghrb \
   "$OUT"/manifest-floor.ghrm "$OUT"/bundle-floor.ghrb \
   "$OUT"/manifest-relabel.ghrm "$OUT"/bundle-relabel.ghrb \
   "$OUT"/manifest-stale.ghrm "$OUT"/manifest-stale.ghrp "$OUT"/stale-bundle.ghrb \
   "$OUT"/manifest-main.ghrm "$OUT"/bundle-mainnet.ghrb \
   "$OUT"/manifest-big.ghrm "$OUT"/bundle-big.ghrb \
   "$OUT"/manifest-2.ghrm "$OUT"/bundle-2.ghrb \
   "$OUT"/manifest-stolen.ghrm "$OUT"/bundle-stolen.ghrb \
   "$OUT"/chain2bad.ghrc "$OUT"/manifest-2bad.ghrm "$OUT"/bundle-2bad.ghrb \
   "$OUT"/manifest-flipsig.ghrm "$OUT"/bundle-flipsig.ghrb \
   "$OUT"/bundle-badindex.ghrb "$OUT"/bundle-badhead.ghrb "$OUT"/bundle-othermsg.ghrb \
   "$OUT"/bundle-nocosig.ghrb "$OUT"/bundle-unknownwit.ghrb \
   "$OUT"/bundle-badrootproof.ghrb \
   "$OUT"/manifest-xroot.ghrm "$OUT"/bundle-xroot.ghrb \
   "$OUT"/manifest-bucket.ghrm "$OUT"/bundle-bucket.ghrb \
   "$OUT"/manifest-removedkey.ghrm "$OUT"/bundle-removedkey.ghrb \
   "$OUT"/chain-31.ghrc "$OUT"/manifest-31.ghrm "$OUT"/bundle-31.ghrb "$OUT"/app-v31.apk \
   "$OUT"/manifest-floorbad.ghrm "$OUT"/bundle-floorbad.ghrb \
   "$OUT"/manifest-ml.ghrp "$OUT"/manifest-badpath.ghrp "$OUT"/bundle-ml.ghrb "$OUT"/bundle-badpath.ghrb \
   "$OUT"/manifest-2x.ghrm "$OUT"/bundle-2x.ghrb \
   "$OUT"/chain5.ghrc "$OUT"/chain6.ghrc "$OUT"/chain-rc.ghrc "$OUT"/chain-swap.ghrc \
   "$OUT"/manifest-5.ghrm "$OUT"/manifest-6.ghrm "$OUT"/manifest-rc.ghrm \
   "$OUT"/bundle-5.ghrb "$OUT"/bundle-6.ghrb "$OUT"/bundle-rc.ghrb "$OUT"/bundle-swap.ghrb "$OUT"/bundle-3att.ghrb \
   "$OUT"/chain4.ghrc "$OUT"/chain4x.ghrc "$OUT"/manifest-4.ghrm "$OUT"/manifest-4x.ghrm \
   "$OUT"/bundle-4.ghrb "$OUT"/bundle-4x.ghrb \
   "$OUT"/app-v2.apk "$OUT"/app-v2-swap.apk "$OUT"/app-v2-extra.apk "$OUT"/app-v2-big.apk "$OUT"/core.apk \
   "$RES/"
cp "$RELAY_DIR" "$RES/bootstrap-relays.txt"

cat > "$W/README.md" <<EOF
# UpdateWorld fixtures (Phase 14 §11.2)

Throwaway software keys (the G-D1 carve-out; never real ceremony material) and the signed
fixture world the JVM update world serves through its model mirrors:

- keys/ — the ops keyset (root-1/2, release-1/2, attest-1/2, apk-1, log-1, witness-1) +
  fixture.ks, the APK signing keystore (storepass: $KEYSTORE_PASS).
- The world documents live in android/update/src/test/resources/update-world/ (regenerated by
  gen-fixtures.sh): the benign chain/manifest/bundle, the real apksigner-signed APKs, and one
  document per hostile mode — equivocating manifests, fast-forward and expired-replay pairs,
  the floor-bound manifest attested by an unknown key, the relabeled relay list, the foreign
  root's manifest, the rotation chain (root v2) and the stolen-release-key manifest, plus the
  GHRB-surgery variants (wrong/withheld proof) and the multi-chunk APK.

Facts of this instance (regenerating changes all of them):
- fixture APK cert sha256: $CERT_SHA
- fixture APK sha256: $APK_SHA (length $APK_LEN); big APK sha256: $APK_BIG_SHA
- issued_day $ISSUED, not_after_day $NOT_AFTER (generated $(date -u +%F))
EOF

sha256sum "$RES/chain.ghrc" "$RES/bundle.ghrb" "$RES/app-v2.apk"
echo "FIXTURES_OK apk_sha256=$APK_SHA cert_sha256=$CERT_SHA"