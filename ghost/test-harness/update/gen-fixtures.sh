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
python3 "$(dirname "$0")/gen-keys.py" "$KEYS" root-1 root-2 root-3 release-1 release-2 attest-1 attest-2 apk-1 log-1 witness-1 witness-2 witness-3

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
# 2048-byte dex payloads, different content, so the two unsigned zips (and thus the signed
# APKs, same key and structure) have equal lengths: the swap reaches the native full-file hash.
a = bytes(((i * 7 + 3) & 0xff) for i in range(2048))
b = bytes(((i * 13 + 5) & 0xff) for i in range(2048))
la = build(f"{out}/unsigned.zip", a)
lb = build(f"{out}/unsigned2.zip", b)
assert la == lb, f"unsigned zips differ in length: {la} vs {lb}"
# The multi-chunk APK (> 4 MiB) for DROP_MID_RANGE and SLOW.
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
sign "$OUT/unsigned2.zip" "$OUT/app-v2-swap.apk"
sign "$OUT/unsigned-big.zip" "$OUT/app-v2-big.apk"
[ "$(stat -c%s "$OUT/app-v2.apk")" = "$(stat -c%s "$OUT/app-v2-swap.apk")" ] || {
  echo "swap APK length mismatch"; exit 1; }

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
bundle1 manifest-stolen "$OUT/bundle-stolen.ghrb"

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
EOF

"$OPS" inspect --bundle "$OUT/bundle.ghrb" --today "$TODAY"

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