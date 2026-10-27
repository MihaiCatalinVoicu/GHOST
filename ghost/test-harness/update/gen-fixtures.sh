#!/usr/bin/env bash
# Regenerates the UpdateWorld fixture world (Phase 14 design §11.2's JVM world): a throwaway
# stagenet chain (network 2, software keys committed under test-harness/update/keys, the G-D1
# carve-out), one signed fixture APK (apksigner, build-tools 37.0.0), a manifest of one release,
# closed-fixture-log proofs and the bundle the model mirrors serve.
#
# Outputs:
#   test-harness/update/keys/                       the throwaway keyset (root/release/attest/apk/log/witness + APK keystore)
#   android/update/src/test/resources/update-world/ chain.ghrc, manifest-1.ghrm, manifest-1.ghrp, root-1.ghrp, bundle.ghrb, app-v2.apk
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

rm -rf "$OUT" "$RES"
mkdir -p "$OUT" "$RES/apk" "$KEYS"
rm -f "$KEYS"/*.hex "$KEYS"/fixture.ks

# ops keygen hardcodes /dev/urandom (Linux-only); the keyset format is 32-byte Ed25519 seeds +
# public keys, generated here with RFC 8032 reference arithmetic (self-checked against the RFC
# test vector; ops' root-build/manifest-build/inspect verify key correspondence downstream).
python3 "$(dirname "$0")/gen-keys.py" "$KEYS"

# --- the fixture APK: a minimal zip, signed v1+v2 with a throwaway RSA key ---------------
python3 - "$OUT/unsigned.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("AndroidManifest.xml", bytes([3, 0, 8, 0]) + b"fixture-world-apk")
    z.writestr("classes.dex", bytes(range(256)) * 8)
PY

"$BT/../../cmdline-tools/latest/bin/keytool" 2>/dev/null || true
JAVA_HOME='C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot'
export JAVA_HOME
"$JAVA_HOME/bin/keytool.exe" -genkeypair -keystore "$KEYS/fixture.ks" -storepass "$KEYSTORE_PASS" \
  -keypass "$KEYSTORE_PASS" -alias fixture -keyalg RSA -keysize 2048 -validity 20000 \
  -dname "CN=Ghost UpdateWorld Fixture, OU=test, O=ghost-fixture" 2>/dev/null

CERT_SHA=$("$JAVA_HOME/bin/keytool.exe" -exportcert -keystore "$KEYS/fixture.ks" -storepass "$KEYSTORE_PASS" \
  -alias fixture 2>/dev/null | sha256sum | cut -d' ' -f1)
echo "fixture APK cert sha256: $CERT_SHA"

cmd //c "$(cygpath -w "$BT/apksigner.bat")" sign --ks "$(cygpath -w "$KEYS/fixture.ks")" \
  --ks-pass "pass:$KEYSTORE_PASS" --key-pass "pass:$KEYSTORE_PASS" \
  --min-sdk-version 29 --max-sdk-version 34 \
  --out "$(cygpath -w "$OUT/app-v2.apk")" "$(cygpath -w "$OUT/unsigned.zip")"

# --- the root and the chain --------------------------------------------------------------
cat > "$OUT/cfg-root.toml" <<EOF
network = 2
version = 1
apk_signers = ["$CERT_SHA"]
witnesses = ["witness-1"]
quorum = 1
[root]
keys = ["root-1"]
threshold = 1
[release]
keys = ["release-1"]
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
mkdir -p "$OUT/roots"
"$OPS" root-build --config "$OUT/cfg-root.toml" --keys "$KEYS" --out "$OUT/root-1.ghrt"
cp "$OUT/root-1.ghrt" "$OUT/roots/"
"$OPS" chain-build --network 2 --roots "$OUT/roots" --out "$OUT/chain.ghrc"

# --- the unsigned core, the manifest, the proofs, the bundle -----------------------------
CORE_LINE=$("$OPS" apk-core --apk "$OUT/app-v2.apk" --extract "$OUT/core.apk")
echo "$CORE_LINE"
APK_SHA=$(sha256sum "$OUT/app-v2.apk" | cut -d' ' -f1)
APK_LEN=$(stat -c%s "$OUT/app-v2.apk")
TODAY=$(python3 -c 'import time; print(int(time.time()/86400))')
ISSUED=$((TODAY - 1))
NOT_AFTER=$((TODAY + 30))
SALT=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
COMMIT=$(printf 'ghost-update-world-fixture-%.0s' 1 | sha256sum | cut -c1-40)

APK_WIN=$(cygpath -m "$OUT/app-v2.apk")
CORE_WIN=$(cygpath -m "$OUT/core.apk")
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
  echo "rollout_permille = 1000"
  echo "rollout_salt = \"$SALT\""
  echo "commit = \"$COMMIT\""
  echo "es_seq = $ES_SEQ"
  echo "es_file = \"$(cygpath -m "$ES_FILE")\""
  echo "[[release.artifacts]]"
  echo "kind = 16"
  echo "file = \"$CORE_WIN\""
  grep '^relay ' "$RELAY_DIR" | while read -r _ onion _op; do
    echo "[[relay]]"
    echo "onion = \"$onion\""
    echo "operator = \"$(grep "^relay $onion" "$RELAY_DIR" | awk '{print $3}')\""
  done
} > "$OUT/cfg-manifest.toml"
"$OPS" manifest-build --source "$OUT/cfg-manifest.toml" --root "$OUT/root-1.ghrt" --keys "$KEYS" \
  --attest-keys attest-1 --out "$OUT/manifest-1.ghrm"

"$OPS" proof-build --file "$OUT/manifest-1.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/manifest-1.ghrp"
"$OPS" proof-build --file "$OUT/root-1.ghrt" --log-index 0 --log-key log-1 --submit-key root-1 \
  --witness witness-1 --keys "$KEYS" --out "$OUT/root-1.ghrp"
"$OPS" bundle --chain "$OUT/chain.ghrc" --manifest "$OUT/manifest-1.ghrm" \
  --manifest-proof "$OUT/manifest-1.ghrp" --out "$OUT/bundle.ghrb"

# The STALE mirror's world: the same release chain, an expired manifest (issued 40 days ago,
# expired 10 days ago), cosigned in its own era so the only refusal ground is expiry.
STALE_ISSUED=$((TODAY - 40))
STALE_NOT_AFTER=$((TODAY - 10))
{
  echo "seq = 1"
  echo "issued_day = $STALE_ISSUED"
  echo "not_after_day = $STALE_NOT_AFTER"
  echo "floor_version_code = 0"
  echo "[[release]]"
  echo "version_code = 2"
  echo "version_name = \"2.0.0-world\""
  echo "min_sdk = 29"
  echo "anchor_root = 1"
  echo "wire_changing = false"
  echo "apk = \"$APK_WIN\""
  echo "unsigned = \"$CORE_WIN\""
  echo "rollout_permille = 1000"
  echo "rollout_salt = \"$SALT\""
  echo "commit = \"$COMMIT\""
  echo "es_seq = $ES_SEQ"
  echo "es_file = \"$(cygpath -m "$ES_FILE")\""
  echo "[[release.artifacts]]"
  echo "kind = 16"
  echo "file = \"$CORE_WIN\""
  grep '^relay ' "$RELAY_DIR" | while read -r _ onion _op; do
    echo "[[relay]]"
    echo "onion = \"$onion\""
    echo "operator = \"$(grep "^relay $onion" "$RELAY_DIR" | awk '{print $3}')\""
  done
} > "$OUT/cfg-manifest-stale.toml"
"$OPS" manifest-build --source "$OUT/cfg-manifest-stale.toml" --root "$OUT/root-1.ghrt" --keys "$KEYS" \
  --attest-keys attest-1 --out "$OUT/manifest-stale.ghrm"
"$OPS" proof-build --file "$OUT/manifest-stale.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 \
  --witness witness-1 --time $((STALE_ISSUED * 86400 + 43200)) --keys "$KEYS" --out "$OUT/manifest-stale.ghrp"
"$OPS" bundle --chain "$OUT/chain.ghrc" --manifest "$OUT/manifest-stale.ghrm" \
  --manifest-proof "$OUT/manifest-stale.ghrp" --out "$OUT/stale-bundle.ghrb"

MANIFEST_SHA=$(sha256sum "$OUT/manifest-1.ghrm" | cut -d' ' -f1)
BUNDLE_SHA=$(sha256sum "$OUT/bundle.ghrb" | cut -d' ' -f1)
cat > "$RES/meta.properties" <<EOF
# The world's fixed clock lives inside the fixture validity window (determinism: a committed
# fixture must not expire under CI weeks later). Regenerated by gen-fixtures.sh.
issued_day=$ISSUED
not_after_day=$NOT_AFTER
apk_sha256=$APK_SHA
manifest_sha256=$MANIFEST_SHA
bundle_sha256=$BUNDLE_SHA
EOF

"$OPS" inspect --bundle "$OUT/bundle.ghrb" --today "$TODAY"

cp "$OUT/chain.ghrc" "$OUT/manifest-1.ghrm" "$OUT/manifest-1.ghrp" "$OUT/root-1.ghrp" \
   "$OUT/bundle.ghrb" "$OUT/stale-bundle.ghrb" "$OUT/manifest-stale.ghrm" "$OUT/manifest-stale.ghrp" \
   "$OUT/app-v2.apk" "$OUT/core.apk" "$RES/"
cat > "$W/README.md" <<EOF
# UpdateWorld fixtures (Phase 14 §11.2)

Throwaway software keys (the G-D1 carve-out; never real ceremony material) and the signed
fixture world the JVM update world serves through its model mirrors:

- keys/ — the ops keyset (root-1, release-1, attest-1, apk-1, log-1, witness-1) + fixture.ks,
  the APK signing keystore (storepass: $KEYSTORE_PASS). Regenerated by gen-fixtures.sh.
- The world documents live in android/update/src/test/resources/update-world/
  (chain.ghrc, manifest-1.ghrm, manifest-1.ghrp, root-1.ghrp, bundle.ghrb, app-v2.apk, core.apk).

Facts of this instance (regenerating changes all of them):
- fixture APK cert sha256: $CERT_SHA
- fixture APK sha256: $APK_SHA (length $APK_LEN)
- issued_day $ISSUED, not_after_day $NOT_AFTER (generated $(date -u +%F))
EOF

sha256sum "$RES/chain.ghrc" "$RES/bundle.ghrb" "$RES/app-v2.apk"
echo "FIXTURES_OK apk_sha256=$APK_SHA cert_sha256=$CERT_SHA"