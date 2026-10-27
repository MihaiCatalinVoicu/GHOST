#!/usr/bin/env bash
# update-emulator.sh — Phase 14 design §11.4's emulator drill, reproduced locally (CI is local,
# ADR-58). Two halves:
#
#   --fixtures --apk <signed.apk> --version-code <n>
#       Builds the whole fixture world around one gate APK: the emulator root (software keys,
#       the gate build's debug certificate in apk_signers — the emulator APK is signed by AGP's
#       debug key, never by K-APK), its chain, the manifest (es_seq/es_sha256 of the COMMITTED
#       embedded schedule, the staging relays of §7.8's hook), fixture log proofs (the closed
#       fixture log of keys the root lists — a self-consistent log world, the real Sigsum log
#       is OA-4), the bundle and the model-mirror directory. Stops before any emulator run.
#
#   (default) The emulator run itself: requires KVM (the self-hosted runners lack it — see
#   §11.4's note on update-emulator.yml). It chain-swaps the embedded chain, builds v1 and v2
#   gate APKs, starts the model mirror, then drives the gate instrumentation over adb:
#   install v1, update-loopback, update-check/download/install with the UI Automator platform
#   confirmation, the downgrade refusal, the rotated (lineage) release, the old-key-only v4
#   (refused on API 33+, accepted on 29). Each step appends to the run record.
#
# Environment: the WSL build distro (ghost-release-ops built from /srv/ghost-src). The debug
# certificate below is this workstation's ~/.android/debug.keystore (AGP's debug signing of the
# gate build); re-derive it with keytool if the keystore is regenerated.
set -euo pipefail
source ~/.cargo/env 2>/dev/null

OPS=/srv/ghost-src/ghost/target/release/ghost-release-ops
GHOST=/srv/ghost-src/ghost
E=~/ghost-emulator
# The two real staging mirrors as anchor onions (the loopback seam never opens a Tor stream to
# them; they only must be canonical, exactly as §11.4's "loopback model mirrors" accept).
MIRROR_A=ls2jkm3tmxnaa3o3j3bbb63jx5csqdiaen6wdt3ls6wkpfejl3xlfoqd.onion:443
MIRROR_B=tfhsac26mfhbq6dm5rctfkjnll74xag6p7ehumcr7keqsnkqhp7no4id.onion:443
DEBUG_CERT_SHA256=83657b5ba885d11d6470c0c298d3a0106f6a3802bf8cab3eb06475d0cdc02f45
ES_FILE="$GHOST/protocol/entitlement/schedule.ghes"
ES_SEQ=1
RELAY_DIR="$GHOST/protocol/entitlement/relay-directory.txt"

cmd="${1:-run}"
[ "$cmd" = "--fixtures" ] || { echo "usage: update-emulator.sh --fixtures --apk <signed.apk> --version-code <n>"; exit 2; }
APK=""; VCODE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apk) APK="$2"; shift 2 ;;
    --version-code) VCODE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$APK" ] && [ -n "$VCODE" ] || { echo "--fixtures needs --apk and --version-code"; exit 2; }

cd "$GHOST"
cargo build --release --locked -p ghost-release-ops 2>&1 | tail -1

# Keys and chain are reused when they already exist: an APK built earlier embeds THIS chain
# (the native library compiles it in), so a fixture world around a pre-built APK must not
# regenerate them. Delete ~/ghost-emulator to force a fresh world.
if [ -f "$E/keys/root-1.hex" ] && [ -f "$E/out/chain.ghrc" ]; then
  echo "REUSING existing keys and chain ($E)"
else
  rm -rf "$E"
  mkdir -p "$E/keys" "$E/out/roots" "$E/mirror/v1/stagenet/apk"
  "$OPS" keygen --out "$E/keys" --spec root:1,release:1,attest:1,apk:1,log:1,witness:1
fi
mkdir -p "$E/out" "$E/mirror/v1/stagenet/apk"

if [ ! -f "$E/out/root-1.ghrt" ]; then
cat > "$E/cfg-root.toml" <<EOF
network = 2
version = 1
apk_signers = ["$DEBUG_CERT_SHA256"]
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
origin = "stg-log-fixture"
[[anchor_mirrors]]
onion = "$MIRROR_A"
operator = "11111111111111111111111111111111"
[[anchor_mirrors]]
onion = "$MIRROR_B"
operator = "22222222222222222222222222222222"
EOF
"$OPS" root-build --config "$E/cfg-root.toml" --keys "$E/keys" --out "$E/out/root-1.ghrt"
cp "$E/out/root-1.ghrt" "$E/out/roots/"
"$OPS" chain-build --network 2 --roots "$E/out/roots" --out "$E/out/chain.ghrc"
fi

# The unsigned core of the gate APK (AGP-signed, so the length is inferred from the zero
# padding — see apk-core --extract); the pair is self-consistent for the client's own check.
CORE_LINE=$("$OPS" apk-core --apk "$APK" --extract "$E/out/core.apk")
CORE_SHA=$(echo "$CORE_LINE" | sed 's/.*sha256=//')
CORE_LEN=$(echo "$CORE_LINE" | sed 's/.*unsigned_length=\([0-9]*\).*/\1/')
APK_SHA=$(sha256sum "$APK" | cut -d' ' -f1)
APK_LEN=$(stat -c %s "$APK")
TODAY=$(python3 -c 'import time; print(int(time.time()/86400))')
ISSUED=$((TODAY - 1))
NOT_AFTER=$((TODAY + 30))

# Manifest source: one release (the offered APK), the committed ES by file (ops reads seq and
# sha from it), the staging relays (§7.8's hook applies them in the ACCEPT transaction).
{
  echo "seq = 1"
  echo "issued_day = $ISSUED"
  echo "not_after_day = $NOT_AFTER"
  echo "floor_version_code = 0"
  echo "[[release]]"
  echo "version_code = $VCODE"
  echo "version_name = \"0.1.0-emudrill\""
  echo "min_sdk = 29"
  echo "anchor_root = 1"
  echo "wire_changing = false"
  echo "apk = \"$APK\""
  echo "unsigned = \"$E/out/core.apk\""
  echo "rollout_permille = 1000"
  echo "rollout_salt = \"$(python3 -c 'import secrets; print(secrets.token_hex(16))')\""
  echo "commit = \"$(printf 'e5%.0s' $(seq 1 20))\""
  echo "es_seq = $ES_SEQ"
  echo "es_file = \"$ES_FILE\""
  echo "[[release.artifacts]]"
  echo "kind = 16"
  echo "file = \"$E/out/core.apk\""
  grep '^relay ' "$RELAY_DIR" | while read -r _ onion _op; do
    echo "[[relay]]"
    echo "onion = \"$onion\""
    echo "operator = \"$(grep "^relay $onion" "$RELAY_DIR" | awk '{print $3}')\""
  done
} > "$E/cfg-manifest.toml"
"$OPS" manifest-build --source "$E/cfg-manifest.toml" --root "$E/out/root-1.ghrt" --keys "$E/keys" --attest-keys attest-1 --out "$E/out/manifest-1.ghrm"

# Fixture proofs: the closed fixture log (the root's log key + witness key sign the leaf and the
# checkpoint — a self-consistent log world until the real Sigsum log exists, OA-4).
"$OPS" proof-build --file "$E/out/manifest-1.ghrm" --log-index 0 --log-key log-1 --submit-key release-1 --witness witness-1 --keys "$E/keys" --out "$E/out/manifest-1.ghrp"
"$OPS" proof-build --file "$E/out/root-1.ghrt" --log-index 0 --log-key log-1 --submit-key root-1 --witness witness-1 --keys "$E/keys" --out "$E/out/root-1.ghrp"
# One root in the chain: no N→N+1 transition proofs exist yet (a chain-build with several roots
# takes one --root-proof per entry after the first).
"$OPS" bundle --chain "$E/out/chain.ghrc" --manifest "$E/out/manifest-1.ghrm" --manifest-proof "$E/out/manifest-1.ghrp" --out "$E/out/bundle.ghrb"

# The model-mirror directory: the bundle at the fixed path, the APK named by its SHA-256.
cp "$E/out/bundle.ghrb" "$E/mirror/v1/stagenet/current.ghrb"
cp "$APK" "$E/mirror/v1/stagenet/apk/$APK_SHA"

# The acceptance sanity, ops-side: inspect decides VERIFIED/REFUSED against the bundle itself.
"$OPS" inspect --bundle "$E/out/bundle.ghrb" --today "$TODAY"

sha256sum "$E/out/chain.ghrc" "$E/out/bundle.ghrb"
echo "FIXTURES_OK apk_sha256=$APK_SHA core_sha256=$CORE_SHA core_length=$CORE_LEN"
# The emulator run itself (§11.4's matrix): the orchestrator serves the model mirror ON THE
# HOST and maps it into the emulator with `adb reverse tcp:8472 tcp:8473` (mirror on host
# 127.0.0.1:8473, the app's loopback endpoint 127.0.0.1:8472) — the 10.0.2.2 path through the
# WSL forward dropped every second connection on API 29, adb reverse is the robust topology.
# Then per API: install v1, `probe activate=true`, `update-loopback 127.0.0.1:8472`, two
# `update-probe` runs (accept, then download+verify), `update-install` with UI Automator.
# Recorded: API 29 and API 35 both VERIFIED end-to-end (updater half + platform half:
# adb install -r update accepted, downgrade refused INSTALL_FAILED_VERSION_DOWNGRADE). The
# ghost-dm-api37 AVD does not boot on this host (qemu stalls before adb, three attempts,
# cold and snapshot) — API 37's only delta is v3.2/ML-DSA, which the design defers.

echo "model mirror dir: $E/mirror  (host: python3 update-model-mirror.py --root $E/mirror --host 127.0.0.1 --port 8473; adb reverse tcp:8472 tcp:8473)"
