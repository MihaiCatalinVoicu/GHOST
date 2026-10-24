#!/bin/bash
# Faza 14 S1: channel test end-to-end on the staging mirrors.
# Build a stagenet bundle with software keys, publish it to both mirrors, fetch over Tor.
set -euo pipefail
source ~/.cargo/env
cd /srv/ghost-src/ghost
cargo build -p ghost-release-ops 2>&1 | tail -1

OPS=/srv/ghost-src/ghost/target/debug/ghost-release-ops
CH=~/ghost-channel
rm -rf "$CH"
mkdir -p "$CH"/{keys,cfg,rel,out}

$OPS keygen --out "$CH/keys" --spec root:2,release:1,attest:1,apk:1,log:1,witness:2

MIRROR_B=ls2jkm3tmxnaa3o3j3bbb63jx5csqdiaen6wdt3ls6wkpfejl3xlfoqd.onion:443
MIRROR_A=tfhsac26mfhbq6dm5rctfkjnll74xag6p7ehumcr7keqsnkqhp7no4id.onion:443

cat > "$CH/cfg/root-1.toml" <<EOF
network = 2
version = 1
apk_signers = ["7777777777777777777777777777777777777777777777777777777777777777"]
witnesses = ["witness-1", "witness-2"]
quorum = 1
[root]
keys = ["root-1", "root-2"]
threshold = 2
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
onion = "$MIRROR_B"
operator = "11111111111111111111111111111111"
[[anchor_mirrors]]
onion = "$MIRROR_A"
operator = "22222222222222222222222222222222"
EOF

$OPS root-build --config "$CH/cfg/root-1.toml" --keys "$CH/keys" --out "$CH/out/root-1.ghrt"
# chain-build reads a directory of *.ghrt
mkdir -p "$CH/out/roots"
cp "$CH/out/root-1.ghrt" "$CH/out/roots/"
$OPS chain-build --network 2 --roots "$CH/out/roots" --out "$CH/out/chain.ghrc"

# Dummy release artifacts (the channel test binds bytes, not a real APK).
printf 'staging-signed-apk-v1'   > "$CH/rel/app.apk"
printf 'staging-unsigned-core-v1' > "$CH/rel/app-unsigned.apk"
printf 'staging-escrow-v1'       > "$CH/rel/escrow.tar.gz"
printf 'staging-es-v1'           > "$CH/rel/es.json"

TODAY=$(( $(date +%s) / 86400 ))
cat > "$CH/cfg/manifest-1.toml" <<EOF
seq = 1
issued_day = $TODAY
not_after_day = $((TODAY + 30))
floor_version_code = 0
[[release]]
version_code = 1
version_name = "0.9.0-stg1"
min_sdk = 29
anchor_root = 1
wire_changing = false
apk = "$CH/rel/app.apk"
unsigned = "$CH/rel/app-unsigned.apk"
rollout_permille = 1000
rollout_salt = "33333333333333333333333333333333"
commit = "$(printf 'ab%.0s' $(seq 1 20))"
es_seq = 2957
es_file = "$CH/rel/es.json"
[[release.artifacts]]
kind = 16
file = "$CH/rel/escrow.tar.gz"
EOF

$OPS manifest-build --source "$CH/cfg/manifest-1.toml" --root "$CH/out/root-1.ghrt" \
  --keys "$CH/keys" --attest-keys attest-1 --out "$CH/out/m1.ghrm"

$OPS proof-build --file "$CH/out/m1.ghrm" --log-index 0 --log-key log-1 \
  --submit-key release-1 --witness witness-1 --witness witness-2 \
  --keys "$CH/keys" --out "$CH/out/m1.ghrp"

$OPS bundle --chain "$CH/out/chain.ghrc" --manifest "$CH/out/m1.ghrm" \
  --manifest-proof "$CH/out/m1.ghrp" --out "$CH/out/current.ghrb"

$OPS inspect --bundle "$CH/out/current.ghrb" --today "$TODAY"
sha256sum "$CH/out/current.ghrb"
