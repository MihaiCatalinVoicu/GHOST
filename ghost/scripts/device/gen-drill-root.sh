#!/usr/bin/env bash
# D26's drill root (faza14 design §11.4): a separate chain, stagenet network byte, software keys
# on this workstation, the gate build's debug certificate in apk_signers, anchor mirrors = the
# two real staging mirrors. Never in a release build (G-D4).
#
# Run in the WSL build distro (ghost-release-ops built from /srv/ghost-src). Outputs:
#   ~/ghost-drill/keys/   software keys (drill workstation only, never committed, never released)
#   ~/ghost-drill/out/    root-1.ghrt, chain.ghrc (the drill chain the gate build embeds)
# Regenerating changes every key and the chain hashes — the drill phone re-installs the gate APK.
# Recorded instance (2026-10-26): root sha256 45af6ddbd9440070ee82d6927de66d2effd3d835610f2201c2ce004324f7e176,
# chain sha256 26980e5f260e6943984e792269f6eb5136fc5b5c5d55c9cbb2887c094250fed5.
set -euo pipefail
source ~/.cargo/env 2>/dev/null
OPS=/srv/ghost-src/ghost/target/release/ghost-release-ops
D=~/ghost-drill
rm -rf "$D"
mkdir -p "$D/cfg" "$D/keys" "$D/out"
"$OPS" keygen --out "$D/keys" --spec root:1,release:1,attest:1,apk:1,log:1,witness:1
cat > "$D/cfg/root-1.toml" <<'EOF'
network = 2
version = 1
apk_signers = ["83657b5ba885d11d6470c0c298d3a0106f6a3802bf8cab3eb06475d0cdc02f45"]
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
onion = "ls2jkm3tmxnaa3o3j3bbb63jx5csqdiaen6wdt3ls6wkpfejl3xlfoqd.onion:443"
operator = "11111111111111111111111111111111"
[[anchor_mirrors]]
onion = "tfhsac26mfhbq6dm5rctfkjnll74xag6p7ehumcr7keqsnkqhp7no4id.onion:443"
operator = "22222222222222222222222222222222"
EOF
"$OPS" root-build --config "$D/cfg/root-1.toml" --keys "$D/keys" --out "$D/out/root-1.ghrt"
mkdir -p "$D/out/roots"
cp "$D/out/root-1.ghrt" "$D/out/roots/"
"$OPS" chain-build --network 2 --roots "$D/out/roots" --out "$D/out/chain.ghrc"
ls -la "$D/out"
sha256sum "$D/out/chain.ghrc" "$D/out/root-1.ghrt"
echo DRILL_ROOT_DONE
