#!/bin/bash
# Publish the stagenet bundle to both mirrors and fetch it back over Tor.
set -euo pipefail
CH=~/ghost-channel
OPS=/srv/ghost-src/ghost/target/debug/ghost-release-ops
URL_PATH=ghost/v1/stagenet/current.ghrb
MIRROR_A=tfhsac26mfhbq6dm5rctfkjnll74xag6p7ehumcr7keqsnkqhp7no4id.onion
MIRROR_B=ls2jkm3tmxnaa3o3j3bbb63jx5csqdiaen6wdt3ls6wkpfejl3xlfoqd.onion

# Publish by atomic rename, per design §5.3 step 5.
for M in a b; do
  sudo mkdir -p "/srv/mirrors/$M/www/ghost/v1/stagenet"
  sudo cp "$CH/out/current.ghrb" "/srv/mirrors/$M/www/$URL_PATH.staged"
  sudo mv "/srv/mirrors/$M/www/$URL_PATH.staged" "/srv/mirrors/$M/www/$URL_PATH"
  echo "PUBLISHED mirror-$M"
done

# Fetch back through the host Tor (127.0.0.1:9050), both listeners.
TODAY=$(( $(date +%s) / 86400 ))
for M in $MIRROR_A $MIRROR_B; do
  for PORT in 80 443; do
    OUT="$CH/out/fetched-$PORT.ghrb"
    CODE=$(curl -sS --socks5-hostname 127.0.0.1:9050 \
      -w "%{http_code}" -o "$OUT" "http://$M:$PORT/$URL_PATH" 2>/dev/null || echo CURL_FAIL)
    if [ "$CODE" = 200 ]; then
      LOCAL=$(sha256sum "$CH/out/current.ghrb" | cut -d" " -f1)
      REMOTE=$(sha256sum "$OUT" | cut -d" " -f1)
      if [ "$LOCAL" = "$REMOTE" ]; then HASH=HASH_EQUAL; else HASH="HASH_DIFF local=$LOCAL remote=$REMOTE"; fi
      echo "FETCH $M:$PORT http=$CODE $HASH"
      $OPS inspect --bundle "$OUT" --today "$TODAY"
    else
      echo "FETCH $M:$PORT http=$CODE"
    fi
  done
done
