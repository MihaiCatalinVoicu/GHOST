#!/usr/bin/env bash
# make-fixture.sh — generate the staging mirror document root: a versioned directory shaped like
# the Phase 14 release layout (manifest + detached signature + artifact), signed with a THROWAWAY
# ed25519 key generated on the spot. Nothing here is a real release key; the real root, release
# keys, GHRM format, transparency log and ceremonies are Phase 14 (ADR-48..52).
#
#   make-fixture.sh <www-dir> <mirror-name> <version>
set -euo pipefail
WWW=${1:?www dir}
NAME=${2:?mirror name}
VERSION=${3:-0.0.0-staging}
mkdir -p "$WWW/v1"
KEY="$WWW/.staging-signing-key.pem"
[ -f "$KEY" ] || openssl genpkey -algorithm ed25519 -out "$KEY" 2>/dev/null

# The artifact: a fixed-size placeholder so length/hash binding is exercised for real.
head -c 1048576 /dev/urandom > "$WWW/v1/ghost-$VERSION.apk"
SUM=$(sha256sum "$WWW/v1/ghost-$VERSION.apk" | cut -d' ' -f1)
LEN=$(stat -c %s "$WWW/v1/ghost-$VERSION.apk")
NOT_AFTER=$(date -u -d "+91 days" +%F)

cat > "$WWW/v1/manifest.json" <<JSON
{
  "format": "ghrm-staging-fixture-v1",
  "mirror": "$NAME",
  "version": "$VERSION",
  "manifest_seq": 1,
  "not_after_day": "$NOT_AFTER",
  "comment": "Staging fixture only - not the Phase 14 GHRM format, not a real release signature.",
  "files": [
    { "path": "v1/ghost-$VERSION.apk", "sha256": "$SUM", "length": $LEN }
  ]
}
JSON
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$WWW/v1/manifest.json" -out "$WWW/v1/manifest.sig"

cat > "$WWW/index.html" <<HTML
<!doctype html><title>GHOST staging mirror $NAME</title>
<h1>GHOST staging mirror ($NAME)</h1>
<p>Static update mirror, stagenet fixture. Channel test only.</p>
<ul><li><a href="v1/manifest.json">v1/manifest.json</a></li>
<li><a href="v1/manifest.sig">v1/manifest.sig</a></li>
<li><a href="v1/ghost-$VERSION.apk">v1/ghost-$VERSION.apk</a></li></ul>
HTML
echo "fixture: $WWW v$VERSION (sha256 $SUM, not_after $NOT_AFTER)"
