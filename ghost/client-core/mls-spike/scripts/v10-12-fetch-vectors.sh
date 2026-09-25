#!/usr/bin/env bash
# V10-12: fetches the MLS WG passive-client test vectors as the openmls repository carries them at
# the commit the crates.io openmls-0.9.0 package was built from (tag openmls-v0.9.0), and verifies
# each file against the git blob id of that tree. Evidence tooling, not product code.
#   v10-12-fetch-vectors.sh <dir>     (default: ../vectors next to this script; not committed)
set -euo pipefail
COMMIT=3a3e35de3feeca8f6605143c464d5452ae584d43
DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/vectors}"
mkdir -p "$DIR"
# name  git-blob-sha1 (from the tree at $COMMIT)
while read -r name blob; do
  curl -sSfL -o "$DIR/$name" "https://raw.githubusercontent.com/openmls/openmls/$COMMIT/openmls/test_vectors/$name"
  got="$(git hash-object "$DIR/$name")"
  [ "$got" = "$blob" ] || { echo "MISMATCH $name: $got != $blob" >&2; exit 1; }
  printf '%s  %s  (git blob %s)\n' "$(sha256sum "$DIR/$name" | cut -c1-64)" "$name" "$blob"
done <<'LIST'
passive-client-welcome.json 15bbfcf01b55f64d2dd60771c7ae8643e1764ec5
passive-client-handling-commit.json c702dcc3227ccb4d36a1770e1b5c44392f62604a
passive-client-random.json ea20d75259ab73ef38e9a4d23c32697f1d849822
LIST
