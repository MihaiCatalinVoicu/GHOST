#!/usr/bin/env bash
# pq-model.sh — the local equivalent of the legacy .github/workflows/pq-model.yml (Phase 9 design
# §22.18: the DM models M-1..M-8 through ProVerif; ADR-58: CI is local). Two steps, unchanged:
# build ProVerif 2.05 from the INRIA source release, pinned by version and by the SHA-256 committed
# in protocol/models/dm/proverif.sha256 (the job — and this script — refuses to build anything
# else), then run scripts/gates/pq-model.sh with PQ_MODEL_TIMEOUT=600, which compares every
# model's result against protocol/models/dm/expected.txt (a ProVerif error or a timeout fails).
# Linux only (the ocaml build); locally that means the ghost-runner WSL distro.
#
# Usage: pq-model.sh [--work <dir>]
#   --work  the build/download directory (default: <repo>/t2-reports/pq-model)
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHOST="$(cd "$DIR/../../" && pwd)"
WORK="$GHOST/t2-reports/pq-model"
VERSION=2.05
URL="https://bblanche.gitlabpages.inria.fr/proverif/proverif$VERSION.tar.gz"
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    *) echo "pq-model: unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$(uname -s)" in
  Linux) ;;
  *) echo "pq-model: the ocaml build of ProVerif needs Linux; run this in the ghost-runner WSL distro" >&2; exit 2 ;;
esac
mkdir -p "$WORK"

pinned="$(tr -d '[:space:]' < "$GHOST/protocol/models/dm/proverif.sha256")"
archive="$WORK/proverif-$VERSION.tar.gz"
if [ ! -f "$archive" ]; then
  curl -fsSL --retry 3 -o "$archive" "$URL" || { echo "pq-model: the ProVerif download failed" >&2; exit 1; }
fi
actual="$(sha256sum "$archive" | cut -d' ' -f1)"
echo "proverif $VERSION sha256: $actual"
if ! [[ "$pinned" =~ ^[0-9a-f]{64}$ ]]; then
  echo "protocol/models/dm/proverif.sha256 holds no pinned hash; check $actual against an" \
    "independent source and commit it (design §22.18)" >&2
  exit 1
fi
[ "$actual" = "$pinned" ] || { echo "ProVerif archive hash $actual != pinned $pinned" >&2; exit 1; }

missing=""
command -v ocamlopt >/dev/null || missing="$missing ocaml-nox"
command -v patch >/dev/null || missing="$missing patch"
if [ -n "$missing" ]; then
  echo "pq-model: missing build tools:$missing — install them (apt-get install -y --no-install-recommends$missing) and rerun" >&2
  exit 2
fi

rm -rf "$WORK/proverif$VERSION"
tar -xzf "$archive" -C "$WORK"
( cd "$WORK/proverif$VERSION" && ./build -nointeract ) > "$WORK/proverif-build.log" 2>&1 || \
  { echo "pq-model: the ProVerif build failed (log: $WORK/proverif-build.log)" >&2; exit 1; }

( cd "$GHOST" && PATH="$WORK/proverif$VERSION:$PATH" PQ_MODEL_TIMEOUT=600 \
    bash scripts/gates/pq-model.sh ) 2>&1 | tee "$WORK/pq-model.txt"
rc=${PIPESTATUS[0]}

grep -E "^(pq-model:|\[pq-model\]|GATE-FAIL)" "$WORK/pq-model.txt" || true
[ "$rc" = 0 ] && echo "pq-model: PASS" || echo "pq-model: FAIL (report: $WORK/pq-model.txt)" >&2
exit "$rc"
