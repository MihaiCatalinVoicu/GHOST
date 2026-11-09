#!/usr/bin/env bash
# Gate G-D4 (Phase 14 design faza14-distribution.md §12.1 row G-D4, §4.3, §4.9): the
# committed release records are consistent, per network under protocol/release/<network>/.
#   (a-c) The root chain verifies by the chain rule from its first entry; the newest root
#       lists the committed apk-signer.crt digest(s); the newest root's anchor mirrors equal
#       anchor-mirrors.txt with >= 2 operators on mainnet. These clauses parse the GHRT
#       documents — signature verification is Rust code's job, not bash's. The gate shells
#       out to a checker: GHOST_D4_CHECKER names an executable called as
#       `<checker> <network-dir>`, which must exit 0 and print a line `RECORDS_OK <net>`
#       per clause it verified. No checker ships in the tree yet (ghost-release-ops has no
#       records-check mode today — verified at slice time), so on the real tree these
#       clauses SKIP WITH A PRINTED NOTICE rather than pass silently; the notice names the
#       exact hook to make them live. Fail-closed: a checker that exits non-zero fails.
#   (d) The release counter never decreases over the first-parent history of its file
#       (protocol/release/<network>/release-counter.txt): each committed version parses as
#       an integer no smaller than the previous. Skipped with a notice while the file (or
#       the git history, for fixture roots) does not exist.
#   (e) The tag-signing allowed-signers file exists — once the network holds any release
#       record (a root chain). The file lands with the first tag key; a network holding
#       roots but no allowed_signers fails.
#   (f) Network separation of the embedded chains: every *.ghrc under a release network
#       dir carries that network's byte (GHRC v1: "GHRC" 0-3, version 4, network 5 —
#       mainnet 1, stagenet 2, stagenet-drill 3); a stagenet root never sits in a mainnet
#       build, and a drill chain (network 3) never in ANY release build.
# Documented as manual: the ceremony's key-holder checks (RK2/RK3 signatures) and the
# CI-workflow half (no .github/workflows in this checkout).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="${GHOST_D4_ROOT:-$GHOST_ROOT}"
REAL_ROOT="$(cd "$GATES_DIR/../.." && pwd -P)"
if [ -n "${GHOST_D4_ROOT:-}" ] && [ "$(cd "$ROOT" && pwd -P)" = "$REAL_ROOT" ]; then
  echo "GHOST_D4_ROOT is a self-test hook for fixture roots only" >&2
  exit 2
fi
RECORDS="$ROOT/protocol/release"
[ -d "$RECORDS" ] || { echo "G-D4: $RECORDS missing" >&2; exit 2; }

net_byte() { # dir name -> the GHRC network byte
  case "$1" in
    mainnet) echo 1 ;;
    stagenet) echo 2 ;;
    stagenet-drill) echo 3 ;;
    *) echo 0 ;;
  esac
}

checker="${GHOST_D4_CHECKER:-}"
if [ -z "$checker" ]; then
  for cand in ghost-release-ops ghost-verify; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" records-check --help >/dev/null 2>&1; then
      checker="$cand records-check"
      break
    fi
  done
fi

found=0
while IFS= read -r netdir; do
  [ -n "$netdir" ] || continue
  net="$(basename "$netdir")"
  byte="$(net_byte "$net")"
  [ "$byte" != 0 ] || fail "protocol/release/$net: an unknown network directory (expected mainnet|stagenet|stagenet-drill)"
  has_record=0
  while IFS= read -r chain; do
    [ -n "$chain" ] || continue
    has_record=1
    rel="${chain#"$ROOT"/}"
    got="$(od -A n -t u1 -j 5 -N 1 "$chain" 2>/dev/null | tr -d ' ')"
    head4="$(head -c 4 "$chain" 2>/dev/null)"
    [ "$head4" = "GHRC" ] || { fail "$rel: not a GHRC document"; continue; }
    if [ "$got" = "3" ]; then
      fail "$rel: a drill chain (network 3) sits in a release build — drill roots never ship"
    elif [ "$byte" != 0 ] && [ "$got" != "$byte" ]; then
      fail "$rel: network byte $got under protocol/release/$net (a $(case $got in 1) echo mainnet;; 2) echo stagenet;; esac) root in another network's build)"
    fi
  done < <(find "$netdir" -maxdepth 1 -name '*.ghrc' -print 2>/dev/null | sort)

  # (a-c) the checker's clauses.
  if [ -n "$checker" ]; then
    if out="$($checker "$netdir" 2>&1)"; then
      printf '%s\n' "$out" | grep -q "RECORDS_OK $net" \
        || fail "protocol/release/$net: the checker verified but printed no RECORDS_OK line"
    else
      fail "protocol/release/$net: the records checker refused: $(printf '%.80s' "$out")"
    fi
  else
    echo "[release-records] notice: no records checker (GHOST_D4_CHECKER) — clauses (a)-(c) for $net skipped, not passed" >&2
  fi

  # (d) the counter never decreases (while the file and the history exist).
  counter="$netdir/release-counter.txt"
  if [ -f "$counter" ] && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    prev=""
    while IFS= read -r rev; do
      [ -n "$rev" ] || continue
      val="$(git -C "$ROOT" show "$rev:protocol/release/$net/release-counter.txt" 2>/dev/null | tr -d '[:space:]' || true)"
      case "$val" in ''|*[!0-9]*) continue ;; esac
      if [ -n "$prev" ] && [ "$val" -lt "$prev" ]; then
        fail "protocol/release/$net/release-counter.txt: $val at ${rev:0:12} decreases the previous $prev"
      fi
      prev="$val"
    done < <(git -C "$ROOT" log --first-parent --reverse --format=%H -- "protocol/release/$net/release-counter.txt" 2>/dev/null || true)
  else
    echo "[release-records] notice: no release counter (or no git history) for $net — clause (d) skipped" >&2
  fi

  # (e) the tag-signing allowed-signers file, once the network holds records.
  if [ "$has_record" = 1 ] && [ ! -f "$netdir/allowed_signers" ]; then
    fail "protocol/release/$net/allowed_signers missing: the network holds root records and the tag-signing allowed-signers file must exist (§4.9)"
  fi
  found=1
done < <(find "$RECORDS" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort)
[ "$found" = 1 ] || echo "[release-records] notice: protocol/release holds no network dirs yet — nothing to check beyond the notices" >&2

finish release-records
