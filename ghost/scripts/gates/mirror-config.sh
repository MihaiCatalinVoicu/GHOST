#!/usr/bin/env bash
# Gate G-D10 (Phase 14 design faza14-distribution.md §12.1 row G-D10, §7.1's "No-log
# configuration, enforced"): the committed mirror configuration keeps no request state.
#   nginx (infra/mirror's server configuration — the entrypoint writes it): access_log off;
#   error_log at crit; log_not_found off; server_tokens off; etag off;
#   if_modified_since off; no add_header setting a cookie or a cache validator
#   (Set-Cookie / Cache-Control / ETag / Last-Modified / Expires); both listeners present
#   (§7.1: the app's HTTP/2-with-prior-knowledge listener and the browser's HTTP/1.1 one).
#   Every compose service sets `logging: driver: none` (Docker's json-file driver would
#   store the official image's linked stdout/stderr logs on disk).
#   One Tor instance per onion service: no two compose services may share a tor state
#   directory (the serving and upload onions run in separate instances, §7.1's hosting
#   rule; a staging tree with a single serving onion per service passes trivially).
# Documented as manual: the S8 container test (requests served, nothing appears in the
# writable layer, nothing on stdout/stderr) and the §7.1 PoW/SafeLogging torrc discipline
# (the relay template's notes, outside this row's line list).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="${GHOST_D10_ROOT:-$GHOST_ROOT}"
REAL_ROOT="$(cd "$GATES_DIR/../.." && pwd -P)"
if [ -n "${GHOST_D10_ROOT:-}" ] && [ "$(cd "$ROOT" && pwd -P)" = "$REAL_ROOT" ]; then
  echo "GHOST_D10_ROOT is a self-test hook for fixture roots only" >&2
  exit 2
fi
MIRROR="$ROOT/infra/mirror"
[ -d "$MIRROR" ] || { echo "G-D10: $MIRROR missing" >&2; exit 2; }

# The nginx configuration as committed: the entrypoint writes it from a heredoc; scan every
# mirror file that can carry it (entrypoint scripts, *.conf, nginx.conf templates).
NGINX_FILES="$(find "$MIRROR" -maxdepth 2 -type f \( -name '*.sh' -o -name '*.conf' -o -name '*nginx*' \) -print 2>/dev/null | sort)"
[ -n "$NGINX_FILES" ] || fail "infra/mirror holds no file that can carry the server configuration"
config="$(printf '%s\n' "$NGINX_FILES" | xargs cat 2>/dev/null)"

line() { # $1 = the exact directive line required
  grep -qE "$1" <<< "$config" || fail "the mirror configuration lacks \`$1\` (design §7.1's no-log line list)"
}
line '[[:space:]]*access_log[[:space:]]+off[[:space:]]*;'
line '[[:space:]]*error_log[[:space:]]+[^;]*crit[[:space:]]*;'
line '[[:space:]]*log_not_found[[:space:]]+off[[:space:]]*;'
line '[[:space:]]*server_tokens[[:space:]]+off[[:space:]]*;'
line '[[:space:]]*etag[[:space:]]+off[[:space:]]*;'
line '[[:space:]]*if_modified_since[[:space:]]+off[[:space:]]*;'
listeners="$(grep -cE '[[:space:]]*listen[[:space:]]+' <<< "$config" || true)"
[ "$listeners" -ge 2 ] || fail "the mirror configuration names fewer than two listeners (§7.1: the app's HTTP/2 listener and the browser's HTTP/1.1 one)"

bad_header="$(grep -nE 'add_header[[:space:]]+[^;]*(Set-Cookie|Cache-Control|[[:space:]]ETag|Last-Modified|Expires)' <<< "$config" || true)"
[ -z "$bad_header" ] || fail "add_header sets a cookie or a cache validator: $(printf '%.70s' "$bad_header")"

# Every compose service logs nowhere.
compose="$(find "$MIRROR" -maxdepth 1 -name 'docker-compose*.yml' -print 2>/dev/null | sort)"
[ -n "$compose" ] || fail "infra/mirror holds no compose file"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  rel="${f#"$ROOT"/}"
  services="$(awk '/^[[:space:]]{2}[A-Za-z0-9_-]+:/{name=$1; sub(/:$/,"",name); print name}' "$f")"
  [ -n "$services" ] || fail "$rel: no services"
  while IFS= read -r svc; do
    [ -n "$svc" ] || continue
    # The service's own indented block must carry logging: driver: none.
    if ! awk -v svc="$svc" '
      $0 ~ "^  " svc ":$" {in_svc=1; next}
      in_svc && /^  [A-Za-z0-9_-]+:/ {exit}
      in_svc && /^[[:space:]]*logging:/ {logging=1}
      in_svc && logging && /driver:[[:space:]]*none/ {found=1}
      END {exit !found}' "$f"; then
      fail "$rel: service $svc sets no logging: driver: none (Docker json-file would store the image's linked logs)"
    fi
  done <<< "$services"
done <<< "$compose"

# One tor state directory per service: two services mounting the same HOST directory would
# share one onion key (the container path /var/lib/tor is per-container and fine).
while IFS= read -r f; do
  [ -n "$f" ] || continue
  dups="$(grep -oE '/srv/[^:"]*[^:"/]' "$f" | sort | uniq -d | head -3)"
  [ -z "$dups" ] || fail "${f#"$ROOT"/}: host directories shared between services: $dups"
done <<< "$compose"

finish mirror-config
