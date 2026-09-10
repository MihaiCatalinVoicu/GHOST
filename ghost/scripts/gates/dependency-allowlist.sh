#!/usr/bin/env bash
# Gate T7 (ADR-06): every Maven coordinate and Gradle plugin used by the Android client must be
# allowlisted by group prefix and must not match the denylist. Rust is covered by cargo-deny.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ALLOW="$GATES_DIR/dependency-allowlist.txt"
DENY="$GATES_DIR/dependency-denylist.txt"
allowed() {
  local g="$1"
  while IFS= read -r prefix; do
    [ -n "$prefix" ] && [ "${prefix#\#}" = "$prefix" ] || continue
    case "$g" in "$prefix"*) return 0;; esac
  done < "$ALLOW"
  return 1
}
denied() {
  local g="$1"
  while IFS= read -r prefix; do
    [ -n "$prefix" ] && [ "${prefix#\#}" = "$prefix" ] || continue
    case "$g" in "$prefix"*) return 0;; esac
  done < "$DENY"
  return 1
}
check() { # $1 = group or plugin id, $2 = origin
  if denied "$1"; then fail "$2: DENIED dependency group '$1'"; return; fi
  allowed "$1" || fail "$2: dependency group '$1' is not allowlisted (add via ADR)"
}
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    *libs.versions.toml)
      while IFS= read -r g; do [ -n "$g" ] && check "$g" "$f"; done < <(grep -oP '^\s*[A-Za-z0-9_-]+\s*=\s*\{[^}]*group\s*=\s*"\K[^"]+' "$f" || true)
      while IFS= read -r mod; do [ -n "$mod" ] && check "${mod%%:*}" "$f"; done < <(grep -oP 'module\s*=\s*"\K[^"]+' "$f" || true)
      while IFS= read -r id; do [ -n "$id" ] && check "$id" "$f (plugin)"; done < <(grep -oP '^\s*[A-Za-z0-9_-]+\s*=\s*\{[^}]*id\s*=\s*"\K[^"]+' "$f" || true)
      ;;
    *.gradle.kts)
      # Inline coordinates "group:artifact:version" and id("plugin.id")
      while IFS= read -r c; do [ -n "$c" ] && check "${c%%:*}" "$f"; done < <(grep -oP '"\K[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.+-]+(?=")' "$f" || true)
      while IFS= read -r id; do [ -n "$id" ] && check "$id" "$f (plugin)"; done < <(grep -oP 'id\("\K[^"]+' "$f" || true)
      ;;
  esac
done < <(gradle_files)
finish dependency-allowlist
