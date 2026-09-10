#!/usr/bin/env bash
# Gate T8: no placeholder, simulated success or unticketed TODO on the production path (DoD).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
PATTERNS=(
  'placeholder'
  'simulat'                      # simulate / simulare / simulated
  '\bmock'
  'in a real implementation'
  'implementare real'
  'for demonstration'
  'demo purposes'
  'return true\s*//'
  'return false\s*//'
  '\bFIXME\b'
  '\bXXX\b'
  'TODO(?!\(GHOST-[0-9]+\))'     # TODO must carry a ticket: TODO(GHOST-123)
  'hardcoded'
)
REGEX="$(IFS='|'; echo "${PATTERNS[*]}")"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if hits="$(grep -nPi -- "$REGEX" "$f" || true)"; [ -n "$hits" ]; then
    while IFS= read -r line; do fail "$f:${line}"; done <<< "$hits"
  fi
done < <(android_main_files; rust_src_files)
finish anti-placeholder
