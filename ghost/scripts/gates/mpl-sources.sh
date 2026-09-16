#!/usr/bin/env bash
# Gate G-L4 (ADR-37 point 2; Phase 9 design §2.10.2): every MPL-2.0 package of a shipped Rust graph
# (licenses/graphs.txt) is used unmodified and has its source in the release source bundle.
#   - licenses/mpl-sources.txt lists exactly the packages used under MPL-2.0, each with the SHA-256
#     that Cargo.lock records for its published .crate archive;
#   - a [patch] of such a package (Cargo.toml, .cargo/config.toml) fails without a published diff
#     (licenses/mpl-patches/<crate>-<version>.diff);
#   - with --bundle <directory>, the .crate archives are copied there from the Cargo cache after their
#     SHA-256 is checked against Cargo.lock: the release source bundle (CI job rust proves it builds).
# Usage: mpl-sources.sh [--bundle <directory>]
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || [ -n "${GHOST_LICENSE_PACKAGES:-}" ] || { echo "cargo not found" >&2; exit 2; }
if [ -z "${GHOST_LICENSE_PACKAGES:-}" ]; then
  (cd "$GHOST_ROOT" && cargo fetch --locked >/dev/null) || fail "cargo fetch --locked"
fi
rc=0
out="$(GHOST_ROOT="$GHOST_ROOT" perl "$GATES_DIR/licenses.pl" mpl "$@")" || rc=$?
while IFS= read -r line; do
  [ -n "$line" ] && fail "${line#GATE-FAIL: }"
done <<< "$out"
[ "$rc" -le 1 ] || fail "licenses.pl mpl stopped (exit $rc)"
finish mpl-sources
