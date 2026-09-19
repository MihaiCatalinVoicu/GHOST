#!/usr/bin/env bash
# Gate G-R5 (ADR-37; Phase 9 design §2.10.2, §22.8.10 point 2): the licences that the shipped Rust
# packages declare, and the ones their sources declare.
# Input: the packages of `cargo tree -e normal --target <shipped triples>` for every graph of
# licenses/graphs.txt (not everything `cargo vendor` extracts), read from their published sources in
# the Cargo registry, and GHOST's own crates of those graphs.
#   - A third-party package's SPDX expression parses and has an alternative made only of licences of
#     the deny.toml allow list (an allowed alternative passes: priority-queue's LGPL-3.0-or-later OR
#     MPL-2.0 passes under MPL-2.0).
#   - A file fails when it declares a GNU licence as its own (an SPDX-License-Identifier naming GPL,
#     LGPL or AGPL; the "under the terms of the GNU ... General Public License" notice; a GNU licence
#     text), or carries a "Signal Messenger" copyright (the wacore-libsignal trap: a package declared
#     MIT whose sources are AGPL-3.0-only).
#   - scripts/gates/rust-license-exceptions.txt (crate, version, file, reason) lists the reviewed files
#     that do not govern the shipped code; an exception that matches nothing fails.
# Self-test hooks: GHOST_LICENSE_PACKAGES, GHOST_LICENSE_EXCEPTIONS (licenses.pl).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || [ -n "${GHOST_LICENSE_PACKAGES:-}" ] || { echo "cargo not found" >&2; exit 2; }
if [ -z "${GHOST_LICENSE_PACKAGES:-}" ]; then
  (cd "$GHOST_ROOT" && cargo fetch --locked >/dev/null) || fail "cargo fetch --locked"
fi
rc=0
out="$(GHOST_ROOT="$GHOST_ROOT" perl "$GATES_DIR/licenses.pl" headers)" || rc=$?
while IFS= read -r line; do
  [ -n "$line" ] && fail "${line#GATE-FAIL: }"
done <<< "$out"
[ "$rc" -le 1 ] || fail "licenses.pl headers stopped (exit $rc)"
finish rust-license-headers
