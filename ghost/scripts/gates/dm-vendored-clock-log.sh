#!/usr/bin/env bash
# Gate G-R8 (Phase 9 design §16.1 G-R8, RG-3, §22.8.10 point 4; defined and frozen by S0′, evidence
# V-8; invariants T3 and T33; S0′ gate slice, §22.33): **no clock, logging, printing or network code
# enters the library through the DM crate's dependencies without a written reason.** vodozemac, the
# libcrux crates and everything they pull in are vendored code GHOST does not review line by line;
# a bump that adds a clock read, a log call or a socket to them would reach every device with no
# test noticing. The gate lists every such site in the compiled library code of the shipped graph
# and requires the list to equal a committed baseline whose every entry carries its justification.
#
# What is scanned (`test-harness/vendored-scan`, V-8's scanner): for each shipped Android triple
# (aarch64-linux-android, x86_64-linux-android), every package of `cargo tree -p ghost-client-dm
# -e normal --features jni-bridge` (the DM crate as `ghost-client-net` links it), each with the
# features it has in the shipped library (`cargo tree -p ghost-client-net -f '{p}|{f}'`). Per
# package, the module tree of its `lib` target with every item, impl item, statement and arm whose
# `#[cfg]` is false for the target removed (`test`, `debug_assertions`, disabled features, other
# architectures; unknown predicates kept), `mod` declarations followed (`#[path]`, `cfg_attr` path),
# macro invocations and `macro_rules!` bodies included, comments excluded. Patterns: `SystemTime`,
# `Instant::now`, `std::time`, `chrono`, `time::`, `log::`, `tracing::`, `println!`, `eprintln!`,
# `dbg!`, `print!`, `eprint!`, and since the evasion review (design §22.33 item 16) the standard
# stream handles `stdout`, `stderr`, `Stdout`, `Stderr`, `StdoutLock`, `StderrLock` (clock-log:
# `writeln!(std::io::stderr(), …)` names no print macro); `std::net`, `TcpStream`, `TcpListener`,
# `UdpSocket`, `ToSocketAddrs`, and `UnixStream`, `UnixListener`, `UnixDatagram` (network:
# `std::os::unix::net` is not `std::net` to a token scan). `cargo:` directives of the packages' build scripts are listed
# separately (`directive` lines: a new `rustc-link-lib` is C code reaching the library), and every
# package scanned is listed (`crate` lines: the graph the sites are complete for). A token scan
# counts names, not calls, so a re-export needs a justification like a call does.
#
# The baseline, `scripts/gates/dm-vendored-clock-log.baseline`: one line per `site`, `directive`,
# `note` and `crate` entry, merged over both triples, as the scanner prints it without the source
# text after ` | `. Every `site`, `directive` and `note` line ends in `  # <reason>`; `crate` lines
# need none. An entry the scan finds and the baseline lacks fails (unjustified), and a baseline
# entry the scan no longer finds fails (stale), so the file is exactly the graph's list: regenerate
# it at a pin change with `GHOST_G_R8_PRINT=1`, which prints the scan in baseline form (reasons of
# unchanged entries kept, new ones marked `# UNJUSTIFIED`) for a reviewer to complete.
#
# Runs in the CI `rust` job (it needs cargo, the lock and the unpacked registry sources, not a build
# of the library) and on every pin change through it.
# Self-test hooks (scripts/gates/self-test.sh): GHOST_G_R8_BASELINE replaces the baseline file;
# GHOST_G_R8_TRIPLES replaces the triple list.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
# cargo's output is parsed here, so it must be plain. With CARGO_TERM_COLOR=always, which the CI
# rust-toolchain action exports, `cargo tree` colours its `(*)` marker into the pipe; the ` (*)`
# suffix was then not stripped from the features column, a package's last line listed
# `macros<escape codes>` instead of `macros`, and hax-lib's `#[cfg(feature = "macros")] mod
# proc_macros` was pruned — the runner reported its note stale (run 36233077404, design §22.33
# item 18) while every uncoloured run passed.
export CARGO_TERM_COLOR=never
cd "$GHOST_ROOT"
BASELINE="${GHOST_G_R8_BASELINE:-$GATES_DIR/dm-vendored-clock-log.baseline}"
TRIPLES="${GHOST_G_R8_TRIPLES:-aarch64-linux-android x86_64-linux-android}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

run() { # a command whose failure fails the gate with its stderr shown
  if ! "$@" 2>"$work/err"; then
    cat "$work/err" >&2
    fail "$* failed"
    finish dm-vendored-clock-log
  fi
}
run cargo build --locked -q --release -p ghost-vendored-scan
# Where cargo put it: CARGO_TARGET_DIR when set (a private target directory), `.exe` on Windows.
SCANNER="${CARGO_TARGET_DIR:-$GHOST_ROOT/target}/release/vendored-scan"
[ -x "$SCANNER" ] || [ ! -x "$SCANNER.exe" ] || SCANNER="$SCANNER.exe"
[ -x "$SCANNER" ] || { fail "the scanner was not built at $SCANNER"; finish dm-vendored-clock-log; }

for triple in $TRIPLES; do
  run cargo tree --locked -q -p ghost-client-dm -e normal --features jni-bridge --target "$triple" --prefix none -f '{p}' > "$work/tree-$triple.raw"
  sed 's/ (\*)//; s/ (proc-macro)//' "$work/tree-$triple.raw" | sort -u > "$work/tree-$triple.txt"
  run cargo tree --locked -q -p ghost-client-net -e normal --target "$triple" --prefix none -f '{p}|{f}' > "$work/features-$triple.raw"
  sort -u "$work/features-$triple.raw" > "$work/features-$triple.txt"
  run cargo tree --locked -q -p ghost-client-dm -e normal,no-proc-macro --features jni-bridge --target "$triple" --prefix none -f '{p}' > "$work/shipped-$triple.raw"
  sed 's/ (\*)//' "$work/shipped-$triple.raw" | sort -u > "$work/shipped-$triple.txt"
  run "$SCANNER" "$GHOST_ROOT/Cargo.toml" "$triple" "$work/tree-$triple.txt" "$work/features-$triple.txt" "$work/shipped-$triple.txt" > "$work/scan-$triple.txt"
  grep -q '^crate ghost-client-dm@' "$work/scan-$triple.txt" || fail "$triple: the scan lists no ghost-client-dm crate (the gate would pass vacuously)"
  grep -q '^crate vodozemac@' "$work/scan-$triple.txt" || fail "$triple: the scan lists no vodozemac crate (the gate would pass vacuously)"
done
# The scan in baseline form: the source text after " | " dropped, merged over the triples.
sed -E 's/ \| .*$//' "$work"/scan-*.txt | sort -u > "$work/scan.txt"

[ -f "$BASELINE" ] || { fail "$BASELINE: missing"; finish dm-vendored-clock-log; }
# The baseline without comments and blank lines; each entry's reason checked.
n=0
: > "$work/baseline.txt"
while IFS= read -r line; do
  n=$((n + 1))
  case "$line" in ''|'#'*) continue ;; esac
  entry="${line%%  # *}"
  reason=""
  [ "$entry" = "$line" ] || reason="${line#*  # }"
  case "$entry" in
    site\ *|directive\ *|note\ *)
      if [ -z "${reason// /}" ] || [ "$reason" = UNJUSTIFIED ]; then
        fail "$(basename "$BASELINE"):$n: no justification for: $entry"
      fi ;;
    crate\ *) ;;
    *) fail "$(basename "$BASELINE"):$n: not a site, directive, note or crate line: $line" ;;
  esac
  printf '%s\n' "$entry" >> "$work/baseline.txt"
done < "$BASELINE"
sort -u -o "$work/baseline.txt" "$work/baseline.txt"

if [ "${GHOST_G_R8_PRINT:-}" = 1 ]; then
  # Baseline form for a reviewer: reasons of unchanged entries kept, new entries marked.
  while IFS= read -r entry; do
    reason="$(grep -F -- "$entry  # " "$BASELINE" | head -1 | sed 's/^.*  # //' || true)"
    case "$entry" in
      crate\ *) printf '%s\n' "$entry" ;;
      *) printf '%s  # %s\n' "$entry" "${reason:-UNJUSTIFIED}" ;;
    esac
  done < "$work/scan.txt"
fi

while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  fail "unjustified: $entry (in the scan, not in $(basename "$BASELINE"); review it and add it with its reason)"
done < <(comm -23 "$work/scan.txt" "$work/baseline.txt")
while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  fail "stale: $entry (in $(basename "$BASELINE"), no longer in the scan; remove it)"
done < <(comm -13 "$work/scan.txt" "$work/baseline.txt")

echo "[dm-vendored-clock-log] $(grep -c '^crate ' "$work/scan.txt") crates, $(grep -c '^site ' "$work/scan.txt") sites, $(grep -c '^directive ' "$work/scan.txt") directives, $(grep -c '^note ' "$work/scan.txt") notes over: $TRIPLES"
finish dm-vendored-clock-log
