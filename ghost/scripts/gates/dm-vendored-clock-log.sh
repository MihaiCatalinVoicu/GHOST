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
# `Instant::now`, `UNIX_EPOCH` and `elapsed` (a clock read through an imported constant or a clock
# value's method; Phase 10 review of S2a, F5), `std::time`, `chrono`, `time::`, `log::`, `tracing::`, `println!`, `eprintln!`,
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
# **G-M8, the MLS graph (Phase 10 design faza10-forum.md §3.6, §13.1 G-M8; T3, T33; slice S2a).** The
# same script for both graphs (S0-18): `--graph mls` (or `mls-vendored-clock-log.sh`) scans the
# compiled library code of `cargo tree -p ghost-client-mls -e normal --features jni-bridge` on both
# triples, each package with the features it has in the shipped library (`cargo tree -p
# ghost-client-net`, which links the crate with its JNI export since slice S2b, design §19.32; S2a
# read the crate's own graph, which left the JNI module and the `jni` subtree out of the scan),
# against `scripts/gates/mls-vendored-clock-log.baseline`. OpenMLS's clock sites of design §3.6 are
# among the entries; so are its `log::` facade calls (no logger is installed, G-M4) and `jni`'s.
#
# Runs in the CI `rust` job (it needs cargo, the lock and the unpacked registry sources, not a build
# of the library) and on every pin change through it.
# Self-test hooks (scripts/gates/self-test.sh): GHOST_G_R8_BASELINE replaces the baseline file;
# GHOST_G_R8_TRIPLES replaces the triple list; GHOST_G_R8_MEDIA_LINKER replaces the package whose
# graph decides where the media scan reads the features (`--graph media` only).
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
GRAPH=dm
if [ "${1:-}" = --graph ]; then
  GRAPH="${2:-}"
  shift 2
fi
case "$GRAPH" in
  dm)
    NAME=dm-vendored-clock-log ROOT_PKG=ghost-client-dm ROOT_FEATURES=(--features jni-bridge)
    FEATURES_PKG=ghost-client-net REQUIRED_CRATES="ghost-client-dm vodozemac" ;;
  mls)
    NAME=mls-vendored-clock-log ROOT_PKG=ghost-client-mls ROOT_FEATURES=(--features jni-bridge)
    FEATURES_PKG=ghost-client-net REQUIRED_CRATES="ghost-client-mls openmls jni" ;;
  media)
    # G-M7 (Phase 11 design faza11-media.md §13.1, §16.1 G-M7; slice S1): the media crate and its
    # graph, each package with the features it has in the crate's own graph while the shipped library
    # does not link it, and with the features it has in ghost-client-net's graph from the commit whose
    # library does (slice S2, through ghost-client-dm): the switch is read from the graph below, not
    # made by hand (the review of S1 found a manual switch left for S2 with no tripwire; S2b had made
    # the channel crate's by hand). GHOST_G_R8_MEDIA_LINKER names the linking package (self-test).
    NAME=media-vendored-clock-log ROOT_PKG=ghost-client-media ROOT_FEATURES=()
    FEATURES_PKG=ghost-client-media REQUIRED_CRATES="ghost-client-media chacha20poly1305 sha2" ;;
  *) echo "usage: dm-vendored-clock-log.sh [--graph dm|mls|media]" >&2; exit 2 ;;
esac
BASELINE="${GHOST_G_R8_BASELINE:-$GATES_DIR/$NAME.baseline}"
TRIPLES="${GHOST_G_R8_TRIPLES:-aarch64-linux-android x86_64-linux-android}"
work="$(mktemp -d)"
trap 'rc=$?; rm -rf "$work"; exit $rc' EXIT

run() { # a command whose failure fails the gate with its stderr shown
  if ! "$@" 2>"$work/err"; then
    cat "$work/err" >&2
    fail "$* failed"
    finish "$NAME"
  fi
}
if [ "$GRAPH" = media ]; then
  linker="${GHOST_G_R8_MEDIA_LINKER:-ghost-client-net}"
  run cargo tree --locked -q -p "$linker" -e normal --target all --prefix none -f '{p}' > "$work/linker.txt"
  if grep -q '^ghost-client-media ' "$work/linker.txt"; then
    FEATURES_PKG="$linker"
    echo "[$NAME] $linker links ghost-client-media: each package's features as $linker's graph has them"
  else
    echo "[$NAME] $linker does not link ghost-client-media yet: each package's features as the crate's own graph has them"
  fi
fi
run cargo build --locked -q --release -p ghost-vendored-scan
# Where cargo put it: CARGO_TARGET_DIR when set (a private target directory), `.exe` on Windows.
SCANNER="${CARGO_TARGET_DIR:-$GHOST_ROOT/target}/release/vendored-scan"
[ -x "$SCANNER" ] || [ ! -x "$SCANNER.exe" ] || SCANNER="$SCANNER.exe"
[ -x "$SCANNER" ] || { fail "the scanner was not built at $SCANNER"; finish "$NAME"; }

for triple in $TRIPLES; do
  run cargo tree --locked -q -p "$ROOT_PKG" -e normal "${ROOT_FEATURES[@]}" --target "$triple" --prefix none -f '{p}' > "$work/tree-$triple.raw"
  sed 's/ (\*)//; s/ (proc-macro)//' "$work/tree-$triple.raw" | sort -u > "$work/tree-$triple.txt"
  run cargo tree --locked -q -p "$FEATURES_PKG" -e normal --target "$triple" --prefix none -f '{p}|{f}' > "$work/features-$triple.raw"
  sort -u "$work/features-$triple.raw" > "$work/features-$triple.txt"
  run cargo tree --locked -q -p "$ROOT_PKG" -e normal,no-proc-macro "${ROOT_FEATURES[@]}" --target "$triple" --prefix none -f '{p}' > "$work/shipped-$triple.raw"
  sed 's/ (\*)//' "$work/shipped-$triple.raw" | sort -u > "$work/shipped-$triple.txt"
  run "$SCANNER" "$GHOST_ROOT/Cargo.toml" "$triple" "$work/tree-$triple.txt" "$work/features-$triple.txt" "$work/shipped-$triple.txt" > "$work/scan-$triple.txt"
  for want in $REQUIRED_CRATES; do
    grep -q "^crate $want@" "$work/scan-$triple.txt" || fail "$triple: the scan lists no $want crate (the gate would pass vacuously)"
  done
done
# The scan in baseline form: the source text after " | " dropped, merged over the triples.
sed -E 's/ \| .*$//' "$work"/scan-*.txt | sort -u > "$work/scan.txt"

[ -f "$BASELINE" ] || { fail "$BASELINE: missing"; finish "$NAME"; }
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

echo "[$NAME] $(grep -c '^crate ' "$work/scan.txt") crates, $(grep -c '^site ' "$work/scan.txt") sites, $(grep -c '^directive ' "$work/scan.txt") directives, $(grep -c '^note ' "$work/scan.txt") notes over: $TRIPLES"
finish "$NAME"
