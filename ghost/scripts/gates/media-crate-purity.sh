#!/usr/bin/env bash
# Gate G-M7, source half (Phase 11 design faza11-media.md §13.1, §16.1 G-M7; slice S1): the media crate
# `client-core/media` (`ghost-client-media`) is pure. Design §13.1: "no JNI, no I/O, no clock, no
# logging, no state", dependencies chacha20poly1305, hkdf, hmac, sha2 and zeroize only; §3.7: no
# randomness inside the crate (the caller passes K_f and object_id); G-M7: no feature but its empty
# `default` in a shipped graph. The graph halves are rust-client-allowlist.sh (G-R1: the crate's graph
# on the allowlist, its direct dependencies the five), rust-feature-policy.sh (G-R2: no feature of its
# own in any graph), media-rust-no-logging.sh (G-R4's graph half), media-vendored-clock-log.sh (G-R8)
# and rust-license-headers.sh (G-R5); no-logging.sh is the logging rule for its sources, as for every
# client-core crate. This file is the rest, each rule with its own message:
#
#   1. clock: `std::time`, `SystemTime`, `Instant`, `UNIX_EPOCH`, `chrono`;
#   2. I/O: `std::fs`, `std::io`, `std::net`, `std::env`, `std::process`, `std::os` (a path, or a
#      name inside a `std::{…}` import), `File::`, `TcpStream`, `TcpListener`, `UdpSocket`;
#   3. state: `std::thread`, `thread_local!`, `static mut`, a `static` of a lock, cell, lazy or
#      atomic type, `lazy_static!`, `once_cell` — except in `src/registry.rs`, the nonce registry of
#      §3.7 point 5, which only the test feature `nonce-registry` compiles (lib.rs gates the module);
#   4. randomness: `rand::`, `getrandom`, `OsRng`, `thread_rng`, `RandomState`;
#   5. unsafe: the keyword anywhere in code, and `src/lib.rs` without `#![forbid(unsafe_code)]`;
#   6. JNI: `jni`, `JNIEnv`, `extern "system"`, `#[no_mangle]` (and `#[unsafe(no_mangle)]`);
#   7. an external crate: a `[dependencies]` entry other than the five, any target-specific or build
#      dependency, or a build script;
#   8. a feature: a `[features]` entry other than `default = []` and `nonce-registry = []`.
# Sources are read through scripts/gates/source-text.pl (comments blanked, string contents blanked
# for the code rules, whitespace and newlines allowed between tokens), so a comment that names a
# banned path is not a hit and a path split across lines is.
# Self-test hooks: GHOST_ROOT (the fixtures under test-harness/gates/media-purity/).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
CRATE="$GHOST_ROOT/client-core/media"
[ -d "$CRATE/src" ] || { fail "$CRATE/src: missing (the media crate's sources)"; finish media-crate-purity; }
[ -f "$CRATE/Cargo.toml" ] || { fail "$CRATE/Cargo.toml: missing"; finish media-crate-purity; }
files="$(find "$CRATE/src" -type f -name '*.rs' | sort)"
[ -n "$files" ] || { fail "$CRATE/src: no Rust source (the gate would pass vacuously)"; finish media-crate-purity; }
if ! out="$(CRATE="$CRATE" GATES_DIR="$GATES_DIR" perl -e '
use strict; use warnings;
require "$ENV{GATES_DIR}/source-text.pl";
my $crate = $ENV{CRATE};
my @rules = (
  [clock => qr/\bstd\s*::\s*time\b|\bSystemTime\b|\bInstant\b|\bUNIX_EPOCH\b|\bchrono\b/,
   "a clock (the media crate reads no clock, design 13.1)"],
  [io => qr/\bstd\s*::\s*(?:fs|io|net|env|process|os)\b|\bstd\s*::\s*\{[^}]*\b(?:fs|io|net|env|process|os)\b|\bFile\s*::|\bTcpStream\b|\bTcpListener\b|\bUdpSocket\b/,
   "I\/O (the media crate does no I\/O: bytes come from and go to the caller, design 13.1)"],
  [state => qr/\bstd\s*::\s*thread\b|\bthread_local\s*!|\bstatic\s+mut\b|\bstatic\s+[A-Za-z_0-9]+\s*:\s*[^=;]*?\b(?:Mutex|RwLock|OnceLock|OnceCell|LazyLock|Lazy|Cell|RefCell|Atomic[A-Za-z0-9]*)\b|\blazy_static\s*!|\bonce_cell\b/,
   "state (the media crate keeps none; only the test registry, design 3.7 point 5)"],
  [random => qr/\brand\s*::|\bgetrandom\b|\bOsRng\b|\bthread_rng\b|\bRandomState\b/,
   "randomness (the caller passes K_f and object_id, design 3.7, 13.1)"],
  [unsafe => qr/\bunsafe\b/, "unsafe code (forbidden in the media crate)"],
  [jni => qr/\bjni\b|\bJNIEnv\b|#\s*!?\s*\[\s*(?:unsafe\s*\(\s*)?no_mangle\b/,
   "JNI (the media crate has none; MediaNative is ghost-client-dm\x27s, slice S2)"],
);
my $n = 0;
for my $file (split /\n/, do { local $/; <STDIN> }) {
  next unless length $file;
  $n++;
  my $text = read_text($file);
  my ($with_strings, $code) = views($text, "rust");
  (my $rel = $file) =~ s{^\Q$crate\E/}{};
  for my $r (@rules) {
    my ($name, $re, $why) = @$r;
    next if $name eq "state" && $rel eq "src/registry.rs";
    while ($code =~ /$re/g) {
      my $line = line_of(\$code, $-[0]);
      print "client-core/media/$rel:$line: $why\n";
    }
  }
  # `extern "system"` names its ABI in a string literal, which the code view blanks.
  while ($with_strings =~ /\bextern\s+"system"/g) {
    print "client-core/media/$rel:" . line_of(\$with_strings, $-[0]) . ": JNI (the media crate has none; MediaNative is ghost-client-dm\x27s, slice S2)\n";
  }
  if ($rel eq "src/lib.rs" && $with_strings !~ /#\s*!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]/) {
    print "client-core/media/src/lib.rs: no #![forbid(unsafe_code)] (unsafe code must stay forbidden)\n";
  }
}
print "SOURCES-READ $n\n";
' <<< "$files")"; then
  fail "the source scan (perl) failed: the purity rules are unproven"
  out=""
fi
read_n="$(sed -n 's/^SOURCES-READ //p' <<< "$out")"
[ "${read_n:-0}" -gt 0 ] || fail "no media source was read (the gate would pass vacuously)"
while IFS= read -r v; do
  [ -n "$v" ] && fail "$v"
done < <(grep -v '^SOURCES-READ ' <<< "$out" || true)
[ -e "$CRATE/build.rs" ] && fail "client-core/media/build.rs: a build script (an external crate's way in, and I/O at build time)"
# The manifest: dependencies and features (sections read line by line; a `[dependencies.x]` table is
# the dependency x).
ALLOWED_DEPS="chacha20poly1305 hkdf hmac sha2 zeroize"
section=""
while IFS= read -r raw; do
  line="${raw%%#*}"
  line="${line%"${line##*[![:space:]]}"}"
  [ -n "$line" ] || continue
  if [[ "$line" =~ ^\[(.*)\]$ ]]; then
    section="${BASH_REMATCH[1]}"
    case "$section" in
      dependencies.*)
        dep="${section#dependencies.}"
        case " $ALLOWED_DEPS " in
          *" $dep "*) ;;
          *) fail "client-core/media/Cargo.toml: dependency '$dep' (an external crate outside design 13.1's chacha20poly1305, hkdf, hmac, sha2, zeroize)" ;;
        esac
        ;;
      build-dependencies*|target.*)
        fail "client-core/media/Cargo.toml: [$section] (an external crate outside design 13.1's list: no build or target-specific dependency)"
        ;;
    esac
    continue
  fi
  key="${line%%=*}"
  key="${key//[[:space:]]/}"
  key="${key%%.*}"
  case "$section" in
    dependencies)
      case " $ALLOWED_DEPS " in
        *" $key "*) ;;
        *) fail "client-core/media/Cargo.toml: dependency '$key' (an external crate outside design 13.1's chacha20poly1305, hkdf, hmac, sha2, zeroize)" ;;
      esac
      ;;
    features)
      value="${line#*=}"
      value="${value//[[:space:]]/}"
      case "$key=$value" in
        "default=[]"|"nonce-registry=[]") ;;
        *) fail "client-core/media/Cargo.toml: feature '$key' = $value (a feature: G-M7 allows only the empty default and the test feature nonce-registry)" ;;
      esac
      ;;
  esac
done < "$CRATE/Cargo.toml"
echo "[media-crate-purity] $read_n source files read"
finish media-crate-purity
