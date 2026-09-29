#!/usr/bin/env bash
# The GHSA watch of gate G-M1 (Phase 10 design faza10-forum.md §13.1 G-M1, §13.2 mls-vendor-tests,
# S0-2; evidence V10-2): cargo-deny and cargo-audit match RustSec entries by package name, and they
# are blind to two things the OpenMLS stack has — OpenMLS's own advisories are published only as
# GitHub security advisories (none reached RustSec: no crates/openmls directory at 593df8c1 or
# e2111519), and two libcrux entries are filed under a crate's former name (RUSTSEC-2026-0209 and
# -0211 under `libcrux-aesgcm`, now `libcrux-aes`). This script closes both gaps:
#
#   1. GitHub advisories of openmls/openmls, celabshq/hpke-rs and celabshq/libcrux (the libcrux and
#      hpke-rs repositories moved from cryspen/): every vulnerability whose package is a pinned crate
#      (or a former name of one) and whose `vulnerable_version_range` contains the pinned version.
#   2. RustSec (a checkout of rustsec/advisory-db): every advisory under `crates/<name>` for the pinned
#      crates **and their former names**, whose pinned version is neither `patched` nor `unaffected`.
#
# It fails on any such advisory that is not listed, with its reason, in
# `scripts/ci/mls-advisories.reviewed` (the RustSec entries under a former name have `patched = []`
# and say in their text that the renamed crate's version fixes them; a reviewer records that there).
# The pinned versions are read from ghost/Cargo.lock.
#
# Usage: mls-advisories.sh [work-dir]                  (network: `gh` authenticated, `git`)
# Self-test hooks: GHOST_ADV_GHSA_DIR=<dir of <owner>__<repo>.json files> replaces the GitHub queries;
# GHOST_ADV_RUSTSEC_DIR=<advisory-db checkout> replaces the clone; GHOST_ADV_REVIEWED replaces the
# reviewed list; GHOST_ADV_LOCK replaces Cargo.lock.
set -euo pipefail
GHOST="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK"
LOCK="${GHOST_ADV_LOCK:-$GHOST/Cargo.lock}"
REVIEWED="${GHOST_ADV_REVIEWED:-$GHOST/scripts/ci/mls-advisories.reviewed}"
REPOS="openmls/openmls celabshq/hpke-rs celabshq/libcrux"
# The crates watched: the OpenMLS stack of design §13.1 G-M1 and the libcrux crates the lock pins.
WATCHED_FIXED="openmls openmls_traits openmls_libcrux_crypto openmls_memory_storage openmls_serialization_helpers hpke-rs hpke-rs-crypto hpke-rs-libcrux tls_codec tls_codec_derive argon2 blake2"
# Former names: <former>=<current>.
FORMER="libcrux-aesgcm=libcrux-aes"

awk '/^\[\[package\]\]/ {n = v = ""} /^name = / {gsub(/"/, "", $3); n = $3} /^version = / {gsub(/"/, "", $3); v = $3; if (n != "") print n " " v}' "$LOCK" \
  | sort -u > "$WORK/lock.txt"
: > "$WORK/pins.txt"
for c in $WATCHED_FIXED $(awk '$1 ~ /^libcrux-/ {print $1}' "$WORK/lock.txt" | sort -u); do
  awk -v n="$c" '$1 == n' "$WORK/lock.txt" >> "$WORK/pins.txt"
done
sort -u -o "$WORK/pins.txt" "$WORK/pins.txt"
grep -q '^openmls ' "$WORK/pins.txt" || { echo "mls-advisories: no openmls in $LOCK (nothing to watch)" >&2; exit 1; }

# 1. GitHub advisories.
mkdir -p "$WORK/ghsa"
for repo in $REPOS; do
  f="$WORK/ghsa/${repo//\//__}.json"
  if [ -n "${GHOST_ADV_GHSA_DIR:-}" ]; then
    cp "$GHOST_ADV_GHSA_DIR/${repo//\//__}.json" "$f"
  else
    gh api --paginate "repos/$repo/security-advisories?per_page=100" > "$f"
  fi
done
# 2. RustSec.
if [ -n "${GHOST_ADV_RUSTSEC_DIR:-}" ]; then
  db="$GHOST_ADV_RUSTSEC_DIR"
else
  db="$WORK/advisory-db"
  rm -rf "$db"
  git clone -q --depth 1 https://github.com/rustsec/advisory-db "$db"
  echo "RustSec advisory-db at $(git -C "$db" rev-parse --short HEAD)"
fi

set +e
PINS="$WORK/pins.txt" FORMER="$FORMER" GHSA_DIR="$WORK/ghsa" DB="$db" REVIEWED="$REVIEWED" perl -MJSON::PP -e '
  use strict; use warnings;
  my %pin;
  open(my $p, "<", $ENV{PINS}) or die; while (<$p>) { chomp; my ($n, $v) = split / /; push @{ $pin{$n} }, $v } close $p;
  my %former = map { split("=", $_, 2) } split(" ", $ENV{FORMER});
  my %reviewed;
  if (open(my $r, "<", $ENV{REVIEWED})) {
    while (<$r>) { next if /^\s*#/ || /^\s*\z/; my ($id, $name, $ver) = split " "; $reviewed{"$id $name $ver"} = 1 if $id }
  }
  sub vparse { my ($v) = @_; $v =~ s/^v//; $v =~ s/[-+].*$//; my @p = split /\./, $v; push @p, 0 while @p < 3; return @p[0..2] }
  sub vcmp { my @a = vparse($_[0]); my @b = vparse($_[1]); for (0..2) { return $a[$_] <=> $b[$_] if $a[$_] != $b[$_] } 0 }
  # One comparator: =, ==, >, >=, <, <=, ^ (caret: same leftmost non-zero part), bare = caret.
  sub cmp1 {
    my ($c, $v) = @_;
    $c =~ s/^\s+|\s+$//g;
    return 1 if $c eq "" || $c eq "*";
    my ($op, $w) = $c =~ /^(>=|<=|==|=|>|<|\^|~)?\s*(\S+)$/ or die "cannot read the requirement [$c]\n";
    $op //= "^";
    my $r = vcmp($v, $w);
    return $r == 0 if $op eq "=" || $op eq "==";
    return $r > 0 if $op eq ">";
    return $r >= 0 if $op eq ">=";
    return $r < 0 if $op eq "<";
    return $r <= 0 if $op eq "<=";
    my @w = vparse($w);
    if ($op eq "~") { my @x = vparse($v); return $r >= 0 && $x[0] == $w[0] && $x[1] == $w[1] }
    my @x = vparse($v);
    return 0 if $r < 0;
    return $x[0] == $w[0] if $w[0] > 0;
    return $x[0] == 0 && $x[1] == $w[1] if $w[1] > 0;
    return $x[0] == 0 && $x[1] == 0 && $x[2] == $w[2];
  }
  sub req { my ($req, $v) = @_; for my $c (split /,/, $req) { return 0 unless cmp1($c, $v) } 1 }
  my (@hits, $checked);
  # 1. GitHub advisories.
  opendir(my $d, $ENV{GHSA_DIR}) or die;
  for my $f (sort grep { /\.json$/ } readdir $d) {
    local $/; open(my $h, "<", "$ENV{GHSA_DIR}/$f") or die; my $j = <$h>; close $h;
    # gh --paginate concatenates pages: split top-level arrays.
    $j =~ s/\]\s*\[/,/g;
    my $list = JSON::PP->new->decode($j);
    for my $a (@$list) {
      next if ($a->{state} // "published") ne "published";
      for my $vul (@{ $a->{vulnerabilities} || [] }) {
        my $name = $vul->{package}{name} // next;
        my $cur = $former{$name} // $name;
        next unless $pin{$cur};
        for my $v (@{ $pin{$cur} }) {
          $checked++;
          my $range = $vul->{vulnerable_version_range} // "";
          push @hits, "$a->{ghsa_id} $cur $v ($f: $name $range)" if $range ne "" && req($range, $v);
        }
      }
    }
  }
  # 2. RustSec, by name and former name.
  my %names = map { $_ => $_ } keys %pin;
  $names{$_} = $former{$_} for keys %former;
  for my $name (sort keys %names) {
    my $dir = "$ENV{DB}/crates/$name";
    next unless -d $dir;
    my $cur = $names{$name};
    next unless $pin{$cur};
    opendir(my $dd, $dir) or die;
    for my $f (sort grep { /\.md$/ } readdir $dd) {
      local $/; open(my $h, "<", "$dir/$f") or die; my $t = <$h>; close $h;
      my ($front) = $t =~ /```toml\s*(.*?)```/s or next;
      next if $front =~ /^\s*withdrawn\s*=/m;
      my ($id) = $front =~ /^\s*id\s*=\s*"([^"]+)"/m;
      my @patched = ($front =~ /^\s*patched\s*=\s*\[(.*?)\]/ms ? $1 : "") =~ /"([^"]*)"/g;
      my @unaff = ($front =~ /^\s*unaffected\s*=\s*\[(.*?)\]/ms ? $1 : "") =~ /"([^"]*)"/g;
      for my $v (@{ $pin{$cur} }) {
        $checked++;
        my $safe = grep { req($_, $v) } (@patched, @unaff);
        push @hits, "$id $cur $v (RustSec crates/$name)" unless $safe;
      }
    }
  }
  my $bad = 0;
  for my $h (@hits) {
    my ($id, $cur, $v) = split / /, $h;
    if ($reviewed{"$id $cur $v"}) { print "reviewed: $h\n"; next }
    print "ADVISORY: $h\n";
    $bad++;
  }
  print "checked $checked (advisory, pinned version) pairs over " . scalar(keys %pin) . " pinned crates\n";
  exit($bad ? 1 : 0);
'
rc=$?
set -e
[ "$rc" = 0 ] && echo "mls-advisories: no open advisory at the pins" || echo "mls-advisories: an advisory affects a pinned version (review it; a fixed one goes to $(basename "$REVIEWED") with its reason)" >&2
exit "$rc"
