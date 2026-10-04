#!/usr/bin/env bash
# Gate G-DM3, Kotlin half (Phase 9 design §16.1, §3.1; invariant T26, static half; §22.33 item 17):
# **no DM derivation in Kotlin takes a public key, a `ghost1` string or a safety number as its key
# input.** The Rust half is `ghost-client-dm`'s unit test
# `every_derive_function_is_enumerated_and_keyed_by_a_typed_secret` (`client-core/dm/src/derive.rs`),
# which enumerates every `derive_*` function of the crate and requires a typed secret as its key.
#
# **Why.** T26: no relay-visible value — a namespace, a verifier, a hint, a relay set — may be
# computable from public identity material without a card or the seed. Every DM derivation of §3.1
# lives in Rust behind typed inputs; what Kotlin still computes is the MESSAGING branch (from the
# seed), the recognition hint (§6.2), the slot order of a relay set (§5.2), the credential verifiers
# (§4.3), the seen tag (§7.6), the Keystore wrapping purposes (§13.8) and, in the `gate` build type
# only, the key-change hook's alternate branch (§15.1). To the compiler a ByteArray is a ByteArray:
# a public key passed where a recognition key belongs would compile, and would put on the wire a
# value anyone can compute.
#
# **The rule as §16.1 words it — "no DM label call site next to a raw ByteArray key input" — does
# not hold on the tree, by design**: §3.2 lets Kotlin hold a recognition key, the namespace that keys
# its own relay set and the seen key, so those HMACs take a raw `ByteArray` key. A text gate cannot
# tell such a key from a public key. **The default applied here, pending the owner's word (§22.33
# item 17), is a motivated allowlist**: every current site is named in
# `scripts/gates/dm-derivation-inputs.allow` (read under GHOST_ROOT, so each fixture carries its own)
# with its call, its count in the file, the declaration its key comes from and the reason it may be
# raw, and anything else fails until it is reviewed and listed. Dedicated key types for those inputs
# (a production change to the three call sites and their callers) are the later fix.
#
# What is read: every Kotlin and Java file of the production source sets (every `src/<set>` but
# `test`, `androidTest`, `testShared`, `testFixtures`, `equivalence`, `deviceRunner`) of
# `android/messaging`, `android/crypto-bridge` and `android/app` — the DM modules and the app's DM
# wiring — and, since Phase 11 slice S3, `android/media` (design faza11-media.md 13.1, 13.2: every media
# derivation, the file key, the fragment keys, the namespace labels, lives in `ghost-client-media`
# behind `MediaNative`, so the Kotlin of `:media` holds no KDF site, no seed branch and no `ghost/v<n>/`
# label, and the allowlist's path check below still names only the three modules that may hold one: an
# entry for `:media` is refused until a later slice widens it on purpose) — each as **one string**
# (`source-text.pl`: comments blanked, so a call written across lines, with a comment inside or with a
# quoted name is the call it spells). Three rules:
#
#   1. **Keys handed to a primitive.** Every `SecretKeySpec(…)` (a MAC or a cipher key: a text gate
#      cannot tell them apart when the algorithm is a constant), every `Hkdf.derive|extract|expand(…)`
#      of `:identity`, and every `RootEntropy.fromRaw|fromMnemonic|generate(…)` (a seed built from
#      bytes the module chose would make every branch computable from them) is a **site**. Each
#      site's call, whitespace removed, must be a `site` entry of its file, found exactly as many
#      times as the entry says (a second copy of an allowed call fails every copy; an entry found
#      fewer times is stale), and the file must hold the entry's provenance — the declaration the key
#      comes from — so a key renamed onto another value fails too.
#   2. **The seed branches.** Every `.deriveBranch(` of those modules takes exactly one
#      `DerivationLabels.X` and no `DerivationLabels` constant appears anywhere else there; the only
#      `fun deriveBranch` of the Android tree is `RootEntropy`'s member in `android/identity`. The
#      MESSAGING and IDENTITY branches are derived from the typed seed and from nothing else.
#   3. **DM labels.** Every string literal of those modules that starts with `ghost/v<n>/` must be a
#      `label` entry of its file (a new label is a new derivation or domain to review), and a
#      literal that looks like a DM label (`ghost/v<n>/dm…`, `…/card/…`, `…/gate/…`, `…-verifier`)
#      anywhere else in Android production code fails: a DM label moved to another module is still
#      a DM label.
#
# **What it does not see.** A key that reaches a listed site through the listed name from a wrong
# source at a **caller** (the provenance pins the declaration, not every call of `Recognition.hint`);
# a MAC initialised with a key object built outside these modules; an unkeyed digest of public
# material under a label this gate already lists (the verifier labels hash a bearer secret today);
# a derivation written without these primitives (a hand-rolled HMAC over `MessageDigest`); and the
# native side, which is the Rust half's. Those are the reviewer's, and the reason typed keys are the
# fix this allowlist stands in for.
#
# Usage: dm-derivation-inputs.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/dm-derivation/*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v perl >/dev/null || { echo "perl not found" >&2; exit 2; }
ALLOW="$GHOST_ROOT/scripts/gates/dm-derivation-inputs.allow"

out="$(GHOST_ROOT="$GHOST_ROOT" GATES_DIR="$GATES_DIR" ALLOW="$ALLOW" perl -e '
use strict;
use warnings;
use File::Find;
require "$ENV{GATES_DIR}/source-text.pl";
my $root = $ENV{GHOST_ROOT};
my %dm_modules = map { $_ => 1 } ("messaging", "crypto-bridge", "app", "media");
my %test_sets = map { $_ => 1 } qw(test androidTest testShared testFixtures equivalence deviceRunner);
sub report { print "VIOLATION\t$_[0]\n" }
# A call or a declaration compared without its layout: whitespace and a trailing comma are formatting.
sub nows { my ($s) = @_; $s =~ s/\s+//g; $s =~ s/,\)/)/g; return $s }

# The allowlist: kind|path|call or label|count|provenance|reason.
my (%site, %label);
if (open my $fh, "<", $ENV{ALLOW}) {
  my $n = 0;
  while (my $l = <$fh>) {
    $n++;
    chomp $l;
    $l =~ s/\r$//;
    next if $l =~ /^\s*(?:#|$)/;
    my ($kind, $path, $what, $count, $prov, $why) = split /\|/, $l, 6;
    if (!defined $why || $why !~ /\S/ || !defined $kind || $kind !~ /^(?:site|label)$/ || !length($path // "")
        || !length($what // "") || ($count // "") !~ /^[1-9][0-9]*$/ || !length($prov // "")) {
      report("scripts/gates/dm-derivation-inputs.allow:$n: malformed entry (kind|path|call or label|count|provenance|reason, every field set)");
      next;
    }
    if ($path !~ m{^android/(?:messaging|crypto-bridge|app)/src/}) {
      report("scripts/gates/dm-derivation-inputs.allow:$n: $path is outside the DM modules (only their sites are listed)");
      next;
    }
    if ($kind eq "site") {
      $site{"$path|" . nows($what)} = { count => $count, prov => nows($prov), prov_shown => $prov, shown => $what, found => 0, at => [] };
    } else {
      $label{"$path|$what"} = { count => $count, found => 0, at => [] };
    }
  }
  close $fh;
}

my @files;
if (-d "$root/android") {
  find({ no_chdir => 1, wanted => sub {
    if (-d $_ && m{/(?:build|\.gradle)$}) { $File::Find::prune = 1; return; }
    push @files, $_ if -f $_ && /\.(?:kt|java)$/;
  } }, "$root/android");
}
my $DM_LABEL = qr{^ghost/v\d+/(?:dm|card/|gate/)|-verifier$};
my $good_branch = qr/\.\s*deriveBranch\s*\(\s*(?:org\s*\.\s*ghost\s*\.\s*identity\s*\.\s*)?DerivationLabels\s*\.\s*[A-Z][A-Z0-9_]*\s*\)/;
my ($scanned, $declarations) = (0, 0);
for my $file (sort @files) {
  (my $rel = $file) =~ s{^\Q$root\E/}{};
  next unless $rel =~ m{^android/([^/]+)/src/([^/]+)/};
  my ($module, $set) = ($1, $2);
  next if $test_sets{$set};
  my $lang = $rel =~ /\.java$/ ? "java" : "kotlin";
  my $text = read_text($file);
  my ($with, $code) = views($text, $lang);

  # Rule 2, the declaration: `deriveBranch` is declared once, as the member of RootEntropy.
  while ($code =~ /\bfun\s+(?:<[^>]*>\s*)?((?:[A-Za-z_][\w.<>?, ]*?)\s*\.\s*)?deriveBranch\s*\(/g) {
    my ($receiver, $at) = ($1, $-[0]);
    if (!defined $receiver && $rel =~ m{^android/identity/src/main/} && $code =~ /\bclass\s+RootEntropy\b/) {
      $declarations++;
    } else {
      report("$rel:" . line_of(\$code, $at) . ": deriveBranch declared outside RootEntropy (G-DM3: a seed branch is derived from the typed seed only)");
    }
  }

  # Rule 3, second half: a DM label outside the DM modules.
  if (!$dm_modules{$module}) {
    for my $lit (string_literals($text, $lang)) {
      my ($line, $body) = @$lit;
      report("$rel:$line: \"$body\": a DM label outside the DM modules (G-DM3; T26)") if $body =~ $DM_LABEL;
    }
    next;
  }
  $scanned++;

  # Rule 1: the sites. The argument list is balanced on the code view (strings blanked) and read
  # back from the view that keeps them, at the same offsets.
  while ($code =~ /\b(?:SecretKeySpec|Hkdf\s*\.\s*(?:derive|extract|expand)|RootEntropy\s*\.\s*(?:fromRaw|fromMnemonic|generate))\s*\(/g) {
    my ($from, $open) = ($-[0], $+[0] - 1);
    my ($depth, $i) = (0, $open);
    for (; $i < length $code; $i++) {
      my $ch = substr($code, $i, 1);
      $depth++ if $ch eq "(";
      $depth-- if $ch eq ")";
      last if $depth == 0;
    }
    my $call = squash(substr($with, $from, $i - $from + 1));
    my $line = line_of(\$code, $from);
    my $entry = $site{"$rel|" . nows($call)};
    if (!$entry) {
      report("$rel:$line: $call is not on G-DM3\x27s allowlist (a key handed to a primitive in a DM module must name its input and why it may be raw; T26)");
      next;
    }
    $entry->{found}++;
    push @{ $entry->{at} }, $line;
    report("$rel:$line: $call, but the file no longer holds the declaration G-DM3 pins its key to ($entry->{prov_shown})")
      if index(nows($with), $entry->{prov}) < 0;
  }

  # Rule 2, the calls: one DerivationLabels constant per deriveBranch, and nowhere else.
  my @good;
  while ($code =~ /$good_branch/g) { push @good, [$-[0], $+[0]] }
  my $inside = sub { my ($at) = @_; for (@good) { return 1 if $at >= $_->[0] && $at < $_->[1] } return 0 };
  while ($code =~ /\bderiveBranch\b/g) {
    my $at = $-[0];
    next if $inside->($at - 1) || $inside->($at);
    next if substr($code, 0, $at) =~ /\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?, ]*?\.\s*)?\z/;
    report("$rel:" . line_of(\$code, $at) . ": deriveBranch called with something other than one DerivationLabels constant (G-DM3: the seed branches take the typed seed and a label)");
  }
  while ($code =~ /\bDerivationLabels\s*\.\s*[A-Z][A-Z0-9_]*/g) {
    next if $inside->($-[0]);
    report("$rel:" . line_of(\$code, $-[0]) . ": a DerivationLabels constant outside RootEntropy.deriveBranch (G-DM3: the seed branches take the typed seed)");
  }

  # Rule 3: every ghost/v<n>/ literal of the DM modules is a listed label of its file.
  for my $lit (string_literals($text, $lang)) {
    my ($line, $body) = @$lit;
    next unless $body =~ m{^ghost/v\d+/} || $body =~ $DM_LABEL;
    my $entry = $label{"$rel|$body"};
    if ($entry) { $entry->{found}++; push @{ $entry->{at} }, $line; next; }
    report("$rel:$line: \"$body\": a DM label that is not on G-DM3\x27s allowlist for this file (T26)");
  }
}

for my $k (sort keys %site) {
  my ($path) = split /\|/, $k, 2;
  my $e = $site{$k};
  if ($e->{found} > $e->{count}) {
    report("$path:$_: $e->{shown} found $e->{found} times, the allowlist permits $e->{count} (G-DM3)") for @{ $e->{at} };
  } elsif ($e->{found} < $e->{count}) {
    report("scripts/gates/dm-derivation-inputs.allow: stale site $path $e->{shown} ($e->{count} allowed, $e->{found} found): remove or correct it");
  }
}
for my $k (sort keys %label) {
  my ($path, $what) = split /\|/, $k, 2;
  my $e = $label{$k};
  if ($e->{found} > $e->{count}) {
    report("$path:$_: \"$what\" found $e->{found} times, the allowlist permits $e->{count} (G-DM3)") for @{ $e->{at} };
  } elsif ($e->{found} < $e->{count}) {
    report("scripts/gates/dm-derivation-inputs.allow: stale label $path \"$what\" ($e->{count} allowed, $e->{found} found): remove or correct it");
  }
}
report("no RootEntropy.deriveBranch declaration found in android/identity/src/main (rule 2 would hold vacuously)") unless $declarations == 1;
print "SCANNED\t$scanned\n";
')" || { echo "dm-derivation-inputs: the scanner stopped" >&2; exit 2; }

scanned=0
while IFS= read -r line; do
  kind="${line%%$'\t'*}"
  rest="${line#*$'\t'}"
  case "$kind" in
    VIOLATION) fail "$rest" ;;
    SCANNED) scanned="$rest" ;;
  esac
done <<< "$out"
[ "$scanned" -gt 0 ] || fail "no production source of the DM modules found under $GHOST_ROOT (the gate would pass vacuously)"
[ -f "$ALLOW" ] || fail "scripts/gates/dm-derivation-inputs.allow: missing (every site would fail)"
echo "[dm-derivation-inputs] $scanned production sources of android/{messaging,crypto-bridge,app,media} read"
finish dm-derivation-inputs
