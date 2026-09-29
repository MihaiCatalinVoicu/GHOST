#!/usr/bin/env bash
# Gate G-M3, script half (Phase 10 design faza10-forum.md §5.2 rule (1), §13.1 G-M3, §19.29.3;
# invariant T36, static half; slice S2a): **every channel derivation takes a typed secret key
# input, and only the open invite's seal takes the one declared public input.** The Rust half is
# `ghost-client-mls`'s unit test `every_derive_function_is_enumerated_and_keyed_by_a_typed_secret`
# (`client-core/mls/src/derive.rs`), which pins every `derive_*` signature.
#
# **Why.** T36: no relay-visible value — a namespace, a verifier, a hint, a seal key — may be
# computable from a `channel_id`, a pseudonym key or a KeyPackage alone. To the compiler a byte
# slice is a byte slice; the typed inputs make a wrong key a type error, and this gate keeps
# derivations from being written outside the typed module or in Kotlin.
#
# What is read: every Rust file of `client-core/mls/src`, each as **one string** with comments and
# strings blanked (`source-text.pl`: a declaration or a call written across lines is still read),
# and every string literal of Android production code (`android_main_files`, `src/main` and
# `src/release`). Four rules:
#
#   1. **Typed key inputs.** Every `fn derive_*` is declared in `src/derive.rs`, and its first
#      parameter's type is one of `&EpochExport`, `&GenerationSecret`, `&ReadBase`, `&DepositBase`,
#      `&JoinKey`, `&InviteSeed`, `&InvitePassword`, `&InvitePasswordKey` — the secrets of §5.2 and
#      the password the Argon2id step consumes — or `&OpenInviteSalt`, the one declared public input,
#      which only `derive_open_invite_seal_key` may take (§5.2 rule (1)'s exemption, §19.29.3).
#   2. **HKDF only in the typed module, keyed by the typed input.** No identifier naming HKDF
#      (`Hkdf`, `SimpleHkdf`, `HkdfExtract`, the `hkdf` crate path, the provider's `hkdf_expand`,
#      any `\w*[Hh]kdf\w*`) appears in another file of the crate. In `src/derive.rs` such an identifier
#      appears only on a `use` line, in the private helper `hkdf32` or inside a `derive_*` function;
#      `hkdf32` is called only from a `derive_*` function and with that function's **first parameter**
#      `.as_bytes()` as its key material — so a helper keyed by `&[u8]` (`expand_untyped`), a
#      function a macro generates, and a second parameter used as the key all fail (review of S2a,
#      F6).
#   3. **The MLS exporter only for the two exports.** `export_secret(` is called only in
#      `src/group.rs`, and each call's label is `derive::LABEL_EPOCH` or `derive::LABEL_GENERATION`
#      (`K_ep(e)` and `G_g`, §5.2): no other value is exported from the key schedule.
#   5. **Typed keys from raw bytes only at reviewed sites.** A typed key input built from bytes —
#      `EpochExport::from_bytes`, `GenerationSecret::from_bytes`, …, the constructor T36's own scenario
#      misuses (`derive_epoch_recognition(&EpochExport::from_bytes(*channel_id))`) — appears in each
#      file of `src/` exactly as often as `client-core/mls/typed-key-sites.txt` pins it (`<file>
#      <type> <count>`, the crate's unit tests included); a new site fails until it is reviewed and
#      pinned, and a pin no site needs fails too (review of S2a, F6).
#   4. **No channel derivation in Kotlin.** No string literal of Android production code looks like a
#      channel label (`ghost/v1/ch/…`, `ghost/v1/ch-…`): parsing, sealing and derivations are native
#      (§10.1). The one exception is the literal `ghost/v1/ch-hint` exactly: Kotlin matches blobs by
#      their hint, `HMAC-SHA256(R, "ghost/v1/ch-hint" ‖ mode ‖ salt)`, with the recognition keys it
#      holds (CS-S5, CS-S6, §6.3.2): a MAC keyed by a secret the native side derived, not a
#      derivation from public material. (`ghost/v1/channel-pseudonym`, `:identity`'s derivation of
#      the pseudonym seed, is not a channel-crate label and is not matched.)
#
# **What it does not see.** A derivation written without HKDF (a hand-rolled HMAC over a public
# value) in another module; a `derive_*` function that calls `Hkdf` directly (not through `hkdf32`)
# with another parameter as the key; and what a pinned `from_bytes` site is given — rule 5 makes a
# new site visible, the reviewer judges its bytes.
#
# Usage: ch-derivation-inputs.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/ch-derivation/*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SRC="$GHOST_ROOT/client-core/mls/src"
SITES="$GHOST_ROOT/client-core/mls/typed-key-sites.txt"
[ -d "$SRC" ] || { fail "$SRC: no channel crate sources (the gate would pass vacuously)"; finish ch-derivation-inputs; }

if ! out="$(SRC="$SRC" SITES="$SITES" GATES="$GATES_DIR" perl -e '
  require "$ENV{GATES}/source-text.pl";
  use File::Find;
  my @files;
  find({ no_chdir => 1, wanted => sub { push @files, $_ if -f $_ && /\.rs$/ } }, $ENV{SRC});
  my %typed = map { $_ => 1 } qw(&EpochExport &GenerationSecret &ReadBase &DepositBase &JoinKey &InviteSeed &InvitePassword &InvitePasswordKey);
  my $key_types = qr/\b(EpochExport|GenerationSecret|ReadBase|DepositBase|JoinKey|InviteSeed|InvitePassword|InvitePasswordKey|OpenInviteSalt|RecognitionKey|SealKey)::from_bytes\b/;
  my (%pinned, %sites);
  if (-f $ENV{SITES}) {
    open(my $p, "<", $ENV{SITES}) or die "cannot read $ENV{SITES}\n";
    while (<$p>) {
      s/#.*//; next unless /\S/;
      my ($file, $type, $n) = split " ";
      $pinned{"$file $type"} = $n;
    }
  }
  my $hkdf_word = qr/\b\w*[Hh]kdf\w*\b/;
  my ($derives, $exports) = (0, 0);
  for my $f (sort @files) {
    my $text = read_text($f);
    my (undef, $code) = views($text, "rust");
    (my $rel = $f) =~ s{^\Q$ENV{SRC}\E/?}{};
    my $is_derive = $rel eq "derive.rs";
    while ($code =~ /$key_types/g) { $sites{"$rel $1"}++ }
    while ($code =~ /\bfn\s+(derive_\w+)/g) {
      my ($name, $at) = ($1, $-[0]);
      my $line = line_of(\$code, $at);
      $derives++;
      print "src/$rel:$line: $name is declared outside src/derive.rs (G-M3 rule 1)\n" unless $is_derive;
      # The first parameter: skip generics, then read to the first top-level comma or parenthesis.
      my $rest = substr($code, pos($code));
      $rest =~ s/^\s*//;
      if ($rest =~ /^</) {
        my $depth = 0; my $i = 0;
        for (; $i < length $rest; $i++) {
          my $c = substr($rest, $i, 1);
          $depth++ if $c eq "<";
          $depth-- if $c eq ">";
          last if $depth == 0;
        }
        $rest = substr($rest, $i + 1);
        $rest =~ s/^\s*//;
      }
      my $ty = "";
      if ($rest =~ /^\(/) {
        my $depth = 0; my $param = "";
        for (my $i = 1; $i < length $rest; $i++) {
          my $c = substr($rest, $i, 1);
          if ($c =~ /[\(\[<]/) { $depth++ }
          elsif ($c =~ /[\]>]/) { $depth-- }
          elsif ($c eq ")") { last if $depth == 0; $depth-- }
          elsif ($c eq "," && $depth == 0) { last }
          $param .= $c;
        }
        $ty = $1 if $param =~ /:(.*)$/s;
        $ty =~ s/\s+//g;
      }
      if ($ty eq "&OpenInviteSalt") {
        print "src/$rel:$line: $name takes the public OpenInviteSalt; only derive_open_invite_seal_key may (G-M3 rule 1, design §19.29.3)\n"
          unless $name eq "derive_open_invite_seal_key";
      } elsif (!$typed{$ty}) {
        my $shown = $ty eq "" ? "no key parameter" : "`$ty`";
        print "src/$rel:$line: $name takes $shown as its key input; T36 allows only the typed secrets (G-M3 rule 1)\n";
      }
    }
    unless ($is_derive) {
      my %seen;
      while ($code =~ /$hkdf_word/g) {
        my $line = line_of(\$code, $-[0]);
        next if $seen{$line}++;
        print "src/$rel:$line: HKDF outside src/derive.rs (G-M3 rule 2: every derivation is a typed derive_* function)\n";
      }
    }
    if ($is_derive) {
      # The functions of the file with their first parameter and their body.
      my @fns;
      while ($code =~ /\bfn\s+(\w+)/g) {
        my ($name, $at) = ($1, $-[0]);
        my $open = index($code, "(", pos($code));
        next if $open < 0;
        my ($depth, $i) = (1, $open + 1);
        while ($i < length $code && $depth) {
          my $c = substr($code, $i, 1);
          $depth++ if $c eq "(";
          $depth-- if $c eq ")";
          $i++;
        }
        my $params = substr($code, $open + 1, $i - $open - 2);
        # The body: the first "{" outside brackets after the parameters (a return type such as
        # [u8; N] holds a ";"); a ";" first is a declaration without a body.
        my ($body, $b) = (-1, 0);
        for (my $q = $i; $q < length $code; $q++) {
          my $c = substr($code, $q, 1);
          if ($c eq "[" || $c eq "(") { $b++ }
          elsif ($c eq "]" || $c eq ")") { $b-- }
          elsif ($b == 0 && $c eq "{") { $body = $q; last }
          elsif ($b == 0 && $c eq ";") { last }
        }
        next if $body < 0;
        my ($d, $j) = (1, $body + 1);
        while ($j < length $code && $d) {
          my $c = substr($code, $j, 1);
          $d++ if $c eq "{";
          $d-- if $c eq "}";
          $j++;
        }
        my ($first) = $params =~ /^\s*(?:mut\s+)?(\w+)\s*:/;
        push @fns, { name => $name, first => $first // "", decl => $at, start => $body, end => $j };
      }
      my $within = sub {
        my $pos = shift;
        my $best;
        for my $fn (@fns) {
          $best = $fn if $fn->{start} < $pos && $pos < $fn->{end} && (!$best || $fn->{start} > $best->{start});
        }
        return $best;
      };
      while ($code =~ /$hkdf_word/g) {
        my ($word, $at) = ($&, $-[0]);
        my $line = line_of(\$code, $at);
        my $bol = rindex($code, "\n", $at) + 1;
        next if substr($code, $bol, $at - $bol) =~ /^\s*(?:pub(?:\([^)]*\))?\s+)?use\b/;
        next if $word eq "hkdf32" && substr($code, 0, $at) =~ /\bfn\s+\z/;
        my $fn = $within->($at);
        if (!$fn || ($fn->{name} ne "hkdf32" && $fn->{name} !~ /^derive_/)) {
          print "src/derive.rs:$line: HKDF (\x60$word\x60) outside a derive_* function and the hkdf32 helper (G-M3 rule 2)\n";
          next;
        }
        next unless $word eq "hkdf32";
        # A call of the helper: its key material is the first parameter of its function.
        my $open = index($code, "(", $at);
        my ($depth, $k, $arg) = (0, $open + 1, "");
        while ($k < length $code) {
          my $c = substr($code, $k, 1);
          last if $depth == 0 && ($c eq "," || $c eq ")");
          $depth++ if $c =~ /[\(\[]/;
          $depth-- if $c =~ /[\)\]]/;
          $arg .= $c;
          $k++;
        }
        $arg =~ s/\s+//g;
        print "src/derive.rs:$line: $fn->{name} keys HKDF with \x60$arg\x60, not its first parameter \x60$fn->{first}\x60 (G-M3 rule 2: the typed input is the key)\n"
          unless $fn->{first} ne "" && $arg eq "$fn->{first}.as_bytes()";
      }
    }
    while ($code =~ /\bexport_secret\s*\(/g) {
      my $at = $-[0];
      my $line = line_of(\$code, $at);
      $exports++;
      if ($rel ne "group.rs") {
        print "src/$rel:$line: export_secret outside src/group.rs (G-M3 rule 3)\n";
        next;
      }
      my $args = substr($code, pos($code), 200);
      my $ok = $args =~ /^\s*[^,]+,\s*(derive::)?LABEL_(EPOCH|GENERATION)\s*,/;
      print "src/$rel:$line: export_secret with a label other than derive::LABEL_EPOCH or LABEL_GENERATION (G-M3 rule 3)\n" unless $ok;
    }
  }
  # Rule 5: every typed key built from bytes is at a pinned site, and every pin is used.
  my %all = (%pinned, %sites);
  for my $k (sort keys %all) {
    my ($file, $type) = split " ", $k;
    my ($have, $want) = ($sites{$k} // 0, $pinned{$k} // 0);
    next if $have == $want;
    print "src/$file: $type\x3a\x3afrom_bytes at $have site(s), typed-key-sites.txt pins $want (G-M3 rule 5: a typed key built from bytes only at a reviewed site)\n";
  }
  print "SUMMARY $derives $exports\n";
')"; then
  fail "the channel source reader (perl) failed: G-M3 rules 1 to 3 are unproven"
  finish ch-derivation-inputs
fi
summary="$(grep '^SUMMARY ' <<< "$out" || true)"
while IFS= read -r line; do
  [ -n "$line" ] && fail "$line"
done < <(grep -v '^SUMMARY ' <<< "$out" || true)
read -r _ derives exports <<< "$summary"
[ "${derives:-0}" -gt 0 ] || fail "no derive_* function found under $SRC (the rules would pass vacuously)"

# Rule 4: no channel label in Kotlin production code. Fail-closed: a perl that fails fails the gate
# (review of S2a, F3).
if ! kt_out="$(android_main_files | FILES_FROM_STDIN=1 GATES="$GATES_DIR" ROOT="$GHOST_ROOT" perl -e '
  require "$ENV{GATES}/source-text.pl";
  while (my $f = <STDIN>) {
    chomp $f;
    next unless length $f;
    my $lang = $f =~ /\.java$/ ? "java" : "kotlin";
    for my $lit (string_literals(read_text($f), $lang)) {
      my ($line, $body) = @$lit;
      if ($body =~ m{ghost/v\d+/ch[/-]} && $body ne "ghost/v1/ch-hint") {
        (my $rel = $f) =~ s{^\Q$ENV{ROOT}\E/?}{};
        print "$rel:$line: a channel derivation label in Kotlin (\"$body\"); channel derivations are native (G-M3 rule 4, design §10.1)\n";
      }
    }
  }')"; then
  fail "the Kotlin literal scan (perl) failed: G-M3 rule 4 is unproven"
  kt_out=""
fi
while IFS= read -r hit; do
  [ -n "$hit" ] && fail "$hit"
done <<< "$kt_out"
echo "[ch-derivation-inputs] ${derives:-0} derive_* functions, ${exports:-0} exporter calls read"
finish ch-derivation-inputs
