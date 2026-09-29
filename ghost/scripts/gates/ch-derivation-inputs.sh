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
#   2. **HKDF only in the typed module.** The token `Hkdf` appears in no other file of the crate:
#      every HKDF of the channel formats is a `derive_*` function.
#   3. **The MLS exporter only for the two exports.** `export_secret(` is called only in
#      `src/group.rs`, and each call's label is `derive::LABEL_EPOCH` or `derive::LABEL_GENERATION`
#      (`K_ep(e)` and `G_g`, §5.2): no other value is exported from the key schedule.
#   4. **No channel derivation in Kotlin.** No string literal of Android production code looks like a
#      channel label (`ghost/v1/ch/…`, `ghost/v1/ch-…`): parsing, sealing and derivations are native
#      (§10.1). The one exception is the literal `ghost/v1/ch-hint` exactly: Kotlin matches blobs by
#      their hint, `HMAC-SHA256(R, "ghost/v1/ch-hint" ‖ mode ‖ salt)`, with the recognition keys it
#      holds (CS-S5, CS-S6, §6.3.2): a MAC keyed by a secret the native side derived, not a
#      derivation from public material. (`ghost/v1/channel-pseudonym`, `:identity`'s derivation of
#      the pseudonym seed, is not a channel-crate label and is not matched.)
#
# **What it does not see.** A derivation written without HKDF (a hand-rolled HMAC over a public
# value) in another module, and a typed key built from public bytes at a caller (`from_bytes` on a
# `channel_id`): the reviewer's, and the Rust half's pins make the second visible at the type.
#
# Usage: ch-derivation-inputs.sh        (scans GHOST_ROOT, default: the ghost/ monorepo)
# Self-test: scripts/gates/self-test.sh points GHOST_ROOT at test-harness/gates/ch-derivation/*.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
SRC="$GHOST_ROOT/client-core/mls/src"
[ -d "$SRC" ] || { fail "$SRC: no channel crate sources (the gate would pass vacuously)"; finish ch-derivation-inputs; }

out="$(SRC="$SRC" GATES="$GATES_DIR" perl -e '
  require "$ENV{GATES}/source-text.pl";
  use File::Find;
  my @files;
  find({ no_chdir => 1, wanted => sub { push @files, $_ if -f $_ && /\.rs$/ } }, $ENV{SRC});
  my %typed = map { $_ => 1 } qw(&EpochExport &GenerationSecret &ReadBase &DepositBase &JoinKey &InviteSeed &InvitePassword &InvitePasswordKey);
  my ($derives, $exports) = (0, 0);
  for my $f (sort @files) {
    my $text = read_text($f);
    my (undef, $code) = views($text, "rust");
    (my $rel = $f) =~ s{^\Q$ENV{SRC}\E/?}{};
    my $is_derive = $rel eq "derive.rs";
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
      while ($code =~ /\bHkdf\b/g) {
        print "src/$rel:" . line_of(\$code, $-[0]) . ": HKDF outside src/derive.rs (G-M3 rule 2: every derivation is a typed derive_* function)\n";
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
  print "SUMMARY $derives $exports\n";
')"
summary="$(grep '^SUMMARY ' <<< "$out" || true)"
while IFS= read -r line; do
  [ -n "$line" ] && fail "$line"
done < <(grep -v '^SUMMARY ' <<< "$out" || true)
read -r _ derives exports <<< "$summary"
[ "${derives:-0}" -gt 0 ] || fail "no derive_* function found under $SRC (the rules would pass vacuously)"

# Rule 4: no channel label in Kotlin production code.
while IFS= read -r hit; do
  [ -n "$hit" ] && fail "$hit"
done < <(android_main_files | FILES_FROM_STDIN=1 GATES="$GATES_DIR" ROOT="$GHOST_ROOT" perl -e '
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
  }')
echo "[ch-derivation-inputs] ${derives:-0} derive_* functions, ${exports:-0} exporter calls read"
finish ch-derivation-inputs
