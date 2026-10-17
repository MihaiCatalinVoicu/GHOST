#!/usr/bin/env bash
# Gate G-T6 (design faza12-transports.md §13): no process-spawning primitive anywhere on the
# production path outside the two allowlisted sites — and those sites contain no primitive at
# all by construction:
#   - the PT wiring in client-core/net is *config* handed to arti's tor-ptmgr (S0-T4: ptmgr's
#     spawn lives inside the tor-ptmgr dependency, never in GHOST sources);
#   - :network's PtInstaller extracts and verifies a file; it spawns nothing.
# So the rule is: zero spawn sites in production Rust (read as code, comments blanked via
# source-text.pl — the S0-T4 doc quote names Command::new without calling it) and zero in
# production Kotlin (`src/main`/`src/release`/`src/gate`). The emulator probe's ProcessBuilder
# lives in androidTest — a test source set, not the production path (S2's notes recorded this
# accounting; the probe is not exempted here, it is out of scope by source set).
# Second half: no production module outside :network and :sync gains an import of the PT types
# (`PtInstaller`, `BridgeLines`, `PtErrorCategories`): the extraction and the storage facade
# are owned by those two modules (design §8.1); anyone else touching them is a change this
# gate is meant to catch.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Rust production sources, comments blanked (the reader fails the gate on its own error and
# reports how many files it read; zero files read would be vacuous).
if ! out="$(GHOST_ROOT="$GHOST_ROOT" GATES="$GATES_DIR" perl -e '
  require "$ENV{GATES}/source-text.pl";
  my @roots = ("$ENV{GHOST_ROOT}/client-core", "$ENV{GHOST_ROOT}/relay", "$ENV{GHOST_ROOT}/issuer");
  my @files;
  use File::Find;
  for my $root (@roots) {
    find({ no_chdir => 1, wanted => sub {
      if (-d $_ && $_ =~ m{/(target|build)$} && $File::Find::name !~ m{/src/}) { $File::Find::prune = 1; return; }
      push @files, $_ if -f $_ && /\.rs$/ && $File::Find::name =~ m{/src/} && $File::Find::name !~ m{/src/main\.rs$};
    } }, $root);
  }
  my $bad = qr/\b(std::process::Command|tokio::process|process::Command\s*::\s*new)\b/;
  for my $f (sort @files) {
    my (undef, $code) = views(read_text($f), "rust");
    while ($code =~ /$bad/g) {
      my $line = line_of(\$code, $-[0]);
      (my $rel = $f) =~ s{^\Q$ENV{GHOST_ROOT}\E/?}{};
      print "$rel:$line: a process spawn outside the allowlisted sites (design §13 G-T6): $1\n";
    }
  }
  print "FILES-READ " . scalar(@files) . "\n";')"; then
  fail "the Rust spawn-site scan (perl) failed: G-T6 is unproven"
  out=""
fi
read_n="$(sed -n 's/^FILES-READ //p' <<< "$out")"
[ "${read_n:-0}" -gt 0 ] || fail "the Rust spawn-site scan read no file (G-T6 would pass vacuously)"
while IFS= read -r line; do
  [ -n "$line" ] && fail "$line"
done < <(grep -v '^FILES-READ ' <<< "$out" || true)

# Kotlin production sources: spawn primitives.
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if hits="$(grep -nE '(^|[^A-Za-z0-9_])(Runtime\.getRuntime\(\)\.exec|ProcessBuilder[[:space:]]*\(|\.exec[[:space:]]*\()' "$f" || true)"; [ -n "$hits" ]; then
    while IFS= read -r line; do fail "${f#"$GHOST_ROOT"/}:${line}"; done <<< "$hits"
  fi
done < <(android_main_files; android_gate_files)

# PT-type imports outside :network and :sync.
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    "$GHOST_ROOT"/android/network/* | "$GHOST_ROOT"/android/sync/*) continue ;;
  esac
  rel="${f#"$GHOST_ROOT"/}"
  while IFS= read -r hit; do
    [ -n "$hit" ] && fail "$rel:${hit%%:*}: imports a PT type outside :network/:sync (design §8.1): ${hit#*:}"
  done < <(grep -nE 'import[[:space:]]+org\.ghost\.network\.(PtInstaller|BridgeLines|PtErrorCategories)' "$f" || true)
done < <(android_main_files; android_gate_files)

finish pt-exec-site
