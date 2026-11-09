#!/usr/bin/env perl
# Licence tooling of the licence gates (ADR-37; Phase 9 design §2.10.2, §16.1, §22.8.10 points 2-3).
# The bash gates call it; it never reaches the network.
#
#   licenses.pl packages
#       the third-party packages of the shipped Rust graphs (ghost/licenses/graphs.txt), one line
#       each: name, version, licence expression, source directory, graphs (tab-separated).
#   licenses.pl rust-notices <graph> <output>
#       G-L1 (Rust part): writes the notices of one shipped graph.
#   licenses.pl android-notices <components> <output>
#       G-L1 (Gradle part) and G-L2: writes the notices of the release runtime components listed by
#       `./gradlew :app:releaseRuntimeComponents`, reading each component's classes jar and the
#       artifact as published next to its POM in the Gradle cache, and checking
#       gradle-license-allowlist.txt and the POMs.
#   licenses.pl headers
#       G-R5: licence expressions and source headers of the shipped Rust packages.
#   licenses.pl mpl [--bundle <directory>]
#       G-L4: the MPL-2.0 packages of the shipped graphs against ghost/licenses/mpl-sources.txt; with
#       --bundle, copies their published .crate archives there after checking them against Cargo.lock.
#   licenses.pl upstream-candidates
#       the Rust packages used under Apache-2.0, whose upstream NOTICE files the snapshot records.
#   licenses.pl spdx-snapshot <spdx crate directory>
#       rewrites ghost/licenses/spdx/ from the licence texts embedded in the pinned spdx crate.
#
# Violations print as "GATE-FAIL: <message>" on stdout, one per line; the exit status is 1 when
# there was one. Environment: GHOST_ROOT (the ghost/ directory), CARGO_HOME; self-test hooks:
# GHOST_LICENSE_PACKAGES (a package list in the `packages` format, directories relative to it,
# instead of cargo), GHOST_LICENSE_EXCEPTIONS (another G-R5 exception file), GHOST_GRADLE_ALLOWLIST
# (another G-L2 allowlist), GHOST_MPL_SOURCES (another G-L4 manifest), GHOST_LICENSE_TEMPLATE_REVIEWED
# (another list of the packages reviewed to carry an SPDX template text), GHOST_LICENSE_GRAPHS
# (another graphs.txt), GHOST_LICENSE_REQUIRED_OWN (the own crates the graphs must read).
use strict;
use warnings;
use File::Basename qw(basename dirname);
use File::Copy qw(copy);
use File::Find ();
use File::Glob qw(bsd_glob);
use File::Path qw(make_path remove_tree);
use File::Spec;
use Digest::SHA ();

my $ROOT = $ENV{GHOST_ROOT} or die "GHOST_ROOT is not set\n";
my $LIC = "$ROOT/licenses";
my $SPDX_VERSION_FILE = "$LIC/spdx/SOURCE.txt";
my @failures;
sub fail { push @failures, join("", @_) }
sub finish { print "GATE-FAIL: $_\n" for @failures; exit(@failures ? 1 : 0) }

sub slurp {
  my ($path) = @_;
  open my $fh, "<:raw", $path or return undef;
  local $/;
  my $data = <$fh>;
  close $fh;
  return $data;
}
sub spew {
  my ($path, $data) = @_;
  make_path(dirname($path));
  open my $fh, ">:raw", $path or die "cannot write $path: $!\n";
  print $fh $data;
  close $fh;
}
# Text as it is committed: LF line ends, no trailing blanks at the end, one final newline.
sub normalize_text {
  my ($t) = @_;
  $t =~ s/\r\n?/\n/g;
  $t =~ s/^\x{FEFF}//;
  $t =~ s/^\xEF\xBB\xBF//;
  $t =~ s/[ \t]+\n/\n/g;
  $t =~ s/\s+\z//;
  return "$t\n";
}
sub lines_of { my ($path) = @_; my $d = slurp($path); return () unless defined $d; return grep { !/^\s*(#|$)/ } split /\r?\n/, $d }

# ---------------------------------------------------------------------------------------------
# Licence policy: the allow list of ghost/deny.toml (cargo-deny) is the list of licences a shipped
# component may be used under. Preference among alternatives when a package offers several.
my @PREFERENCE = ("MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0",
  "Unlicense", "CC0-1.0", "Apache-2.0 WITH LLVM-exception", "MPL-2.0");
my %RANK = map { $PREFERENCE[$_] => $_ } 0 .. $#PREFERENCE;

sub allowed_licences {
  my $deny = slurp("$ROOT/deny.toml") // die "deny.toml missing\n";
  my ($section) = $deny =~ /^\[licenses\]\s*\n(.*?)(?=^\[)/ms or die "deny.toml: no [licenses] section\n";
  my ($list) = $section =~ /^allow\s*=\s*\[(.*?)\]/ms or die "deny.toml: no licenses allow list\n";
  my %allowed = map { $_ => 1 } $list =~ /"([^"]+)"/g;
  return \%allowed;
}

# SPDX expression -> list of alternatives, each an array of licence terms ("ID" or "ID WITH EXC").
sub expression_options {
  my ($expr) = @_;
  my $e = $expr;
  $e =~ s{\s*/\s*}{ OR }g; # the legacy crates.io separator
  my @tok = $e =~ /\(|\)|[A-Za-z0-9.+:-]+/g;
  my $pos = 0;
  my ($parse_or, $parse_and, $parse_atom);
  $parse_atom = sub {
    my $t = $tok[$pos] // die "unexpected end\n";
    if ($t eq "(") { $pos++; my $r = $parse_or->(); ($tok[$pos] // "") eq ")" or die "missing )\n"; $pos++; return $r }
    die "unexpected '$t'\n" if $t =~ /^(AND|OR|WITH|\))$/;
    $pos++;
    my $term = $t;
    $term =~ s/\+$//;
    if (($tok[$pos] // "") eq "WITH") { $pos++; my $x = $tok[$pos++] // die "WITH without exception\n"; $term = "$term WITH $x" }
    return [[$term]];
  };
  $parse_and = sub {
    my $left = $parse_atom->();
    while (($tok[$pos] // "") eq "AND") {
      $pos++;
      my $right = $parse_atom->();
      my @prod;
      for my $a (@$left) { for my $b (@$right) { push @prod, [@$a, @$b] } }
      $left = \@prod;
    }
    return $left;
  };
  $parse_or = sub {
    my $left = $parse_and->();
    while (($tok[$pos] // "") eq "OR") { $pos++; push @$left, @{ $parse_and->() } }
    return $left;
  };
  my $r = eval { my $x = $parse_or->(); die "trailing '$tok[$pos]'\n" if $pos < @tok; $x };
  return (undef, $@ =~ s/\n$//r) unless $r;
  for my $opt (@$r) { my %s = map { $_ => 1 } @$opt; @$opt = sort keys %s }
  return ($r, undef);
}

# Full licence texts recognised by their wording (whitespace collapsed, lower case).
sub classify_text {
  my ($raw) = @_;
  my $t = lc $raw;
  $t =~ s/\s+/ /g;
  my %ids;
  $ids{"Apache-2.0"} = 1 if $t =~ /apache license,? version 2\.0/ && $t =~ /terms and conditions for use, reproduction,? and distribution/;
  $ids{"MIT"} = 1 if $t =~ /permission is hereby granted, free of charge, to any person obtaining a copy of this software/;
  if ($t =~ /redistribution and use in source and binary forms/) {
    if ($t =~ /neither the name|names of its contributors may be used|may not be used to endorse/) { $ids{"BSD-3-Clause"} = 1 } else { $ids{"BSD-2-Clause"} = 1 }
  }
  $ids{"ISC"} = 1 if $t =~ /permission to use, copy, modify, and\/?or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies/;
  $ids{"0BSD"} = 1 if $t =~ /permission to use, copy, modify, and\/?or distribute this software for any purpose with or without fee is hereby granted\. the software is provided "as is"/;
  $ids{"Zlib"} = 1 if $t =~ /provided .as-is., without any express or implied warranty/ && $t =~ /altered source versions must be plainly marked/;
  $ids{"Unicode-3.0"} = 1 if $t =~ /unicode license v3/ || ($t =~ /unicode, inc/ && $t =~ /data files/ && $t =~ /permission is hereby granted/);
  $ids{"Unlicense"} = 1 if $t =~ /this is free and unencumbered software released into the public domain/;
  $ids{"CC0-1.0"} = 1 if $t =~ /cc0 1\.0 universal/;
  $ids{"MPL-2.0"} = 1 if $t =~ /mozilla public license,? version 2\.0/ && $t =~ /1\. definitions/;
  $ids{"LGPL"} = 1 if $t =~ /^\W*gnu lesser general public license/;
  $ids{"GPL"} = 1 if $t =~ /^\W*gnu general public license/;
  $ids{"AGPL"} = 1 if $t =~ /^\W*gnu affero general public license/;
  return \%ids;
}
sub covers { my ($ids, $term) = @_; my ($base) = split / WITH /, $term; $base =~ s/-(only|or-later)$//; return $ids->{$term} || $ids->{$base} || ($base =~ /^LGPL/ && $ids->{LGPL}) }

my $LICENCE_NAME = qr/^(?:licen[cs]e|copying|copyright|notice|unlicense|patents|third[-_]?party)/i;
my $ALTERNATIVE_NAME = qr/^(?:licen[cs]e|copying)(?:[-_.](?:apache|mit|bsd|0bsd|isc|zlib|unicode|unlicense|mpl|lgpl|gpl|cc0)[-_.0-9a-z]*)?(?:\.(?:txt|md))?$/i;
my $SPDX_FILE_NAME = qr/^(?:MIT|Apache-2\.0|BSD-[23]-Clause|ISC|Zlib|Unicode-3\.0|Unlicense|CC0-1\.0|MPL-2\.0|L?GPL-[23]\.0(?:-only|-or-later)?|AGPL-3\.0(?:-only|-or-later)?)(?:\.txt|\.md)?$/i;

# Licence and notice files a package ships at its root (and a license-file elsewhere).
sub package_licence_files {
  my ($dir, $licence_file) = @_;
  my %files;
  opendir my $dh, $dir or return ();
  for my $f (readdir $dh) {
    next if $f =~ /^\./ || !-f "$dir/$f";
    next if $f =~ /^Cargo\.(?:toml|lock)/ || $f =~ /\.(?:rs|toml|json|yml|yaml|sh|py)$/i;
    $files{$f} = 1 if $f =~ $LICENCE_NAME || $f =~ $SPDX_FILE_NAME || $f =~ /licen[cs]e/i;
  }
  closedir $dh;
  if (-d "$dir/LICENSES") {
    opendir my $lh, "$dir/LICENSES";
    $files{"LICENSES/$_"} = 1 for grep { -f "$dir/LICENSES/$_" } readdir $lh;
    closedir $lh;
  }
  $files{$licence_file} = 1 if defined $licence_file && -f "$dir/$licence_file";
  return sort keys %files;
}

# Licence-named files below a package's root, outside its tests, benches, examples and fuzz targets.
sub nested_licence_files {
  my ($dir) = @_;
  my @found;
  File::Find::find({ no_chdir => 1, wanted => sub {
    my $path = $File::Find::name;
    return unless -f $path;
    (my $rel = $path) =~ s{^\Q$dir\E/}{};
    return if $rel !~ m{/} || $rel =~ m{^LICENSES/} || $rel =~ m{(?:^|/)(?:tests?|benches|examples|fuzz|\.github)/};
    my $name = basename($rel);
    return if $name =~ /\.(?:rs|sh|py|pl|c|h|cc|cpp|s|asm|toml|json|ya?ml|in|am|ac|m4|cmake|html?|js|go|java|kt)$/i;
    push @found, $rel if $name =~ $LICENCE_NAME || $name =~ $SPDX_FILE_NAME;
  } }, $dir);
  return sort @found;
}

my $VENDORED;
sub vendored {
  return $VENDORED if $VENDORED;
  my %v;
  for (lines_of("$LIC/vendored-licences.txt")) {
    my ($action, $crate, $version, $path, $reason) = /^(include|exclude)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/ or do { fail "vendored-licences.txt: malformed line (include|exclude crate version path reason): $_"; next };
    $v{"$crate $version"}{$path} = { action => $action, reason => $reason, seen => 0 };
  }
  return $VENDORED = \%v;
}
sub check_vendored_entries {
  my ($pkgs, $graph) = @_;
  my $v = vendored();
  for my $key (sort keys %$v) {
    my $p = $pkgs->{$key};
    if (!$p) { fail "vendored-licences.txt: $key is not a package of a shipped graph (remove its lines)"; next }
    next unless $p->{graphs}{$graph};
    for my $path (sort keys %{ $v->{$key} }) {
      fail "vendored-licences.txt: $key $path is not a licence file of vendored sources in that package" unless $v->{$key}{$path}{seen};
    }
  }
}

# The packages reviewed to carry an SPDX template text (licenses/template-texts-reviewed.txt:
# "<name> <version>  # reason"; hook GHOST_LICENSE_TEMPLATE_REVIEWED). A missing file is an empty list.
my $TEMPLATE_REVIEWED;
sub template_reviewed {
  return $TEMPLATE_REVIEWED if $TEMPLATE_REVIEWED;
  my $file = $ENV{GHOST_LICENSE_TEMPLATE_REVIEWED} // "$LIC/template-texts-reviewed.txt";
  my %r;
  if (-f $file) {
    for (lines_of($file)) {
      my ($name, $version, $reason) = /^(\S+)\s+(\S+)\s+#\s*(\S.*)$/ or do { fail "template-texts-reviewed.txt: malformed line (name version  # reason): $_"; next };
      $r{"$name $version"} = { reason => $reason, used => 0 };
    }
  }
  return $TEMPLATE_REVIEWED = \%r;
}
sub check_template_entries {
  my ($pkgs, $graph) = @_;
  my $r = template_reviewed();
  for my $key (sort keys %$r) {
    my $p = $pkgs->{$key};
    if (!$p) { fail "template-texts-reviewed.txt: $key is not a package of a shipped graph (remove the line)"; next }
    next unless $p->{graphs}{$graph};
    fail "template-texts-reviewed.txt: $key is not needed (it ships the text of the licence it is used under)" unless $r->{$key}{used};
  }
}

sub spdx_text {
  my ($term) = @_;
  my ($base, $exception) = split / WITH /, $term;
  my $text = slurp("$LIC/spdx/$base.txt");
  return undef unless defined $text;
  if (defined $exception) {
    my $x = slurp("$LIC/spdx/$exception.txt");
    return undef unless defined $x;
    $text .= "\n$x";
  }
  return $text;
}
sub spdx_version {
  my $s = slurp($SPDX_VERSION_FILE) // "";
  my ($v) = $s =~ /^license-list-version\s+(\S+)/m;
  return $v // "unknown";
}
# The notices name the SPDX License List as the provenance of every text a component ships none of,
# so the snapshot must still be the one SOURCE.txt records: every text has its recorded SHA-256, and
# neither side has a file the other does not (ADR-37; Phase 9 design §22.8.10 point 3). Editing a
# text and regenerating the notices moves both together; this check does not.
my $SPDX_SNAPSHOT_CHECKED = 0;
sub check_spdx_snapshot {
  return if $SPDX_SNAPSHOT_CHECKED++;
  my $source = slurp($SPDX_VERSION_FILE);
  if (!defined $source) { fail "licenses/spdx/SOURCE.txt is missing (licenses.pl spdx-snapshot writes it)"; return }
  my %recorded;
  $recorded{$1} = $2 while $source =~ /^text\s+(\S+)\s+([0-9a-f]{64})\s*$/mg;
  if (!%recorded) { fail "licenses/spdx/SOURCE.txt records no licence text (licenses.pl spdx-snapshot writes it)"; return }
  for my $path (sort { $a cmp $b } bsd_glob("$LIC/spdx/*.txt")) {
    my $id = basename($path, ".txt");
    next if $id eq "SOURCE";
    my $sha = delete $recorded{$id};
    if (!defined $sha) { fail "licenses/spdx/$id.txt: SOURCE.txt records no SHA-256 for it"; next }
    fail "licenses/spdx/$id.txt does not match the SHA-256 that SOURCE.txt records" if Digest::SHA::sha256_hex(slurp($path) // "") ne $sha;
  }
  fail "licenses/spdx/$_.txt is missing; SOURCE.txt records it" for sort keys %recorded;
}

# Chooses the licence alternative a component is used under: only allowed licences; the fewest
# licences without a text shipped by the component; then the preference order.
sub elect {
  my ($options, $allowed, $shipped) = @_;
  my @ok = grep { my $o = $_; !grep { !$allowed->{$_} } @$o } @$options;
  return undef unless @ok;
  my @scored = map {
    my $o = $_;
    my $missing = grep { !covers($shipped, $_) } @$o;
    [$o, $missing, join(",", map { sprintf "%02d", $RANK{$_} // 99 } @$o), scalar @$o];
  } @ok;
  @scored = sort { $a->[1] <=> $b->[1] or $a->[2] cmp $b->[2] or $a->[3] <=> $b->[3] } @scored;
  return $scored[0][0];
}

# ---------------------------------------------------------------------------------------------
# Shipped Rust graphs and their packages.
sub graphs {
  my %g;
  my @order;
  my @notes;
  for (lines_of($ENV{GHOST_LICENSE_GRAPHS} // "$LIC/graphs.txt")) {
    my @f = split " ";
    if (@f >= 3 && $f[0] eq "note") { push @notes, [$f[1], join(" ", @f[2 .. $#f])]; next }
    die "graphs.txt: malformed line: $_\n" unless @f == 4 && $f[0] eq "graph";
    $g{$f[1]} = { name => $f[1], packages => [split /,/, $f[2]], targets => [split /,/, $f[3]] };
    push @order, $f[1];
  }
  die "graphs.txt: no graph\n" unless @order;
  for my $n (@notes) {
    die "graphs.txt: a note for the unknown graph '$n->[0]'\n" unless $g{$n->[0]};
    $g{$n->[0]}{note} = defined $g{$n->[0]}{note} ? "$g{$n->[0]}{note} $n->[1]" : $n->[1];
  }
  return (\%g, \@order);
}

sub cargo_home { return $ENV{CARGO_HOME} // File::Spec->catdir($ENV{HOME} // $ENV{USERPROFILE}, ".cargo") }

my $FETCHED = 0;
sub registry_dir {
  my ($name, $version) = @_;
  # A cargo process sharing CARGO_HOME may be extracting the same sources: fetch once, then retry.
  for my $attempt (1 .. 5) {
    my ($dir) = grep { -f "$_/Cargo.toml" && -f "$_/.cargo-ok" } sort { $a cmp $b } bsd_glob(cargo_home() . "/registry/src/*/$name-$version");
    return $dir if $dir;
    if (!$FETCHED++) { system("cd \"$ROOT\" && cargo fetch --locked >/dev/null 2>&1") } else { sleep 2 }
  }
  return undef;
}

sub manifest_fields {
  my ($dir) = @_;
  my $toml = slurp("$dir/Cargo.toml") // return {};
  $toml =~ s/\r\n/\n/g;
  my ($package) = $toml =~ /^\[package\]\n(.*?)(?=^\[|\z)/ms;
  $package //= "";
  my %f;
  for my $key (qw(license license-file repository)) {
    $f{$key} = $1 if $package =~ /^\Q$key\E\s*=\s*"((?:[^"\\]|\\.)*)"/m;
  }
  if ($package =~ /^authors\s*=\s*\[(.*?)\]/ms) { $f{authors} = [ $1 =~ /"((?:[^"\\]|\\.)*)"/g ] }
  return \%f;
}

my $PACKAGES;
sub packages {
  return $PACKAGES if $PACKAGES;
  my %pkgs;
  if (my $list = $ENV{GHOST_LICENSE_PACKAGES}) {
    my $base = dirname($list);
    for (lines_of($list)) {
      my ($name, $version, $licence, $dir, $graphs, $own) = split /\t/;
      $pkgs{"$name $version"} = { name => $name, version => $version, license => $licence // "", dir => "$base/$dir", own => ($own // "") eq "own", graphs => { map { $_ => 1 } split /,/, $graphs // "fixture" } };
    }
    return $PACKAGES = \%pkgs;
  }
  my ($graphs, $order) = graphs();
  for my $g (@$order) {
    my $spec = $graphs->{$g};
    for my $target (@{ $spec->{targets} }) {
      my @cmd = ("cargo", "tree", "--locked", (map { ("-p", $_) } @{ $spec->{packages} }), "-e", "normal", "--target", $target, "--prefix", "none", "-f", "{p}|{l}");
      my $out = qx{cd "$ROOT" && @{[ join " ", map { "'$_'" } @cmd ]}};
      die "cargo tree failed for $g ($target)\n" if $? != 0;
      for my $line (split /\n/, $out) {
        next unless $line =~ /\S/;
        $line =~ s/ \(\*\)$//;
        my ($p, $licence) = split /\|/, $line, 2;
        my ($name, $version, $rest) = $p =~ /^(\S+) v(\S+)(.*)$/ or die "cargo tree: unexpected line: $line\n";
        die "cargo tree: $name $version comes from a git or other non-registry source ($rest)\n" if $rest =~ /\((?:https?|git|ssh):/;
        my $key = "$name $version";
        # A path package is one of GHOST's own crates: G-R5 scans its sources, the notices skip it.
        # An exception: third_party/ holds VENDORED UPSTREAM sources (a [patch.crates-io] of an
        # upstream crate, e.g. saturating-time) — those keep their own licence and are third-party
        # for every licence gate; "own" must mean a GHOST crate or the header and licence.workspace
        # clauses demand the proprietary licence of someone else's code.
        if ($rest =~ /\(((?:[A-Za-z]:)?[\/\\][^)]*)\)/) {
          (my $dir = $1) =~ tr{\\}{/};
          my $vendored_upstream = $dir =~ m{(?:^|/)third_party/} ? 1 : 0;
          $pkgs{$key} //= { name => $name, version => $version, license => $licence // "", graphs => {}, own => $vendored_upstream ? 0 : 1, dir => $dir };
        }
        $pkgs{$key} //= { name => $name, version => $version, license => $licence // "", graphs => {}, own => 0 };
        $pkgs{$key}{graphs}{$g} = 1;
      }
    }
  }
  # Third-party packages without a source dir yet: resolved from the cargo registry. (Vendored
  # upstream under third_party/ already carry theirs — see the classification above.)
  for my $p (grep { !$_->{own} && !$_->{dir} } values %pkgs) {
    $p->{dir} = registry_dir($p->{name}, $p->{version}) // die "no extracted sources for $p->{name} $p->{version} under " . cargo_home() . "/registry/src\n";
  }
  # GHOST's own crates that a shipped library holds, or will hold once its slice links it, are each
  # read by the graphs, as a root or inside one (the review of Phase 11's S1: with `,ghost-client-media`
  # dropped from graphs.txt the header scan read nothing of the crate, passed, and only the notices'
  # introduction line changed, which `--write` would have blessed). A failure here also stops the
  # notices from being written.
  for my $req (split " ", $ENV{GHOST_LICENSE_REQUIRED_OWN} // "ghost-client-net ghost-client-dm ghost-client-mls ghost-client-media ghost-relay-node ghost-issuer ghost-issuer-ops") {
    fail "licenses/graphs.txt: GHOST's own crate $req is in no shipped graph, so the licence gates read nothing of it (G-R5, G-L1, G-L4; Phase 11 design §22.2 row 19(e))"
      unless grep { $_->{own} && $_->{name} eq $req } values %pkgs;
  }
  return $PACKAGES = \%pkgs;
}
# Third-party packages (of one graph); with $own, GHOST's own crates too.
sub sorted_packages {
  my ($pkgs, $graph, $own) = @_;
  return sort { $a->{name} cmp $b->{name} or $a->{version} cmp $b->{version} } grep { ($own || !$_->{own}) && (!defined $graph || $_->{graphs}{$graph}) } values %$pkgs;
}

# Upstream snapshot: files captured from a component's repository at its published commit
# (ghost/licenses/upstream/index.txt; scripts/license-upstream-snapshot.sh writes it).
my $UPSTREAM;
sub upstream {
  return $UPSTREAM if $UPSTREAM;
  my %u;
  for (lines_of("$LIC/upstream/index.txt")) {
    my @f = split " ";
    my ($eco, $name, $version, $repo, $commit, $result, @files) = @f;
    my $entry = { repo => $repo, commit => $commit, result => $result, files => [] };
    if ($result eq "captured") {
      while (my ($path, $sha) = splice @files, 0, 2) { push @{ $entry->{files} }, { path => $path, sha256 => $sha } }
    }
    $u{"$eco $name $version"} = $entry;
  }
  return $UPSTREAM = \%u;
}
sub upstream_store { my ($eco, $name, $version, $path) = @_; (my $n = $name) =~ s/:/__/g; (my $p = $path) =~ s{/}{__}g; return "$LIC/upstream/$eco/$n-$version/$p" }

# ---------------------------------------------------------------------------------------------
# Notices document.
sub notices_document {
  my (%a) = @_; # title, intro, components => [{label, lines => [..], texts => [[label, text], ..]}], sections => [[title, body]]
  my (%text_id, @texts);
  my @component_blocks;
  for my $c (@{ $a{components} }) {
    my @ids;
    for my $t (@{ $c->{texts} }) {
      my ($label, $body) = @$t;
      my $norm = normalize_text($body);
      my $id = $text_id{$norm};
      unless ($id) { push @texts, [$label, $norm]; $id = $text_id{$norm} = scalar @texts }
      push @ids, $id;
    }
    my %seen;
    @ids = grep { !$seen{$_}++ } @ids;
    push @component_blocks, join("", "$c->{label}\n", map({ "  $_\n" } @{ $c->{lines} }), "  texts: " . join(", ", map { "[$_]" } @ids) . "\n");
  }
  my $out = "$a{title}\n" . ("=" x length $a{title}) . "\n\n$a{intro}\n";
  $out .= "Components (" . scalar(@component_blocks) . ")\n" . ("-" x (length(scalar @component_blocks) + 13)) . "\n\n" . join("\n", @component_blocks);
  for my $s (@{ $a{sections} // [] }) { $out .= "\n$s->[0]\n" . ("-" x length $s->[0]) . "\n\n$s->[1]" }
  $out .= "\nTexts (" . scalar(@texts) . ")\n" . ("-" x (length(scalar @texts) + 8)) . "\n";
  for my $i (0 .. $#texts) { $out .= "\n[" . ($i + 1) . "] $texts[$i][0]\n\n$texts[$i][1]" }
  return "$out\n\n"; # blank lines before the part that follows in the APK asset
}

sub wrap {
  my ($text, $width) = @_;
  my @out;
  for my $para (split /\n\n/, $text) {
    my $line = "";
    for my $w (split /\s+/, $para) {
      next if $w eq "";
      if ($line ne "" && length($line) + 1 + length($w) > $width) { push @out, $line; $line = $w } else { $line = $line eq "" ? $w : "$line $w" }
    }
    push @out, $line, "";
  }
  pop @out;
  return join("\n", @out) . "\n";
}

# Texts and licence choice of one Rust package; records violations.
sub rust_package_texts {
  my ($p, $allowed) = @_;
  my $fields = manifest_fields($p->{dir});
  my $expr = $p->{license} ne "" ? $p->{license} : ($fields->{license} // "");
  my $where = "$p->{name} $p->{version}";
  my @files = package_licence_files($p->{dir}, $fields->{"license-file"});
  my (%shipped, %class);
  for my $f (@files) {
    my $c = classify_text(slurp("$p->{dir}/$f") // "");
    $class{$f} = $c;
    $shipped{$_} = 1 for keys %$c;
  }
  if ($expr eq "") {
    if (defined $fields->{"license-file"} && -f "$p->{dir}/$fields->{'license-file'}") {
      fail "$where: declares no SPDX licence expression, only license-file $fields->{'license-file'} (review it and list the package in rust-license-exceptions.txt)";
    } else {
      fail "$where: declares no licence";
    }
    return undef;
  }
  my ($options, $err) = expression_options($expr);
  if (!$options) { fail "$where: licence expression '$expr' does not parse ($err)"; return undef }
  my $elected = elect($options, $allowed, \%shipped);
  if (!$elected) { fail "$where: no alternative of '$expr' is an allowed licence (deny.toml)"; return undef }
  my %elected = map { $_ => 1 } @$elected;
  my %expression_ids = map { $_ => 1 } map { @$_ } @$options;
  my @texts;
  my %covered;
  for my $f (@files) {
    my $c = $class{$f};
    # The text of an alternative the component is not used under (LICENSE-APACHE of a package used
    # under MIT, the LGPL text of priority-queue) is left out; every other file is kept.
    my @ids = keys %$c;
    my $elected_hit = grep { my $id = $_; grep { covers({ $id => 1 }, $_) } @$elected } @ids;
    my $alternatives = grep { my $id = $_; grep { covers({ $id => 1 }, $_) } keys %expression_ids } @ids;
    next if @ids && !$elected_hit && $alternatives == @ids && basename($f) =~ /$ALTERNATIVE_NAME|$SPDX_FILE_NAME/;
    for my $term (@$elected) { $covered{$term} = 1 if covers($c, $term) }
    push @texts, ["$f of $where", slurp("$p->{dir}/$f")];
  }
  # Licence files of vendored sources below the package root (xz in liblzma-sys, zstd in zstd-sys):
  # each is decided in ghost/licenses/vendored-licences.txt, included or excluded with a reason.
  for my $rel (nested_licence_files($p->{dir})) {
    my $d = vendored()->{"$p->{name} $p->{version}"}{$rel};
    if (!$d) { fail "$where: $rel: a licence file of vendored sources that ghost/licenses/vendored-licences.txt does not decide"; next }
    $d->{seen} = 1;
    push @texts, ["$rel of $where", slurp("$p->{dir}/$rel")] if $d->{action} eq "include";
  }
  my @spdx_terms;
  for my $term (@$elected) {
    next if $covered{$term};
    my $t = spdx_text($term);
    if (!defined $t) { fail "$where: no text for licence $term: the package ships none and ghost/licenses/spdx has none"; next }
    # A template (MIT's "Copyright (c) <year> <copyright holders>", BSD's "<year> <owner>") names no
    # copyright holder: the notices then carry the licence without the notice it requires. A package
    # may use one only after review (Phase 10 review of S2a, F1; design faza10-forum.md §19.31).
    if ($t =~ /<year>|<copyright holders>|<owner>/) {
      my $r = template_reviewed()->{$where};
      if ($r) { $r->{used} = 1 }
      else { fail "$where: ships no $term text, and the SPDX one is a template without a copyright line (<year>, <copyright holders>): capture the upstream licence file (scripts/license-upstream-snapshot.sh) or review it in licenses/template-texts-reviewed.txt" }
    }
    push @texts, ["$term, SPDX License List " . spdx_version(), $t];
    push @spdx_terms, $term;
  }
  if ($elected{"Apache-2.0"}) {
    my $u = upstream()->{"cargo $p->{name} $p->{version}"};
    if (!$u) {
      fail "$where: used under Apache-2.0 without an upstream NOTICE snapshot entry (run scripts/license-upstream-snapshot.sh)";
    } else {
      for my $file (@{ $u->{files} }) {
        my $stored = upstream_store("cargo", $p->{name}, $p->{version}, $file->{path});
        my $data = slurp($stored);
        if (!defined $data) { fail "$where: dropped NOTICE: $file->{path} of the upstream snapshot is missing ($stored)"; next }
        if (Digest::SHA::sha256_hex($data) ne $file->{sha256}) { fail "$where: upstream snapshot file $file->{path} does not match its recorded SHA-256"; next }
        push @texts, ["$file->{path} of $u->{repo} at $u->{commit}", $data];
      }
    }
  }
  my @lines = ("licence: $expr; used under: " . join(" AND ", @$elected));
  if (@spdx_terms && $fields->{authors} && @{ $fields->{authors} }) {
    my @authors = map { (my $x = $_) =~ s/\s*<[^>]*>//g; $x } @{ $fields->{authors} };
    push @lines, "authors: " . join(", ", @authors);
  }
  push @lines, "source: https://crates.io/crates/$p->{name}/$p->{version}" . ($fields->{repository} ? ", $fields->{repository}" : "");
  return { label => $where, lines => \@lines, texts => \@texts, elected => $elected };
}

sub cargo_lock_checksums {
  my $lock = slurp("$ROOT/Cargo.lock") // die "Cargo.lock missing\n";
  my %sum;
  while ($lock =~ /\[\[package\]\]\n(.*?)(?=\n\[\[package\]\]|\z)/sg) {
    my $b = $1;
    my ($n) = $b =~ /^name = "([^"]+)"/m;
    my ($v) = $b =~ /^version = "([^"]+)"/m;
    my ($c) = $b =~ /^checksum = "([0-9a-f]+)"/m;
    $sum{"$n $v"} = $c if $n && $v && $c;
  }
  return \%sum;
}

my %GRAPH_TITLE = (
  "client-net" => "libghost_client_net.so, the native library of the GHOST Android app",
  "relay" => "ghost-relay, the GHOST relay",
  "issuer" => "ghost-issuer and ghost-issuer-ops, the GHOST issuer and its operator tools",
);

sub cmd_rust_notices {
  my ($graph, $output) = @_;
  my ($graphs) = graphs();
  die "unknown graph '$graph'\n" unless $graphs->{$graph};
  check_spdx_snapshot();
  my $allowed = allowed_licences();
  my $pkgs = packages();
  my $sums = cargo_lock_checksums();
  my (@components, @mpl);
  for my $p (sorted_packages($pkgs, $graph)) {
    my $c = rust_package_texts($p, $allowed) or next;
    push @components, $c;
    push @mpl, $p if grep { $_ eq "MPL-2.0" } @{ $c->{elected} };
  }
  check_vendored_entries($pkgs, $graph);
  check_template_entries($pkgs, $graph);
  my $spec = $graphs->{$graph};
  my $title = "Third-party notices: " . ($GRAPH_TITLE{$graph} // $graph);
  my $intro = wrap("This part lists the third-party Rust components linked into " . ($GRAPH_TITLE{$graph} // $graph)
    . " (Cargo packages " . join(", ", @{ $spec->{packages} }) . " for " . join(", ", @{ $spec->{targets} })
    . "), the licence under which each is used, and then the texts of those licences and the notices the components ship."
    . "\n\nGenerated by scripts/gates/license-notices.sh from Cargo.lock and the published source of each component; do not edit."
    . " Where a component ships no text of the licence under which it is used, the text comes from the SPDX License List " . spdx_version() . "."
    . (defined $spec->{note} ? "\n\n$spec->{note}" : ""), 100);
  my @sections;
  if (@mpl) {
    my $body = wrap("The components below are used unmodified under the Mozilla Public License 2.0. Their Source Code Form is the published crate archive named here, identified by its SHA-256 as recorded in Cargo.lock. A copy of each archive is provided with every GHOST release, on the channels that distribute the release, and the archive can also be downloaded from crates.io at the address given.", 100) . "\n";
    for my $p (@mpl) {
      my $sum = $sums->{"$p->{name} $p->{version}"} // "unknown";
      $body .= "\n" unless $body =~ /\n\n\z/;
      $body .= "$p->{name} $p->{version}\n  https://crates.io/api/v1/crates/$p->{name}/$p->{version}/download\n  SHA-256 $sum\n";
    }
    push @sections, ["MPL-2.0 source offer", $body];
  }
  my $doc = notices_document(title => $title, intro => $intro, components => \@components, sections => \@sections);
  spew($output, $doc) unless @failures;
  finish();
}

# ---------------------------------------------------------------------------------------------
# Gradle part (G-L1) and the Gradle licence allowlist (G-L2).
my @POM_LICENCES = (
  [qr/^(?:the )?apache (?:software )?license,? version 2\.0$|^apache-2\.0$|^apache license 2\.0$|^apache 2\.0$/i, qr{apache\.org/licenses/LICENSE-2\.0}i, "Apache-2.0"],
  [qr/^(?:the )?mit license$|^mit$/i, qr{opensource\.org/licenses/MIT}i, "MIT"],
  [qr/^bouncy castle licen[cs]e$/i, qr{bouncycastle\.org/licen[cs]e\.html}i, "MIT"],
  [qr/^$/, qr{zetetic\.net/sqlcipher/license}i, "BSD-3-Clause"],
);
sub pom_licence_id {
  my ($name, $url) = @_;
  for my $m (@POM_LICENCES) {
    my ($n, $u, $id) = @$m;
    return $id if ($name ne "" && $name =~ $n) || ($url ne "" && $url =~ $u && ($name eq "" || $name =~ $n));
  }
  return undef;
}
sub pom_path {
  my ($gradle_home, $group, $artifact, $version) = @_;
  return (sort { $a cmp $b } bsd_glob("$gradle_home/caches/modules-2/files-2.1/$group/$artifact/$version/*/$artifact-$version.pom"))[0];
}
# The component as published, next to its POM: the AAR (or the jar of a plain Java library), whose
# root carries the licence and notice files that classes.jar does not. The file name is the one the
# module metadata gives (androidx.compose.ui:ui-android publishes ui.aar), so every archive of the
# version's cache directories counts, source and documentation jars apart.
sub published_archives {
  my ($gradle_home, $group, $artifact, $version) = @_;
  my @found;
  for my $path (bsd_glob("$gradle_home/caches/modules-2/files-2.1/$group/$artifact/$version/*/*")) {
    next unless -f $path;
    my $name = basename($path);
    next unless $name =~ /\.(?:aar|jar)$/i;
    next if $name =~ /-(?:sources|javadoc|tests)\.jar$/i;
    push @found, $path;
  }
  return sort { $a cmp $b } @found;
}
sub pom_licences {
  my ($gradle_home, $group, $artifact, $version, $depth) = @_;
  my $path = pom_path($gradle_home, $group, $artifact, $version) or return (undef, "no POM for $group:$artifact:$version in the Gradle cache");
  my $pom = slurp($path);
  my @l;
  if ($pom =~ /<licenses>(.*?)<\/licenses>/s) {
    my $block = $1;
    while ($block =~ /<license>(.*?)<\/license>/sg) {
      my $b = $1;
      my ($n) = $b =~ /<name>\s*(.*?)\s*<\/name>/s;
      my ($u) = $b =~ /<url>\s*(.*?)\s*<\/url>/s;
      push @l, [$n // "", $u // ""];
    }
  }
  return (\@l, undef) if @l || $depth >= 3;
  if ($pom =~ /<parent>(.*?)<\/parent>/s) {
    my $p = $1;
    my ($g) = $p =~ /<groupId>\s*(.*?)\s*<\/groupId>/s;
    my ($a) = $p =~ /<artifactId>\s*(.*?)\s*<\/artifactId>/s;
    my ($v) = $p =~ /<version>\s*(.*?)\s*<\/version>/s;
    return pom_licences($gradle_home, $g, $a, $v, $depth + 1) if $g && $a && $v;
  }
  return (\@l, undef);
}

sub cmd_android_notices {
  my ($components_file, $output) = @_;
  check_spdx_snapshot();
  my $allowed = allowed_licences();
  delete $allowed->{"MPL-2.0"}; # ADR-37 point 2: MPL only for the two Arti packages, never in the Gradle graph
  my $allowlist_file = $ENV{GHOST_GRADLE_ALLOWLIST} // "$ROOT/scripts/gates/gradle-license-allowlist.txt";
  my %allow;
  for (lines_of($allowlist_file)) {
    my ($coord, $expr) = /^(\S+)\s+(.+?)\s*$/ or do { fail "gradle-license-allowlist.txt: malformed line: $_"; next };
    $allow{$coord} = $expr;
  }
  my @lines = lines_of($components_file);
  fail "$components_file lists no component" unless @lines;
  my (@components, %used);
  for my $line (sort @lines) {
    my ($coord, $file) = split /\t/, $line;
    my ($group, $artifact, $version) = split /:/, $coord;
    my $ga = "$group:$artifact";
    $used{$ga} = 1;
    my $where = "$coord";
    my $expr = $allow{$ga};
    if (!defined $expr) { fail "$where: unknown licence: $ga is not in gradle-license-allowlist.txt"; next }
    my ($options, $err) = expression_options($expr);
    if (!$options) { fail "$where: gradle-license-allowlist.txt: '$expr' does not parse ($err)"; next }
    (my $gradle_home = $file // "") =~ s{\\}{/}g;
    $gradle_home =~ s{/caches/.*$}{};
    my ($pom, $perr) = pom_licences($gradle_home, $group, $artifact, $version, 0);
    my %declared_ids;
    if (!$pom) {
      fail "$where: $perr";
    } elsif (!@$pom) {
      fail "$where: its POM declares no licence";
    } else {
      for my $l (@$pom) {
        my $id = pom_licence_id(@$l);
        if (!$id) { fail "$where: unknown licence in its POM: '$l->[0]' $l->[1]"; next }
        $declared_ids{$id} = 1;
        fail "$where: its POM declares $id, gradle-license-allowlist.txt says '$expr'" unless grep { grep { $_ eq $id } @$_ } @$options;
      }
    }
    # Both archives of the component: the classes jar AGP transforms out of it, and the artifact as
    # published, next to the POM in the Gradle cache. An AAR keeps its licence and notice files at
    # its own root, outside classes.jar, so reading only the classes jar drops texts the component
    # ships (Apache-2.0 §4(d)).
    my (@texts, %shipped, %scanned);
    my @archives = grep { defined && $_ ne "" } ($file);
    fail "$where: the components file names no classes jar" unless @archives;
    my @published = published_archives($gradle_home, $group, $artifact, $version);
    if (@published) { push @archives, @published } else { fail "$where: no aar or jar of the component in the Gradle cache" }
    for my $archive (@archives) {
      next if $scanned{$archive}++;
      if (!-f $archive) { fail "$where: the archive $archive is missing"; next }
      my @entries = grep { m{^META-INF/(?:.*/)?(?:LICEN[CS]E|NOTICE|COPYING|COPYRIGHT)[^/]*$}i } split /\n/, scalar qx{unzip -Z1 "$archive" 2>/dev/null};
      for my $e (sort @entries) {
        my $data = qx{unzip -p "$archive" "$e" 2>/dev/null};
        next if $data !~ /\S/;
        $shipped{$_} = 1 for keys %{ classify_text($data) };
        push @texts, ["$e of $coord", $data];
      }
    }
    my $u = upstream()->{"maven $ga $version"};
    if ($u) {
      for my $f (@{ $u->{files} }) {
        my $stored = upstream_store("maven", $ga, $version, $f->{path});
        my $data = slurp($stored);
        if (!defined $data) { fail "$where: dropped upstream file $f->{path} ($stored)"; next }
        if (Digest::SHA::sha256_hex($data) ne $f->{sha256}) { fail "$where: upstream snapshot file $f->{path} does not match its recorded SHA-256"; next }
        $shipped{$_} = 1 for keys %{ classify_text($data) };
        push @texts, ["$f->{path} of $u->{repo} at $u->{commit}", $data];
      }
    }
    my $elected = elect($options, $allowed, \%shipped);
    if (!$elected) { fail "$where: '$expr' is not an allowed licence (copyleft or unknown; deny.toml allow list without MPL-2.0)"; next }
    for my $term (@$elected) {
      next if covers(\%shipped, $term);
      my $t = spdx_text($term);
      if (!defined $t) { fail "$where: no text for licence $term"; next }
      push @texts, ["$term, SPDX License List " . spdx_version(), $t];
    }
    push @components, { label => $coord, lines => ["licence: $expr" . (%declared_ids ? " (POM: " . join(", ", sort keys %declared_ids) . ")" : "") . "; used under: " . join(" AND ", @$elected)], texts => \@texts };
  }
  for my $ga (sort keys %allow) { fail "gradle-license-allowlist.txt: $ga is not a release runtime component any more (remove the line)" unless $used{$ga} }
  my $intro = wrap("This part lists the third-party Java and Kotlin libraries packaged in the GHOST Android app (the release runtime classpath of :app), the licence under which each is used, and then the texts of those licences and the notices the libraries ship."
    . "\n\nGenerated by scripts/gates/license-notices.sh from the resolved Gradle components, their POMs and gradle-license-allowlist.txt; do not edit. Where a library ships no text of its licence, the text comes from the SPDX License List " . spdx_version() . ".", 100);
  my $doc = notices_document(title => "Third-party notices: the Java and Kotlin libraries of the GHOST Android app", intro => $intro, components => \@components);
  spew($output, $doc) unless @failures;
  finish();
}

# ---------------------------------------------------------------------------------------------
# G-R5: licence expressions and the licence declared by the source files themselves.
sub cmd_headers {
  my $allowed = allowed_licences();
  my $pkgs = packages();
  my $exceptions_file = $ENV{GHOST_LICENSE_EXCEPTIONS} // "$ROOT/scripts/gates/rust-license-exceptions.txt";
  my %exceptions;
  for (lines_of($exceptions_file)) {
    my ($crate, $version, $file, $reason) = /^(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/ or do { fail "rust-license-exceptions.txt: malformed line (crate version file reason): $_"; next };
    $exceptions{"$crate $version"}{$file} = { reason => $reason, used => 0 };
  }
  my $count = 0;
  for my $p (sorted_packages($pkgs, undef, 1)) {
    $count++;
    my $where = "$p->{name} $p->{version}";
    my $exc = $exceptions{$where};
    my $fields = manifest_fields($p->{dir});
    my $expr = $p->{license} ne "" ? $p->{license} : ($fields->{license} // "");
    if ($p->{own}) {
      # GHOST's own crates carry LicenseRef-GHOST-Proprietary (root LICENSE); their sources are scanned
      # below. G-M7 (Phase 11 design faza11-media.md §16.1; slice S1): the declaration is checked, so
      # an own crate whose manifest declares no licence, or another one, fails (a crate's licence
      # header is its manifest's `license`, inherited from the workspace).
      fail "$where: GHOST's own crate declares " . ($expr eq "" ? "no licence" : "'$expr'") . ", not LicenseRef-GHOST-Proprietary (license.workspace = true; G-R5, G-M7)"
        unless $expr eq "LicenseRef-GHOST-Proprietary";
    } elsif ($expr eq "") {
      if ($exc && $exc->{"Cargo.toml"}) { $exc->{"Cargo.toml"}{used} = 1 } else { fail "$where: declares no SPDX licence expression" }
    } else {
      my ($options, $err) = expression_options($expr);
      if (!$options) { fail "$where: licence expression '$expr' does not parse ($err)" }
      elsif (!grep { my $o = $_; !grep { !$allowed->{$_} } @$o } @$options) { fail "$where: no alternative of '$expr' is an allowed licence (deny.toml)" }
    }
    my @files;
    File::Find::find({ no_chdir => 1, wanted => sub {
      if (-d $File::Find::name && basename($File::Find::name) =~ /^(?:target|build|\.git)$/) { $File::Find::prune = 1; return }
      push @files, $File::Find::name if -f $File::Find::name;
    } }, $p->{dir});
    for my $path (sort @files) {
      (my $rel = $path) =~ s{^\Q$p->{dir}\E/}{};
      next if $rel =~ m{^\.cargo_vcs_info\.json$|^\.cargo-ok$};
      my $data = slurp($path);
      next unless defined $data;
      next if index(substr($data, 0, 8192), "\0") >= 0;
      my @why;
      while ($data =~ /SPDX-License-Identifier:\s*([^\n\r*]*)/g) {
        my $v = $1;
        push @why, "SPDX-License-Identifier: $v" if $v =~ /\b(?:A|L)?GPL-[0-9]/;
      }
      if ($data =~ /General\s+Public\s+Licen[cs]e/i) {
        (my $flat = $data) =~ s/^[ \t]*(?:\/\/+!?|#+|\*+|\/\*+|--|;+|%+)[ \t]?//mg;
        $flat =~ s/\s+/ /g;
        push @why, "a GNU licence notice (\"$1\")" if $flat =~ /(under the terms of the GNU (?:Affero |Lesser |Library )?General Public Licen[cs]e)/i;
        push @why, "the text of a GNU licence" if $flat =~ /^\W*(GNU (?:AFFERO |LESSER |LIBRARY )?GENERAL PUBLIC LICEN[CS]E)/i;
      }
      push @why, "a Signal Messenger copyright" if $data =~ /Copyright\b[^\n]{0,80}Signal Messenger/i;
      next unless @why;
      my %u;
      @why = grep { !$u{$_}++ } @why;
      if ($exc && ($exc->{$rel} || $exc->{"*"})) { ($exc->{$rel} // $exc->{"*"})->{used} = 1; next }
      fail "$where: $rel: " . join("; ", @why);
    }
  }
  fail "no shipped Rust package read" unless $count;
  for my $key (sort keys %exceptions) {
    for my $file (sort keys %{ $exceptions{$key} }) {
      fail "rust-license-exceptions.txt: $key $file is not needed (no such package in a shipped graph, or nothing flagged there)" unless $exceptions{$key}{$file}{used};
    }
  }
  finish();
}

# ---------------------------------------------------------------------------------------------
# G-L4: MPL-2.0 packages and their published sources.
sub cmd_mpl {
  my (@args) = @_;
  my $bundle;
  if (@args && $args[0] eq "--bundle") { $bundle = $args[1] // die "--bundle needs a directory\n" }
  my $allowed = allowed_licences();
  my $pkgs = packages();
  my $sums = cargo_lock_checksums();
  my %want;
  for my $p (sorted_packages($pkgs)) {
    my ($options) = expression_options($p->{license});
    next unless $options;
    my %shipped;
    for my $f (package_licence_files($p->{dir}, undef)) { $shipped{$_} = 1 for keys %{ classify_text(slurp("$p->{dir}/$f") // "") } }
    my $elected = elect($options, $allowed, \%shipped) or next;
    $want{"$p->{name} $p->{version}"} = $p if grep { $_ eq "MPL-2.0" } @$elected;
  }
  my %have;
  for (lines_of($ENV{GHOST_MPL_SOURCES} // "$LIC/mpl-sources.txt")) {
    my ($name, $version, $sha) = split " ";
    $have{"$name $version"} = $sha // "";
  }
  for my $key (sort keys %want) {
    my $lock = $sums->{$key};
    if (!defined $have{$key}) { fail "$key is used under MPL-2.0 and missing from ghost/licenses/mpl-sources.txt (with its Cargo.lock checksum $lock)"; next }
    fail "$key: mpl-sources.txt records $have{$key}, Cargo.lock $lock" if !defined $lock || $have{$key} ne $lock;
  }
  for my $key (sort keys %have) { fail "mpl-sources.txt: $key is not an MPL-2.0 package of a shipped graph (remove the line)" unless $want{$key} }
  # [patch] on an MPL crate needs a published diff (ghost/licenses/mpl-patches/<crate>-<version>.diff).
  for my $config ("$ROOT/Cargo.toml", "$ROOT/.cargo/config.toml") {
    my $t = slurp($config) // next;
    while ($t =~ /^\[patch\.[^\]]+\]\n(.*?)(?=^\[|\z)/msg) {
      my $block = $1;
      for my $crate ($block =~ /^([A-Za-z0-9_-]+)\s*=/mg) {
        for my $key (grep { /^\Q$crate\E / } keys %want) {
          (my $diff = $key) =~ s/ /-/;
          fail "$config: [patch] on the MPL-2.0 package $key without a published diff (ghost/licenses/mpl-patches/$diff.diff)" unless -f "$LIC/mpl-patches/$diff.diff";
        }
      }
    }
  }
  if (defined $bundle && !@failures) {
    make_path($bundle);
    for my $key (sort keys %want) {
      my $p = $want{$key};
      my $crate = (sort { $a cmp $b } bsd_glob(cargo_home() . "/registry/cache/*/$p->{name}-$p->{version}.crate"))[0];
      if (!$crate) { fail "$key: no published .crate archive in " . cargo_home() . "/registry/cache"; next }
      my $sha = Digest::SHA->new(256)->addfile($crate, "b")->hexdigest;
      if ($sha ne ($sums->{$key} // "")) { fail "$key: $crate has SHA-256 $sha, Cargo.lock records " . ($sums->{$key} // "none"); next }
      copy($crate, "$bundle/" . basename($crate)) or fail "$key: cannot copy $crate: $!";
    }
  }
  finish();
}

# Rust packages used under Apache-2.0, for scripts/license-upstream-snapshot.sh: ecosystem, name,
# version, repository, published commit, path in the repository (tab-separated).
sub cmd_upstream_candidates {
  my $allowed = allowed_licences();
  my $pkgs = packages();
  for my $p (sorted_packages($pkgs)) {
    my ($options) = expression_options($p->{license});
    next unless $options;
    my %shipped;
    for my $f (package_licence_files($p->{dir}, undef)) { $shipped{$_} = 1 for keys %{ classify_text(slurp("$p->{dir}/$f") // "") } }
    my $elected = elect($options, $allowed, \%shipped) or next;
    next unless grep { $_ eq "Apache-2.0" } @$elected;
    my $vcs = slurp("$p->{dir}/.cargo_vcs_info.json") // "";
    my ($sha) = $vcs =~ /"sha1"\s*:\s*"([0-9a-f]{40})"/;
    my ($path) = $vcs =~ /"path_in_vcs"\s*:\s*"([^"]*)"/;
    print join("\t", "cargo", $p->{name}, $p->{version}, manifest_fields($p->{dir})->{repository} // "-", $sha // "-", $path // ""), "\n";
  }
}

sub cmd_packages {
  my $pkgs = packages();
  print join("\t", $_->{name}, $_->{version}, $_->{license}, $_->{dir}, join(",", sort keys %{ $_->{graphs} })), "\n" for sorted_packages($pkgs);
}

sub cmd_spdx_snapshot {
  my ($crate_dir) = @_;
  my $ids = slurp("$crate_dir/src/identifiers.rs") // die "not an spdx crate: $crate_dir\n";
  my ($list_version) = $ids =~ /pub const VERSION: &str = "([^"]+)"/ or die "no licence-list VERSION in $crate_dir\n";
  my ($crate_version) = (slurp("$crate_dir/Cargo.toml") // "") =~ /^version = "([^"]+)"/m;
  my $allowed = allowed_licences();
  my %want;
  for my $term (keys %$allowed) { my ($b, $x) = split / WITH /, $term; $want{$b} = "licenses"; $want{$x} = "exceptions" if $x }
  remove_tree("$LIC/spdx");
  my $source = "# SPDX licence texts for the licences of the deny.toml allow list (licenses.pl spdx-snapshot).\n"
    . "license-list-version $list_version\n"
    . "source crates.io spdx $crate_version, src/text/{licenses,exceptions}\n";
  my ($archive) = grep { -f $_ } bsd_glob(cargo_home() . "/registry/cache/*/spdx-$crate_version.crate");
  $source .= "crate-sha256 " . Digest::SHA->new(256)->addfile($archive, "b")->hexdigest . "\n" if $archive;
  for my $id (sort keys %want) {
    my $raw = slurp("$crate_dir/src/text/$want{$id}/$id") // die "no text for $id in the spdx crate\n";
    my ($text) = $raw =~ /^r#+"(.*)"#+\s*$/s or die "unexpected text format for $id\n";
    spew("$LIC/spdx/$id.txt", normalize_text($text));
    $source .= "text $id " . Digest::SHA::sha256_hex(normalize_text($text)) . "\n";
  }
  spew($SPDX_VERSION_FILE, $source);
}

my $cmd = shift @ARGV // die "usage: licenses.pl <command> ...\n";
if ($cmd eq "packages") { cmd_packages() }
elsif ($cmd eq "rust-notices") { cmd_rust_notices(@ARGV) }
elsif ($cmd eq "android-notices") { cmd_android_notices(@ARGV) }
elsif ($cmd eq "headers") { cmd_headers() }
elsif ($cmd eq "upstream-candidates") { cmd_upstream_candidates() }
elsif ($cmd eq "mpl") { cmd_mpl(@ARGV) }
elsif ($cmd eq "spdx-snapshot") { cmd_spdx_snapshot(@ARGV) }
else { die "unknown command '$cmd'\n" }
