#!/usr/bin/env bash
# Gate G-L5 (ADR-37, ADR-39; Phase 9 design §2.10.2, §16.2, §22.8.9 point 3): no workflow publishes
# a closed binary.
#   - The repository's visibility is declared in scripts/gates/repository-visibility.txt (one word,
#     `private` or `public`). In GitHub Actions the event payload ($GITHUB_EVENT_PATH) must agree:
#     a repository switched back to public without changing the declaration fails here.
#   - Every actions/upload-artifact step sets `retention-days` to an integer from 1 to 7 (§16.2:
#     every upload has a retention against the artifact storage budget).
#   - A binary upload is one whose artifact name or path names an APK, AAB, AAR, DEX, JAR, a shared
#     library (.so), a jniLibs directory, a Gradle apk/bundle/aar output directory or a disk or
#     container image (.img, .qcow2, .iso, .vhdx, .oci). While the repository is public, no workflow
#     uploads one. While it is private, the only binary uploads allowed are the internal native
#     hand-offs named in HANDOFFS, with `retention-days: 1`, downloaded by a job of the same workflow.
#   - No workflow publishes anything: GitHub releases and release assets, GitHub Pages, container
#     registry pushes, Gradle or Cargo publication (release signing and distribution are offline,
#     FR-8.2, ADR-07).
# Comment lines never satisfy or break a rule. Fixture roots mirror the repository:
# GHOST_ROOT=<root>/ghost, workflows in <root>/.github/workflows
# (test-harness/gates/no-public-binaries/README.md).
# Self-test hook: GHOST_VISIBILITY_EVENT names the event payload to compare with the declaration
# (default $GITHUB_EVENT_PATH; set and empty: no comparison).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
GHOST_ROOT="$(cd "$GHOST_ROOT" && pwd)"
REPO_ROOT="$(cd "$GHOST_ROOT/.." && pwd)"
DECLARATION="$GHOST_ROOT/scripts/gates/repository-visibility.txt"
WORKFLOWS="$REPO_ROOT/.github/workflows"
if [ -n "${GHOST_VISIBILITY_EVENT+x}" ]; then EVENT="$GHOST_VISIBILITY_EVENT"; else EVENT="${GITHUB_EVENT_PATH:-}"; fi
# Internal native hand-offs (§22.8.9 point 3): android-native builds libghost_client_net.so twice and
# hands the checked bytes to the android and reproducible jobs of the same run.
HANDOFFS="ghost-client-net-jniLibs"

visibility=""
if [ ! -f "$DECLARATION" ]; then
  fail "scripts/gates/repository-visibility.txt missing: declare the repository private or public"
else
  visibility="$(grep -vE '^\s*(#|$)' "$DECLARATION" | tr -d '[:space:]')"
  case "$visibility" in
    private|public) ;;
    *) fail "scripts/gates/repository-visibility.txt: '$visibility' is neither private nor public"; visibility="" ;;
  esac
fi
if [ -n "$visibility" ] && [ -n "$EVENT" ]; then
  if [ ! -r "$EVENT" ]; then
    fail "event payload $EVENT is not readable"
  else
    event_private="$(perl -MJSON::PP -e '
      local $/; open my $fh, "<", $ARGV[0] or exit 2; my $e = JSON::PP->new->decode(<$fh>);
      my $p = $e->{repository}{private}; print defined $p ? ($p ? "private" : "public") : "unknown";' "$EVENT" 2>/dev/null || echo unknown)"
    case "$event_private" in
      private|public)
        [ "$event_private" = "$visibility" ] || fail "the event payload says the repository is $event_private; scripts/gates/repository-visibility.txt declares it $visibility" ;;
      *) fail "event payload $EVENT does not state the repository's visibility" ;;
    esac
  fi
fi

if [ ! -d "$WORKFLOWS" ]; then
  fail ".github/workflows missing"
  finish no-public-binaries
fi
rc=0
rules="$(VISIBILITY="$visibility" HANDOFFS="$HANDOFFS" REPO_ROOT="$REPO_ROOT" perl -e '
use strict; use warnings;
my $visibility = $ENV{VISIBILITY} // "";
my %handoff = map { $_ => 1 } split " ", $ENV{HANDOFFS};
my $binary = qr{\.(?:apk|aab|aar|dex|jar|so|img|qcow2|iso|vhdx|oci)(?:\b|$)|\.so\.|jniLibs|outputs/(?:apk|bundle|aar)\b}i;
my $publish = qr{\b(?:gh\s+release\s+(?:create|upload|edit)|docker\s+(?:image\s+)?push|docker/build-push-action|softprops/action-gh-release|actions/create-release|actions/upload-release-asset|ncipollo/release-action|actions/deploy-pages|peaceiris/actions-gh-pages|JamesIves/github-pages-deploy-action|gradlew?\s+(?:\S+\s+)*publish\w*|cargo\s+publish)\b};
for my $file (sort glob("$ENV{REPO_ROOT}/.github/workflows/*.{yml,yaml}")) {
  (my $rel = $file) =~ s{^\Q$ENV{REPO_ROOT}\E/}{};
  open my $fh, "<", $file or do { print "$rel: unreadable\n"; next };
  my @lines = <$fh>;
  close $fh;
  chomp @lines;
  s/\r$// for @lines;
  my (@steps, %downloads);
  for my $i (0 .. $#lines) {
    my $l = $lines[$i];
    next if $l =~ /^\s*#/;
    print "$rel:", $i + 1, ": publishes outside the repository ($&)\n" if $l =~ $publish;
    next unless $l =~ /^(\s*)-\s+\S/;
    my $indent = length $1;
    my $end = $i;
    for my $j ($i + 1 .. $#lines) {
      my $m = $lines[$j];
      next if $m =~ /^\s*(?:#|$)/;
      $m =~ /^(\s*)/;
      last if length($1) <= $indent;
      $end = $j;
    }
    push @steps, [$i, $end];
  }
  my @uploads;
  for my $s (@steps) {
    my ($from, $to) = @$s;
    my @body = @lines[$from .. $to];
    my $uses = join("\n", grep { !/^\s*#/ } @body);
    my $kind = $uses =~ /^\s*(?:-\s+)?uses:\s*actions\/upload-artifact@/m ? "upload"
             : $uses =~ /^\s*(?:-\s+)?uses:\s*actions\/download-artifact@/m ? "download" : next;
    my ($name, $retention, @paths, $with_indent, $in_path, $path_indent);
    for my $k (0 .. $#body) {
      my $l = $body[$k];
      next if $l =~ /^\s*(?:#|$)/;
      $l =~ /^(\s*)/;
      my $ind = length $1;
      if ($l =~ /^(\s*)with:\s*$/) { $with_indent = length $1; $in_path = 0; next }
      next unless defined $with_indent;
      if ($ind <= $with_indent) { undef $with_indent; $in_path = 0; next }
      if ($in_path && $ind > $path_indent) { (my $p = $l) =~ s/^\s+//; push @paths, $p; next }
      $in_path = 0;
      if ($l =~ /^(\s*)name:\s*(.*?)\s*$/) { ($name = $2) =~ s/^["\x27]|["\x27]$//g; next }
      if ($l =~ /^\s*retention-days:\s*(.*?)\s*$/) { $retention = [$1, $from + $k + 1]; next }
      if ($l =~ /^(\s*)path:\s*(.*?)\s*$/) {
        my ($pi, $v) = (length $1, $2);
        if ($v =~ /^[|>][-+]?$/) { $in_path = 1; $path_indent = $pi } else { push @paths, $v }
      }
    }
    if ($kind eq "download") { $downloads{$name} = 1 if defined $name; next }
    push @uploads, { line => $from + 1, name => $name // "", retention => $retention, paths => \@paths };
  }
  for my $u (@uploads) {
    my $where = "$rel:$u->{line}";
    my $label = $u->{name} ne "" ? "artifact \x27$u->{name}\x27" : "an unnamed artifact";
    my $days;
    if (!defined $u->{retention}) {
      print "$where: $label sets no retention-days (1 to 7)\n";
    } elsif ($u->{retention}[0] !~ /^[1-7]$/) {
      print "$rel:$u->{retention}[1]: $label: retention-days \x27$u->{retention}[0]\x27 is not an integer from 1 to 7\n";
    } else {
      $days = $u->{retention}[0];
    }
    my $is_binary = grep { $_ =~ $binary } ($u->{name}, @{ $u->{paths} });
    next unless $is_binary;
    if ($visibility ne "private") {
      print "$where: $label uploads binaries (APK, AAR, .so, jniLibs or an image) while the repository is not declared private\n";
      next;
    }
    if (!$handoff{$u->{name}}) {
      print "$where: $label uploads binaries and is not an internal native hand-off ($ENV{HANDOFFS})\n";
      next;
    }
    print "$where: hand-off $label must set retention-days: 1\n" if defined $days && $days ne "1";
    print "$where: hand-off $label: no job of this workflow downloads it\n" unless $downloads{$u->{name}};
  }
}
')" || rc=$?
# The rule engine reports every violation on stdout and ends with status 0: any other status means it
# could not run, and the gate fails closed rather than reporting a workflow set it never read.
[ "$rc" = 0 ] || fail "no-public-binaries.sh rule engine stopped (exit $rc)"
while IFS= read -r line; do
  [ -n "$line" ] && fail "$line"
done <<< "$rules"
finish no-public-binaries
