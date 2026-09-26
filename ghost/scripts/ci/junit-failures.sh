#!/usr/bin/env bash
# Prints the failed and errored test cases of JUnit XML reports as Markdown, for a CI job summary
# (Phase 9 design §22.33). A job whose test reports cannot be uploaded (the artifact storage quota
# stopped every upload from 2026-09-20) must still say *why* a test failed: the first gate-scale run
# of the DM privacy world failed on all ten seed pairs with a bare `java.sql.SQLException at
# DmPrivacyWorldTest.kt:33` in the log and its stack trace only in the report nobody could download.
#
# Usage: junit-failures.sh <directory of TEST-*.xml>...   (exit 0 whatever it finds; prints nothing
# when no case failed; at most the first 40 lines of each failure's stack trace)
set -uo pipefail
for dir in "$@"; do
  [ -d "$dir" ] || continue
  find "$dir" -type f -name 'TEST-*.xml' -print0 2>/dev/null | sort -z | xargs -0 -r perl -e '
    use strict; use warnings;
    for my $file (@ARGV) {
      open my $fh, "<", $file or next; local $/; my $x = <$fh>; close $fh;
      # A passing case is self-closing (`<testcase ... />`) and must not open a match that would run
      # on into the body of the next case and name the wrong test.
      while ($x =~ m{<testcase\s+name="([^"]*)"\s+classname="([^"]*)"[^>]*?(?<!/)>(.*?)</testcase>}gs) {
        my ($name, $class, $body) = ($1, $2, $3);
        next unless $body =~ m{<(failure|error)\s+message="([^"]*)"[^>]*>(.*?)</\1>}s;
        my ($kind, $message, $trace) = ($1, $2, $3);
        for ($message, $trace) {
          s/&lt;/</g; s/&gt;/>/g; s/&quot;/"/g; s/&#39;/\x27/g; s/&apos;/\x27/g; s/&#10;/\n/g; s/&amp;/&/g;
        }
        my @lines = split /\n/, $trace;
        splice @lines, 40 if @lines > 40;
        print "### $kind: $class.$name\n\n";
        print "```\n", join("\n", @lines), "\n```\n\n";
      }
    }' 2>/dev/null
done
exit 0
